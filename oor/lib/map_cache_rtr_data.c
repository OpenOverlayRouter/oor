/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "map_cache_entry.h"
#include "map_cache_rtr_data.h"
#include "oor_log.h"
#include "timers_utils.h"
#include "util.h"


/************************** Function declaration *****************************/

int _mc_rtr_data_nat_update(mcache_entry_t *mc, mapping_t *rcv_map, lisp_addr_t *rtr_addr,
        lisp_addr_t *xTR_pub_addr, uint16_t xTR_port, lisp_addr_t *xTR_prv_addr,
        lisp_xtr_id *xtr_id);

rloc_nat_data_t *rloc_nat_data_new_init(lisp_addr_t *rtr_addr, lisp_addr_t *xTR_pub_addr,
        uint16_t xTR_port, lisp_addr_t *xTR_prv_addr, lisp_xtr_id *xtr_id,
        uint8_t priority, uint8_t weight);
void rloc_nat_data_destroy(rloc_nat_data_t *rloc_nat_data);

/*****************************************************************************/

inline mc_rtr_data_t *
mc_rtr_data_new()
{
    return (xzalloc(sizeof(mc_rtr_data_t)));
}

mc_rtr_data_t *
mc_rtr_data_nat_new()
{
    mc_rtr_nat_data_t *nat_data;
    mc_rtr_data_t *rtr_data;

    rtr_data = mc_rtr_data_new();
    if (!rtr_data ){
        return (NULL);
    }
    nat_data = xzalloc(sizeof(mc_rtr_nat_data_t));
    if (!nat_data ){
        return (NULL);
    }
    rtr_data->nat_data = nat_data;
    nat_data->xtrid_to_nat = shash_new_managed((free_value_fn_t)glist_destroy);
    nat_data->loc_to_nat_data = htable_ptrs_new();

    return(rtr_data);
}

void
mc_rtr_data_destroy(mc_rtr_data_t *mc)
{
    if(!mc){
        return;
    }
    if (mc->nat_data){
        shash_destroy(mc->nat_data->xtrid_to_nat);
        htable_ptrs_destroy(mc->nat_data->loc_to_nat_data);
        free(mc->nat_data);
    }
    free(mc);
}

rloc_nat_data_t *
rloc_nat_data_new_init(lisp_addr_t *rtr_addr,
        lisp_addr_t *xTR_pub_addr, uint16_t xTR_port, lisp_addr_t *xTR_prv_addr,
        lisp_xtr_id *xtr_id, uint8_t priority, uint8_t weight)
{
    rloc_nat_data_t *rloc_nat_data;

    rloc_nat_data = xzalloc(sizeof(rloc_nat_data_t));
    if (!rloc_nat_data){
        return (NULL);
    }
    rloc_nat_data->pub_addr = lisp_addr_clone(xTR_pub_addr);
    rloc_nat_data->priv_addr = lisp_addr_clone(xTR_prv_addr);
    rloc_nat_data->rtr_rloc = lisp_addr_clone(rtr_addr);
    rloc_nat_data->pub_port = xTR_port;
    memcpy(&rloc_nat_data->xtr_id, xtr_id, sizeof(lisp_xtr_id));
    rloc_nat_data->priority = priority;
    rloc_nat_data->weight = weight;

    return (rloc_nat_data);
}

void
rloc_nat_data_destroy(rloc_nat_data_t *rloc_nat_data)
{
    stop_timers_from_obj(rloc_nat_data,ptrs_to_timers_ht, nonces_ht);
    lisp_addr_del(rloc_nat_data->priv_addr);
    lisp_addr_del(rloc_nat_data->pub_addr);
    lisp_addr_del(rloc_nat_data->rtr_rloc);
    free(rloc_nat_data);
}

char *
rloc_nat_data_to_char(rloc_nat_data_t *rloc_nat_data)
{
    static char buf[3][1000];
    size_t buf_size = sizeof(buf[0]);
    static int i=0;

    /* hack to allow more than one locator per line */
    i++; i = i % 3;
    *buf[i] = '\0';
    if (!rloc_nat_data){
        sprintf(buf[i], "_NULL_");
        return (buf[i]);
    }
    snprintf(buf[i] + strlen(buf[i]),buf_size - strlen(buf[i]),""
            "xTR -> Priv addr: %s, Pub addr: %s,  Port: %d | RTR addr: %s | p: %d , w: %d",
            lisp_addr_to_char(rloc_nat_data->priv_addr),lisp_addr_to_char(rloc_nat_data->pub_addr),
            rloc_nat_data->pub_port,lisp_addr_to_char(rloc_nat_data->rtr_rloc),rloc_nat_data->priority,
            rloc_nat_data->weight);

    return (buf[i]);
}


int
_mc_rtr_data_nat_update(mcache_entry_t *mce, mapping_t *rcv_map, lisp_addr_t *rtr_addr,
        lisp_addr_t *xTR_pub_addr, uint16_t xTR_port, lisp_addr_t *xTR_prv_addr,
        lisp_xtr_id *xtr_id)
{
    mc_rtr_data_t *rtr_data = mce->dev_specific_data;
    locator_t *loct;
    locator_t *emr_loct = NULL; // Locator from where we received EMReg
    uint8_t  match;
    glist_t *xtrid_nat_locts, *match_nat_locts; // <rloc_nat_data_t>
    glist_entry_t *nat_it, *aux_nat_it;
    rloc_nat_data_t *nat_loct_data, *new_nat_loct_data = NULL;

    /* Get the nat locator data list already learned from previous Encap Map Reg associated
     * to the xTR-ID. If it doesn't exist, create it*/
    xtrid_nat_locts = shash_lookup(rtr_data->nat_data->xtrid_to_nat,get_char_from_xTR_ID(xtr_id));
    if (!xtrid_nat_locts){
        OOR_LOG(LDBG_3, "_mc_rtr_data_nat_update: Added xtr-id %s to the EID prefix %s", get_char_from_xTR_ID(xtr_id),
                lisp_addr_to_char(mapping_eid(rcv_map)));
        xtrid_nat_locts = glist_new_managed((glist_del_fct)rloc_nat_data_destroy);
        shash_insert(rtr_data->nat_data->xtrid_to_nat,strdup(get_char_from_xTR_ID(xtr_id)),xtrid_nat_locts);
        xtrid_nat_locts = shash_lookup(rtr_data->nat_data->xtrid_to_nat,get_char_from_xTR_ID(xtr_id));
    }
    /* Update the nat locator data with the information of the locators of the received mapping.
     * Only update the information of the existing nat data locators, except the locator that
     * generates Encap map registration. In that case, we can generate the nat data locator.*/

    match_nat_locts = glist_new();
    mapping_foreach_active_locator(rcv_map, loct){
        if (locator_R_bit(loct) == 0){
            // Check if this is the locator from where we receive the EMReg
            if (lisp_addr_cmp(locator_addr(loct),xTR_prv_addr) == 0){
                emr_loct = loct;
            }
            match = FALSE;
            glist_for_each_entry(nat_it,xtrid_nat_locts){
                nat_loct_data = (rloc_nat_data_t *)glist_entry_data(nat_it);
                // The nat locator data correspond to the mapping locator if the private
                // address and the locator address are the same
                if (lisp_addr_cmp(locator_addr(loct),nat_loct_data->priv_addr) == 0){
                    match = TRUE;
                    nat_loct_data->priority = locator_priority(loct);
                    nat_loct_data->weight = locator_weight(loct);
                    glist_add(nat_loct_data, match_nat_locts);
                    break;
                }
            }
            /* Only add a new nat locator data for the locator which sends the EMreg */
            if (match == FALSE && emr_loct){
                new_nat_loct_data = rloc_nat_data_new_init(rtr_addr, xTR_pub_addr, xTR_port,
                        xTR_prv_addr,xtr_id,locator_priority(loct),locator_weight(loct));
                glist_add(new_nat_loct_data, match_nat_locts);
                // add the new nat loct to xtrid_nat_locts outside the bucle to not affect it
                OOR_LOG(LDBG_2,"New NAT info created using Map Notify: %s", rloc_nat_data_to_char(new_nat_loct_data));
            }
            emr_loct = NULL;
        }
    }mapping_foreach_active_locator_end;
    if (new_nat_loct_data){
        glist_add(new_nat_loct_data, xtrid_nat_locts);
    }
    /* If match_nat_locts empty (xTR no include in the mapping of the Map Reg the locators
     * behind nat), use private/internal address to update or create the nat locator data */
    if (glist_size(match_nat_locts) == 0){
        match = FALSE;
        glist_for_each_entry(nat_it,xtrid_nat_locts){
            nat_loct_data = (rloc_nat_data_t *)glist_entry_data(nat_it);
            if (lisp_addr_cmp(xTR_prv_addr,nat_loct_data->priv_addr) == 0){
                match = TRUE;
                // XXX May be we should use the priority and weight of the RTR loct of the mapping
                nat_loct_data->priority = 1;
                nat_loct_data->weight = 100;
                break;
            }
        }
        if (match == FALSE){
            new_nat_loct_data = rloc_nat_data_new_init(rtr_addr, xTR_pub_addr, xTR_port,
                    xTR_prv_addr,xtr_id,locator_priority(loct),locator_weight(loct));
            glist_add(new_nat_loct_data, xtrid_nat_locts);
            OOR_LOG(LDBG_2,"New NAT info created using Map Notify:: %s", rloc_nat_data_to_char(new_nat_loct_data));
        }
    }else{
        /* Remove nat locators that are configured but they are not present in the mapping */
        glist_for_each_entry_safe(nat_it,aux_nat_it,xtrid_nat_locts){
            nat_loct_data = (rloc_nat_data_t *)glist_entry_data(nat_it);
            if (!glist_contain(nat_loct_data,match_nat_locts)){
                /* Timers are destroyed using the function defined in the list */
                glist_remove_obj(nat_loct_data, xtrid_nat_locts);
            }
        }
    }
    glist_destroy(match_nat_locts);
    return (GOOD);
}

int
mc_rtr_data_mapping_update(mcache_entry_t *mc, mapping_t *rcv_map, lisp_addr_t *rtr_addr,
        lisp_addr_t *xTR_pub_addr, uint16_t xTR_port, lisp_addr_t *xTR_prv_addr,
        lisp_xtr_id *xtr_id)
{
    mc_rtr_data_t *rtr_data = mc->dev_specific_data;
    mapping_t *aux_map, *map;
    htable_ptrs_t *aux_loc_to_nat_data;
    glist_t *xtrid_nat_locts_lists, *nat_locts_lst, *xtr_ids_list;
    glist_entry_t *lst_it, *nat_loct_it, *xtrid_it;
    rloc_nat_data_t *nat_loct_data;
    locator_t *loct;
    char * xtr_id_str;

    map = mcache_entry_mapping(mc);
    /* It doesn't clone the locators list */
    aux_map = mapping_clone(map);
    aux_loc_to_nat_data = htable_ptrs_new();

    if (_mc_rtr_data_nat_update(mc, rcv_map, rtr_addr, xTR_pub_addr, xTR_port,
            xTR_prv_addr,xtr_id) != GOOD){
        return (BAD);
    }

    /* With the updated nat information, we generate an aux mapping and htable for locators
     * to rloc_nat_data */
    xtrid_nat_locts_lists = shash_values(rtr_data->nat_data->xtrid_to_nat);
    glist_for_each_entry(lst_it,xtrid_nat_locts_lists){
        nat_locts_lst = (glist_t *)glist_entry_data(lst_it);
        glist_for_each_entry(nat_loct_it,nat_locts_lst){
            nat_loct_data = (rloc_nat_data_t *)glist_entry_data(nat_loct_it);
            loct = locator_new_init(nat_loct_data->priv_addr,UP,0,1,nat_loct_data->priority,
                    nat_loct_data->weight,255,0);
            mapping_add_locator(aux_map,loct);
            htable_ptrs_insert(aux_loc_to_nat_data, (void *)loct, nat_loct_data);
        }
    }
    glist_destroy(xtrid_nat_locts_lists);

    /* If the generated mapping is different from the one already created, update it */
    if (mapping_cmp(aux_map,map) != 0){
        htable_ptrs_destroy(rtr_data->nat_data->loc_to_nat_data);
        mapping_del(map);
        mc->mapping = aux_map;
        rtr_data->nat_data->loc_to_nat_data = aux_loc_to_nat_data;
        /* LOG information */
        OOR_LOG(LDBG_2,"mc_rtr_data_mapping_update: NAT info updated for EID %s", lisp_addr_to_char(mapping_eid(aux_map)));
        xtr_ids_list = shash_keys(rtr_data->nat_data->xtrid_to_nat);
        glist_for_each_entry(xtrid_it, xtr_ids_list){
            xtr_id_str = (char *)glist_entry_data(xtrid_it);
            OOR_LOG(LDBG_2,"  Locators nat info from xtr %s:",xtr_id_str);
            nat_locts_lst = (glist_t *)shash_lookup(rtr_data->nat_data->xtrid_to_nat,xtr_id_str);
            glist_dump(nat_locts_lst, (glist_to_char_fct)rloc_nat_data_to_char, LDBG_2);
        }
        glist_destroy(xtr_ids_list);
        OOR_LOG(LDBG_2,"mc_rtr_data_mapping_update: The auxiliar mapping is: %s",mapping_to_char(aux_map));

        return (UPDATED);
    }
    OOR_LOG(LDBG_2,"mc_rtr_data_mapping_update: No changes in NAT info");

    mapping_del(aux_map);
    htable_ptrs_destroy(aux_loc_to_nat_data);
    return (GOOD);
}

int
mc_rm_rtr_rloc_nat_data(mcache_entry_t *mce, rloc_nat_data_t *rloc_nat_data)
{
    mc_rtr_data_t *rtr_data = mce->dev_specific_data;
    glist_t *loct_lst, *xtrid_rloc_nat_lst;
    glist_entry_t *loct_it;
    locator_t *loct;
    mapping_t *map = mcache_entry_mapping(mce);

    OOR_LOG(LDBG_2,"Removing entry for xTR-ID %s and local locator address %s of the Map Cache entry with EID %s",
            get_char_from_xTR_ID(&rloc_nat_data->xtr_id), lisp_addr_to_char(rloc_nat_data->priv_addr),
            lisp_addr_to_char(mapping_eid(map)));

    loct_lst = htable_ptrs_keys(rtr_data->nat_data->loc_to_nat_data);
    glist_for_each_entry(loct_it,loct_lst){
        loct = (locator_t *)glist_entry_data(loct_it);
        if (htable_ptrs_lookup(rtr_data->nat_data->loc_to_nat_data,loct) == rloc_nat_data){
            htable_ptrs_remove(rtr_data->nat_data->loc_to_nat_data, loct);
            mapping_remove_locator(map,loct);
            break;
        }
    }
    glist_destroy(loct_lst);
    xtrid_rloc_nat_lst = shash_lookup(rtr_data->nat_data->xtrid_to_nat, get_char_from_xTR_ID(&rloc_nat_data->xtr_id));
    glist_remove_obj_with_ptr(rloc_nat_data, xtrid_rloc_nat_lst);
    return (GOOD);
}

rloc_nat_data_t *
mc_rtr_data_get_rloc_nat_data(mcache_entry_t *mc, lisp_xtr_id *xtr_id, lisp_addr_t *xTR_prv_addr)
{
    mc_rtr_data_t *rtr_data = mc->dev_specific_data;
    glist_t *xtrid_nat_locts;
    glist_entry_t *lst_it;
    rloc_nat_data_t *nat_loct_data;

    xtrid_nat_locts = shash_lookup(rtr_data->nat_data->xtrid_to_nat,get_char_from_xTR_ID(xtr_id));
    if (!xtrid_nat_locts){
        goto not_found;
    }
    glist_for_each_entry(lst_it,xtrid_nat_locts){
        nat_loct_data = (rloc_nat_data_t *)glist_entry_data(lst_it);
        if (lisp_addr_cmp(nat_loct_data->priv_addr,xTR_prv_addr) == 0){
            return (nat_loct_data);
        }
    }
not_found:
    OOR_LOG(LDBG_2,"RTR Nat info for locator %s of the xTR-ID %s not found", lisp_addr_to_char(xTR_prv_addr),
            get_char_from_xTR_ID(xtr_id));
    return (NULL);
}


