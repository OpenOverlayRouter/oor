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

#include "oor_log.h"
#include "map_local_entry.h"
#include "timers_utils.h"
#include "../defs.h"

static nat_info_t * nat_info_new();
static void nat_info_del(nat_info_t *nat_info);

inline mapping_t *
map_local_entry_mapping(map_local_entry_t *mle)
{
    return (mle->mapping);
}

inline void
map_local_entry_set_mapping(
        map_local_entry_t *mle,
        mapping_t *map)
{
    mle->mapping = map;
}

inline void *
map_local_entry_fwd_info(map_local_entry_t *mle)
{
    return (mle->fwd_info);
}

inline void
map_local_entry_set_fwd_info(
        map_local_entry_t *mle,
        void *fwd_info,
        fwd_info_del_fct fwd_del_fct)
{
    mle->fwd_info = fwd_info;
    if (fwd_del_fct == NULL){
        OOR_LOG(LDBG_1, "map_local_entry_set_fwd_info: No specified function to delete fwd info.");
    }
    mle->fwd_inf_del = fwd_del_fct;
}

inline lisp_addr_t *
map_local_entry_eid(map_local_entry_t *mle){
    return (mapping_eid(map_local_entry_mapping(mle)));
}

map_local_entry_t *
map_local_entry_new()
{
	map_local_entry_t *mle;
	mle = xzalloc(sizeof(map_local_entry_t));

	return (mle);
}

map_local_entry_t *
map_local_entry_new_init(mapping_t *map)
{
    map_local_entry_t *mle;
    mle = xzalloc(sizeof(map_local_entry_t));
    if (mle == NULL){
        OOR_LOG(LDBG_1, "map_local_entry_new_init: Can't create local database mapping with EID prefix %s.",
            lisp_addr_to_char(mapping_eid(map)));
        return (NULL);
    }
    mle->mapping = map;
    mle->nat_info = nat_info_new();

    return (mle);
}

void
map_local_entry_init(map_local_entry_t *mle, mapping_t *map)
{
	mle->mapping = map;
}

void
map_local_entry_del(map_local_entry_t *mle)
{
    locator_t *loct;

    assert(mle);
    mapping_foreach_locator(map_local_entry_mapping(mle),loct){
        stop_timers_from_obj(loct,ptrs_to_timers_ht, nonces_ht);
    }mapping_foreach_locator_end;
    stop_timers_from_obj(mle,ptrs_to_timers_ht, nonces_ht);
	mapping_del(mle->mapping);
	if (mle->fwd_info != NULL){
	    mle->fwd_inf_del(mle->fwd_info);
	}
	nat_info_del(mle->nat_info);

	free(mle);
}

void
map_local_entry_dump(map_local_entry_t *mle, int log_level)
{
	// TODO
    OOR_LOG(log_level,mapping_to_char(mle->mapping));
}

char *
map_local_entry_to_char(map_local_entry_t *mle)
{
    // TODO
    return (mapping_to_char(mle->mapping));
}



static nat_info_t *
nat_info_new()
{
    nat_info_t *nat_info;

    nat_info = xmalloc(sizeof(nat_info_t));
    if (!nat_info){
        return (NULL);
    }
    nat_info->loct_addr_to_rtrs = shash_new_managed((free_value_fn_t)glist_destroy);
    nat_info->rtr_addr_to_locts = shash_new_managed((free_value_fn_t)glist_destroy);

    return(nat_info);
}

static void
nat_info_del(nat_info_t *nat_info)
{
    shash_destroy(nat_info->loct_addr_to_rtrs);
    shash_destroy(nat_info->rtr_addr_to_locts);
    free(nat_info);
}


void
mle_nat_info_update(map_local_entry_t *mle, locator_t *loct, glist_t *new_rtr_list)
{
    nat_info_t *nat_info = mle->nat_info;
    glist_t *loct_list;
    glist_t *rtr_list;
    glist_entry_t *rtr_it;
    mapping_t * map = map_local_entry_mapping(mle);
    locator_t * rtr_loct;
    lisp_addr_t *loct_addr = locator_addr(loct), *rtr_addr;

    rtr_list = shash_lookup(nat_info->loct_addr_to_rtrs, lisp_addr_to_char(loct_addr));
    /* If we already have information of the RTRs for this locator, we have to
     * remove it before we can update it */
    if (rtr_list){
        glist_for_each_entry(rtr_it, rtr_list){
            rtr_addr = (lisp_addr_t *)glist_entry_data(rtr_it);
            /* Remove loctor from list of locators associated to the rtr */
            loct_list = shash_lookup(nat_info->rtr_addr_to_locts,lisp_addr_to_char(rtr_addr));
            glist_remove_obj_with_ptr(loct,loct_list);
            if(glist_size(loct_list) == 0){
                shash_remove(nat_info->rtr_addr_to_locts,lisp_addr_to_char(rtr_addr));
                /* The RTR is not associated with any loctor. Remove the rtr locator from the mapping */
                rtr_loct = mapping_get_loct_with_addr(map, rtr_addr);
                mapping_remove_locator(map,rtr_loct);
            }
        }
        glist_destroy(rtr_list);
    }

    /* Update the nat information with the new list */
    rtr_list = glist_clone(new_rtr_list,(glist_clone_obj)lisp_addr_clone);
    shash_insert(
            nat_info->loct_addr_to_rtrs,
            strdup(lisp_addr_to_char(loct_addr)),
            rtr_list);

    glist_for_each_entry(rtr_it, rtr_list){
        rtr_addr = (lisp_addr_t *)glist_entry_data(rtr_it);
        loct_list = shash_lookup(nat_info->rtr_addr_to_locts,lisp_addr_to_char(rtr_addr));
        if (!loct_list){
            loct_list = glist_new();
            shash_insert(
                    nat_info->rtr_addr_to_locts,
                    strdup(lisp_addr_to_char(rtr_addr)),
                    loct_list);
        }
        glist_add(loct,loct_list);
        /* Create the logical locator for the RTR -> L=0, R=1 */
        rtr_loct = locator_new_init(rtr_addr,UP,0,1,1,100,255,0);
        mapping_add_locator(map,rtr_loct);
    }
}

glist_t *
mle_rtr_addr_list(map_local_entry_t *mle)
{
    glist_t *rtr_addr_lst, *rtr_str_addr_lst;
    glist_entry_t *rtr_addr_it;
    lisp_addr_t * rtr_addr;
    char *rtr_str_addr;

    rtr_addr_lst = glist_new_managed((glist_del_fct)lisp_addr_del);
    rtr_str_addr_lst = shash_keys(mle->nat_info->rtr_addr_to_locts);
    glist_for_each_entry(rtr_addr_it, rtr_str_addr_lst){
       rtr_str_addr = (char *)glist_entry_data(rtr_addr_it);
       rtr_addr = lisp_addr_new();
       lisp_addr_ip_from_char(rtr_str_addr,rtr_addr);
       glist_add (rtr_addr, rtr_addr_lst);
    }
    glist_destroy(rtr_str_addr_lst);
    return (rtr_addr_lst);
}

