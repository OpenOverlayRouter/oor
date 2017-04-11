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

#include "flow_balancing.h"
#include "fwd_entry_tuple.h"
#include "../balancing_locators.h"
#include "../fwd_addr_func.h"
#include "../fwd_policy.h"
#include "../../lib/oor_log.h"
#include "../../liblisp/liblisp.h"
#include "../../control/oor_ctrl_device.h"

fb_dev_parm *fb_dev_parm_new();
void *fb_new_dev_policy_inf(oor_ctrl_dev_t *ctrl_dev,
        fwd_policy_dev_parm *dev_parm_inf);
void fb_del_dev_policy_inf(void *dev_parm);
int fb_init_map_loc_policy_inf(void *dev_parm, map_local_entry_t *mle,
        fwd_policy_map_parm *map_parm);
int fb_init_map_cache_policy_inf(void *dev_parm, mcache_entry_t *mce);
int fb_get_fwd_entry(void *fwd_dev_parm,  map_local_entry_t *mle, mcache_entry_t *mce,
        mcache_entry_t *petrs, packet_tuple_t *tuple, fwd_info_t *fwd_info);
int fb_get_fwd_entry_2(void *fwd_dev_parm,  map_local_entry_t *mle, mcache_entry_t *mce,
        packet_tuple_t *tuple, fwd_info_t *fwd_info);


int fb_updated_map_loc_inf(void *dev_parm, map_local_entry_t *mle);
int fb_updated_map_cache_inf(void *dev_parm, mcache_entry_t *mce);


fwd_policy_class  fwd_policy_flow_balancing = {
        .new_dev_policy_inf = fb_new_dev_policy_inf,
        .del_dev_policy_inf = fb_del_dev_policy_inf,
        .init_map_loc_policy_inf = fb_init_map_loc_policy_inf,
        .del_map_loc_policy_inf = balancing_locators_vecs_del,
        .init_map_cache_policy_inf = fb_init_map_cache_policy_inf,
        .del_map_cache_policy_inf = balancing_locators_vecs_del,
        .updated_map_loc_inf = fb_updated_map_loc_inf,
        .updated_map_cache_inf = fb_updated_map_cache_inf,
        .get_fwd_info = fb_get_fwd_entry,
        .get_fwd_ip_addr = laddr_get_fwd_ip_addr
};


fb_dev_parm *
fb_dev_parm_new()
{
    fb_dev_parm *dev_parm;
    dev_parm = (fb_dev_parm *)xzalloc(sizeof(fb_dev_parm));
    if(dev_parm == NULL){
        OOR_LOG(LWRN, "fb_dev_parm_new: Couldn't allocate memory for fb_dev_parm");
    }

    return(dev_parm);
}

void *
fb_new_dev_policy_inf(oor_ctrl_dev_t *ctrl_dev,
        fwd_policy_dev_parm *dev_parm_inf)
{
    fb_dev_parm *   dev_parm;

    dev_parm = fb_dev_parm_new();
    if(dev_parm == NULL){
        return (NULL);
    }
    dev_parm->dev_type = ctrl_dev_mode(ctrl_dev);
    dev_parm->loc_loct = ctrl_rlocs(ctrl_dev_ctrl(ctrl_dev));

    return(dev_parm);
}

inline void
fb_del_dev_policy_inf(void *dev_parm)
{
    free((fb_dev_parm *)dev_parm);
}



int
fb_init_map_loc_policy_inf(void *dev_parm, map_local_entry_t *mle, fwd_policy_map_parm *map_parm)
{
    fb_dev_parm *dev_p = (fb_dev_parm *)dev_parm;
    void * fwd_inf = balancing_locators_vecs_new_init(map_local_entry_mapping(mle),dev_p->loc_loct,FALSE);
    if (!fwd_inf){
        return (BAD);
    }
    map_local_entry_set_fwd_info(mle, fwd_inf, balancing_locators_vecs_del);
    return (GOOD);
}

int
fb_init_map_cache_policy_inf(void *dev_parm, mcache_entry_t *mce)
{
    fb_dev_parm *dev_p = (fb_dev_parm *)dev_parm;
    void * routing_inf =  balancing_locators_vecs_new_init(mcache_entry_mapping(mce),dev_p->loc_loct,TRUE);
    if (!routing_inf){
        return (BAD);
    }
    mcache_entry_set_routing_info(mce, routing_inf, balancing_locators_vecs_del);
    return (GOOD);
}


int
fb_updated_map_loc_inf(void *dev_parm,map_local_entry_t *mle){
    fb_dev_parm *dev_p = (fb_dev_parm *)dev_parm;
    return (balancing_vectors_calculate(map_local_entry_fwd_info(mle),
            map_local_entry_mapping(mle),dev_p->loc_loct,FALSE));
}

int
fb_updated_map_cache_inf(void *dev_parm,mcache_entry_t *mce){
    fb_dev_parm *dev_p = (fb_dev_parm *)dev_parm;
    return (balancing_vectors_calculate(mcache_entry_routing_info(mce),
            mcache_entry_mapping(mce),dev_p->loc_loct, TRUE));
}


/* Select the source and destination RLOC according to the priority and weight.
 * The destination RLOC is selected according to the AFI of the selected source
 * RLOC */


int
fb_get_fwd_entry(void *fwd_dev_parm,  map_local_entry_t *mle, mcache_entry_t *mce,
        mcache_entry_t *petrs, packet_tuple_t *tuple, fwd_info_t *fwd_info)
{
    mapping_t *dmap;
    lisp_addr_t * src_eid = map_local_entry_eid(mle);
    lisp_addr_t * dst_eid = mcache_entry_eid(mce);

    if (lisp_addr_cmp_afi(src_eid,dst_eid) != 0){
        if (!(lisp_addr_is_no_addr(src_eid) || lisp_addr_is_no_addr(dst_eid))){ // RTRs
            OOR_LOG(LDBG_3, "fb_get_fwd_entry: Src (%s) and dst (%s) EID should be of the same type",
                    lisp_addr_to_char(src_eid), lisp_addr_to_char(dst_eid));
            fwd_info->neg_map_reply_act = ACT_NO_ACTION;
            return(ERR_NO_ROUTE);
        }
    }

    if (fb_get_fwd_entry_2(fwd_dev_parm,mle,mce,tuple,fwd_info) == ERR_NO_ROUTE){
        dmap = mcache_entry_mapping(mce);
        if (lisp_addr_is_lcaf(mapping_eid(dmap))){
            fwd_info->neg_map_reply_act = ACT_DROP;
            return (GOOD);
        }
        if(mapping_action(dmap) == ACT_NATIVE_FWD){
            if (petrs){
                // Try to send the packet to PeTRs
                if (fb_get_fwd_entry_2(fwd_dev_parm,mle,petrs,tuple,fwd_info) == ERR_NO_ROUTE){
                    if (mcache_has_locators(petrs) == TRUE){
                        OOR_LOG(LDBG_3, "fb_get_fwd_entry: No PETR compatible with local locators afi");
                    }else{
                        OOR_LOG(LDBG_3, "fb_get_fwd_entry: No compatible src and dst rlocs. No PeTRs configured");
                    }
                    fwd_info->neg_map_reply_act = ACT_NO_ACTION;
                }else{
                    fwd_info->neg_map_reply_act = ACT_NATIVE_FWD;
                    OOR_LOG(LDBG_3, "Forwarding packet to PeTR");
                }
            }else{
                fwd_info->neg_map_reply_act = ACT_NO_ACTION;
            }
        }
    }
    return (GOOD);
}


int
fb_get_fwd_entry_2(void *fwd_dev_parm,  map_local_entry_t *mle, mcache_entry_t *mce,
        packet_tuple_t *tuple, fwd_info_t *fwd_info)
{
    fwd_entry_tuple_t *fwd_entry;
    fb_dev_parm * dev_parm = (fb_dev_parm *)fwd_dev_parm;
    balancing_locators_vecs * src_blv = (balancing_locators_vecs *)map_local_entry_fwd_info(mle);
    balancing_locators_vecs * dst_blv = (balancing_locators_vecs *)mcache_entry_routing_info(mce);
    int src_vec_len, dst_vec_len;
    uint32_t pos, hash;
    locator_t ** src_loc_vec;
    locator_t ** dst_loc_vec;
    locator_t * src_loct;
    locator_t * dst_loct;


    lisp_addr_t * src_addr;
    lisp_addr_t * dst_addr;
    lisp_addr_t * src_ip_addr = NULL;
    lisp_addr_t * dst_ip_addr = NULL;
    int afi, res;

    if (mapping_locator_count(mcache_entry_mapping(mce)) == 0){
        fwd_info->neg_map_reply_act = mapping_action(mcache_entry_mapping(mce));
        res = ERR_NO_ROUTE;
        OOR_LOG(LDBG_3, "fb_get_fwd_entry_2: No locators");
        goto done;
    }

    if (src_blv->balancing_locators_vec != NULL
            && dst_blv->balancing_locators_vec != NULL) {
        src_loc_vec = src_blv->balancing_locators_vec;
        src_vec_len = src_blv->locators_vec_length;
    } else if (src_blv->v6_balancing_locators_vec != NULL
            && dst_blv->v6_balancing_locators_vec != NULL) {
        src_loc_vec = src_blv->v6_balancing_locators_vec;
        src_vec_len = src_blv->v6_locators_vec_length;
    } else if (src_blv->v4_balancing_locators_vec != NULL
            && dst_blv->v4_balancing_locators_vec != NULL) {
        src_loc_vec = src_blv->v4_balancing_locators_vec;
        src_vec_len = src_blv->v4_locators_vec_length;
    } else {
        if (src_blv->v4_balancing_locators_vec == NULL
                && src_blv->v6_balancing_locators_vec == NULL) {
            OOR_LOG(LDBG_3, "fb_get_fwd_entry: No SRC locators "
                    "available");
        }else if (dst_blv->v4_balancing_locators_vec == NULL
                && dst_blv->v6_balancing_locators_vec == NULL) {
            OOR_LOG(LDBG_3, "fb_get_fwd_entry: No DST locators "
                    "available");
        } else {
            OOR_LOG(LDBG_3, "fb_get_fwd_entry: Source and "
                    "destination RLOCs are not compatible");
        }
        res = ERR_NO_ROUTE;
        goto done;
    }

    hash = pkt_tuple_hash(tuple);
    if (hash == 0) {
        OOR_LOG(LDBG_1, "fb_get_fwd_entry_2: Couldn't get the hash of the tuple "
                "to select the rloc. Using the default rloc");
        //pos = hash%x_vec_len -> 0%x_vec_len = 0;
    }

    pos = hash % src_vec_len;
    src_loct = src_loc_vec[pos];
    src_addr = locator_addr(src_loct);

    /* decide dst afi based on src afi*/


    src_ip_addr = laddr_get_fwd_ip_addr(src_addr,dev_parm->loc_loct);
    afi = lisp_addr_ip_afi(src_ip_addr);

    switch (afi) {
    case (AF_INET):
        dst_loc_vec = dst_blv->v4_balancing_locators_vec;
        dst_vec_len = dst_blv->v4_locators_vec_length;
        break;
    case (AF_INET6):
        dst_loc_vec = dst_blv->v6_balancing_locators_vec;
        dst_vec_len = dst_blv->v6_locators_vec_length;
        break;
    default:
        OOR_LOG(LDBG_2, "select_locs_from_maps: Unknown IP AFI %d",
                lisp_addr_ip_afi(src_addr));
        res = ERR_NO_ROUTE;
        src_ip_addr = NULL;
        goto done;
    }

    pos = hash % dst_vec_len;
    dst_loct = dst_loc_vec[pos];
    dst_addr = locator_addr(dst_loct);
    dst_ip_addr = laddr_get_fwd_ip_addr(dst_addr,dev_parm->loc_loct);
    res = GOOD;


    OOR_LOG(LDBG_3, "select_locs_from_maps: EID: %s -> %s, protocol: %d, "
            "port: %d -> %d\n  --> RLOC: %s -> %s",
            lisp_addr_to_char(&(tuple->src_addr)),
            lisp_addr_to_char(&(tuple->dst_addr)), tuple->protocol,
            tuple->src_port, tuple->dst_port,
            lisp_addr_to_char(src_ip_addr),
            lisp_addr_to_char(dst_ip_addr));

done:
    if (fwd_info->dp_conf_inf){
        fwd_entry_tuple_del(fwd_info->dp_conf_inf);
    }
    fwd_entry = fwd_entry_tuple_new_init(tuple, src_ip_addr, dst_ip_addr, tuple->iid, NULL);
    fwd_info->dp_conf_inf = fwd_entry;
    fwd_info->data_del_fn = (fwd_info_data_del_fn)fwd_entry_tuple_del;
    return (res);
}
