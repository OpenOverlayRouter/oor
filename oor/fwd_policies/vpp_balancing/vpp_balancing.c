/*
 * vpp_balancing.c
 *
 *  Created on: Sep 14, 2016
 *      Author: alopez
 */


#include "fwd_entry_vpp.h"
#include "vpp_balancing.h"
#include "../fwd_policy.h"
#include "../fwd_utils.h"
#include "../fwd_addr_func.h"
#include "../../control/oor_ctrl_device.h"
#include "../../lib/oor_log.h"
#include "../../lib/util.h"

#include <math.h>

vpp_dev_parm *vpp_dev_parm_new();
void vpp_dev_parm_del(vpp_dev_parm * dev_parm);
vpp_map_policy_inf *vpp_map_policy_inf_new();
void vpp_map_policy_inf_del(vpp_map_policy_inf * vpp_inf);
int vpp_map_policy_inf_calc(vpp_map_policy_inf *pi, mapping_t * map, glist_t *loc_loct, uint8_t is_mce);
void vpp_map_policy_inf_reset(vpp_map_policy_inf *pi);
void * vpp_new_dev_policy_inf(oor_ctrl_dev_t *ctrl_dev,fwd_policy_dev_parm *dev_parm_inf);
void vpp_del_dev_policy_inf(void * dev_parm);
int vpp_init_map_loc_policy_inf(void *dev_parm, map_local_entry_t *mle, fwd_policy_map_parm *map_parm);
void vpp_del_map_loc_policy_inf(void * map_loc_policy_inf);
int vpp_init_map_cache_policy_inf(void *dev_parm, mcache_entry_t *mce);
void vpp_del_map_cache_policy_inf(void * mcache_policy_inf);
int vpp_updated_map_loc_inf(void *dev_parm,map_local_entry_t *mle);
int vpp_updated_map_cache_inf(void *dev_parm,mcache_entry_t *mce);
static int select_best_priority_loct_lst(glist_t *loct_list, uint8_t is_mce, glist_t *best_loct_list,
        int *min_priority, int *total_weight);
int vpp_get_fwd_entry(void *fwd_dev_parm,  map_local_entry_t *mle, mcache_entry_t *mce,
        mcache_entry_t *petrs, packet_tuple_t *tuple, fwd_info_t *fwd_info);
int vpp_get_fwd_entry_2(void *fwd_dev_parm,  map_local_entry_t *mle, mcache_entry_t *mce,
        packet_tuple_t *tuple, fwd_info_t *fwd_info);
void fwd_entry_vpp_fill (fwd_entry_vpp_t *fwd_entry, glist_t *locl_loct, glist_t *rmt_loct,
        int weight_locl, int weight_rmt, glist_t *locl_rlocs_lst);


fwd_policy_class  fwd_policy_vpp_balancing = {
        .new_dev_policy_inf = vpp_new_dev_policy_inf,
        .del_dev_policy_inf = vpp_del_dev_policy_inf,
        .init_map_loc_policy_inf = vpp_init_map_loc_policy_inf,
        .del_map_loc_policy_inf = vpp_del_map_loc_policy_inf,
        .init_map_cache_policy_inf = vpp_init_map_cache_policy_inf,
        .del_map_cache_policy_inf = vpp_del_map_cache_policy_inf,
        .updated_map_loc_inf = vpp_updated_map_loc_inf,
        .updated_map_cache_inf = vpp_updated_map_cache_inf,
        .get_fwd_info = vpp_get_fwd_entry,
        .get_fwd_ip_addr = laddr_get_fwd_ip_addr
};

inline vpp_dev_parm *
vpp_dev_parm_new()
{
    vpp_dev_parm *dev_parm;
    dev_parm = (vpp_dev_parm *)xzalloc(sizeof(vpp_dev_parm));
    if(dev_parm == NULL){
        OOR_LOG(LWRN, "vpp_dev_parm_new: Couldn't allocate memory for fb_dev_parm");
    }

    return(dev_parm);
}

inline void
vpp_dev_parm_del(vpp_dev_parm * dev_parm)
{
    free(dev_parm);
    dev_parm = NULL;
}

inline vpp_map_policy_inf *
vpp_map_policy_inf_new()
{
    vpp_map_policy_inf * vpp_inf;
    vpp_inf = xzalloc(sizeof(vpp_map_policy_inf));
    vpp_inf->ipv4_loct_lst = glist_new();
    vpp_inf->ipv6_loct_lst = glist_new();
    return (vpp_inf);
}

inline void
vpp_map_policy_inf_del(vpp_map_policy_inf * vpp_inf)
{
    glist_destroy(vpp_inf->ipv4_loct_lst);
    glist_destroy(vpp_inf->ipv6_loct_lst);
    free(vpp_inf);
    vpp_inf = NULL;
}

int
vpp_map_policy_inf_calc(vpp_map_policy_inf *pi, mapping_t * map, glist_t *loc_loct, uint8_t is_mce)
{
    glist_t *ipv4_loct_list = glist_new();
    glist_t *ipv6_loct_list = glist_new();

    vpp_map_policy_inf_reset(pi);
    locators_classify_in_4_6(map,loc_loct,ipv4_loct_list,ipv6_loct_list, laddr_get_fwd_ip_addr);

    if (glist_size(ipv4_loct_list) != 0){
        select_best_priority_loct_lst(ipv4_loct_list,is_mce,pi->ipv4_loct_lst,
                &(pi->priority4),&(pi->sum_weight4));
    }

    if (glist_size(ipv6_loct_list) != 0){
        select_best_priority_loct_lst(ipv6_loct_list,is_mce,pi->ipv6_loct_lst,
                &(pi->priority6),&(pi->sum_weight6));
    }

    return (GOOD);
}

void
vpp_map_policy_inf_reset(vpp_map_policy_inf *pi)
{
    glist_remove_all(pi->ipv4_loct_lst);
    glist_remove_all(pi->ipv6_loct_lst);
    pi->priority4 = 255;
    pi->priority6 = 255;
    pi->sum_weight4 = 0;
    pi->sum_weight6 = 0;
}



void *
vpp_new_dev_policy_inf(oor_ctrl_dev_t *ctrl_dev,fwd_policy_dev_parm *dev_parm_inf)
{
    vpp_dev_parm * dev_parm;
    dev_parm = vpp_dev_parm_new();
    if(!dev_parm){
        return (NULL);
    }
    dev_parm->dev_type = ctrl_dev_mode(ctrl_dev);
    dev_parm->loc_loct = ctrl_rlocs(ctrl_dev_get_ctrl_t(ctrl_dev));

    return(dev_parm);
}

void
vpp_del_dev_policy_inf(void * dev_parm)
{
    vpp_dev_parm_del(dev_parm);
}

int
vpp_init_map_loc_policy_inf(void *dev_parm, map_local_entry_t *mle, fwd_policy_map_parm *map_parm)
{
    vpp_dev_parm *dev_p = (vpp_dev_parm *)dev_parm;
    vpp_map_policy_inf * fwd_inf = vpp_map_policy_inf_new();
    if (!fwd_inf){
        return (BAD);
    }
    vpp_map_policy_inf_calc(fwd_inf, map_local_entry_mapping(mle), dev_p->loc_loct, FALSE);
    map_local_entry_set_fwd_info(mle,(void *)fwd_inf,vpp_del_map_loc_policy_inf);
    return (GOOD);
}

void
vpp_del_map_loc_policy_inf(void * map_loc_policy_inf)
{
    vpp_map_policy_inf_del(map_loc_policy_inf);
}

int
vpp_init_map_cache_policy_inf(void *dev_parm, mcache_entry_t *mce)
{
    vpp_dev_parm *dev_p = (vpp_dev_parm *)dev_parm;
    vpp_map_policy_inf * routing_inf = vpp_map_policy_inf_new();
    if (!routing_inf){
        return (BAD);
    }
    vpp_map_policy_inf_calc(routing_inf, mcache_entry_mapping(mce), dev_p->loc_loct, TRUE);
    mcache_entry_set_routing_info(mce, routing_inf, vpp_del_map_cache_policy_inf);
    return (GOOD);
}

void
vpp_del_map_cache_policy_inf(void * mcache_policy_inf)
{
    vpp_map_policy_inf_del(mcache_policy_inf);
}

int
vpp_updated_map_loc_inf(void *dev_parm,map_local_entry_t *mle)
{
    vpp_dev_parm *dev_p = (vpp_dev_parm *)dev_parm;
    vpp_map_policy_inf_calc(map_local_entry_fwd_info(mle),map_local_entry_mapping(mle),
            dev_p->loc_loct, FALSE);
    return (GOOD);
}

int
vpp_updated_map_cache_inf(void *dev_parm,mcache_entry_t *mce)
{
    vpp_dev_parm *dev_p = (vpp_dev_parm *)dev_parm;
    vpp_map_policy_inf_calc(mcache_entry_routing_info(mce),mcache_entry_mapping(mce),
            dev_p->loc_loct, TRUE);
    return (GOOD);
}

static int
select_best_priority_loct_lst(glist_t *loct_list, uint8_t is_mce, glist_t *best_loct_list,
        int *min_priority, int *total_weight)
{
    locator_t *selected_locators[33];
    glist_entry_t *it_loct;
    locator_t *locator;
    int min_pri = UNUSED_RLOC_PRIORITY - 1;
    int weight = 0;
    int pos = 0;

    if (glist_size(loct_list) == 0){
        return (BAD);
    }
    selected_locators[0] = NULL;
    glist_for_each_entry(it_loct,loct_list){
        locator = (locator_t *)glist_entry_data(it_loct);
        /* Only use locators with status UP  */
        if (locator_state(locator) == DOWN
                || locator_priority(locator) == UNUSED_RLOC_PRIORITY ) {
            continue;
        }
        /* For local mappings, the locator should be local */
        if (!is_mce && locator_L_bit(locator) == 0){
            continue;
        }
        /* If priority of the locator equal to min_pri, then add the
         * locator to the list */
        if (locator_priority(locator) == min_pri) {
            selected_locators[pos] = locator;
            pos++;
            selected_locators[pos] = NULL;
        }else if (locator_priority(locator) < min_pri) {
            /* If priority of the locator is minor than the min_pri, then
            * min_pri and list of rlocs is updated */
            pos = 0;
            min_pri = locator_priority(locator);
            selected_locators[pos] = locator;
            pos++;
            selected_locators[pos] = NULL;
        }
    }

    pos = 0;
    while (selected_locators[pos] != NULL){
        weight+=locator_weight(selected_locators[pos]);
        glist_add(selected_locators[pos],best_loct_list);
        pos++;
    }
    *min_priority = min_pri;
    *total_weight = weight;
    return (GOOD);
}

int
vpp_get_fwd_entry(void *fwd_dev_parm,  map_local_entry_t *mle, mcache_entry_t *mce,
        mcache_entry_t *petrs, packet_tuple_t *tuple, fwd_info_t *fwd_info)
{
    fwd_entry_vpp_t *fwd_entry;
    mapping_t *dmap;
    lisp_addr_t * src_eid = map_local_entry_eid(mle);
    lisp_addr_t * dst_eid = mcache_entry_eid(mce);
    uint8_t free_src_eid = FALSE, free_dst_eid = FALSE;


    if (lisp_addr_cmp_afi(src_eid,dst_eid) != 0){

        if (lisp_addr_is_no_addr(src_eid)){ //RTR
            src_eid = laddr_get_full_space_pref_from_type(dst_eid);
            free_src_eid = TRUE;
        }else{
            OOR_LOG(LDBG_3, "fb_get_fwd_entry: Src (%s) and dst (%s) EID should be of the same type",
                    lisp_addr_to_char(src_eid), lisp_addr_to_char(dst_eid));
            fwd_info->neg_map_reply_act = ACT_NO_ACTION;
            return(ERR_NO_ROUTE);
        }
    }
    if (fwd_info->dp_conf_inf){
        fwd_entry_vpp_del(fwd_info->dp_conf_inf);
    }
    fwd_entry = fwd_entry_vpp_new_init(src_eid,dst_eid,tuple->iid);
    fwd_info->dp_conf_inf = fwd_entry;
    fwd_info->data_del_fn = (fwd_info_data_del_fn)fwd_entry_vpp_del;

    if (vpp_get_fwd_entry_2(fwd_dev_parm,mle,mce,tuple,fwd_info) == ERR_NO_ROUTE){
        dmap = mcache_entry_mapping(mce);
        // If the destination EID is an LCAF, we don't send traffic to PeTRs -> DROP packets
        if (lisp_addr_is_lcaf(mapping_eid(dmap))){
            fwd_info->neg_map_reply_act = ACT_DROP;
            goto done;
        }
        if(mapping_action(dmap) == ACT_NATIVE_FWD){
            if (petrs){
                // Try to send the packet to PeTRs
                if (vpp_get_fwd_entry_2(fwd_dev_parm,mle,petrs,tuple,fwd_info) == ERR_NO_ROUTE){
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
                // No PeTRs availables, drop packets
                fwd_info->neg_map_reply_act = ACT_NO_ACTION;
            }
        }
    }
done:
    if (free_src_eid){
        lisp_addr_del(src_eid);
    }
    if (free_dst_eid){
        lisp_addr_del(dst_eid);
    }
    return (GOOD);
}


int
vpp_get_fwd_entry_2(void *fwd_dev_parm,  map_local_entry_t *mle, mcache_entry_t *mce,
        packet_tuple_t *tuple, fwd_info_t *fwd_info)
{
    vpp_dev_parm * dev_parm = (vpp_dev_parm *)fwd_dev_parm;
    vpp_map_policy_inf * src_fwd_inf = (vpp_map_policy_inf *)map_local_entry_fwd_info(mle);
    vpp_map_policy_inf * dst_fwd_inf = (vpp_map_policy_inf *)mcache_entry_routing_info(mce);
    int afi_support = NO_AFI_SUPPOT;
    fwd_entry_vpp_t *fwd_entry = (fwd_entry_vpp_t *)fwd_info->dp_conf_inf;

    if (mapping_locator_count(mcache_entry_mapping(mce)) == 0){
        fwd_info->neg_map_reply_act = mapping_action(mcache_entry_mapping(mce));
        OOR_LOG(LDBG_3, "vpp_get_fwd_entry: No locators");
        return (ERR_NO_ROUTE);
    }

    if (glist_size(src_fwd_inf->ipv4_loct_lst)>0 && glist_size(dst_fwd_inf->ipv4_loct_lst)>0){
        afi_support = IPv4_SUPPORT;
    }

    if (glist_size(src_fwd_inf->ipv6_loct_lst)>0 && glist_size(dst_fwd_inf->ipv6_loct_lst)>0){
        afi_support = afi_support | IPv6_SUPPORT;
    }

    if (afi_support == (IPv4_SUPPORT | IPv6_SUPPORT)){

        /* If we have support for both IP families but one of the is more
         * preferable, use only this one */
        if (dst_fwd_inf->priority4 < dst_fwd_inf->priority6){
            afi_support = IPv4_SUPPORT;
        }else if (dst_fwd_inf->priority4 > dst_fwd_inf->priority6){
            afi_support = IPv6_SUPPORT;
        }
    }

    switch (afi_support){
    case NO_AFI_SUPPOT:
        OOR_LOG(LDBG_3, "vpp_get_fwd_entry: Source and destination RLOCs are not compatible");
        return (ERR_NO_ROUTE);
    case IPv4_SUPPORT:
        fwd_entry_vpp_fill (fwd_entry,src_fwd_inf->ipv4_loct_lst,dst_fwd_inf->ipv4_loct_lst,
                src_fwd_inf->sum_weight4, dst_fwd_inf->sum_weight4,dev_parm->loc_loct);
        break;
    case IPv6_SUPPORT:
        fwd_entry_vpp_fill (fwd_entry,src_fwd_inf->ipv6_loct_lst,dst_fwd_inf->ipv6_loct_lst,
                src_fwd_inf->sum_weight6, dst_fwd_inf->sum_weight6,dev_parm->loc_loct);
        break;
    default: //IPv4 and IPv6 compatibles
        fwd_entry_vpp_fill (fwd_entry,src_fwd_inf->ipv4_loct_lst,dst_fwd_inf->ipv4_loct_lst,
                src_fwd_inf->sum_weight4, dst_fwd_inf->sum_weight4,dev_parm->loc_loct);
        fwd_entry_vpp_fill (fwd_entry,src_fwd_inf->ipv6_loct_lst,dst_fwd_inf->ipv6_loct_lst,
                src_fwd_inf->sum_weight6, dst_fwd_inf->sum_weight6,dev_parm->loc_loct);
    }

    fwd_entry_vpp_dump(fwd_entry,LDBG_3);

    return (GOOD);
}


void
fwd_entry_vpp_fill (fwd_entry_vpp_t *fwd_entry, glist_t *locl_loct_lst, glist_t *rmt_loct_lst,
        int weight_locl, int weight_rmt, glist_t *locl_rlocs_lst)
{
    vpp_loct_pair *loct_pair;
    float factor, decimal = 0, aux_weight;
    int w_locl = 0, w_rmt = 0;
    glist_entry_t *locl_lst_elt, *rmt_lst_elt, *l_head, *r_head, *aux_elt;
    locator_t *locl_loct, *rmt_loct;
    lisp_addr_t *src_addr, *dst_addr, *src_ip_addr, *dst_ip_addr;

    factor = (float)weight_rmt / weight_locl;
    locl_lst_elt = glist_head(locl_loct_lst);
    rmt_lst_elt = glist_head(rmt_loct_lst);
    l_head = locl_lst_elt;
    r_head = rmt_lst_elt;

    while(1){
        if (w_locl == 0){
            locl_lst_elt = glist_next(locl_lst_elt);
            if (locl_lst_elt == l_head){
                break;
            }
            locl_loct = glist_entry_data(locl_lst_elt);
            aux_weight = locator_weight(locl_loct)*factor;
            aux_elt = glist_next(locl_lst_elt);
            if (aux_elt == l_head){ // Is the last element of the list
                w_locl = (int)ceil(aux_weight + decimal);
            }else{
                w_locl = (int)floor(aux_weight);
                decimal += (aux_weight - w_locl);
                if (decimal >= 1){
                    w_locl += 1;
                    decimal -= 1;
                }
            }
        }
        if (w_rmt == 0){
            rmt_lst_elt = glist_next(rmt_lst_elt);
            if (rmt_lst_elt == r_head){
                break;
            }
            rmt_loct = glist_entry_data(rmt_lst_elt);
            w_rmt = locator_weight(rmt_loct);
        }

        src_addr = locator_addr(locl_loct);
        src_ip_addr = laddr_get_fwd_ip_addr(src_addr,locl_rlocs_lst);
        dst_addr = locator_addr(rmt_loct);
        dst_ip_addr = laddr_get_fwd_ip_addr(dst_addr,locl_rlocs_lst);
        if (w_rmt >= w_locl){
            loct_pair = vpp_loct_pair_new_init(src_ip_addr,dst_ip_addr,w_locl);
            w_rmt = w_rmt - w_locl;
            w_locl = 0;

        }else{
            loct_pair = vpp_loct_pair_new_init(src_ip_addr,dst_ip_addr,w_rmt);
            w_locl = w_locl - w_rmt;
            w_rmt = 0;
        }
        glist_add(loct_pair,fwd_entry->loc_pair_lst);

    }

    return;
}
