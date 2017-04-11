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



#include "../lib/oor_log.h"
#include "fwd_addr_func.h"
#include "fwd_policy.h"

lisp_addr_t *lcaf_get_fwd_ip_addr(lcaf_addr_t *lcaf, glist_t *locl_rlocs_addr);
lisp_addr_t *elp_type_get_fwd_ip_addr(void *elp, glist_t *locl_rlocs_addr);
lisp_addr_t * rle_type_get_fwd_ip_addr(void *rle, glist_t *locl_rlocs_addr);

get_fwd_ip_addr_fct fb_get_fwd_ip_addr_fcts[MAX_LCAFS] = {
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        elp_type_get_fwd_ip_addr,
        0,
        0,
        rle_type_get_fwd_ip_addr,
        0,
        0};

lisp_addr_t *
laddr_get_fwd_ip_addr(lisp_addr_t *addr, glist_t *locl_rlocs_addr)
{
    switch (lisp_addr_lafi(addr)) {
    case LM_AFI_IP:
        return (addr);
    case LM_AFI_IPPREF:
        OOR_LOG(LWRN, "laddr_get_fwd_ip_addr: Not applicable to prefixes");
        return (NULL);
    case LM_AFI_LCAF:
        return (lcaf_get_fwd_ip_addr(lisp_addr_get_lcaf(addr),locl_rlocs_addr));
    default:
        return (NULL);
    }
    return (NULL);
}

/* obtain fwd IP address from LCAF*/
lisp_addr_t *
lcaf_get_fwd_ip_addr(lcaf_addr_t *lcaf, glist_t *locl_rlocs_addr)
{
    if (!fb_get_fwd_ip_addr_fcts[lcaf_addr_get_type(lcaf)]) {
        OOR_LOG(LDBG_1, "lcaf_get_fwd_ip_addr: lcaf type %d not supported", lcaf_addr_get_type(lcaf));
        return (NULL);
    }

    return (*fb_get_fwd_ip_addr_fcts[lcaf_addr_get_type(lcaf)])(lcaf_addr_get_addr(lcaf), locl_rlocs_addr);
}


lisp_addr_t *
elp_type_get_fwd_ip_addr(void *elp, glist_t *locl_rlocs_addr)
{
    lisp_addr_t *addr;
    glist_entry_t *it;

    glist_t *elp_list = ((elp_t *)elp)->nodes;
    int elp_size = glist_size(elp_list);
    int elp_pos = 0;
    // XXX to be checked

    glist_for_each_entry(it,elp_list){
        elp_pos ++;
        addr = elp_node_addr((elp_node_t *)glist_entry_data(it));
        if (lisp_addr_is_lcaf(addr) && lisp_addr_lcaf_type(addr) == LCAF_EXPL_LOC_PATH){
            addr = laddr_get_fwd_ip_addr(addr, locl_rlocs_addr);
            if (addr != NULL){
                return (addr);
            }
            continue;
        }
        addr = lisp_addr_get_ip_addr(addr);
        if (glist_contain_using_cmp_fct(addr, locl_rlocs_addr,(glist_cmp_fct)lisp_addr_cmp) == TRUE){
            if (elp_pos == elp_size){
                // Command invoked by xTR of the ELP (RTR-RTR-RTR-xTR).
                // Return the last address -> It will be used as the source address of the ELP
                return (addr);
            }
            // Command invoked by an RTR of the ELP
            // Return the next ip addr of the ELP
            it = glist_next(it);
            addr = elp_node_addr((elp_node_t *)glist_entry_data(it));
            return (lisp_addr_get_ip_addr(addr));
        }
    }
    // Command invoked by an iTR
    return (lisp_addr_get_ip_addr(elp_node_addr((elp_node_t *)glist_first_data(elp_list))));
}

lisp_addr_t *
rle_type_get_fwd_ip_addr(void *rle, glist_t *locl_rlocs_addr)
{
    lisp_addr_t *addr = NULL;
    glist_entry_t *it;
    rle_node_t *rnode;
    int level   = -1;

    /* find the first highest level replication node */
    glist_for_each_entry(it, ((rle_t *)rle)->nodes) {
        rnode = glist_entry_data(it);
        if (rnode->level > level) {
            level = rnode->level;
            addr = rnode->addr;
        }
    }
    return(addr);
}

lisp_addr_t *
laddr_get_special_addr_from_type(lisp_addr_t *address)
{
    lisp_addr_t *addr = lisp_addr_clone(address);
    lisp_addr_t *ip_pref = lisp_addr_get_ip_pref_addr(addr);

    if (!ip_pref){
        return (NULL);
    }
    switch (lisp_addr_ip_afi(ip_pref)){
    case AF_INET:
        lisp_addr_ippref_from_char(FULL_IPv4_ADDRESS_SPACE,ip_pref);
        break;
    case AF_INET6:
        lisp_addr_ippref_from_char(FULL_IPv6_ADDRESS_SPACE,ip_pref);
        break;
    }
    return(addr);
}
