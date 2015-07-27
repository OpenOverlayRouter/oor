/*
 * fb_lisp_addr.c
 *
 *  Created on: 17/02/2015
 *      Author: albert
 */

#include "fb_lisp_addr_func.h"
#include "../../lib/lmlog.h"
#include "../fwd_policy.h"

lisp_addr_t *fb_elp_type_get_fwd_ip_addr(void *elp, glist_t *locl_rlocs_addr);
lisp_addr_t * fb_rle_type_get_fwd_ip_addr(void *rle, glist_t *locl_rlocs_addr);

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
        fb_elp_type_get_fwd_ip_addr,
        0,
        0,
        fb_rle_type_get_fwd_ip_addr,
        0,
        0};

lisp_addr_t *
fb_lisp_addr_get_fwd_ip_addr(lisp_addr_t *addr, glist_t *locl_rlocs_addr)
{
    switch (lisp_addr_lafi(addr)) {
    case LM_AFI_IP:
        return (addr);
    case LM_AFI_IPPREF:
        LMLOG(LWRN, "fb_lisp_addr_get_fwd_ip_addr: Not applicable to prefixes");
        return (NULL);
    case LM_AFI_LCAF:
        return (fb_lcaf_get_fwd_ip_addr(lisp_addr_get_lcaf(addr),locl_rlocs_addr));
    default:
        return (NULL);
    }
    return (NULL);
}

/* obtain fwd IP address from LCAF*/
lisp_addr_t *
fb_lcaf_get_fwd_ip_addr(lcaf_addr_t *lcaf, glist_t *locl_rlocs_addr)
{

    if (!fb_get_fwd_ip_addr_fcts[lcaf_addr_get_type(lcaf)]) {
        LMLOG(LDBG_1, "fb_lcaf_get_fwd_ip_addr: lcaf type %d not supported", lcaf_addr_get_type(lcaf));
        return (NULL);
    }

    return (*fb_get_fwd_ip_addr_fcts[lcaf_addr_get_type(lcaf)])(lcaf_addr_get_addr(lcaf), locl_rlocs_addr);
}


lisp_addr_t *fb_elp_type_get_fwd_ip_addr(void *elp, glist_t *locl_rlocs_addr)
{
    lisp_addr_t *addr = NULL;
    glist_entry_t *it = NULL;
    glist_t *elp_list = ((elp_t *)elp)->nodes;
    int elp_size = glist_size(elp_list);
    int elp_pos = 0;
    // XXX to be checked

    glist_for_each_entry(it,elp_list){
        elp_pos ++;
        addr = elp_node_addr((elp_node_t *)glist_entry_data(it));
        if (lisp_addr_is_lcaf(addr) && lisp_addr_lcaf_type(addr) == LCAF_EXPL_LOC_PATH){
            addr = fb_lisp_addr_get_fwd_ip_addr(addr, locl_rlocs_addr);
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

lisp_addr_t * fb_rle_type_get_fwd_ip_addr(void *rle, glist_t *locl_rlocs_addr)
{
    lisp_addr_t     *addr = NULL;
    glist_entry_t   *it = NULL;
    rle_node_t      *rnode  = NULL;
    int             level   = -1;

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
