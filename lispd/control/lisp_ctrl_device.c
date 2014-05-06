/*
 * lisp_ctrl_device.c
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Florin Coras <fcoras@ac.upc.edu>
 */


#include "lisp_ctrl_device.h"
#include <lispd_external.h>
#include <lispd_sockets.h>
#include <packets.h>
#include <lispd_lib.h>

static ctrl_dev_class_t *
ctrl_dev_class_find(lisp_dev_type type)
{
    return(reg_ctrl_dev_cls[type]);
}

int
ctrl_dev_recv(lisp_ctrl_dev_t *dev, lbuf_t *b, uconn_t *uc)
{
    return(dev->ctrl_class->recv_msg(dev, b, uc));
}

void
ctrl_dev_run(lisp_ctrl_dev_t *dev)
{
    dev->ctrl_class->run(dev);
}

int
ctrl_dev_create(lisp_dev_type type, lisp_ctrl_dev_t **devp)
{
    lisp_ctrl_dev_t *dev;
    ctrl_dev_class_t *class;

    *devp = NULL;

    /* find type of device */
    class = ctrl_dev_class_find(type);
    dev = class->alloc();
    dev->mode =type;
    dev->ctrl_class = class;
    dev->ctrl_class->construct(dev);

    *devp = dev;
    return(GOOD);
}

void
ctrl_dev_destroy(lisp_ctrl_dev_t *dev)
{
    if (!dev) {
        return;
    }

    dev->ctrl_class->destruct(dev);
    dev->ctrl_class->dealloc(dev);
}

int
send_msg(lisp_ctrl_dev_t *dev, lisp_msg *msg, uconn_t *uc)
{
    ctrl_send_msg(dev->ctrl, msg, uc);
    return(GOOD);
}


int
ctrl_dev_program_smr(lisp_ctrl_dev_t *dev)
{
    void *arg;
    timer *t;

    /* used only with tunnel routers */
    if (dev->mode != xTR_MODE && dev->mode != RTR_MODE) {
        return(GOOD);
    }

    return(program_smr(dev, LISPD_SMR_TIMEOUT));
}

/* Select the source RLOC according to the priority and weight. */
static int
select_srloc_from_bvec(mapping_t *src_mapping, packet_tuple tuple,
        locator_t **src_locator)
{
    int src_vec_len = 0;
    uint32_t pos = 0;
    uint32_t hash = 0;
    balancing_locators_vecs *src_blv = NULL;
    locator_t **src_loc_vec = NULL;
    lcl_mapping_extended_info *leinf;

    leinf = src_mapping->extended_info;
    src_blv = &leinf->outgoing_balancing_locators_vecs;

    if (src_blv->balancing_locators_vec != NULL){
        src_loc_vec = src_blv->balancing_locators_vec;
        src_vec_len = src_blv->locators_vec_length;
    }else if (src_blv->v6_balancing_locators_vec != NULL){
        src_loc_vec = src_blv->v6_balancing_locators_vec;
        src_vec_len = src_blv->v6_locators_vec_length;
    }else {
        src_loc_vec = src_blv->v4_balancing_locators_vec;
        src_vec_len = src_blv->v4_locators_vec_length;
    }
    if (src_vec_len == 0){
        lmlog(DBG_3,"select_src_locators_from_balancing_locators_vec: No "
                "source locators available to send packet");
        return(BAD);
    }
    hash = get_hash_from_tuple (tuple);
    if (hash == 0){
        lmlog(DBG_1,"select_src_locators_from_balancing_locators_vec: "
                "Couldn't get the hash of the tuple to select the rloc. "
                "Using the default rloc");
    }
    pos = hash%src_vec_len; // if hash = 0 then pos = 0
    *src_locator =  src_loc_vec[pos];

    lmlog(DBG_3,"select_src_locators_from_balancing_locators_vec: src RLOC: "
            "%s", lisp_addr_to_char(locator_addr(*src_locator)));

    return (GOOD);
}

/* Select the source and destination RLOC according to the priority and weight.
 * The destination RLOC is selected according to the AFI of the selected source
 * RLOC */

int
select_rmt_srloc_from_bvec(mapping_t *src_map, mapping_t *dst_map,
        packet_tuple tuple, locator_t **src_locp, locator_t **dst_locp)
{
    int src_vec_len = 0;
    int dst_vec_len = 0;
    uint32_t pos = 0;
    uint32_t hash = 0;
    balancing_locators_vecs *src_blv = NULL;
    balancing_locators_vecs *dst_blv = NULL;
    locator_t **src_loc_vec = NULL;
    locator_t **dst_loc_vec = NULL;
    lcaf_addr_t *lcaf = NULL;
    lisp_addr_t *loc_addr;
    int afi = 0, lafi = 0;
    lcl_mapping_extended_info *leinf;
    rmt_mapping_extended_info *reinf;

    leinf = src_map->extended_info;
    reinf = dst_map->extended_info;
    src_blv = &leinf->outgoing_balancing_locators_vecs;
    dst_blv = &reinf->rmt_balancing_locators_vecs;

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
            lmlog(DBG_2, "get_rloc_from_balancing_locator_vec: No src locators "
                    "available");
        } else {
            lmlog(DBG_2, "get_rloc_from_balancing_locator_vec: Source and "
                    "destination RLOCs have differnet afi");
        }
        return (BAD);
    }

    hash = get_hash_from_tuple(tuple);
    if (hash == 0) {
        lmlog(DBG_1, "get_rloc_from_tuple: Couldn't get the hash of the tuple "
                "to select the rloc. Using the default rloc");
        //pos = hash%x_vec_len -> 0%x_vec_len = 0;
    }
    pos = hash % src_vec_len;
    *src_locp = src_loc_vec[pos];
    loc_addr = locator_addr(*src_locp);

    /* decide dst afi based on src afi*/
    lafi = lisp_addr_afi(loc_addr);
    switch (lafi) {
    case LM_AFI_IP:
        afi = lisp_addr_ip_afi(loc_addr);
        break;
    case LM_AFI_LCAF:
        lcaf = lisp_addr_get_lcaf(loc_addr);
        switch (lcaf_addr_get_type(lcaf)) {
        case LCAF_EXPL_LOC_PATH: {
            /* the afi of the first node in the elp */
            elp_node_t *enode = glist_first_data(lcaf_elp_node_list(lcaf));
            afi = lisp_addr_ip_afi(enode->addr);
        }
            break;
        default:
            lmlog(DBG_2, "select_src_rmt_locators_from_balancing_locators_vec:"
                    " LCAF type %d not supported", lcaf_addr_get_type(lcaf));
            return (BAD);
        }
        break;
    default:
        lmlog(DBG_2, "select_src_rmt_locators_from_balancing_locators_vec: LISP"
                " addr afi %d not supported", lisp_addr_afi(loc_addr));
        return (BAD);
    }

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
        lmlog(DBG_2, "select_src_rmt_locators_from_balancing_locators_vec: "
                "Unknown IP AFI %d", lisp_addr_ip_afi(loc_addr));
        return (BAD);
    }

    pos = hash % dst_vec_len;
    *dst_locp = dst_loc_vec[pos];

    lmlog(DBG_3, "select_src_rmt_locators_from_balancing_locators_vec: "
            "src EID: %s, rmt EID: %s, protocol: %d, src port: %d , dst port:"
            " %d --> src RLOC: %s, dst RLOC: %s",
            lisp_addr_to_char(mapping_eid(src_map)),
            lisp_addr_to_char(mapping_eid(dst_map)), tuple.protocol,
            tuple.src_port, tuple.dst_port,
            lisp_addr_to_char((*src_locp)->addr),
            lisp_addr_to_char((*dst_locp)->addr));

    return (GOOD);
}

static int
get_dst_from_lcaf(lisp_addr_t *laddr, lisp_addr_t **dst)
{
    lcaf_addr_t *lcaf = NULL;
    elp_node_t *enode;

    lcaf = lisp_addr_get_lcaf(laddr);
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_EXPL_LOC_PATH:
        /* we're the ITR, so the destination is the first elp hop, the src we
         * choose outside */
        enode = glist_first_data(lcaf_elp_node_list(lcaf));
        *dst = enode->addr;
        break;
    default:
        *dst = NULL;
        lmlog(DBG_1, "get_locator_from_lcaf: Type % not supported!, ",
                lcaf_addr_get_type(lcaf));
        return (BAD);
    }
    return (GOOD);
}


forwarding_entry *
tr_get_forwarding_entry(lisp_ctrl_dev_t *dev, packet_tuple *tuple)
{
    mapping_t *smap = NULL;
    mapping_t *dmap = NULL;
    locator_t *out_srloc = NULL;
    locator_t *out_drloc = NULL;
    forwarding_entry *fwd_entry = NULL;
    lcl_locator_extended_info *leinfo;
    lisp_xtr_t *xtr;

    xtr = CONTAINER_OF(dev, lisp_xtr_t, super);

    /* should be retrieved from a cache in the future */
    fwd_entry = xzalloc(sizeof(forwarding_entry));

    /* If the packet doesn't have an EID source, forward it natively */
    if (!(smap = local_map_db_lookup_eid(xtr->local_mdb, &(tuple->src_addr)))) {
        return (fwd_entry);
    }

    /* If we are behind a full nat system, send the message directly to the RTR */
    if (nat_aware && (nat_status == FULL_NAT)) {
        if (select_srloc_from_bvec(smap, *tuple, &out_srloc) != GOOD) {
            free(fwd_entry);
            return (NULL);
        }

        leinfo = out_srloc->extended_info;

        if (!out_srloc || !leinfo || !leinfo->rtr_locators_list->locator) {
            lmlog(DBG_2, "No RTR for the selected src locator (%s).",
                    lisp_addr_to_char(out_srloc->addr));
            free(fwd_entry);
            return (NULL);
        }

        fwd_entry->src_rloc = out_srloc->addr;
        fwd_entry->dst_rloc = &leinfo->rtr_locators_list->locator->address;
        fwd_entry->out_socket = *(leinfo->out_socket);

        return (fwd_entry);
    }

    //arnatal TODO TODO: Check if local -> Do not encapsulate (can be solved with proper route configuration)
    //arnatal: Do not need to check here if route metrics setted correctly -> local more preferable than default (tun)

    /* FC TODO: implement unicast FIB instead of using the map-cache? */
    dmap = tr_mcache_lookup_mapping(xtr, &(tuple->dst_addr));

    /* There is no entry in the map cache */
    if (!dmap) {
        lmlog(DBG_1, "No map cache retrieved for eid %s. Sending Map-Request!",
                lisp_addr_to_char(&tuple->dst_addr));
        handle_map_cache_miss(xtr, &(tuple->dst_addr), &(tuple->src_addr));
    }

    /* No map-cache entry or no output locators (negative entry) */
    if (!dmap || (mapping_locator_count(dmap) == 0)) {
        /* Try PETRs */
        if (!xtr->petrs) {
            lmlog(DBG_3, "Trying to forward to PxTR but none found ...");
            return (fwd_entry);
        }
        if ((select_rmt_srloc_from_bvec(smap, xtr->petrs->mapping, *tuple,
                &out_srloc, &out_drloc)) != GOOD) {
            lmlog(DBG_3, "No Proxy-etr compatible with local locators afi");
            free(fwd_entry);
            return (NULL);
        }

        /* There is an entry in the map cache
         * Find locators to be used */
    } else {
        if (select_rmt_srloc_from_bvec(smap, dmap, *tuple, &out_srloc,
                &out_drloc) != GOOD) {
            /* If no match between afi of source and destination RLOC, try to
             * forward to petr*/
            return (fwd_entry);
        }
    }

    if (!out_srloc) {
        lmlog(DBG_2, "get_forwarding_entry: No output src locator");
        return (fwd_entry);
    }
    if (!out_drloc) {
        lmlog(DBG_2, "get_forwarding_entry: No destination locator selectable");
        return (fwd_entry);
    }

    fwd_entry->dst_rloc = locator_addr(out_drloc);
    fwd_entry->src_rloc = locator_addr(out_srloc);

    /* Decide what happens when src or dst are LCAFs */
    if (lisp_addr_afi(locator_addr(out_drloc)) == LM_AFI_LCAF) {
        get_dst_from_lcaf(locator_addr(out_drloc), &fwd_entry->dst_rloc);
    }

    /* if our src rloc is an LCAF, just use the default data address */
    if (lisp_addr_afi(locator_addr(out_srloc)) == LM_AFI_LCAF) {
        if (lisp_addr_ip_afi(fwd_entry->dst_rloc) == AF_INET) {
            fwd_entry->src_rloc = default_out_iface_v4->ipv4_address;
        } else {
            fwd_entry->src_rloc = default_out_iface_v6->ipv6_address;
        }
    }

    leinfo = out_srloc->extended_info;
    fwd_entry->out_socket = *(leinfo->out_socket);

    return (fwd_entry);
}


static int
rtr_get_src_and_dst_from_lcaf(lisp_addr_t *laddr, lisp_addr_t **src,
        lisp_addr_t **dst)
{
    lcaf_addr_t *lcaf = NULL;
    elp_node_t *elp_node, next_elp;
    iface_list_elt *iface = NULL;
    glist_entry_t *it = NULL;
    lisp_addr_t *if_v4, *if_v6;

    lcaf = lisp_addr_get_lcaf(laddr);
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_EXPL_LOC_PATH:
        /* lookup in the elp list the first RLOC to also pertain to the RTR */
        glist_for_each_entry(it, lcaf_elp_node_list(lcaf)) {
            elp_node = glist_entry_data(it);
            iface = head_interface_list;
            while (iface) {
                if_v4 = iface->iface->ipv4_address;
                if (lisp_addr_cmp(if_v4, elp_node->addr) == 0) {
                    next_elp = glist_entry_data(glist_next(it));
                    *dst = next_elp->addr;
                    *src = elp_node->addr;
                    return (GOOD);
                }
                if_v6 = iface->iface->ipv6_address;
                if (lisp_addr_cmp(if_v6, elp_node->addr) == 0) {
                    next_elp = glist_entry_data(glist_next(it));
                    *dst = next_elp->addr;
                    *dst = elp_node->addr;
                    return (GOOD);
                }
                iface = iface->next;
            }
        }
        return (GOOD);
    default:
        lmlog(DBG_1, "get_locator_from_lcaf: Type % not supported!, ",
                lcaf_addr_get_type(lcaf));
        return (BAD);
    }
}

forwarding_entry *
tr_get_reencap_forwarding_entry(lisp_ctrl_dev_t *dev, packet_tuple *tuple)
{
    mapping_t *dst_mapping = NULL;
    forwarding_entry *fwd_entry = NULL;
    locators_list_t *lit_array[2] = { NULL, NULL };
    locators_list_t *lit = NULL;
    locator_t *locator = NULL;
    int ctr;
    lisp_xtr_t *xtr;

    xtr = CONTAINER_OF(dev, lisp_xtr_t, super);

    /* should be retrieved from a cache in the future */
    fwd_entry = xzalloc(sizeof(forwarding_entry));

    dst_mapping = tr_mcache_lookup_mapping(xtr, &(tuple->dst_addr));

    /* There is no entry in the map cache */
    if (!dst_mapping) {
        lmlog(DBG_1, "get_forwarding_entry: No map cache retrieved for eid %s."
                " Sending Map-Request!", lisp_addr_to_char(&tuple->dst_addr));
        /* the inner src is not registered by the RTR, so don't use it when
         * doing map-requests */
        handle_map_cache_miss(dev, &(tuple->dst_addr), NULL);
        return (fwd_entry);
    }

    /* just lookup the first LCAF in the dst mapping and obtain the src/dst
     * rlocs */
    lit_array[0] = dst_mapping->head_v4_locators_list;
    lit_array[1] = dst_mapping->head_v6_locators_list;
    for (ctr = 0; ctr < 2; ctr++) {
        lit = lit_array[ctr];
        while (lit) {
            locator = lit->locator;
            if (lisp_addr_afi(locator_addr(locator)) == LM_AFI_LCAF) {
                rtr_get_src_and_dst_from_lcaf(locator_addr(locator),
                        &fwd_entry->src_rloc, &fwd_entry->dst_rloc);
                break;
            }
            lit = lit->next;
        }
    }

    if (!fwd_entry->src_rloc || !fwd_entry->dst_rloc) {
        lmlog(LWRN, "Couldn't find src/dst rloc pair");
        return (NULL);
    }

    if (lisp_addr_afi(fwd_entry->src_rloc))
        fwd_entry->out_socket = default_out_iface_v4->out_socket_v4;
    else
        fwd_entry->out_socket = default_out_iface_v6->out_socket_v6;

    return (fwd_entry);
}
