/*
 * lispd_re.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
 *
 * Copyright (C) 2012 Cisco Systems, Inc, 2012. All rights reserved.
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
 *    Florin Coras  <fcoras@ac.upc.edu>
 *
 */

#include "lispd_re.h"
#include "lispd_map_cache_db.h"
#include "lisp_ctrl_device.h"
#include "lispd_external.h"

/*
 * Interface to end-hosts
 */

int re_join_channel(lisp_addr_t *mceid) {
    mapping_t *mapping  = NULL;

    /* first step, obtain a mapping for mceid */
    mapping = mcache_lookup_mapping(mceid);
    if (!mapping) {
        if (handle_map_cache_miss(mceid, lcaf_mc_get_src(lisp_addr_get_lcaf(mceid))) != GOOD)
            return(BAD);
        return(GOOD);
    }

    /* once the mapping is obtained (generally this is reached on a second function call)
     * do a mr-signaling join
     */
    re_send_join_request(mapping);

    return(GOOD);
}

int re_leave_channel(lisp_addr_t *mceid) {
    mapping_t   *mapping = NULL;
    re_send_leave_request(mceid);

    mapping = mcache_lookup_mapping(mceid);
    if (!mapping) {
        if (handle_map_cache_miss(mceid, lcaf_mc_get_src(lisp_addr_get_lcaf(mceid))) != GOOD)
            return(BAD);
        return(GOOD);
    }

    return(GOOD);
}



/*
 * Interface to lisp-re overlay
 */

int re_recv_join_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair) {

    remdb_t             *jib                = NULL;
    remdb_member_t      *member             = NULL;
    lcaf_addr_t         *lcaf               = NULL;
    lisp_addr_t         *peer               = NULL;

    /* add dst (S-RLOC, DG/RLOC) to jib */
    if (!(jib = re_get_jib(ch)))
        return (BAD);

    lcaf = lisp_addr_get_lcaf(rloc_pair);
    /* downstream node */
    peer = lcaf_mc_get_grp(lcaf);
    member = remdb_find_member(peer, jib);

    if (member) {
        /* XXX: renew timer + update locator list*/
        return(GOOD);
    } else {
        remdb_add_member(peer, rloc_pair, jib);
    }

    return(GOOD);

}

/* remove dst (S-RLOC, DG/RLOC) from jib */
int re_recv_leave_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair) {
    remdb_t         *jib        = NULL;
    lcaf_addr_t     *lcaf       = NULL;
    lisp_addr_t     *peer       = NULL;

    jib = re_get_jib(ch);
    lcaf = lisp_addr_get_lcaf(rloc_pair);
    peer = lcaf_mc_get_grp(lcaf);
    remdb_del_member(peer, jib);
    return (GOOD);
}

int re_recv_join_ack(lisp_addr_t *eid, uint32_t nonce) {
    re_upstream_t    *upstream               = NULL;

    upstream = re_get_upstream(eid);

//    /* Check if the nonces are identical */
//    if (check_nonce(upstream->nonces, nonce)==BAD){
//        lispd_log_msg(LISP_LOG_DEBUG_2,"re_recv_join_ack:  The nonce of the Map-Reply doesn't "
//                "match the nonce of the generated Map-Request. Discarding message ...");
//        return (BAD);
//    }

    if (upstream->join_pending) {
        lispd_log_msg(LISP_LOG_DEBUG_2,"re_recv_join_ack: Message confirms correct join!");
        upstream->join_pending = 0;
    } else {
        lispd_log_msg(LISP_LOG_DEBUG_2,"re_recv_join_ack: Received join ack with correct nonce although "
                "we didn't send one! Discarding ... ");
        return(BAD);
    }

    return(GOOD);
}

int re_recv_leave_ack(lisp_addr_t *eid, uint32_t nonce) {
    re_upstream_t    *upstream               = NULL;
    upstream = re_get_upstream(eid);

    /* Check if the nonces are identical */
    if (check_nonce(upstream->nonces, nonce)==BAD){
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  The nonce of the Map-Reply doesn't match the nonce of the generated Map-Request. Discarding message ...");
        return (BAD);
    }

    if (upstream->leave_pending) {

    } else {
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record: Received leave ack with correct nonce although "
                "we didn't send one! Discarding ... ");
        return(BAD);
    }

    return(GOOD);
}

int re_send_join_request(mapping_t *ch_mapping) {

    lisp_addr_t     *mceid          = NULL;
    lisp_addr_t     *dst_rloc       = NULL;
    lisp_addr_t     *src_rloc       = NULL;
    lisp_addr_t     *delivery_grp   = NULL;
    uint64_t        nonce           = 0;
    re_upstream_t   *upstream       = NULL;
    mcinfo_mapping_extended_info *einfo = NULL;

    mceid = mapping_eid(ch_mapping);
    /* choose the first available RLOC as RTR RLOC
     * TODO: implement better policy */
    if (ch_mapping->head_v4_locators_list)
        dst_rloc = locator_addr(ch_mapping->head_v4_locators_list->locator);
    else if (ch_mapping->head_v6_locators_list)
        dst_rloc = locator_addr(ch_mapping->head_v6_locators_list->locator);
    else {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_send_join_request: no upstream RLOC for channel %s. Aborting join!",
                lisp_addr_to_char(mceid));
        return(BAD);
    }

    src_rloc =  (lisp_addr_ip_get_afi(mapping_eid(ch_mapping)) == AF_INET) ?
            default_out_iface_v4->ipv4_address : default_out_iface_v6->ipv6_address;

    if (!src_rloc) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_send_join_request: couldn't find a src RLOC for channel %s. Aborting join!",
                lisp_addr_to_char(mceid));
        return(BAD);
    }

    delivery_grp = lisp_addr_build_mc(dst_rloc, src_rloc);

    /* ch_mapping should be ch eid but mapping sent due to legacy functions */
    if (mrsignaling_send_join(ch_mapping, delivery_grp, dst_rloc, &nonce) == GOOD) {
        /* initialize extended info and upstream */
        upstream = calloc(1, sizeof(re_upstream_t));
        upstream->join_pending = 1;
        upstream->locator = dst_rloc;
        einfo = calloc(1, sizeof(mcinfo_mapping_extended_info));
        if (!einfo)
            return(BAD);

        einfo->upstream = upstream;
        mapping_set_extended_info(ch_mapping, einfo);

        /* TODO: initialize timers */
    }

    return(GOOD);
}

int re_send_leave_request(lisp_addr_t *mceid) {

    return(GOOD);
}




re_upstream_t *re_get_upstream(lisp_addr_t *eid) {
    mapping_t   *mapping    = NULL;

    /* Find eid's map-cache entry*/
    mapping = mcache_lookup_mapping_exact(eid);
    if (!mapping){
        lispd_log_msg(LISP_LOG_DEBUG_2,"re_get_upstream:  No map cache entry found for %s",
                lisp_addr_to_char(eid));
        return (BAD);
    }

    return(mapping_get_re_upstream(mapping));
}

remdb_t *re_get_jib(lisp_addr_t *eid) {
    mapping_t       *mapping    = NULL;

    if (!lisp_addr_is_mc(eid)) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_get_jib: The requested address is not multicast %s", lisp_addr_to_char(eid));
        return(NULL);
    }

    /* TODO: implement real multicast FIB instead of using the mapping db */
    /* Find eid's map-cache entry*/
    mapping = mcache_lookup_mapping_exact(eid);
    if (!mapping){
        lispd_log_msg(LISP_LOG_DEBUG_2,"re_get_upstream:  No map cache entry found for %s",
                lisp_addr_to_char(eid));
        return (BAD);
    }

    /* get output RLOC list (subset of the jib - joinig information base)
     * Current implementation: the jib is pointed to from  the mapping
     * extended info of mcinfo type.  */

    /* packets with no active mapping are dropped */
    if (!mapping){
        lispd_log_msg(LISP_LOG_DEBUG_1, "re_get_jib: Map cache entry carrying the jib, with eid %s, not found or not active!",
                lisp_addr_to_char(eid));
        /* fcoras TODO: what should we return here? */
        return (NULL);
    }

    return(mapping_get_jib(mapping));
}

/*
 * Interface to data plane
 */
glist_t *re_get_orlist(lisp_addr_t *dst_addr) {
    remdb_t           *jib        = NULL;
    glist_t    *or_list    = NULL;

    if (!lisp_addr_is_mc(dst_addr)) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_get_orlist: The requested address is not multicast %s", lisp_addr_to_char(dst_addr));
        return(NULL);
    }

    jib = re_get_jib(dst_addr);
    or_list = remdb_get_orlist(jib);

    if (glist_size(or_list) == 0)
        return(NULL);
    else
        return(or_list);
}






/*
 * The following should manage the joins for all multicast protocols
 * (lisp-re, lisp-multicast ...). For the time being, we have only lisp-re
 */






