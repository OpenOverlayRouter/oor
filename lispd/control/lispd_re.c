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

/*
 * Interface to end-hosts
 */

int re_join_channel(ip_addr_t *src, ip_addr_t *grp) {
    lisp_addr_t *mceid = re_build_mceid(src, grp);
    re_send_join_request(mceid);

    lisp_addr_del(mceid);
    return(GOOD);
}

int re_leave_channel(ip_addr_t *src, ip_addr_t *grp) {
    lisp_addr_t *mceid = re_build_mceid(src, grp);
    re_send_leave_request(mceid);

    lisp_addr_del(mceid);
    return(GOOD);
}



/*
 * Interface to lisp-re overlay
 */

int re_recv_join_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair) {

    lispd_remdb_t           *jib                = NULL;
    lispd_remdb_member_t    *member             = NULL;
    lcaf_addr_t             *lcaf               = NULL;
    lisp_addr_t             *peer                = NULL;

    /* add dst (S-RLOC, DG/RLOC) to jib */
    if (!(jib = re_get_jib(ch)))
        return (BAD);

    lcaf = lisp_addr_get_lcaf(rloc_pair);
    peer = lcaf_mc_get_grp(lcaf);
    member = remdb_find_member(peer, jib);

    if (member) {
        /* XXX: renew timer + update locator list*/
        return(GOOD);
    }

    remdb_add_member(peer, rloc_pair, jib);
    return(GOOD);

}

/* remove dst (S-RLOC, DG/RLOC) from jib */
int re_recv_leave_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair) {

    lispd_remdb_t           *jib        = NULL;
    lcaf_addr_t             *lcaf       = NULL;
    lisp_addr_t             *peer        = NULL;


    jib = re_get_jib(ch);
    lcaf = lisp_addr_get_lcaf(rloc_pair);
    peer = lcaf_mc_get_grp(lcaf);
    remdb_del_member(peer, jib);
    return (GOOD);
}

int re_recv_join_ack(lisp_addr_t *eid, uint32_t nonce) {
    lispd_upstream_t    *upstream               = NULL;

    upstream = re_get_upstream(eid);

    /* Check if the nonces are identical */
    if (check_nonce(upstream->nonces, nonce)==BAD){
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  The nonce of the Map-Reply doesn't "
                "match the nonce of the generated Map-Request. Discarding message ...");
        return (BAD);
    }

    if (upstream->join_pending) {

    } else {
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record: Received join ack with correct nonce although "
                "we didn't send one! Discarding ... ");
        return(BAD);
    }


    return(GOOD);
}

int re_recv_leave_ack(lisp_addr_t *eid, uint32_t nonce) {
    lispd_upstream_t    *upstream               = NULL;
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

int re_send_join_request(lisp_addr_t *mceid) {

    return(GOOD);
}

int re_send_leave_request(lisp_addr_t *mceid) {

    return(GOOD);
}




lispd_upstream_t *re_get_upstream(lisp_addr_t *eid) {
    lispd_map_cache_entry                   *cache_entry            = NULL;
    mapping_t                       *mapping                = NULL;

    /* Find eid's map-cache entry*/
    cache_entry = map_cache_lookup_exact(eid);
    if (!cache_entry){
        lispd_log_msg(LISP_LOG_DEBUG_2,"re_get_upstream:  No map cache entry found for %s",
                lisp_addr_to_char(eid));
        return (BAD);
    }

    mapping = mcache_entry_get_mapping(cache_entry);
    return(((mcinfo_mapping_extended_info*)mapping->extended_info)->upstream);
}

lispd_remdb_t *re_get_jib(lisp_addr_t *mcaddr) {
    lispd_map_cache_entry   *mcentry    = NULL;
    mapping_t       *mapping    = NULL;

    if (!lisp_addr_is_mc(mcaddr)) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_get_jib: The requested address is not multicast %s", lisp_addr_to_char(mcaddr));
        return(NULL);
    }

    /* TODO: implement real multicast FIB instead of using the mapping db */
//    mcentry = lookup_eid_in_db(mcaddr);
    mcentry = map_cache_lookup_exact(mcaddr);


    if (!mcentry) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "get_re_orlist: No map-cache "
                "entry found for EID %s. This shouldn't happen!",
                lisp_addr_to_char(mcaddr));
        return(BAD);
    }

    /* get output RLOC list (subset of the jib - joinig information base)
     * Current implementation: the jib is pointed to from  the mapping
     * extended info of mcinfo type.  */
    mapping = mcache_entry_get_mapping(mcentry);

    /* packets with no active mapping are dropped */
    if (mcache_entry_get_active(mcentry) == NO_ACTIVE){
        lispd_log_msg(LISP_LOG_DEBUG_1, "re_get_jib: Map cache entry carrying the jib, with eid %s, is NOT active!",
                lisp_addr_to_char(mcaddr));
        /* fcoras TODO: what should we return here? */
        return (NULL);
    }

    return(mapping_get_jib(mapping));
}

/*
 * Interface to data plane
 */
glist_t *re_get_orlist(lisp_addr_t *dst_addr) {
    lispd_remdb_t           *jib        = NULL;
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




/* auxiliary stuff */


lisp_addr_t *re_build_mceid(ip_addr_t *src, ip_addr_t *grp) {
    lisp_addr_t     *mceid;
    uint8_t         mlen;

    mlen = (ip_addr_get_afi(src) == AF_INET) ? 32 : 128;
    mceid = lisp_addr_new();
    lcaf_addr_set_mc(lisp_addr_get_lcaf(mceid), lisp_addr_init_ip(src), lisp_addr_init_ip(grp), mlen, mlen, 0);
//    lisp_addr_set_lcaf(lisp_addr_get_lcaf(mceid),
//            lcaf_addr_init_mc(
//                    lisp_addr_init_ip(src),
//                    lisp_addr_init_ip(grp),
//                    mlen, mlen, 0));
    return(mceid);
}

