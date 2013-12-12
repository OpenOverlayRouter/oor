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

    /* TODO: in the future we should have only one function parameter, a map_request object!  */

    lispd_jib_t         *jib                = NULL;
    lispd_locators_list *locator_list       = NULL;
    lisp_addr_t         *locp               = NULL;


    /* add dst (S-RLOC, DG/RLOC) to jib */
    if (!(jib = re_get_jib(ch)))
        return (BAD);

    locator_list  = calloc(1, sizeof(lispd_locators_list));
    locator_list->next = NULL;

    /* the pair is of the type (S-RLOC, D-RLOC)
     * If the join will carry in the future more D-RLOCs for TE
     * add them one by one to the locator list
     */
    lisp_addr_copy(locator_list->locator, rloc_pair);
    jib_add_locator_list(locator_list, jib);

    return(GOOD);

}


int re_recv_leave_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair) {
    /* remove dst (S-RLOC, DG/RLOC) from jib */

    lispd_jib_t         *jib        = NULL;
    lispd_locators_list *loc_list   = NULL;

    jib = re_get_jib(ch);
    /* XXX NEED PROPER DELETE */
    jib_del_locator_list(rloc_pair, jib);
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

}

int re_send_leave_request() {

}




lispd_upstream_t *re_get_upstream(lisp_addr_t *eid) {
    lispd_map_cache_entry                   *cache_entry            = NULL;
    lispd_mapping_elt                       *mapping                = NULL;

    /* Find eid's map-cache entry*/
    cache_entry = lookup_map_cache_exact(eid);
    if (!cache_entry){
        lispd_log_msg(LISP_LOG_DEBUG_2,"re_get_upstream:  No map cache entry found for %s",
                lisp_addr_to_char(eid));
        return (BAD);
    }

    mapping = mcache_entry_get_mapping(mapping);
    return(((mcinfo_mapping_extended_info*)mapping->extended_info)->upstream);
}

lispd_jib_t *re_get_jib(lisp_addr_t *mcaddr) {
    lispd_map_cache_entry   *mcentry    = NULL;
    lispd_mapping_elt       *mapping    = NULL;

    if (!lisp_addr_is_mc(mcaddr)) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_get_jib: The requested address is not multicast %s", lisp_addr_to_char(dst_addr));
        return(NULL);
    }

    /* TODO: implement real multicast FIB instead of using the mapping db */
//    mcentry = lookup_eid_in_db(mcaddr);
    mcentry = lookup_map_cache_exact(mcaddr);


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
lispd_generic_list_t *re_get_orlist(lisp_addr_t *dst_addr) {
    lispd_jib_t             *jib        = NULL;
    lispd_generic_list_t    *or_list    = NULL;

    if (!lisp_addr_is_mc(dst_addr)) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_get_orlist: The requested address is not multicast %s", lisp_addr_to_char(dst_addr));
        return(NULL);
    }

    jib = re_get_jib(dst_addr);
    or_list = jib_get_orlist(jib);

    if (generic_list_size(or_list) == 0)
        return(NULL);
    else
        return(or_list);
}




/*
 * Interface to end-hosts
 */

void multicast_join_channel(ip_addr_t *src, ip_addr_t *grp) {
    re_join_channel(src, grp);
}

void multicast_leave_channel(ip_addr_t *src, ip_addr_t *grp) {
    re_leave_channel(src, grp);
}

/*
 * The following should manage the joins for all multicast protocols
 * (lisp-re, lisp-multicast ...). For the time being, we have only lisp-re
 */


int mrsignaling_recv_mrequest(
        uint8_t **offset,
        lisp_addr_t *src_eid,
        lisp_addr_t *local_rloc,
        lisp_addr_t *remote_rloc,
        uint16_t    dport,
        uint64_t    nonce) {

    mrsignaling_flags_t             mc_flags;
    uint8_t                         *cur_ptr;
    lispd_pkt_mapping_record_t      *record;
    lisp_addr_t                     *dst_eid;
    lispd_mapping_elt               *registered_mapping;
    int                             ret;


    cur_ptr = *offset;
    record = (lispd_pkt_map_request_eid_prefix_record_t *)cur_ptr;

    mc_flags = lcaf_mcinfo_get_flags((uint8_t *)&((record)->eid_prefix_afi));
    cur_ptr = (uint8_t *)&(record->eid_prefix_afi);

    dst_eid = lisp_addr_new();

    /* Read destination/requested EID prefix */
    if(!lisp_addr_read_from_pkt(&cur_ptr, dst_eid)) {
        lisp_addr_del(dst_eid);
        return(BAD);
    }

    if (!lisp_addr_is_mc(dst_eid)) {
        lispd_log_msg(LISP_LOG_WARNING, "mrsignaling_process_mreq_message: The destination EID is not multicast!");
        lisp_addr_del(dst_eid);
        return(BAD);
    }

    if (mc_flags->jbit == 1 && mc_flags->lbit == 1) {
        lisd_log_msg(LISP_LOG_DEBUG_1, "mrsignaling_recv_mrequest_message: Both join and leave flags are set!");
        return(BAD);
    }

    if(!(registered_mapping = lookup_eid_in_db(dst_eid))) {
        lispd_log_msg(LISP_LOG_DEBUG_2,"re_recv_join_request: received join request for multicast channel %s. "
                "But we're not replicating it. Dropping ... ", lisp_addr_to_char(dst_eid));
        return(BAD);
    }

    /* hardwired to re, should change when we support lisp-multicast */
    if (mc_flags->jbit == 1)
        ret = re_recv_join_request(dst_eid, src_eid);
    else if (mc_flags->lbit == 1)
        ret = re_recv_leave_request(dst_eid, src_eid);
    else if (mc_flags->rbit == 1) {
        ret = BAD;
        lisd_log_msg(LISP_LOG_WARNING, "re_process_mrsignaling: PIM join received, not implemented!");
    }

    if (ret == GOOD)
        err = mrsignaling_send_mreply(registered_mapping, local_rloc, remote_rloc, dport, nonce, mc_flags);

    *offset = cur_ptr;
    lisp_addr_del(dst_eid);
    return (err);

}

int mrsignaling_send_mreply(
        lispd_mapping_elt *registered_mapping,
        lisp_addr_t *local_rloc,
        lisp_addr_t *remote_rloc,
        uint16_t dport,
        uint64_t nonce,
        mrsignaling_flags_t mc_flags) {

    map_reply_opts mropts;

    mropts.send_rec   = 1;
    mropts.echo_nonce = 0;
    mropts.rloc_probe = 0;
    mropts.mrsig.jbit = mc_flags.jbit;
    mropts.mrsig.lbit = mc_flags.lbit;
    mropts.mrsig.rbit = mc_flags.rbit;

    return(build_and_send_map_reply_msg(registered_mapping, local_rloc, remote_rloc, dport, nonce, mropts));
}

void mrsignaling_set_flags_in_pkt(uint8_t *offset, mrsignaling_flags_t mc_flags) {

    lispd_lcaf_mcinfo_hdr_t *mc_ptr;

    /* jump the afi */
    offset = CO(offset, sizeof(uint16_t));
    mc_ptr = (lispd_lcaf_mcinfo_hdr_t *) offset;
    mc_ptr->jbit = mc_flags.jbit;
    mc_ptr->lbit = mc_flags.lbit;
    mc_ptr->rbit = mc_flags.rbit;
}

int mrsignaling_recv_mreply(uint8_t **offset, uint64_t nonce) {

    uint8_t                                 *cur_ptr                = NULL;
    lispd_pkt_mapping_record_t              *record                 = NULL;
    lisp_addr_t                             *eid                    = NULL;
    mrsignaling_flags_t                     mc_flags;

    record = (lispd_pkt_mapping_record_t *)(*offset);
    cur_ptr = (uint8_t *)&(record->eid_prefix_afi);

    mc_flags = lcaf_mcinfo_get_flags(cur_ptr);

    eid = lisp_addr_new();
    if(!lisp_addr_read_from_pkt(&cur_ptr, eid)) {
        lisp_addr_del(eid);
        return(err);
    }

    if (mc_flags->jbit == 1 && mc_flags->lbit == 1) {
        lisd_log_msg(LISP_LOG_DEBUG_1, "re_process_mrsignaling: Both join and leave flags are set!");
        return(BAD);
    }

    /* hardwired to re, should change when we support lisp-multicast */
    if (mc_flags->jbit == 1)
        re_recv_join_ack(eid);
    else if (mc_flags->lbit == 1)
        re_recv_leave_ack(eid);
    else if (mc_flags->rbit == 1) {
        lisd_log_msg(LISP_LOG_WARNING, "mrsignaling_recv_mreply_message: PIM join received, not implemented!");
        return(BAD);
    }

    lisp_addr_del(eid);
    *offset = cur_ptr;

    return(GOOD);
}

/* auxiliary stuff */
inline int lisp_addr_is_mc(lisp_addr_t *addr) {
    assert(addr);
    if (lisp_addr_get_afi(addr) == LM_AFI_LCAF && lcaf_addr_is_mc(lisp_addr_get_lcaf(addr)))
        return(1);
    else
        return(0);
}

lisp_addr_t *re_build_mceid(ip_addr_t *src, ip_addr_t *grp) {
    lisp_addr_t     *mceid;
    mc_addr_t       *mc;
    lcaf_addr_t     *lcaf;

    mceid = lisp_addr_new_afi(LM_AFI_LCAF);
    lcaf = lisp_addr_get_lcaf(mceid);

    mc = mc_addr_init(src, grp,
            (ip_addr_get_afi(src) == AF_INET) ? 32 : 128,
            (ip_addr_get_afi(grp) == AF_INET) ? 32 : 128,
            0);

    lcaf_addr_set(lcaf, mc, LCAF_MCAST_INFO);
    return(mceid);
}

