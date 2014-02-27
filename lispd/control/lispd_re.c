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
    mapping_t           *mapping     = NULL;
    lisp_addr_t         *src            = NULL;

    /* FIRST STEP
     * obtain a mapping for mceid
     */
    mapping = mcache_lookup_mapping(mceid);
    if (!mapping) {
        src = lcaf_mc_get_src(lisp_addr_get_lcaf(mceid));
        if (handle_map_cache_miss(mceid, local_map_db_get_main_eid(lisp_addr_ip_get_afi(src))) != GOOD)
            return(BAD);
        return(GOOD);
    }


    /* SECOND STEP
     * once the mapping is obtained (generally this is reached
     * on a second function call) do a mr-signaling join
     */
    /* TODO: maybe worth using a timer instead of a second call */
    re_join_upstream(mapping);

    return(GOOD);
}

void re_mapping_extended_info_del(void *eidata) {
    mcinfo_mapping_extended_info *einfo = eidata;
    if (einfo->upstream) re_upstream_del(einfo->upstream);
    if (einfo->jib) remdb_del(einfo->jib);
    free(einfo);
}

static int re_select_upstream(re_upstream_t *upstream, mapping_t *ch_mapping) {
    lisp_addr_t         *mceid          = NULL;
    lisp_addr_t         *src_rloc       = NULL;
    lisp_addr_t         *dst_rloc       = NULL;
    lisp_addr_t         *rleaddr        = NULL;
    lcaf_addr_t         *rle            = NULL;
    lispd_locators_list *ll             = NULL;
    glist_entry_t       *it             = NULL;
    rle_node_t          *rnode          = NULL;
    int                 level           = 0;


    mceid = mapping_eid(ch_mapping);
    src_rloc = get_default_ctrl_address(lisp_addr_ip_get_afi(mceid));

    if (!src_rloc) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_send_join_request: couldn't find a src RLOC for channel %s. Aborting join!",
                lisp_addr_to_char(mceid));
        return(BAD);
    }


    if (lisp_addr_ip_get_afi(src_rloc) == AF_INET)
        ll = ch_mapping->head_v4_locators_list;
    else
        ll = ch_mapping->head_v6_locators_list;

    if (!ll) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_join_upstream: No compatible upstream RLOC found for channel %s!",
                lisp_addr_to_char(mceid));
        return(BAD);
    }

    rleaddr = locator_addr(ll->locator);
    if (lisp_addr_get_afi(rleaddr) != LM_AFI_LCAF || lisp_addr_lcaf_get_type(rleaddr) != LCAF_RLE) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_select_upstream: Locator for ch %s mapping is NOT RLE. Aborting! ",
                lisp_addr_to_char(mceid));
        return(BAD);
    }

    /* choose the first, highest level rle node  RLOC as RTR RLOC
     * TODO: implement better policy */

    rle = lisp_addr_lcaf_get_addr(rleaddr);

    level = -1;
    glist_for_each_entry(it, lcaf_rle_node_list(rle)) {
        rnode = glist_entry_data(it);
        /* TODO: avoid black listed nodes and check status (how to save the status?)! */
        if (rnode->level > level) {
            level = rnode->level;
            dst_rloc = rnode->addr;
        }
    }

    dst_rloc = glist_first_data(lcaf_rle_node_list(rle));

    if (!dst_rloc) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "re_join_upstream: couldn't find upstream RLOC for %s! Aborting!",
                lisp_addr_to_char(mceid));
    }

    if (upstream->locator)
        free_locator(upstream->locator);

    upstream->locator = locator_init_remote(dst_rloc);
    upstream->delivery_rloc = lisp_addr_build_mc(dst_rloc, src_rloc);

    /* TODO: start timers checking the upstream's RLOC */

    lispd_log_msg(LISP_LOG_DEBUG_1, "Found upstream with locator %s for channel eid %s",
            lisp_addr_to_char(locator_addr(upstream->locator)), lisp_addr_to_char(mceid));
    return(GOOD);
}

static int mapping_new_re_data(mapping_t *ch_mapping) {
    mcinfo_mapping_extended_info *einfo = NULL;

    if (!mapping_extended_info(ch_mapping)) {
        einfo = calloc(1, sizeof(mcinfo_mapping_extended_info));
        if (!einfo)
            return(BAD);
        mapping_set_extended_info(ch_mapping, einfo, re_mapping_extended_info_del);
    }

    einfo->upstream = calloc(1, sizeof(re_upstream_t));
    ch_mapping->type = MAPPING_RE;
    return(GOOD);
}

static int mapping_re_new_upstream(mapping_t *ch_mapping) {
    mcinfo_mapping_extended_info *einfo = mapping_extended_info(ch_mapping);
    einfo->upstream = calloc(1, sizeof(re_upstream_t));
    return(GOOD);
}

int re_join_upstream(mapping_t *ch_mapping) {
    re_upstream_t       *upstream       = NULL;
    uint64_t            nonce           = 0;

    /* TODO: should build black list of nodes we can't join */
    /* TODO: change code such that when upstream locator probing fails, this process is reran */

    /* already joined an upstream */
    if (mapping_extended_info(ch_mapping) && (upstream = mapping_get_re_upstream(ch_mapping))) {
        /* just send a periodical Join-Request */
        if (upstream->locator && (*upstream->locator->state) == UP)
            return(mrsignaling_send_join(ch_mapping, upstream->delivery_rloc, locator_addr(upstream->locator), &nonce));
    }

    /* new mc_data/upstream */
    if (!mapping_extended_info(ch_mapping) && (mapping_new_re_data(ch_mapping) != GOOD))
        return(BAD);
    else if (!upstream && (mapping_re_new_upstream(ch_mapping) != GOOD))
        return(BAD);

    upstream = mapping_get_re_upstream(ch_mapping);
    if (re_select_upstream(upstream, ch_mapping) != GOOD) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "re_join_upstream: Couldn't set upstream for channel %s",
                lisp_addr_to_char(mapping_eid(ch_mapping)));
    }

    upstream->join_pending = 1;

    /* ch_mapping should be ch eid but mapping sent due to legacy functions */
    return(mrsignaling_send_join(ch_mapping, upstream->delivery_rloc, locator_addr(upstream->locator), &nonce));
}

int re_leave_channel(lisp_addr_t *mceid) {
    mapping_t       *mapping = NULL;
    re_upstream_t   *upstream   = NULL;
    uint64_t        nonce       = 0;

    mapping = mcache_lookup_mapping(mceid);
    if (!mapping) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "re_leave_channel: Request to leave channel %s but we're not a member. Discarding!",
                lisp_addr_to_char(mceid));
        return(BAD);
    }

    upstream = mapping_get_re_upstream(mapping);
    if (!upstream) {
        lispd_log_msg(LISP_LOG_DEBUG_1,"re_leave_channel: Channel %s has no upstream configured! Discarding request!",
                lisp_addr_to_char(mceid));
        return(BAD);
    }

    /* the upstream is freed in the leave_ack */
    if (!upstream->leave_pending)
        return(mrsignaling_send_leave(mapping, upstream->delivery_rloc, locator_addr(upstream->locator), &nonce));

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
        jib = remdb_new();

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

    if (upstream->leave_pending) {
        re_upstream_del(upstream);
    } else {
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record: Received leave ACK with correct nonce although "
                "we didn't send one! Discarding ... ");
        return(BAD);
    }

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






