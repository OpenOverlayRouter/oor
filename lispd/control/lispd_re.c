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

int re_upstream_join_cb(timer *t, void *arg) {
    timer_upstream_join *argtimer = arg;
    mapping_t *mapping = mcache_lookup_mapping(argtimer->mceid);

    if (!mapping) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "Failed to get a map-reply for %s. Aborting Join!",
                lisp_addr_to_char(argtimer->mceid));
    } else {
        re_join_upstream(mapping);
    }

    lisp_addr_del(argtimer->mceid);
    free(t);
    return(GOOD);
}

int re_join_channel(lisp_addr_t *mceid) {
    mapping_t           *mapping     = NULL;
    lisp_addr_t         *src            = NULL;
    timer               *t = NULL;
    timer_upstream_join *argtimer = NULL;
    /* FIRST STEP
     * obtain a mapping for mceid
     */
    mapping = mcache_lookup_mapping(mceid);
    if (!mapping) {
        src = lcaf_mc_get_src(lisp_addr_get_lcaf(mceid));
        if (handle_map_cache_miss(mceid, local_map_db_get_main_eid(lisp_addr_ip_get_afi(src))) != GOOD)
            return(BAD);
    }

    /* SECOND STEP
     * once the mapping is obtained do a mr-signaling join
     *
     * we start a timer that waits some seconds prior to checking if the mapping is solved
     */
    t = create_timer(RE_UPSTREAM_JOIN_TIMER);

    argtimer = calloc(1, sizeof(timer_upstream_join));
    argtimer->mceid = lisp_addr_clone(mceid);
    start_timer(t, RE_ITR_MR_SOLVE_TIMEOUT, re_upstream_join_cb, (void *)argtimer);

    return(GOOD);
}

void re_mapping_data_del(void *eidata) {
    re_mapping_data *einfo = eidata;
    if (einfo->upstream) re_upstream_del(einfo->upstream);
    if (einfo->jib) remdb_del(einfo->jib);
    if (einfo->itr_solve_timer) free(einfo->itr_solve_timer);
    free(einfo);
}

static int get_level_from_mapping(mapping_t *mapping) {
    lisp_addr_t *eid = NULL, *rloc = NULL;
    rle_node_t  *rnode = NULL;
    glist_t *node_list;

    if (!mapping)
        return(127);

    eid = mapping_eid(mapping);

    if (!lisp_addr_is_mc(eid))
        return(-1);

    if (lisp_addr_ip_get_afi(lcaf_mc_get_src(lisp_addr_get_lcaf(eid))) == AF_INET)
        rloc = locator_addr(mapping->head_v4_locators_list->locator);
    else
        rloc = locator_addr(mapping->head_v6_locators_list->locator);

    if (lisp_addr_get_afi(rloc) != LM_AFI_LCAF && lisp_addr_lcaf_get_type(rloc) != LCAF_RLE)
        return(-1);

    node_list = lcaf_rle_node_list(lisp_addr_get_lcaf(rloc));
    if (glist_size(node_list)>1) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "get_level_from_mapping: RLE in mapping has more than 1 RLE node!");
        return(-1);
    }

    rnode = glist_first_data(node_list);

    return(rnode->level);
}

static int re_select_upstream(re_upstream_t *upstream, mapping_t *ch_mapping, mapping_t *loc_mapping) {
    lisp_addr_t         *mceid = NULL, *src_rloc = NULL, *dst_rloc = NULL, *rleaddr = NULL, *itr_eid = NULL;
    mapping_t           *itr_mapping = NULL;
    lcaf_addr_t         *rle            = NULL;
    lispd_locators_list *ll             = NULL;
    glist_entry_t       *it             = NULL;
    rle_node_t          *rnode          = NULL;
    int                 level = 0, local_level = 0;


    mceid = mapping_eid(ch_mapping);
    src_rloc = get_default_ctrl_address(lisp_addr_ip_get_afi(lcaf_mc_get_src(lisp_addr_get_lcaf(mceid))));

    if (!src_rloc) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_select_upstream: couldn't find a src RLOC for channel %s. Aborting join!",
                lisp_addr_to_char(mceid));
        return(BAD);
    }

    local_level = get_level_from_mapping(loc_mapping);

    if (local_level < 0) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "re_select_upstream: local level can't be determined for %s. Abort!",
                lisp_addr_to_char(mceid));
        return(BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_1, "re_select_upstream: Local level is %d for ch %s", local_level,
            lisp_addr_to_char(mceid));

    if (upstream->locator)
        free_locator(upstream->locator);

    /* top RTR, must connect to ITR */
    if (local_level == 0) {
        if (ctrl_dev->mode != RTR_MODE) {
            lispd_log_msg(LISP_LOG_WARNING, "re_select_upstream: our level is 0 in channel %s but we're NOT an RTR!",
                    lisp_addr_to_char(mceid));
            return(BAD);
        }
        itr_eid = lcaf_mc_get_src(lisp_addr_get_lcaf(mceid));
        itr_mapping = mcache_lookup_mapping(itr_eid);

        if (!itr_mapping && upstream->itr_resolution_pending) {
            lispd_log_msg(LISP_LOG_DEBUG_3, "ITR resolution failed! Aborting");
            upstream->itr_resolution_pending = 0;
            return(BAD);
        } else if (!itr_mapping) {
            lispd_log_msg(LISP_LOG_DEBUG_3, "re_select_upstream: must obtain RLOC of ITR. Sending Map-Request for %s",
                    lisp_addr_to_char(itr_eid));
            return(handle_map_cache_miss(itr_eid, NULL));
        }

        if (lisp_addr_ip_get_afi(src_rloc))
            dst_rloc = locator_addr(itr_mapping->head_v4_locators_list->locator);
        else
            dst_rloc = locator_addr(itr_mapping->head_v6_locators_list->locator);

    } else {

        /* FIND RLE in ch_mapping */
        if (lisp_addr_ip_get_afi(src_rloc) == AF_INET)
            ll = ch_mapping->head_v4_locators_list;
        else
            ll = ch_mapping->head_v6_locators_list;

        if (!ll) {
            lispd_log_msg(LISP_LOG_DEBUG_3, "re_select_upstream: No compatible upstream RLOC found for channel %s!",
                    lisp_addr_to_char(mceid));
            return(BAD);
        }

        while(ll) {
            if (lisp_addr_get_afi(locator_addr(ll->locator)) == LM_AFI_LCAF &&
                    lisp_addr_lcaf_get_type(locator_addr(ll->locator)) == LCAF_RLE)
                break;
            ll = ll->next;
        }

        if (!ll) {
            lispd_log_msg(LISP_LOG_DEBUG_3, "re_select_upstream: Locator for ch %s mapping is NOT RLE. Aborting! ",
                    lisp_addr_to_char(mceid));
            return(BAD);
        }

        rleaddr = locator_addr(ll->locator);

        /* choose the first, highest level rle node  RLOC as RTR RLOC
         * TODO: implement better policy */

        rle = lisp_addr_get_lcaf(rleaddr);

        level = -1;
        glist_for_each_entry(it, lcaf_rle_node_list(rle)) {
            rnode = glist_entry_data(it);
            /* TODO: avoid black listed nodes and check status (how to save the status?)! */
            if (rnode->level > level && rnode->level < local_level) {
                level = rnode->level;
                dst_rloc = rnode->addr;
            }
        }

        lispd_log_msg(LISP_LOG_DEBUG_1, "re_select_upstream: rle %s and dst rloc is %s",
                lcaf_addr_to_char(rle), lisp_addr_to_char(dst_rloc));

        if (!dst_rloc) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "re_select_upstream: couldn't find upstream RLOC for %s! Aborting!",
                    lisp_addr_to_char(mceid));
        }
    }

    upstream->locator = locator_init_remote(dst_rloc);
    upstream->delivery_rloc = lisp_addr_build_mc(dst_rloc, src_rloc);

    /* TODO: start timers checking the upstream's RLOC */

    lispd_log_msg(LISP_LOG_DEBUG_1, "Found upstream with locator %s for channel eid %s",
            lisp_addr_to_char(locator_addr(upstream->locator)), lisp_addr_to_char(mceid));
    return(GOOD);
}

int mapping_init_re_data(mapping_t *ch_mapping) {
    re_mapping_data *einfo = NULL;

    lispd_log_msg(LISP_LOG_DEBUG_3, "Initializing re data for channel %s", lisp_addr_to_char(mapping_eid(ch_mapping)));
    if (!mapping_extended_info(ch_mapping)) {
        einfo = calloc(1, sizeof(re_mapping_data));
        if (!einfo)
            return(BAD);
        mapping_set_extended_info(ch_mapping, einfo, re_mapping_data_del);
    } else {
        mapping_extended_info_del(ch_mapping);
        einfo = calloc(1, sizeof(re_mapping_data));
        if (!einfo)
            return(BAD);
        mapping_set_extended_info(ch_mapping, einfo, re_mapping_data_del);
    }

    einfo->upstream = calloc(1, sizeof(re_upstream_t));
    einfo->jib = remdb_new();
    ch_mapping->type = MAPPING_RE;
    return(GOOD);
}


static int mapping_re_new_upstream(mapping_t *ch_mapping) {
    re_mapping_data *einfo = mapping_extended_info(ch_mapping);
    einfo->upstream = calloc(1, sizeof(re_upstream_t));
    return(GOOD);
}

static timer *mapping_re_itr_solve_timer(mapping_t *ch_mapping) {
    re_mapping_data *einfo = mapping_extended_info(ch_mapping);
    return(einfo->itr_solve_timer);
}

static int re_itr_solve_cb(timer *t, void *arg) {
    timer_itr_resolution *argtimer = arg;
    re_join_upstream(argtimer->ch_mapping);
    return(GOOD);
}

int re_join_upstream(mapping_t *ch_mapping) {
    re_upstream_t       *upstream   = NULL;
    uint64_t            nonce       = 0;
    timer               *t          =  NULL;
    mapping_t           *local_map  = NULL;
    timer_itr_resolution *argtimer  = NULL;

    /* TODO: should build black list of nodes we can't join */
    /* TODO: change code such that when upstream locator probing fails, this process is reran */

    /* already joined an upstream */
    if (mapping_extended_info(ch_mapping) && (upstream = mapping_get_re_upstream(ch_mapping))) {
        /* just send a periodical Join-Request */
        if (upstream->locator && (*upstream->locator->state) == UP)
            return(mrsignaling_send_join(ch_mapping, upstream->delivery_rloc, locator_addr(upstream->locator), &nonce));
    }

    /* new mc_data/upstream */
    if (!mapping_extended_info(ch_mapping) && (mapping_init_re_data(ch_mapping) != GOOD))
        return(BAD);
    else if (!upstream && (mapping_re_new_upstream(ch_mapping) != GOOD))
        return(BAD);

    upstream = mapping_get_re_upstream(ch_mapping);

    if (ctrl_dev->mode == RTR_MODE)
        local_map = local_map_db_lookup_eid(mapping_eid(ch_mapping));
    else
        local_map = NULL;

    if (re_select_upstream(upstream, ch_mapping, local_map) != GOOD) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "re_join_upstream: Couldn't find upstream for channel %s",
                lisp_addr_to_char(mapping_eid(ch_mapping)));
        return(BAD);
    }

    /* returned GOOD from select but no locator set => M-Req for ITR */
    if (!upstream->locator) {
        if (ctrl_dev->mode == RTR_MODE) {
            /* set timer to return to this function */
            t = mapping_re_itr_solve_timer(ch_mapping);
            if (!t)
                t = create_timer(RE_ITR_RESOLUTION_TIMER);
            argtimer = calloc(1, sizeof(timer_itr_resolution));
            argtimer->ch_mapping = ch_mapping;
            upstream->itr_resolution_pending = 1;
            start_timer(t, RE_ITR_MR_SOLVE_TIMEOUT, re_itr_solve_cb, (void *)argtimer);
            return(GOOD);
        }

        /* ETRs have nothing more to do */
        return(BAD);
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

//    remdb_t             *jib                = NULL;
    remdb_member_t      *member = NULL;
    lcaf_addr_t         *lcaf = NULL;
    lisp_addr_t         *peer = NULL, *src_eid = NULL;
    re_mapping_data     *redata = NULL;
    mapping_t           *ch_mapping = NULL, *src_eid_mapping = NULL;

    timer               *t = NULL;
    timer_itr_joined    *argtimer = NULL;


    lispd_log_msg(LISP_LOG_DEBUG_1, "Received Join-Request for channel %s requesting replication pair %s",
            lisp_addr_to_char(ch), lisp_addr_to_char(rloc_pair));

    ch_mapping = mcache_lookup_mapping(ch);
    if (!ch_mapping) {
        src_eid = lcaf_mc_get_src(lisp_addr_get_lcaf(ch));
        src_eid_mapping = local_map_db_lookup_eid(src_eid);
        if (src_eid_mapping) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "re_recv_join_request: Received Join-Request for %s. We are the source ITR! Sending Map-Request",
                    lisp_addr_to_char(ch));
            handle_map_cache_miss(ch, src_eid);
            return(GOOD);

//            t = create_timer(RE_UPSTREAM_JOIN_TIMER);
//            argtimer = calloc(1, sizeof(timer_upstream_join));
//            argtimer->mceid = lisp_addr_clone(ch);
//            argtimer->rloc_pair = lisp_addr_clone(rloc_pair);
//            start_timer(t, RE_ITR_MR_SOLVE_TIMEOUT, re_upstream_join_cb, (void *)argtimer);
//
//            ch_mapping = mcache_lookup_mapping(ch);
//            mapping_init_re_data(ch_mapping);
        } else {
            lispd_log_msg(LISP_LOG_DEBUG_1, "Couldn't find a mapping for channel %s. Aborting",
                    lisp_addr_to_char(ch));
            return(BAD);
        }
    }

    redata = mapping_get_re_data(ch_mapping);

    /* add dst (S-RLOC, DG/RLOC) to jib */
    if (!redata->jib)
        redata->jib = remdb_new();

    lcaf = lisp_addr_get_lcaf(rloc_pair);
    /* downstream node */
    peer = lcaf_mc_get_grp(lcaf);
    member = remdb_find_member(peer, redata->jib);

    if (member) {
        /* TODO: renew timer + update locator list*/
        return(GOOD);
    } else {
        remdb_add_member(peer, lisp_addr_clone(rloc_pair), redata->jib);
        remdb_dump(redata->jib, LISP_LOG_DEBUG_3);
    }

    if (!redata->upstream->locator) {
        re_join_upstream(ch_mapping);
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
    map_cache_dump_db(LISP_LOG_DEBUG_1);
    mapping = mcache_lookup_mapping(eid);
    if (!mapping){
        lispd_log_msg(LISP_LOG_DEBUG_2,"re_get_jib:  No map cache entry found for %s",
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

re_mapping_data *re_get_ch_data(lisp_addr_t *eid) {
    mapping_t *mapping;

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

    /* packets with no active mapping are dropped */
    if (!mapping){
        lispd_log_msg(LISP_LOG_DEBUG_1, "re_get_data: Map cache entry for eid %s, not found or not active!",
                lisp_addr_to_char(eid));
        /* fcoras TODO: what should we return here? */
        return (NULL);
    }

    return(mapping_get_re_data(mapping));
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
    if (jib)
        or_list = remdb_get_orlist(jib);
    else
        return(NULL);

    if (!or_list || glist_size(or_list) == 0)
        return(NULL);
    else
        return(or_list);
}





/*
 * The following should manage the joins for all multicast protocols
 * (lisp-re, lisp-multicast ...). For the time being, we have only lisp-re
 */






