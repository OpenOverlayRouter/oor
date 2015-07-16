/*
 * lisp_xtr.h
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

#include <unistd.h>

#include "../lib/iface_locators.h"
#include "lisp_xtr.h"
#include "../lib/sockets.h"
#include "../lib/util.h"
#include "../lib/lmlog.h"

static int mc_entry_expiration_timer_cb(lmtimer_t *t, void *arg);
static void mc_entry_start_expiration_timer(lisp_xtr_t *, mcache_entry_t *);
static int handle_petr_probe_reply(lisp_xtr_t *, uint64_t);
static int handle_locator_probe_reply(lisp_xtr_t *, mapping_t *,  locator_t *,
        uint64_t);
static int update_mcache_entry(lisp_xtr_t *, mapping_t *, uint64_t nonce);
static int tr_recv_map_reply(lisp_xtr_t *, lbuf_t *);
static int tr_reply_to_smr(lisp_xtr_t *, lisp_addr_t *);
static int tr_recv_map_request(lisp_xtr_t *, lbuf_t *, uconn_t *);
static int tr_recv_map_notify(lisp_xtr_t *, lbuf_t *);

static int send_map_request(lisp_ctrl_dev_t *, lbuf_t *, lisp_addr_t *,
        lisp_addr_t *);
static int send_map_request_to_mr(lisp_xtr_t *, lbuf_t *, lisp_addr_t *,
        lisp_addr_t *);
static glist_t *build_rloc_list(mapping_t *m);
static int build_and_send_smr_mreq(lisp_xtr_t *, mapping_t *, lisp_addr_t *,
        lisp_addr_t *);
static int build_and_send_smr_mreq_to_map(lisp_xtr_t *, mapping_t *,
        mapping_t *);
static int send_all_smr_cb(lmtimer_t *, void *arg);
static void send_all_smr_and_reg(lisp_xtr_t *);
static int send_smr_invoked_map_request(lisp_xtr_t *, mcache_entry_t *);
static int program_smr(lisp_xtr_t *, int time);
static int send_map_request_retry(lisp_xtr_t *xtr, mcache_entry_t *);
//static int send_map_reg(lisp_xtr_t *, lbuf_t *, lisp_addr_t *);
static int build_and_send_map_reg(lisp_xtr_t *, mapping_t *);
static int build_and_send_ecm_map_reg(lisp_xtr_t *, mapping_t *, lisp_addr_t *,
        uint64_t);
int program_map_register(lisp_xtr_t *xtr, int time);
static int map_register_process(lisp_xtr_t *);
static int rloc_probing(lisp_xtr_t *, mapping_t *, locator_t *loc);
static void program_rloc_probing(lisp_xtr_t *, mapping_t *, locator_t *, int);
static void program_mapping_rloc_probing(lisp_xtr_t *, mapping_t *);
static void program_petr_rloc_probing(lisp_xtr_t *, int time);
static inline lisp_xtr_t *lisp_xtr_cast(lisp_ctrl_dev_t *);

static void proxy_etrs_dump(lisp_xtr_t *, int log_level);

static fwd_entry_t *tr_get_forwarding_entry(lisp_ctrl_dev_t *,
        packet_tuple_t *);

glist_t *get_local_locators_with_address(local_map_db_t *local_db, lisp_addr_t *addr);
map_local_entry_t *get_map_loc_ent_containing_loct_ptr(local_map_db_t *local_db, locator_t *locator);
glist_t *get_map_local_entry_to_smr(lisp_xtr_t *xtr);
static lisp_addr_t * get_map_resolver(lisp_xtr_t *xtr);

/* Called when the timer associated with an EID entry expires. */
static int
mc_entry_expiration_timer_cb(lmtimer_t *t, void *arg)
{
    mapping_t *mapping = NULL;
    lisp_addr_t *addr = NULL;

    mapping = mcache_entry_mapping(arg);
    addr = mapping_eid(mapping);
    LMLOG(LDBG_1,"Got expiration for EID %s", lisp_addr_to_char(addr));

    tr_mcache_remove_mapping(t->owner, addr);
    return(GOOD);
}

static void
mc_entry_start_expiration_timer(lisp_xtr_t *xtr, mcache_entry_t *mce)
{
    /* Expiration cache timer */
    if (!mce->expiry_cache_timer) {
        mce->expiry_cache_timer = lmtimer_create(EXPIRE_MAP_CACHE_TIMER);
    }

    lmtimer_start(mce->expiry_cache_timer, mapping_ttl(mcache_entry_mapping(mce))*60,
            mc_entry_expiration_timer_cb, xtr, mce);

    LMLOG(LDBG_1,"The map cache entry of EID %s will expire in %d minutes.",
            lisp_addr_to_char(mapping_eid(mcache_entry_mapping(mce))),
            mapping_ttl(mcache_entry_mapping(mce)));
}


static int
handle_petr_probe_reply(lisp_xtr_t *xtr,uint64_t nonce)
{
    mapping_t *petrs_map = NULL;
    glist_t *loct_list = NULL;
    glist_entry_t *it_list = NULL;
    glist_entry_t *it_loct = NULL;
    rmt_locator_extended_info_t *rmt_ext_inf = NULL;
    locator_t *loct = NULL, *aux_loct = NULL;

    petrs_map = mcache_entry_mapping(xtr->petrs);
    /* find locator */
    if (glist_size(mapping_locators_lists(petrs_map)) == 0){
        LMLOG(LDBG_1, "handle_petr_probe_reply: No PeTRs configured");
        return (BAD);
    }
    glist_for_each_entry(it_list,mapping_locators_lists(petrs_map)){
        loct_list = (glist_t *)glist_entry_data(it_list);
        if (glist_size(loct_list)==0){
            continue;
        }
        glist_for_each_entry(it_loct,loct_list){
            aux_loct = (locator_t *)glist_entry_data(it_loct);
            rmt_ext_inf = aux_loct->extended_info;
            if ((nonce_check(rmt_ext_inf->rloc_probing_nonces, nonce))
                    == GOOD) {
                free(rmt_ext_inf->rloc_probing_nonces);
                rmt_ext_inf->rloc_probing_nonces = NULL;
                loct = aux_loct;
                break;
            }
        }
        if (loct != NULL){
            break;
        }
    }

    if (!loct) {
        LMLOG(LDBG_1, "Nonce of Negative Map-Reply Probe (%s) doesn't match "
                "any nonce of Proxy-ETR locators", nonce_to_char(nonce));
        return (BAD);
    }

    LMLOG(LDBG_1, "Map-Reply probe reachability to the PETR with RLOC %s",
            lisp_addr_to_char(locator_addr(loct)));

    rmt_ext_inf = loct->extended_info;
    if (!rmt_ext_inf->probe_timer){
       LMLOG(LDBG_1," Map-Reply Probe was not requested! Discarding!");
       return (BAD);
    }

    /* Reprogramming timers of rloc probing */
    program_rloc_probing(xtr, petrs_map, loct, xtr->probe_interval);

    return (GOOD);
}

/* Process a record from map-reply probe message */
static int
handle_locator_probe_reply(lisp_xtr_t *xtr, mapping_t *recv_map,
        locator_t *probed, uint64_t nonce)
{
    lisp_addr_t *       src_eid = NULL;
    locator_t *         loc     = NULL;
    mcache_entry_t *    mce     = NULL;
    mapping_t *         map      = NULL;
    rmt_locator_extended_info_t *rmt_ext_inf = NULL;

    src_eid = mapping_eid(recv_map);

    /* Lookup src EID in map cache */
    mce = mcache_lookup_exact(xtr->map_cache,src_eid);
    if(!mce) {
        LMLOG(LDBG_1, "Source EID %s couldn't be found in the map-cache",
                lisp_addr_to_char(src_eid));
        return(BAD);
    }
    map = mcache_entry_mapping(mce);

    /* Find probed locator in mapping */
    loc = mapping_get_loct_with_addr(map, locator_addr(probed));
    if (!loc){
        LMLOG(LDBG_2,"Probed locator %s not part of the the mapping %s",
                lisp_addr_to_char(locator_addr(probed)),
                lisp_addr_to_char(mapping_eid(map)));
        return (ERR_NO_EXIST);
    }

    /* Compare nonces */
    rmt_ext_inf = loc->extended_info;
    if (!rmt_ext_inf || !rmt_ext_inf->rloc_probing_nonces) {
        LMLOG(LDBG_1, "Locator %s has no nonces!",
                lisp_addr_to_char(locator_addr(loc)));
        return(BAD);
    }

    /* Check if the nonce of the message match with the one stored in the
     * structure of the locator */
    if ((nonce_check(rmt_ext_inf->rloc_probing_nonces, nonce)) == GOOD) {
        free(rmt_ext_inf->rloc_probing_nonces);
        rmt_ext_inf->rloc_probing_nonces = NULL;
    } else {
        LMLOG(LDBG_1, "Nonce of Map-Reply Probe doesn't match nonce of the "
                "Map-Request Probe. Discarding message ...");
        return (BAD);
    }

    LMLOG(LDBG_1," Successfully probed RLOC %s of cache entry with EID %s",
                lisp_addr_to_char(locator_addr(loc)),
                lisp_addr_to_char(mapping_eid(map)));


    if (loc->state == DOWN) {
        loc->state = UP;

        LMLOG(LDBG_1," Locator %s state changed to UP",
                lisp_addr_to_char(locator_addr(loc)));

        /* [re]Calculate forwarding info if status changed*/
        xtr->fwd_policy->updated_map_cache_inf(
                xtr->fwd_policy_dev_parm,
                mcache_entry_routing_info(mce),
                map);
    }

    if (!rmt_ext_inf->probe_timer) {
       LMLOG(LDBG_1," Map-Reply Probe was not requested! Discarding!");
       return (BAD);
    }

    /* Reprogramming timers of rloc probing */
    program_rloc_probing(xtr, map, loc, xtr->probe_interval);

    return (GOOD);

}

static int
update_mcache_entry(lisp_xtr_t *xtr, mapping_t *recv_map, uint64_t nonce)
{
    mcache_entry_t *mce = NULL;
    mapping_t *map = NULL;
    lisp_addr_t *eid = NULL;

    eid = mapping_eid(recv_map);

    /* Serch map cache entry exist*/
    mce = mcache_lookup_exact(xtr->map_cache, eid);
    if (!mce){
        LMLOG(LDBG_2,"No map cache entry for %s", lisp_addr_to_char(eid));
        return (BAD);
    }

    /* Check if map cache entry contains the nonce*/
    if (nonce_check(mce->nonces, nonce) == BAD) {
        LMLOG(LDBG_2, " Nonce doesn't match the Map-Request nonce. "
                "Discarding message!");
        return(BAD);
    } else {
        mcache_entry_destroy_nonces(mce);
        mcache_entry_requester_del(mce);
    }

    LMLOG(LDBG_2, "Mapping with EID %s already exists, replacing!",
            lisp_addr_to_char(eid));

    map = mcache_entry_mapping(mce);

    /* DISCARD all locator state */
    mapping_update_locators(map, mapping_locators_lists(recv_map));

    /* Update forwarding info */
    xtr->fwd_policy->updated_map_cache_inf(
            xtr->fwd_policy_dev_parm,
            mcache_entry_routing_info(mce),
            map);

    /* Remove Map Request retry timer */
    mcache_entry_stop_req_retry_timer(mce);
    mcache_entry_stop_smr_inv_timer(mce);

    /* Reprogramming timers */
    mc_entry_start_expiration_timer(xtr, mce);

    /* RLOC probing timer */
    program_mapping_rloc_probing(xtr, map);

    return (GOOD);
}

static int
tr_recv_map_reply(lisp_xtr_t *xtr, lbuf_t *buf)
{
    void *          mrep_hdr= NULL;
    locator_t *     probed  = NULL;
    lisp_addr_t *   eid     = NULL;
    mapping_t *     m       = NULL;
    lbuf_t          b;
    mcache_entry_t *mce     = NULL;
    int             i       = 0;

    /* local copy */
    b = *buf;

    mrep_hdr = lisp_msg_pull_hdr(&b);

    for (i = 0; i < MREP_REC_COUNT(mrep_hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(&b, m, &probed) != GOOD) {
            goto err;
        }

        if (!MREP_RLOC_PROBE(mrep_hdr)) {
            /* Check if the map reply corresponds to a not active map cache */
            mce = lookup_nonce_in_no_active_map_caches(xtr->map_cache,
                    mapping_eid(m), MREP_NONCE(mrep_hdr));

            /* Mapping is NOT ACTIVE */
            if (mce) {
                /* delete placeholder/dummy mapping and install the new one */
                eid = mapping_eid(mcache_entry_mapping(mce));
                tr_mcache_remove_mapping(xtr, eid);

                /* DO NOT free mapping in this case */
                tr_mcache_add_mapping(xtr, m);

            /* Mapping is ACTIVE */
            } else {
                /* the reply might be for an active mapping (SMR)*/
                update_mcache_entry(xtr, m, MREP_NONCE(mrep_hdr));
                mapping_del(m);
            }

            mcache_dump_db(xtr->map_cache, LDBG_3);

            /*
            if (is_mrsignaling()) {
                mrsignaling_recv_ack();
                continue;
            } */
        } else {
            if (mapping_locator_count(m) > 0) {
                if (probed == NULL){
                    LMLOG(LDBG_1,"Received a Map Reply pobe without probed locator. Discarding message");
                    mapping_del(m);
                    return (BAD);
                }
                handle_locator_probe_reply(xtr, m, probed,
                        MREP_NONCE(mrep_hdr));
            } else {
                /* If negative probe map-reply, then the probe was for
                 * proxy-ETR (PETR) */
                handle_petr_probe_reply(xtr, MREP_NONCE(mrep_hdr));
            }

            /* No need to free 'probed' since it's a pointer to a locator in
             * of m's */
            mapping_del(m);
        }

    }

    return(GOOD);
err:
    locator_del(probed);
    mapping_del(m);
    return(BAD);
}


static int
tr_reply_to_smr(lisp_xtr_t *xtr, lisp_addr_t *eid)
{
    mcache_entry_t *mce = NULL;

    /* Lookup the map cache entry that match with the source EID prefix
     * of the message */
    if (!(mce = mcache_lookup(xtr->map_cache, eid))) {
        return(BAD);
    }


    /* Only accept one solicit map request for an EID prefix. If node which
     * generates the message has more than one locator, it probably will
     * generate a solicit map request for each one. Only the first one is
     * considered. If map_cache_entry->nonces is different from null, we have
     * already received a solicit map request  */
    if (!mcache_entry_nonces(mce)) {
        mcache_entry_init_nonces(mce);
        if (!mcache_entry_nonces(mce)) {
            return(BAD);
        }
        send_smr_invoked_map_request(xtr, mce);
    }

    return(GOOD);
}

static int
tr_recv_map_request(lisp_xtr_t *xtr, lbuf_t *buf, uconn_t *uc)
{
    lisp_addr_t *seid = NULL;
    lisp_addr_t *deid = NULL;
    map_local_entry_t *map_loc_e = NULL;
    mapping_t *map = NULL;
    glist_t *itr_rlocs = NULL;
    void *mreq_hdr = NULL;
    void *mrep_hdr = NULL;
    int i = 0;
    lbuf_t *mrep = NULL;
    lbuf_t  b;

    /* local copy of the buf that can be modified */
    b = *buf;

    seid = lisp_addr_new();
    deid = lisp_addr_new();

    mreq_hdr = lisp_msg_pull_hdr(&b);

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }

    /* If packet is a Solicit Map Request, process it */
    if (lisp_addr_lafi(seid) != LM_AFI_NO_ADDR && MREQ_SMR(mreq_hdr)) {
        if(tr_reply_to_smr(xtr, seid) != GOOD) {
            goto err;
        }
        /* Return if RLOC probe bit is not set */
        if (!MREQ_RLOC_PROBE(mreq_hdr)) {
            goto done;
        }
    }

    if (MREQ_RLOC_PROBE(mreq_hdr) && MREQ_REC_COUNT(mreq_hdr) > 1) {
        LMLOG(LDBG_1, "More than one EID record in RLOC probe. Discarding!");
        goto err;
    }

    /* Process additional ITR RLOCs */
    itr_rlocs = laddr_list_new();
    lisp_msg_parse_itr_rlocs(&b, itr_rlocs);

    /* Process records and build Map-Reply */
    mrep = lisp_msg_create(LISP_MAP_REPLY);
    for (i = 0; i < MREQ_REC_COUNT(mreq_hdr); i++) {
        if (lisp_msg_parse_eid_rec(&b, deid) != GOOD) {
            goto err;
        }

        LMLOG(LDBG_1, " dst-eid: %s", lisp_addr_to_char(deid));

        /* Check the existence of the requested EID */
        map_loc_e = local_map_db_lookup_eid(xtr->local_mdb, deid);
        if (!map_loc_e) {
            LMLOG(LDBG_1,"EID %s not locally configured!",
                    lisp_addr_to_char(deid));
            continue;
        }
        map = map_local_entry_mapping(map_loc_e);
        lisp_msg_put_mapping(mrep, map, MREQ_RLOC_PROBE(mreq_hdr)
                ? &uc->la: NULL);
    }

    mrep_hdr = lisp_msg_hdr(mrep);
    MREP_RLOC_PROBE(mrep_hdr) = MREQ_RLOC_PROBE(mreq_hdr);
    MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);

    /* SEND MAP-REPLY */
    laddr_list_get_addr(itr_rlocs, lisp_addr_ip_afi(&uc->la), &uc->ra);
    LMLOG(LDBG_1, "Sending %s", lisp_msg_hdr_to_char(mrep));
    send_msg(&xtr->super, mrep, uc);

done:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    lisp_addr_del(deid);
    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    lisp_addr_del(deid);
    return(BAD);
}



static int
handle_merge_semantics(lisp_xtr_t *xtr, mapping_t *rec_map)
{
    lisp_addr_t *       eid         = NULL;
    mcache_entry_t *    mce         = NULL;
    mapping_t *         mcache_map  = NULL;

    eid = mapping_eid(rec_map);

    LMLOG(LDBG_1, "Merge-Semantics on, moving returned mapping to "
            "map-cache");

    /* XXX, TODO: done thinking of lisp-re, MUST change to be more general */
    /* Save the mapping returned by the map-notify in the mapping
     * cache */
    mce = mcache_lookup(xtr->map_cache,eid);

    if(mce == NULL){
        /* FIRST registration */
        if (tr_mcache_add_mapping(xtr, rec_map) != GOOD) {
            mapping_del(rec_map);
            return(BAD);
        }

        /* for MC initialize the JIB */
        /*
               if (lisp_addr_is_mc(eid)
                   && !mapping_get_re_data(mcache_entry_mapping(mce))) {
                   mapping_init_re_data(mcache_entry_mapping(mce));
               } */
        return (GOOD);
    }
    mcache_map = mcache_entry_mapping(mce);
    if (mapping_cmp(mcache_map, rec_map) != 0) {
        /* UPDATED rlocs */
        LMLOG(LDBG_3, "Prefix %s already registered, updating locators",
                lisp_addr_to_char(eid));
        mapping_update_locators(mcache_map,mapping_locators_lists(rec_map));

        /* Update forward info*/
        xtr->fwd_policy->updated_map_cache_inf(
                xtr->fwd_policy_dev_parm,
                mcache_entry_routing_info(mce),
                mcache_map);

        program_mapping_rloc_probing(xtr, mcache_map);

    }
    return(GOOD);
}

static int
tr_recv_map_notify(
        lisp_xtr_t      *xtr,
        lbuf_t          *buf)
{
    lisp_addr_t *       eid         = NULL;
    map_local_entry_t * map_loc_e	= NULL;
    mapping_t *         m           = NULL;
    mapping_t *         local_map   = NULL;
    void *              hdr         = NULL;
    locator_t *         probed      = 0;
    glist_entry_t *     it          = NULL;
    map_server_elt *    ms          = NULL;
    int                 i           = 0;
    int                 res         = BAD;
    lbuf_t              b;

    /* local copy */
    b = *buf;
    hdr = lisp_msg_pull_hdr(&b);

    /* TODO: compare nonces in all cases not only NAT */
    if (MNTF_XTR_ID_PRESENT(hdr) == TRUE) {
        if (nonce_check(xtr->nat_emr_nonces, MNTF_NONCE(hdr)) == GOOD){
            LMLOG(LDBG_3, "Correct nonce");
            /* Free nonce if authentication is ok */
        } else {
            LMLOG(LDBG_1, "No Map Register sent with nonce: %s",
                    nonce_to_char(MNTF_NONCE(hdr)));
            return (BAD);
        }
    }

    /* TODO: match eid/nonce to ms-key */
    glist_for_each_entry(it,xtr->map_servers){
        ms = (map_server_elt *)glist_entry_data(it);
        res = lisp_msg_check_auth_field(buf, ms->key);
        if (res == GOOD){
            break;
        }
    }
    if (res != GOOD){
        LMLOG(LDBG_1, "Map-Notify message is invalid");
        program_map_register(xtr, LISPD_INITIAL_EMR_TIMEOUT);
        return(BAD);
    }

    lisp_msg_pull_auth_field(&b);

    for (i = 0; i < MNTF_REC_COUNT(hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(&b, m, &probed) != GOOD) {
            mapping_del(m);
            return(BAD);
        }

        eid = mapping_eid(m);
        map_loc_e = local_map_db_lookup_eid_exact(xtr->local_mdb, eid);
        local_map = map_local_entry_mapping(map_loc_e);

        if (!local_map) {
            LMLOG(LDBG_1, "Map-Notify confirms registration of UNKNOWN EID %s."
                    " Dropping!", lisp_addr_to_char(eid));
            continue;
        }

        LMLOG(LDBG_1, "Map-Notify message confirms correct registration of %s",
                lisp_addr_to_char(eid));

        /* MULTICAST MERGE SEMANTICS */
        if (lisp_addr_is_mc(eid) && mapping_cmp(local_map, m) != 0) {
            handle_merge_semantics(xtr, m);
        }

        if (MNTF_XTR_ID_PRESENT(hdr) == TRUE) {
            free(xtr->nat_emr_nonces);
            xtr->nat_emr_nonces = NULL;
        }

        mapping_del(m);
        program_map_register(xtr, MAP_REGISTER_INTERVAL);

    }

    return(GOOD);
}


static int
send_map_request(lisp_ctrl_dev_t *dev, lbuf_t *b, lisp_addr_t *srloc,
        lisp_addr_t *drloc) {
    uconn_t uc;

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, srloc, drloc);
    return(send_msg(dev, b, &uc));
}

static int
send_map_request_to_mr(
        lisp_xtr_t *    xtr,
        lbuf_t *        b,
        lisp_addr_t *   in_srloc,
        lisp_addr_t *   in_drloc)
{
    lisp_addr_t *drloc = NULL, *srloc = NULL;

    /* encap */
    lisp_msg_encap(b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, in_srloc,
            in_drloc);

    /* prepare outer headers */
    drloc = get_map_resolver(xtr);
    srloc = NULL;

    LMLOG(LDBG_1, "%s, inner IP: %s -> %s, inner UDP: %d -> %d",
            lisp_msg_ecm_hdr_to_char(b), lisp_addr_to_char(in_srloc),
            lisp_addr_to_char(in_drloc), LISP_CONTROL_PORT,
            LISP_CONTROL_PORT);

    return(send_map_request(&xtr->super, b, srloc, drloc));
}

void
send_map_request_for_not_active_mce(lisp_xtr_t *    xtr)
{
    mcache_entry_t *    mce             = NULL;

    mcache_foreach_not_active_entry(xtr->map_cache, mce) {
        send_map_request_retry(xtr, mce);
    } mcache_foreach_end;
}

int
handle_map_cache_miss(lisp_xtr_t *xtr, lisp_addr_t *requested_eid,
        lisp_addr_t *src_eid)
{
    mcache_entry_t *    mce         = mcache_entry_new();
    mapping_t *         m           = NULL;
    void *              routing_inf = NULL;

    /* install temporary, NOT active, mapping in map_cache
     * TODO: should also build a nonce hash table for faster
     *       nonce lookups*/
    m = mapping_new_init(requested_eid);
    mcache_entry_init(mce, m);
    routing_inf = xtr->fwd_policy->new_map_cache_policy_inf(xtr->fwd_policy_dev_parm,m);
    if (routing_inf == NULL){
        LMLOG(LWRN, "handle_map_cache_miss: Couldn't create routing info for map cache entry %s!. Discarding it.",
                lisp_addr_to_char(requested_eid));
        mcache_entry_del(mce);
        return(BAD);
    }
    mcache_entry_set_routing_info(mce,routing_inf,xtr->fwd_policy->del_map_cache_policy_inf);
    if (mcache_add_entry(xtr->map_cache, mapping_eid(m), mce) != GOOD) {
        LMLOG(LWRN, "Couln't install temporary map cache entry for %s!",
                lisp_addr_to_char(requested_eid));
        mcache_entry_del(mce);
        return(BAD);
    }

    if (src_eid) {
        mcache_entry_set_requester(mce, lisp_addr_clone(src_eid));
    } else {
        mcache_entry_set_requester(mce, NULL);
    }

    return(send_map_request_retry(xtr, mce));
}

static glist_t *
build_rloc_list(mapping_t *mapping) {
    glist_t *rlocs = glist_new();
    glist_entry_t *it_list = NULL;
    glist_entry_t *it_loct = NULL;
    glist_t *loct_list = NULL;
    locator_t *locator = NULL;
    lisp_addr_t *loc_addr = NULL;

    if (glist_size(mapping_locators_lists(mapping)) == 0){
        return (rlocs);
    }

    glist_for_each_entry(it_list, mapping_locators_lists(mapping)){
        loct_list = (glist_t *)glist_entry_data(it_list);
        if (glist_size(loct_list) == 0){
            continue;
        }
        locator = (locator_t *)glist_first_data(loct_list);
        if (lisp_addr_is_no_addr(locator_addr(locator))== TRUE){
            continue;
        }
        glist_for_each_entry(it_loct,loct_list){
            locator = (locator_t *)glist_entry_data(it_loct);
            loc_addr = locator_addr(locator);
            glist_add_tail(loc_addr,rlocs);
        }
    }

    return(rlocs);
}

static int
build_and_send_smr_mreq(lisp_xtr_t *xtr, mapping_t *smap,
        lisp_addr_t *deid, lisp_addr_t *drloc)
{
    lbuf_t *        b           = NULL;
    lisp_addr_t *   seid        = NULL;
    lisp_addr_t *   srloc       = NULL;
    void *          hdr         = NULL;
    glist_t *       itr_rlocs   = NULL;
    int             res         = GOOD;

    seid = mapping_eid(smap);
    itr_rlocs = build_rloc_list(smap);

    /* build Map-Request */
    b = lisp_msg_mreq_create(seid, itr_rlocs, deid);

    if (b == NULL){
        lisp_msg_destroy(b);
        return (BAD);
    }

    hdr = lisp_msg_hdr(b);
    MREQ_SMR(hdr) = 1;

    LMLOG(LDBG_1, "%s, itr-rlocs: %s, src-eid: %s, req-eid: %s ", lisp_msg_hdr_to_char(b),
            laddr_list_to_char(itr_rlocs), lisp_addr_to_char(seid), lisp_addr_to_char(deid));
    glist_destroy(itr_rlocs);

    srloc = ctrl_default_rloc(xtr->super.ctrl, lisp_addr_ip_afi(drloc));
    if (!srloc) {
        LMLOG(LDBG_2, "No compatible RLOC was found to send SMR Map-Request "
                "for local EID %s", lisp_addr_to_char(seid));
        lisp_msg_destroy(b);
        return(BAD);
    }

    res = send_map_request(&xtr->super, b, srloc, drloc);
    lisp_msg_destroy(b);

    return(res);
}

/* solicit SMRs for 'src_map' to all locators of 'dst_map'*/
static int
build_and_send_smr_mreq_to_map(
        lisp_xtr_t  *xtr,
        mapping_t   *src_map,
        mapping_t   *dst_map)
{
    glist_t *loct_list = NULL;
    glist_entry_t *it_lists = NULL;
    glist_entry_t *it_loct = NULL;
    lisp_addr_t *deid = NULL, *drloc = NULL;
    locator_t *loct = NULL;

    deid = mapping_eid(dst_map);

    glist_for_each_entry(it_lists,mapping_locators_lists(dst_map)){
    	loct_list = (glist_t *)glist_entry_data(it_lists);
        glist_for_each_entry(it_loct,loct_list){
        	loct = (locator_t *)glist_entry_data(it_loct);
        	if (loct->state == UP){
        		drloc = locator_addr(loct);
        		build_and_send_smr_mreq(xtr, src_map, deid, drloc);
        	}
        }
    }

    return(GOOD);
}

static int
send_all_smr_cb(lmtimer_t *t, void *arg)
{
    send_all_smr_and_reg((lisp_xtr_t *)arg);
    return(GOOD);
}

/* Send a solicit map request for each rloc of all eids in the map cache
 * database */
static void
send_all_smr_and_reg(lisp_xtr_t *xtr)
{
    map_local_entry_t * map_loc_e       = NULL;
    mcache_entry_t *    mce             = NULL;
    mapping_t *         mcache_map      = NULL;
    mapping_t *         map             = NULL;
    glist_t *           map_loc_e_list  = NULL; //<map_local_entry_t *>
    glist_entry_t *     it              = NULL;
    glist_entry_t *     it_pitr         = NULL;
    lisp_addr_t *       pitr_addr       = NULL;
    lisp_addr_t *       eid             = NULL;

    LMLOG(LDBG_2,"\n*** Re-Register and send SMRs for mappings with updated "
            "RLOCs ***");

    /* Get a list of mappings that require smrs */
    map_loc_e_list = get_map_local_entry_to_smr(xtr);

    /* Send map register and SMR request for each mapping */
    glist_dump(map_loc_e_list,(glist_to_char_fct)map_local_entry_to_char,LDBG_1);

    glist_for_each_entry(it, map_loc_e_list) {
        map_loc_e = (map_local_entry_t *)glist_entry_data(it);
        map = map_local_entry_mapping(map_loc_e);

        /* Send map register for all mappings */
        if (nat_aware == FALSE || nat_status == NO_NAT) {
            build_and_send_map_reg(xtr, map);
        } else if (nat_status != UNKNOWN) {
            /* TODO : We suppose one EID and one interface.
             * To be modified when multiple elements */
            map_register_process(xtr);
        }

        eid = mapping_eid(map);

        LMLOG(LDBG_1, "Start SMR for local EID %s", lisp_addr_to_char(eid));

        /* For each map cache entry with same afi as local EID mapping */
        if (lisp_addr_lafi(eid) == LM_AFI_IP ) {
            LMLOG(LDBG_3, "send_all_smr_and_reg: SMR request for %s. Shouldn't "
                    "receive SMR for IP in mapping?!", lisp_addr_to_char(eid));
        } else if (lisp_addr_lafi(eid) != LM_AFI_IPPREF) {
            LMLOG(LDBG_3, "send_all_smr_and_reg: SMR request for %s. SMR "
                    "supported only for IP-prefixes for now!",
                    lisp_addr_to_char(eid));
            continue;
        }

        /* no SMRs for now for multicast */
        if (lisp_addr_is_mc(eid))
            continue;

        glist_dump(map_loc_e_list,(glist_to_char_fct)map_local_entry_to_char,LDBG_1);


        /* TODO: spec says SMRs should be sent only to peer ITRs that sent us
         * traffic in the last minute. Should change this in the future*/
        /* XXX: works ONLY with IP */
        mcache_foreach_active_entry_in_ip_eid_db(xtr->map_cache, eid, mce) {
            mcache_map = mcache_entry_mapping(mce);
            build_and_send_smr_mreq_to_map(xtr, map, mcache_map);
        } mcache_foreach_active_entry_in_ip_eid_db_end;

        /* SMR proxy-itr */
        LMLOG(LDBG_1, "Sending SMRs to PITRs");
        glist_for_each_entry(it_pitr, xtr->pitrs){
            pitr_addr = (lisp_addr_t *)glist_entry_data(it_pitr);
            build_and_send_smr_mreq(xtr, map, eid, pitr_addr);
        }
    }

    glist_destroy(map_loc_e_list);
    LMLOG(LDBG_2,"*** Finished sending notifications ***\n");
}

static int
smr_invoked_map_request_cb(lmtimer_t *t, void *arg)
{
    return(send_smr_invoked_map_request(t->owner, arg));
}

static int
send_smr_invoked_map_request(lisp_xtr_t *xtr, mcache_entry_t *mce)
{
    struct lbuf *b = NULL;
    void *hdr = NULL;
    nonces_list_t *nonces = NULL;
    mapping_t *m = NULL;
    lisp_addr_t *deid = NULL, empty, *s_in_addr = NULL, *d_in_addr = NULL;
    lmtimer_t *t = NULL;
    glist_t *rlocs = NULL;
    int afi ;

    m = mcache_entry_mapping(mce);
    deid = mapping_eid(m);
    afi = lisp_addr_ip_afi(deid);
    lisp_addr_set_lafi(&empty, LM_AFI_NO_ADDR);

    nonces = mcache_entry_nonces(mce);
    /* Sanity Check */
    if (!nonces) {
        mcache_entry_init_nonces(mce);
        if (!(nonces = mcache_entry_nonces(mce))) {
            LMLOG(LWRN, "send_smr_invoked_map_request: Unable to allocate"
                    " memory for nonces.");
            return (BAD);
        }
    }

    if (nonces->retransmits - 1 < LISPD_MAX_SMR_RETRANSMIT) {
        LMLOG(LDBG_1,"SMR: Map-Request for EID: %s (%d retries)",
                lisp_addr_to_char(deid), nonces->retransmits);

        /* BUILD Map-Request */

        /* no source EID and mapping, so put default control rlocs */
        rlocs = ctrl_default_rlocs(xtr->super.ctrl);
        b = lisp_msg_mreq_create(&empty, rlocs, mapping_eid(m));
        if (b == NULL){
            glist_destroy(rlocs);
            return (BAD);
        }

        hdr = lisp_msg_hdr(b);
        MREQ_SMR_INVOKED(hdr) = 1;
        nonces->nonce[nonces->retransmits] = nonce_build_time();
        MREQ_NONCE(hdr) = nonces->nonce[nonces->retransmits];

        /* we could put anything here. Still, better put something that
         * makes a bit of sense .. */
        s_in_addr = local_map_db_get_main_eid(xtr->local_mdb, afi);
        d_in_addr = deid;
        /* If we don't have a source EID as an RTR, we use an RLOC. May be, RTR could have a loopback EID address */
        if (s_in_addr == NULL){
            s_in_addr = ctrl_default_rloc(lisp_ctrl_dev_get_ctrl_t(&(xtr->super)),afi);
            if (s_in_addr == NULL){
                LMLOG(LDBG_1,"SMR: Couldn't generate Map-Request for EID: %s. No source inner ip address available)",
                               lisp_addr_to_char(deid));
                return (BAD);
            }
        }

        /* SEND */
        LMLOG(LDBG_1, "%s, itr-rlocs:%s src-eid: %s, req-eid: %s",
                lisp_msg_hdr_to_char(b), laddr_list_to_char(rlocs),
                lisp_addr_to_char(&empty), lisp_addr_to_char(mapping_eid(m)));
        glist_destroy(rlocs);

        if (send_map_request_to_mr(xtr, b, s_in_addr, d_in_addr) != GOOD) {
            return(BAD);
        }
        lisp_msg_destroy(b);

        /* init or delete and init, if needed, the timer */
        t = mcache_entry_init_smr_inv_timer(mce);

        lmtimer_start(t, LISPD_INITIAL_SMR_TIMEOUT,
                smr_invoked_map_request_cb, xtr, mce);
        nonces->retransmits ++;

    } else {
        mcache_entry_stop_smr_inv_timer(mce);
        LMLOG(LDBG_1,"SMR: No Map Reply for EID %s. Stopping ...",
                lisp_addr_to_char(deid));
    }
    return (GOOD);

}

static int
program_smr(lisp_xtr_t *xtr, int time) {
    if (!xtr->smr_timer) {
        xtr->smr_timer = lmtimer_create(SMR_TIMER);
    }

    lmtimer_start(xtr->smr_timer, LISPD_SMR_TIMEOUT, send_all_smr_cb, xtr,
            xtr);
    return(GOOD);
}


static int
send_map_request_retry_cb(lmtimer_t *t, void *arg) {
    int ret;

    ret = send_map_request_retry(t->owner, arg);
    return(ret);
}


/* Sends a Map-Request for EID in 'mce' and sets-up a retry timer */
static int
send_map_request_retry(lisp_xtr_t *xtr, mcache_entry_t *mce)
{
    lmtimer_t *t = NULL;
    nonces_list_t *nonces = NULL;
    mapping_t *m = NULL;
    lisp_addr_t *deid = NULL, *seid = NULL;
    glist_t *rlocs = NULL;
    lbuf_t *b = NULL;
    void *mr_hdr = NULL;

    if (glist_size(xtr->map_resolvers) == 0){
        LMLOG(LDBG_1, "Couldn't send map request: No map resolver configured");
        return (BAD);
    }

    nonces = mcache_entry_nonces(mce);
    m = mcache_entry_mapping(mce);
    deid = mapping_eid(m);

    if (!nonces) {
        mcache_entry_init_nonces(mce);
        nonces = mcache_entry_nonces(mce);
    }

    if (nonces->retransmits - 1 < xtr->map_request_retries) {
        if (nonces->retransmits > 0) {
            LMLOG(LDBG_1, "Retransmitting Map Request for EID: %s (%d retries)",
                    lisp_addr_to_char(deid), nonces->retransmits);
        }

        /* BUILD Map-Request */
        seid = mcache_entry_requester(mce);

        // Rlocs to be used as ITR of the map req.
        rlocs = ctrl_default_rlocs(xtr->super.ctrl);
        LMLOG(LDBG_1, "locators for req: %s", laddr_list_to_char(rlocs));
        b = lisp_msg_mreq_create(seid, rlocs, deid);
        if (b == NULL) {
            glist_destroy(rlocs);
            return(BAD);
        }

        mr_hdr = lisp_msg_hdr(b);
        nonces->nonce[nonces->retransmits] = nonce_build_time();
        MREQ_NONCE(mr_hdr) = nonces->nonce[nonces->retransmits];

        LMLOG(LDBG_1, "%s, itr-rlocs:%s, src-eid: %s, req-eid: %s",
                lisp_msg_hdr_to_char(b), laddr_list_to_char(rlocs),
                lisp_addr_to_char(seid), lisp_addr_to_char(deid));
        glist_destroy(rlocs);


        /* SEND */
        send_map_request_to_mr(xtr, b, seid, deid);
        lisp_msg_destroy(b);

        /* prepare callback
         * init or delete and init, if needed, the timer */
        t = mcache_entry_init_req_retry_timer(mce);
        lmtimer_start(t, LISPD_INITIAL_SMR_TIMEOUT,
                send_map_request_retry_cb, xtr, mce);

        nonces->retransmits++;

    } else {
        LMLOG(LDBG_1, "No Map-Reply for EID %s after %d retries. Aborting!",
                lisp_addr_to_char(deid), nonces->retransmits - 1);
        tr_mcache_remove_mapping(xtr, deid);
    }

    return(GOOD);
}

/* build and send generic map-register with one record
 * for each map server */
static int
build_and_send_map_reg(
        lisp_xtr_t *    xtr,
        mapping_t *     m)
{
    lbuf_t *            b       = NULL;
    void *              hdr     = NULL;
    lisp_addr_t *       drloc   = NULL;
    glist_entry_t *     it      = NULL;
    map_server_elt *    ms      = NULL;
    uconn_t         uc;

    glist_for_each_entry(it, xtr->map_servers) {
        ms = (map_server_elt *)glist_entry_data(it);

        b = lisp_msg_mreg_create(m, ms->key_type);

        if (!b) {
            return(BAD);
        }

        hdr = lisp_msg_hdr(b);
        MREG_PROXY_REPLY(hdr) = ms->proxy_reply;

        if (lisp_msg_fill_auth_data(b, ms->key_type,
                ms->key) != GOOD) {
            return(BAD);
        }
        drloc =  ms->address;

        LMLOG(LDBG_1, "%s, EID: %s, MS: %s", lisp_msg_hdr_to_char(b),
                lisp_addr_to_char(mapping_eid(m)), lisp_addr_to_char(drloc));

        uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
        send_msg(&xtr->super, b, &uc);

        lisp_msg_destroy(b);
    }
    return(GOOD);
}

static int
build_and_send_ecm_map_reg(
        lisp_xtr_t *    xtr,
        mapping_t *     m,
        lisp_addr_t *   dst,
        uint64_t        nonce)
{
    lbuf_t *            b           = NULL;
    void *              hdr         = NULL;
    lisp_addr_t *       in_drloc    = NULL;
    lisp_addr_t *       in_srloc    = NULL;
    glist_entry_t *     it          = NULL;
    map_server_elt *    ms          = NULL;
    uconn_t             uc;

    glist_for_each_entry(it, xtr->map_servers) {
        ms = (map_server_elt *)glist_entry_data(it);
        b = lisp_msg_nat_mreg_create(m, ms->key, &xtr->site_id,
                &xtr->xtr_id, ms->key_type);
        hdr = lisp_msg_hdr(b);

        /* XXX Quick hack */
        /* Cisco IOS RTR implementation drops Data-Map-Notify if ECM Map Register
         * nonce = 0 */

        MREG_NONCE(hdr) = nonce;
        MREG_PROXY_REPLY(hdr) = 1;

        in_drloc = ms->address;
        in_srloc = ctrl_default_rloc(xtr->super.ctrl, lisp_addr_ip_afi(in_drloc));

        lisp_msg_encap(b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, in_srloc,
                in_drloc);

        LMLOG(LDBG_1, "%s, Inner IP: %s -> %s, EID: %s, RTR: %s",
                lisp_msg_hdr_to_char(b), lisp_addr_to_char(in_srloc),
                lisp_addr_to_char(in_drloc), lisp_addr_to_char(mapping_eid(m)),
                lisp_addr_to_char(dst));

        uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, dst);
        send_msg(&xtr->super, b, &uc);

        lisp_msg_destroy(b);
    }
    return(GOOD);
}

static int
map_register_cb(lmtimer_t *t, void *arg)
{
    return(map_register_process(t->owner));
}

int
program_map_register(lisp_xtr_t *xtr, int time)
{
    lmtimer_t *t = xtr->map_register_timer;
    if (glist_size(xtr->map_resolvers) == 0){
        return (BAD);
    }
    if (!t) {
        xtr->map_register_timer = lmtimer_create(MAP_REGISTER_TIMER);
        t = xtr->map_register_timer;
    }

    /* Configure timer to send the next map register. */
    lmtimer_start(t, time, map_register_cb, xtr, NULL);
    LMLOG(LDBG_1, "(Re)programmed Map-Register process in %d seconds", time);
    return(GOOD);
}



static int
map_register_process_default(lisp_xtr_t *xtr)
{
    map_local_entry_t * map_loc_e   = NULL;
    mapping_t *         mapping     = NULL;
    void *              it          = NULL;

    /* TODO
     * - configurable keyid
     * - multiple MSes
     */

    local_map_db_foreach_entry(xtr->local_mdb, it) {
        map_loc_e = (map_local_entry_t *)it;
        mapping = map_local_entry_mapping(map_loc_e);
        if (mapping->locator_count != 0) {
            build_and_send_map_reg(xtr, mapping);
        }
    } local_map_db_foreach_end;

    program_map_register(xtr, MAP_REGISTER_INTERVAL);

    return(GOOD);
}


static locator_t *
get_locator_behind_nat(mapping_t *m)
{
//    locator_list_t *loc_list[2] = { NULL, NULL };
    locator_t *loc = NULL;
//    lcl_locator_extended_info_t *leinf;
//    int ctr1;
//
//    if (mapping_locator_count(m) == 0) {
//        return(NULL);
//    }
//
//    /* Find the locator behind NAT */
//    loc_list[0] = m->head_v4_locators_list;
//    loc_list[1] = m->head_v6_locators_list;
//    for (ctr1 = 0 ; ctr1 < 2 ; ctr1++) {
//        while (loc_list[ctr1] != NULL) {
//            loc = loc_list[ctr1]->locator;
//            leinf = loc->extended_info;
//            if (leinf->rtr_locators_list != NULL) {
//                break;
//            }
//            loc = NULL;
//            loc_list[ctr1] = loc_list[ctr1]->next;
//        }
//        if (loc != NULL){
//            break;
//        }
//    }

    return(loc);
}

static int
map_register_process_encap(lisp_xtr_t *xtr)
{
    map_local_entry_t *     map_loc_e       = NULL;
    mapping_t *             mapping         = NULL;
    locator_t *             loct            = NULL;
    lisp_addr_t *           nat_rtr         = NULL;
    int                     next_timer_time = 0;
    void *                  it              = NULL;
    nonces_list_t *         nemrn           = NULL;
    lcl_locator_extended_info_t *leinf      = NULL;

    nemrn = xtr->nat_emr_nonces;
    if (!nemrn) {
        xtr->nat_emr_nonces = nonces_list_new();
        LMLOG(LWRN,"map_register_process_encap: nonces unallocated!"
                " Aborting!");
        exit_cleanup();
    }

    if (nemrn->retransmits <= LISPD_MAX_RETRANSMITS) {

        if (nemrn->retransmits > 0) {
            LMLOG(LDBG_1,"No Map Notify received. Retransmitting encapsulated "
                    "map register.");
        }

        local_map_db_foreach_entry(xtr->local_mdb, it) {
            map_loc_e = (map_local_entry_t *)it;
            mapping = map_local_entry_mapping(map_loc_e);
            loct = get_locator_behind_nat(mapping);

            /* If found a locator behind NAT, send
             * Encapsulated Map Register */
            if (loct != NULL) {
                leinf  = loct->extended_info;
                nat_rtr = &leinf->rtr_locators_list->locator->address;
                /* ECM map register only sent to the first Map Server */
                nemrn->nonce[nemrn->retransmits] = nonce_build_time();
                build_and_send_ecm_map_reg(xtr, mapping, nat_rtr,
                        nemrn->nonce[nemrn->retransmits]);
                nemrn->retransmits++;
            } else {
                LMLOG(LERR,"encapsulated_map_register_process: "
                        "Couldn't send encapsulated map register. "
                        "No RTR found");
            }

            next_timer_time = LISPD_INITIAL_EMR_TIMEOUT;
        } local_map_db_foreach_end;

    } else {
        free(nemrn);
        nemrn = NULL;
        LMLOG(LERR,"encapsulated_map_register_process: Communication error "
                "between LISPmob and RTR/MS. Retry after %d seconds",
                MAP_REGISTER_INTERVAL);
        next_timer_time = MAP_REGISTER_INTERVAL;
    }

    program_map_register(xtr, next_timer_time);

    return(GOOD);
}


static int
map_register_process(lisp_xtr_t *xtr)
{
    int ret = 0;

    if (glist_size(xtr->map_servers) == 0) {
        LMLOG(LCRIT, "No Map Servers configured!");
        return (BAD);
    }

    if (xtr->nat_aware == TRUE) {
        /* NAT procedure instead of the standard one */
        /* TODO: if possible move info_request_process out */
        if (xtr->nat_status == UNKNOWN) {
            /*ret = initial_info_request_process(); */
        }

        if (xtr->nat_status == FULL_NAT) {
            ret = map_register_process_encap(xtr);
        }
    }

    /* Standard Map-Register mechanism */
    if ((xtr->nat_aware == FALSE)
         || ((xtr->nat_aware == TRUE)  && (xtr->nat_status == NO_NAT))) {
        ret = map_register_process_default(xtr);
    }

    return (ret);
}

static int
rloc_probing_cb(lmtimer_t *t, void *arg)
{
    timer_rloc_probe_argument *rparg = arg;
    return(rloc_probing(t->owner, rparg->mapping, rparg->locator));
}

/* Send a Map-Request probe to check status of 'loc'. If the number of
 * retries without answer is higher than rloc_probe_retries. Change the status
 * of the 'loc' to down */
static int
rloc_probing(lisp_xtr_t *xtr, mapping_t *map, locator_t *loc)
{
    rmt_locator_extended_info_t *   einf    = NULL;
    nonces_list_t *                 nonces  = NULL;
    lisp_addr_t *                   deid    = NULL;
    lisp_addr_t *                   drloc   = NULL;
    lisp_addr_t                     empty;
    lbuf_t *                        b       = NULL;
    glist_t *                       rlocs   = NULL;
    lmtimer_t *                     t       = NULL;
    void *                          hdr     = NULL;
    void *                          arg     = NULL;
    mcache_entry_t *                mce     = NULL;


    deid = mapping_eid(map);

    if (xtr->probe_interval == 0) {
        LMLOG(LDBG_2, "rloc_probing: No RLOC Probing for %s cache entry. "
                "RLOC Probing disabled",  lisp_addr_to_char(deid));
        return (GOOD);
    }

    // XXX alopez -> What we have to do with ELP and probe bit
    drloc = xtr->fwd_policy->get_fwd_ip_addr(locator_addr(loc), ctrl_rlocs(xtr->super.ctrl));
    lisp_addr_set_lafi(&empty, LM_AFI_NO_ADDR);
    einf = loc->extended_info;
    nonces = einf->rloc_probing_nonces;
    t = einf->probe_timer;
    arg = einf->probe_timer->cb_argument;

    /* Generate Nonce structure */
    if (!nonces) {
        nonces = einf->rloc_probing_nonces = nonces_list_new();
        if (!nonces) {
            LMLOG(LWRN,"rloc_probing: Unable to allocate memory "
                    "for nonces. Reprogramming RLOC Probing");
            lmtimer_start(t, xtr->probe_interval, rloc_probing_cb, xtr, arg);
            return(BAD);
        }
    }


    /* If the number of retransmits is less than rloc_probe_retries, then try
     * to send the Map Request Probe again */
    if (nonces->retransmits - 1 < xtr->probe_retries) {
        rlocs = ctrl_default_rlocs(xtr->super.ctrl);
        b = lisp_msg_mreq_create(&empty, rlocs, deid);
        glist_destroy(rlocs);
        if (b == NULL){
            return (BAD);
        }

        hdr = lisp_msg_hdr(b);
        nonces->nonce[nonces->retransmits] = nonce_build_time() ;
        MREQ_NONCE(hdr) = nonces->nonce[nonces->retransmits];
        MREQ_RLOC_PROBE(hdr) = 1;

        if (nonces->retransmits > 0) {
            LMLOG(LDBG_1,"Retry Map-Request Probe for locator %s and "
                    "EID: %s (%d retries)", lisp_addr_to_char(drloc),
                    lisp_addr_to_char(deid), nonces->retransmits);
        } else {
            LMLOG(LDBG_1,"Map-Request Probe for locator %s and "
                    "EID: %s", lisp_addr_to_char(drloc),
                    lisp_addr_to_char(deid));
        }

        send_map_request(&xtr->super, b, NULL, drloc);

        nonces->retransmits++;

        /* Reprogram time for next retry */
        lmtimer_start(t, xtr->probe_retries_interval, rloc_probing_cb, xtr,
                arg);

        lisp_msg_destroy(b);
    } else {
        /* If we have reached maximum number of retransmissions, change remote
         *  locator status */
        if (locator_state(loc) == UP) {
            locator_set_state(loc, DOWN);
            LMLOG(LDBG_1,"rloc_probing: No Map-Reply Probe received for locator"
                    " %s and EID: %s -> Locator state changes to DOWN",
                    lisp_addr_to_char(drloc), lisp_addr_to_char(deid));

            /* [re]Calculate forwarding info  if it has been a change
             * of status*/
            mce = mcache_lookup_exact(xtr->map_cache,deid);
            if (mce == NULL){
                /* It is a PeTR RLOC */
                if ( mcache_entry_mapping(xtr->petrs) != map ){
                    LMLOG(LERR,"rloc_probing: No map cache entry for EID %s. It should never happend",
                            lisp_addr_to_char(deid));
                    return (BAD);
                }
                mce = xtr->petrs;
            }

            xtr->fwd_policy->updated_map_cache_inf(
                    xtr->fwd_policy_dev_parm,
                    mcache_entry_routing_info(mce),
                    map);
        }

        free(einf->rloc_probing_nonces);
        einf->rloc_probing_nonces = NULL;

        /* Reprogram time for next probe interval */
        lmtimer_start(t, xtr->probe_interval, rloc_probing_cb, xtr, arg);
        LMLOG(LDBG_2,"Reprogramed RLOC probing of the locator %s of the EID %s "
                "in %d seconds", lisp_addr_to_char(drloc),
                lisp_addr_to_char(deid), xtr->probe_interval);
    }

    return (GOOD);
}

static void
program_rloc_probing(lisp_xtr_t *xtr, mapping_t *m,
        locator_t *loc, int time)
{
    rmt_locator_extended_info_t *einf = NULL;
    timer_rloc_probe_argument *arg = NULL;

    einf = loc->extended_info;

    /* create timer and arg if needed*/
    if (!einf->probe_timer) {
        einf->probe_timer = lmtimer_create(RLOC_PROBING_TIMER);
        arg = xzalloc(sizeof(timer_rloc_probe_argument));
        LMLOG(LDBG_2,"Programming probing of EID's %s locator %s (%d seconds)",
                    lisp_addr_to_char(mapping_eid(m)),
                    lisp_addr_to_char(locator_addr(loc)), time);
    } else {
        arg = einf->probe_timer->cb_argument;
        LMLOG(LDBG_2,"Reprogramming probing of EID's %s locator %s (%d seconds)",
                    lisp_addr_to_char(mapping_eid(m)),
                    lisp_addr_to_char(locator_addr(loc)), time);
    }

    arg->locator = loc;
    arg->mapping = m;
    lmtimer_start(einf->probe_timer, time, rloc_probing_cb, xtr, arg);

}

/* Program RLOC probing for each locator of the mapping */
static void
program_mapping_rloc_probing(lisp_xtr_t *xtr, mapping_t *map)
{
	glist_t *loct_list = NULL;
	glist_entry_t *it_list = NULL;
	glist_entry_t *it_loct = NULL;
    locator_t *locator = NULL;

    if (xtr->probe_interval == 0) {
        return;
    }

    /* Start rloc probing for each locator of the mapping */
    glist_for_each_entry(it_list, mapping_locators_lists(map)){
    	loct_list = (glist_t*)glist_entry_data(it_list);
    	glist_for_each_entry(it_loct,loct_list){
    		locator = (locator_t *)glist_entry_data(it_loct);
    		// XXX alopez: Check if RLOB probing available for all LCAF. ELP RLOC Probing bit
    		program_rloc_probing(xtr, map, locator, xtr->probe_interval);
    	}

    }
}

/* Program RLOC probing for each proxy-ETR */
static void
program_petr_rloc_probing(lisp_xtr_t *xtr, int time)
{
	glist_t *loct_list = NULL;
	glist_entry_t *it_list = NULL;
	glist_entry_t *it_loct = NULL;
    locator_t *locator = NULL;

    if (xtr->probe_interval == 0 || xtr->petrs == NULL) {
        return;
    }
    /* Start rloc probing for each locator of the mapping */
    glist_for_each_entry(it_list, mapping_locators_lists(xtr->petrs->mapping)){
    	loct_list = (glist_t*)glist_entry_data(it_list);
    	glist_for_each_entry(it_loct,loct_list){
    		locator = (locator_t *)glist_entry_data(it_loct);
    		// XXX alopez: Check if RLOB probing available for all LCAF. ELP RLOC Probing bit
    		program_rloc_probing(xtr, xtr->petrs->mapping, locator, xtr->probe_interval);
    	}

    }
}


int
tr_mcache_add_mapping(lisp_xtr_t *xtr, mapping_t *m)
{
    mcache_entry_t *mce         = NULL;
    void *          routing_inf = NULL;

    mce = mcache_entry_new();
    if (mce == NULL){
        return (BAD);
    }

    mcache_entry_init(mce, m);

    routing_inf = xtr->fwd_policy->new_map_cache_policy_inf(xtr->fwd_policy_dev_parm,m);
    if (routing_inf == NULL){
        LMLOG(LDBG_1, "tr_mcache_add_mapping: Couldn't create routing info for map cache entry %s!. Discarding it.",
                lisp_addr_to_char(mapping_eid(m)));
        mcache_entry_del(mce);
        return(BAD);
    }
    mcache_entry_set_routing_info(mce,routing_inf,xtr->fwd_policy->del_map_cache_policy_inf);

    if (mcache_add_entry(xtr->map_cache, mapping_eid(m), mce) != GOOD) {
        LMLOG(LDBG_1, "tr_mcache_add_mapping: Couldn't add map cache entry %s to data base!. Discarding it.",
                lisp_addr_to_char(mapping_eid(m)));
        mcache_entry_del(mce);
        return(BAD);
    }

    mcache_entry_set_active(mce, ACTIVE);

    /* Reprogramming timers */
    mc_entry_start_expiration_timer(xtr, mce);

    /* RLOC probing timer */
    program_mapping_rloc_probing(xtr, m);

    return(GOOD);
}

int
tr_mcache_add_static_mapping(lisp_xtr_t *xtr, mapping_t *m)
{
    mcache_entry_t *    mce         = NULL;
    void *              routing_inf = NULL;

    mce = mcache_entry_new();
    if (mce == NULL){
        return(BAD);
    }
    mcache_entry_init_static(mce, m);

    routing_inf = xtr->fwd_policy->new_map_cache_policy_inf(xtr->fwd_policy_dev_parm,m);
    if (routing_inf == NULL){
        LMLOG(LDBG_1, "tr_mcache_add_static_mapping: Couldn't create routing info for map cache entry %s!. Discarding it.",
                lisp_addr_to_char(mapping_eid(m)));
        mcache_entry_del(mce);
        return(BAD);
    }
    mcache_entry_set_routing_info(mce,routing_inf,xtr->fwd_policy->del_map_cache_policy_inf);

    if (mcache_add_entry(xtr->map_cache, mapping_eid(m), mce) != GOOD) {
        LMLOG(LDBG_1, "tr_mcache_add_static_mapping: Couldn't add static map cache entry %s to data base!. Discarding it.",
                        lisp_addr_to_char(mapping_eid(m)));
        return(BAD);
    }

    program_mapping_rloc_probing(xtr, m);

    return(GOOD);
}

int
tr_mcache_remove_mapping(lisp_xtr_t *xtr, lisp_addr_t *laddr)
{
    void *data = NULL;

    data = mcache_remove_entry(xtr->map_cache, laddr);
    mcache_entry_del(data);
    mcache_dump_db(xtr->map_cache, LDBG_3);

    return (GOOD);
}

mapping_t *
tr_mcache_lookup_mapping(lisp_xtr_t *xtr, lisp_addr_t *laddr)
{

    mcache_entry_t *mce  = NULL;

    mce = mcache_lookup(xtr->map_cache, laddr);

    if ((mce == NULL) || (mce->active == NOT_ACTIVE)) {
        return (NULL);
    } else {
        return (mcache_entry_mapping(mce));
    }
}

mapping_t *
tr_mcache_lookup_mapping_exact(lisp_xtr_t *xtr, lisp_addr_t *laddr)
{
    mcache_entry_t *mce  = NULL;

    mce = mcache_lookup_exact(xtr->map_cache, laddr);

    if (!mce || (mce->active == NOT_ACTIVE)) {
        return (NULL);
    } else {
        return (mcache_entry_mapping(mce));
    }
}
/*
 * Notify an event in a interface (changes are monolitic):
 *    Old Addr     New Addr     Status
 *     x            x           V        ---> Change of status
 *     V            V           V        ---> Change of address
 *     X            V           V        ---> Activation of address (iface down when LISP start)
 * @param dev General control device
 * @param iface_name Name of the modified interface
 * @param old_addr Address of the interface before changing. Null if iface was not initialized
 *                 or no address change
 * @paran new_addr Address of the interface after changing. Null if address not changed
 * @param status Status of the interfac
 * @return GOOD if finish correctly or an error code otherwise
 */
static int xtr_if_event(
        lisp_ctrl_dev_t     *dev,
        char                *iface_name,
        lisp_addr_t         *old_addr,
        lisp_addr_t         *new_addr,
        uint8_t             status)
{
    lisp_xtr_t *        xtr                 = lisp_xtr_cast(dev);
    iface_locators *    if_loct             = NULL;
    glist_t *           loct_list           = NULL;
    glist_t *           locators            = NULL;
    locator_t *         locator             = NULL;
    map_local_entry_t * map_loc_e           = NULL;
    mapping_t *         mapping             = NULL;
    int                 afi                 = AF_UNSPEC;
    glist_entry_t *     it                  = NULL;
    glist_entry_t *     it_aux              = NULL;
    glist_entry_t *     it_m                = NULL;
    lisp_addr_t **      prev_addr           = NULL;

    if_loct = (iface_locators *)shash_lookup(xtr->iface_locators_table,iface_name);
    if (if_loct  == NULL){
        LMLOG(LDBG_2, "xtr_if_event: Iface %s not found in the list of ifaces for xTR device",
                        iface_name);
        free(iface_name);
        lisp_addr_del(old_addr);
        lisp_addr_del(new_addr);
        return (BAD);
    }

    /*
     * Update locators with the new interface status.
     */
    /* New address*/
    if (new_addr != NULL){
        afi = lisp_addr_lafi(new_addr) == LM_AFI_IP ? lisp_addr_ip_afi(new_addr)  : AF_UNSPEC;
        switch(afi){
        case AF_INET:
            locators = if_loct->ipv4_locators;
            prev_addr = &(if_loct->ipv4_prev_addr);
            break;
        case AF_INET6:
            locators = if_loct->ipv6_locators;
            prev_addr = &(if_loct->ipv6_prev_addr);
            break;
        default:
            LMLOG(LDBG_2, "xtr_if_event: Afi of the new address not known");
            free(iface_name);
            lisp_addr_del(old_addr);
            lisp_addr_del(new_addr);
            return (BAD);
        }
        glist_for_each_entry_safe(it,it_aux,locators){
            locator = (locator_t *)glist_entry_data(it);
            if (lisp_addr_is_no_addr(locator_addr(locator))==TRUE){
                /* If locator was not active, activate it */
                map_loc_e = get_map_loc_ent_containing_loct_ptr(xtr->local_mdb,locator);
                if(map_loc_e == NULL){
                    continue;
                }
                /* Check if exists an active locator with the same address.
                 * If it exists, remove not activated locator: Duplicated */
                mapping = map_local_entry_mapping(map_loc_e);
                if (mapping_get_loct_with_addr(mapping,new_addr) != NULL){
                    LMLOG(LDBG_2, "xtr_if_event: A non active locator is duplicated. Removing it");
                    loct_list = mapping_get_loct_lst_with_afi(mapping,LM_AFI_NO_ADDR,0);
                    iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                    glist_remove_obj_with_ptr(locator,loct_list);
                    continue;
                }
                /* Activate locator */
                locator_clone_addr(locator,new_addr);
                mapping_activate_locator(mapping,locator);
            }else{
                locator_clone_addr(locator,new_addr);
            }

        }
        /* Transition check */
        if (*prev_addr != NULL){
            if (lisp_addr_cmp(*prev_addr, new_addr) == 0){
                lisp_addr_del(*prev_addr);
                *prev_addr = NULL;
            }else{
                if (old_addr != NULL){
                    lisp_addr_copy(*prev_addr,old_addr);
                }else{
                    /* Iface was not initialized. Add a value to prev_addr in order to do SMR */
                    lisp_addr_copy(*prev_addr,new_addr);
                }
            }
        }else{
            if (old_addr != NULL){
                *prev_addr = lisp_addr_clone(old_addr);
            }else{
                /* Iface was not initialized. Add a value to prev_addr in order to do SMR */
                *prev_addr = lisp_addr_clone(new_addr);
            }
        }
        /* Reorder locators */
        glist_for_each_entry(it_m, if_loct->map_loc_entries){
            map_loc_e = (map_local_entry_t *)glist_entry_data(it_m);
            mapping = map_local_entry_mapping(map_loc_e);
            mapping_sort_locators(mapping, new_addr);
        }
    /* New status */
    }else{
        glist_for_each_entry(it,if_loct->ipv4_locators){
            locator = (locator_t *)glist_entry_data(it);
            locator_set_state(locator,status);
        }
        glist_for_each_entry(it,if_loct->ipv6_locators){
            locator = (locator_t *)glist_entry_data(it);
            locator_set_state(locator,status);
        }
        /* Transition check */
        if (if_loct->status_changed == TRUE){
            if_loct->status_changed = FALSE;
        }else{
            if_loct->status_changed = TRUE;
        }
        /* Recalculate forwarding info of the affected mappings */
        glist_for_each_entry(it_m, if_loct->map_loc_entries){
            map_loc_e = (map_local_entry_t *)glist_entry_data(it_m);
            xtr->fwd_policy->updated_map_loc_inf(
                    xtr->fwd_policy_dev_parm,
                    map_local_entry_fwd_info(map_loc_e),
                    map_local_entry_mapping(map_loc_e));
        }
    }
    if (xtr->super.mode == RTR_MODE && xtr->all_locs_map) {
        xtr->fwd_policy->updated_map_loc_inf(
                            xtr->fwd_policy_dev_parm,
                            map_local_entry_fwd_info(xtr->all_locs_map),
                            map_local_entry_mapping(xtr->all_locs_map));
    }

    free(iface_name);
    lisp_addr_del(old_addr);
    lisp_addr_del(new_addr);

    return(program_smr(xtr, LISPD_SMR_TIMEOUT));
}

static int
xtr_recv_msg(lisp_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc) {
    int ret = 0;
    lisp_msg_type_e type;
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);

    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (lisp_msg_ecm_decap(msg, &uc->rp) != GOOD) {
            return (BAD);
        }
        type = lisp_msg_type(msg);
    }


    switch (type) {
    case LISP_MAP_REPLY:
        ret = tr_recv_map_reply(xtr, msg);
        break;
    case LISP_MAP_REQUEST:
        ret = tr_recv_map_request(xtr, msg, uc);
        break;
    case LISP_MAP_REGISTER:
        break;
    case LISP_MAP_NOTIFY:
        ret = tr_recv_map_notify(xtr, msg);
        break;
    case LISP_INFO_NAT:
        /*FC: temporary fix until info_nat uses liblisp */
        /*
        lmlog(LDBG_1, "Info-Request/Info-Reply message");
        if (!process_info_nat_msg(lbuf_data(msg), usk.ra)) {
            return (BAD);
        }
        return (GOOD);*/
        break;
    default:
        LMLOG(LDBG_1, "xTR: Unidentified type (%d) control message received",
                type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        LMLOG(LDBG_1,"xTR: Failed to process LISP control message");
        return (BAD);
    } else {
        LMLOG(LDBG_3, "xTR: Completed processing of LISP control message");
        return (ret);
    }
}

map_server_elt * map_server_elt_new_init(
        lisp_addr_t *   address,
        uint8_t         key_type,
        char *          key,
        uint8_t         proxy_reply)
{
    map_server_elt *ms = NULL;
    ms = xzalloc(sizeof(map_server_elt));
    if (ms == NULL){
        LMLOG(LWRN,"Couldn't allocate memory for a map_server_elt structure");
        return (NULL);
    }
    ms->address     = lisp_addr_clone(address);
    ms->key_type    = key_type;
    ms->key         = strdup(key);
    ms->proxy_reply = proxy_reply;

    return (ms);
}

void map_server_elt_del (map_server_elt *map_server)
{
    if (map_server == NULL){
        return;
    }
    lisp_addr_del (map_server->address);
    free(map_server->key);
    free(map_server);
}

static inline lisp_xtr_t *
lisp_xtr_cast(lisp_ctrl_dev_t *dev)
{
    /* make sure */
    lm_assert(dev->ctrl_class == &xtr_ctrl_class);
    return(CONTAINER_OF(dev, lisp_xtr_t, super));
}

static lisp_ctrl_dev_t *
xtr_ctrl_alloc()
{
    lisp_xtr_t *xtr;
    xtr = xzalloc(sizeof(lisp_xtr_t));
    return(&xtr->super);
}

static int
xtr_ctrl_construct(lisp_ctrl_dev_t *dev)
{
    lisp_xtr_t *    xtr         = lisp_xtr_cast(dev);
    lisp_addr_t	    addr;
    mapping_t *     map         = NULL;


    LMLOG(LDBG_1, "Creating map cache and local mapping database");

    /* set up databases */
    xtr->local_mdb = local_map_db_new();
    xtr->map_cache = mcache_new();
    xtr->map_servers = glist_new_managed((glist_del_fct)map_server_elt_del);
    xtr->map_resolvers = glist_new_managed((glist_del_fct)lisp_addr_del);
    xtr->pitrs = glist_new_managed((glist_del_fct)lisp_addr_del);
    xtr->petrs = mcache_entry_new();
    xtr->iface_locators_table = shash_new_managed((h_key_del_fct)iface_locators_del);

    if (!xtr->local_mdb || !xtr->map_cache || !xtr->map_servers ||
            !xtr->map_resolvers || !xtr->pitrs || !xtr->petrs ||
            !xtr->iface_locators_table) {
        return(BAD);
    }

    lisp_addr_ip_from_char("0.0.0.0", &addr);
    map = mapping_new_init(&addr);
    mcache_entry_init_static(xtr->petrs, map);

    LMLOG(LDBG_1, "Finished Constructing xTR");

    return(GOOD);
}

static void
xtr_ctrl_destruct(lisp_ctrl_dev_t *dev)
{
    map_local_entry_t * map_loc_e   = NULL;
    void *              it          = NULL;
    lisp_xtr_t *        xtr         = lisp_xtr_cast(dev);


    local_map_db_foreach_entry(xtr->local_mdb, it) {
        map_loc_e = (map_local_entry_t *)it;
        ctrl_unregister_eid_prefix(dev,map_local_entry_eid(map_loc_e));
    } local_map_db_foreach_end;

    if (xtr->fwd_policy_dev_parm != NULL){
        xtr->fwd_policy->del_dev_policy_inf(xtr->fwd_policy_dev_parm);
    }

    shash_del(xtr->iface_locators_table);
    mcache_del(xtr->map_cache);
    mcache_entry_del(xtr->petrs);
    local_map_db_del(xtr->local_mdb);
    glist_destroy(xtr->map_resolvers);
    glist_destroy(xtr->pitrs);
    glist_destroy(xtr->map_servers);
    map_local_entry_del(xtr->all_locs_map);
    lmtimer_stop(xtr->smr_timer);
    LMLOG(LDBG_1,"xTR device destroyed");
}

static void
xtr_ctrl_dealloc(lisp_ctrl_dev_t *dev) {
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    free(xtr);
    LMLOG(LDBG_1, "Freed xTR ...");
}


static void
xtr_run(lisp_xtr_t *xtr)
{
    map_local_entry_t *     map_loc_e   = NULL;
    void *                  it          = NULL;

    if (xtr->super.mode == MN_MODE){
        LMLOG(LDBG_1, "\nStarting xTR MN ...\n");
    }
    if (xtr->super.mode == xTR_MODE){
        LMLOG(LDBG_1, "\nStarting xTR ...\n");
    }

    if (glist_size(xtr->map_servers) == 0) {
        LMLOG(LCRIT, "**** NO MAP SERVER CONFIGURED. Your EID will not be registered in the Mapping System.");
        sleep(3);
    }

    if (glist_size(xtr->map_resolvers) == 0) {
        LMLOG(LCRIT, "**** NO MAP RESOLVER CONFIGURES. You can not request mappings to the mapping system");
        sleep(3);
    }

    if (xtr->petrs == NULL) {
        LMLOG(LWRN, "No Proxy-ETR defined. Packets to non-LISP destinations "
                "will be forwarded natively (no LISP encapsulation). This "
                "may prevent mobility in some scenarios.");
        sleep(3);
    } else {
        xtr->fwd_policy->updated_map_cache_inf(
                xtr->fwd_policy_dev_parm,
                mcache_entry_routing_info(xtr->petrs),
                mcache_entry_mapping(xtr->petrs));
    }

    /* Check configured parameters when NAT-T activated. */
    if (xtr->nat_aware == TRUE) {
        if (0) {
            LMLOG(LCRIT, "NAT aware on -> This version of LISPmob is limited to"
                    " one EID prefix and one interface when NAT-T is enabled");
            exit_cleanup();
        }

        if (glist_size(xtr->map_servers) > 1
                || lisp_addr_ip_afi(((map_server_elt *)glist_first_data(xtr->map_servers))->address) != AF_INET) {
            LMLOG(LINF, "NAT aware on -> This version of LISPmob is limited to "
                    "one IPv4 Map Server.");
            exit_cleanup();
        }

        if (glist_size(xtr->map_resolvers) > 1
                || lisp_addr_ip_afi((lisp_addr_t *)glist_first_data(xtr->map_resolvers)) != AF_INET) {
            LMLOG(LINF, "NAT aware on -> This version of LISPmob is limited to "
                    "one IPv4 Map Resolver.");
            exit_cleanup();
        }

        if (xtr->probe_interval > 0) {
            xtr->probe_interval = 0;
            LMLOG(LINF, "NAT aware on -> disabling RLOC Probing");
        }
    }

    if (xtr->super.mode == MN_MODE){
        /* Check number of EID prefixes */

        if (local_map_db_num_ip_eids(xtr->local_mdb, AF_INET) > 1) {
            LMLOG(LERR, "LISPmob in mobile node mode only supports one IPv4 EID "
                    "prefix and one IPv6 EID prefix");
            exit_cleanup();
        }
        if (local_map_db_num_ip_eids(xtr->local_mdb, AF_INET6) > 1) {
            LMLOG(LERR, "LISPmob in mobile node mode only supports one IPv4 EID "
                    "prefix and one IPv6 EID prefix");
            exit_cleanup();
        }
    }

    LMLOG(LDBG_1, "****** Summary of the xTR configuration ******");
    local_map_db_dump(xtr->local_mdb, LDBG_1);
    mcache_dump_db(xtr->map_cache, LDBG_1);

    map_servers_dump(xtr, LDBG_1);
    LMLOG(LDBG_1, "************* %13s ***************", "Map Resolvers");
        glist_dump(xtr->map_resolvers, (glist_to_char_fct)lisp_addr_to_char, LDBG_1);
    proxy_etrs_dump(xtr, LDBG_1);
    LMLOG(LDBG_1, "************* %13s ***************", "Proxy-ITRs");
    glist_dump(xtr->pitrs, (glist_to_char_fct)lisp_addr_to_char, LDBG_1);

    local_map_db_foreach_entry(xtr->local_mdb, it) {
        /* Register EID prefix to control */
        map_loc_e = (map_local_entry_t *)it;
        ctrl_register_eid_prefix(&(xtr->super),map_local_entry_eid(map_loc_e));
        /* Update forwarding info of the local mappings. When it is created during conf file process,
         * the local rlocs are not set. For this reason should be calculated again. It can not be removed
         * from the conf file process -> In future could appear fwd_map_info parameters*/
        xtr->fwd_policy->updated_map_loc_inf(
                xtr->fwd_policy_dev_parm,
                map_local_entry_fwd_info(map_loc_e),
                map_local_entry_mapping(map_loc_e));

    } local_map_db_foreach_end;

    /*  Register to the Map-Server(s) */
    program_map_register(xtr, 1);

    /* SMR proxy-ITRs list to be updated with new mappings */
    program_smr(xtr, 1);

    /* RLOC Probing proxy ETRs */
    program_petr_rloc_probing(xtr, 1);
}

static void
rtr_run(lisp_xtr_t *xtr)
{
    mapping_t * mapping = NULL;

    LMLOG(LINF, "\nStarting RTR ...\n");


    if (glist_size(xtr->map_resolvers) == 0) {
        LMLOG(LCRIT, "**** NO MAP RESOLVER CONFIGURES. You can not request mappings to the mapping system");
        sleep(3);
    }

    LMLOG(LINF, "****** Summary of the configuration ******");
    local_map_db_dump(xtr->local_mdb, LINF);
    mcache_dump_db(xtr->map_cache, LINF);
    if (xtr->all_locs_map) {
        mapping = map_local_entry_mapping(xtr->all_locs_map);
        LMLOG(LINF, "Active interfaces status");
        xtr->fwd_policy->updated_map_loc_inf(
                xtr->fwd_policy_dev_parm,
                map_local_entry_fwd_info(xtr->all_locs_map),
                mapping);
        LMLOG(LINF, "%s", mapping_to_char(mapping));
    }

}

static void
xtr_ctrl_run(lisp_ctrl_dev_t *dev)
{
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);


    if (xtr->super.mode == xTR_MODE || xtr->super.mode == MN_MODE) {
        xtr_run(xtr);
    } else if (xtr->super.mode == RTR_MODE) {
        rtr_run(xtr);
    }

}

/* implementation of ctrl base functions */
ctrl_dev_class_t xtr_ctrl_class = {
        .alloc = xtr_ctrl_alloc,
        .construct = xtr_ctrl_construct,
        .dealloc = xtr_ctrl_dealloc,
        .destruct = xtr_ctrl_destruct,
        .run = xtr_ctrl_run,
        .recv_msg = xtr_recv_msg,
        .if_event = xtr_if_event,
        .get_fwd_entry = tr_get_forwarding_entry
};


static void
proxy_etrs_dump(lisp_xtr_t *xtr, int log_level)
{
	glist_t *loct_list = NULL;
	glist_entry_t *it_list = NULL;
	glist_entry_t *it_loct = NULL;
	locator_t *locator = NULL;

    LMLOG(log_level, "************************* Proxy ETRs List ****************************");
    LMLOG(log_level, "|               Locator (RLOC)            | Status | Priority/Weight |");

	/* Start rloc probing for each locator of the mapping */
	glist_for_each_entry(it_list, mapping_locators_lists(xtr->petrs->mapping)){
		loct_list = (glist_t*)glist_entry_data(it_list);
		glist_for_each_entry(it_loct,loct_list){
			locator = (locator_t *)glist_entry_data(it_loct);
			locator_to_char(locator);
		}

	}
}

void
map_servers_dump(lisp_xtr_t *xtr, int log_level)
{
    map_server_elt *    ms          = NULL;
    glist_entry_t *     it          = NULL;
    char                str[80];

    if (glist_size(xtr->map_servers) == 0 || is_loggable(log_level) == FALSE) {
        return;
    }

    LMLOG(log_level, "******************* Map-Servers list ********************************");
    LMLOG(log_level, "|               Locator (RLOC)            |       Key Type          |");

    glist_for_each_entry(it, xtr->map_servers) {
        ms = (map_server_elt *)glist_entry_data(it);
        sprintf(str, "| %39s |", lisp_addr_to_char(ms->address));
        if (ms->key_type == NO_KEY) {
            sprintf(str + strlen(str), "          NONE           |");
        } else if (ms->key_type == HMAC_SHA_1_96) {
            sprintf(str + strlen(str), "     HMAC-SHA-1-96       |");
        } else {
            sprintf(str + strlen(str), "    HMAC-SHA-256-128     |");
        }
        LMLOG(log_level, "%s", str);
    }
}



//static int
//rtr_get_src_and_dst_from_lcaf(lisp_xtr_t *xtr, lisp_addr_t *laddr, lisp_addr_t **src,
//        lisp_addr_t **dst)
//{
//    lcaf_addr_t *lcaf = NULL;
//    elp_node_t *elp_node, *next_elp;
//    glist_entry_t *it = NULL, *rit;
//    lisp_addr_t *raddr;
//    glist_t *rlocs;
//
//    lcaf = lisp_addr_get_lcaf(laddr);
//    switch (lcaf_addr_get_type(lcaf)) {
//    case LCAF_EXPL_LOC_PATH:
//        /* lookup in the elp list the first RLOC to also pertain to the RTR */
//        glist_for_each_entry(it, lcaf_elp_node_list(lcaf)) {
//            elp_node = glist_entry_data(it);
//            rlocs = ctrl_rlocs(xtr->super.ctrl,
//                    lisp_addr_ip_afi(elp_node->addr));
//
//            glist_for_each_entry(rit, rlocs) {
//                raddr = glist_entry_data(rit);
//                if (lisp_addr_cmp(raddr, elp_node->addr) == 0) {
//                    next_elp = glist_entry_data(glist_next(it));
//                    *dst = next_elp->addr;
//                    *src = elp_node->addr;
//                    return (GOOD);
//                }
//            }
//        }
//        return (GOOD);
//    default:
//        LMLOG(LDBG_1, "get_locator_from_lcaf: Type % not supported!, ",
//                lcaf_addr_get_type(lcaf));
//        return (BAD);
//    }
//}


static fwd_entry_t *
tr_get_fwd_entry(lisp_xtr_t *xtr, packet_tuple_t *tuple)
{
    mcache_entry_t *mce = NULL;
    map_local_entry_t *map_loc_e = NULL;
    mapping_t *dmap = NULL;
    fwd_entry_t *fe = NULL;

    if (xtr->super.mode == xTR_MODE) {
        /* lookup local mapping for source EID */
        map_loc_e = local_map_db_lookup_eid(xtr->local_mdb, &tuple->src_addr);
//      /* This can only happend in a multithreded process when removing an EID */
//        if (unlikely(map_loc_e == NULL)){
//            LMLOG(LDBG_1, "The source address %s is not a local EID", lisp_addr_to_char(&tuple->src_addr));
//            return (NULL);
//        }
    }else if ( xtr->super.mode == MN_MODE ) {
        /* lookup local mapping for source EID */
        map_loc_e = local_map_db_lookup_eid(xtr->local_mdb, &tuple->src_addr);
        /* Communications directly to the RLOC of the MN */
        if (map_loc_e == NULL){
            LMLOG(LDBG_3, "The source address %s is not a local EID", lisp_addr_to_char(&tuple->src_addr));
            return (NULL);
        }
    }else {
        map_loc_e = xtr->all_locs_map;
    }

    mce = mcache_lookup(xtr->map_cache, &tuple->dst_addr);

    if (!mce) {
        LMLOG(LDBG_1, "No map cache for EID %s. Sending Map-Request!",
                lisp_addr_to_char(&tuple->dst_addr));
        handle_map_cache_miss(xtr, &tuple->dst_addr, &tuple->src_addr);
        if (xtr->petrs == NULL){
            LMLOG(LDBG_3, "Trying to forward to PETR but none found ...");
            return (NULL);
        }
        mce = xtr->petrs;
    } else if (mce->active == NOT_ACTIVE) {
        LMLOG(LDBG_2, "Already sent Map-Request for %s. Waiting for reply!",
                lisp_addr_to_char(&tuple->dst_addr));
        if (xtr->petrs == NULL){
            LMLOG(LDBG_3, "Trying to forward to PETR but none found ...");
            return (NULL);
        }
        LMLOG(LDBG_3, "Forwarding packet to PeTR");
        mce = xtr->petrs;
    }

    dmap = mcache_entry_mapping(mce);
    if (mapping_locator_count(dmap) == 0) {
        LMLOG(LDBG_3, "Destination %s has a NEGATIVE mapping!",
                lisp_addr_to_char(&tuple->dst_addr));
        if (xtr->petrs == NULL){
            LMLOG(LDBG_3, "Trying to forward to PETR but none found ...");
            return (NULL);
        }
        LMLOG(LDBG_3, "Forwarding packet to PeTR");
        mce = xtr->petrs;
    }


    fe = xtr->fwd_policy->policy_get_fwd_entry(
            xtr->fwd_policy_dev_parm,
            map_local_entry_fwd_info(map_loc_e),
            mcache_entry_routing_info(mce),
            tuple);

    if (fe == NULL){
        if (mce != xtr->petrs){
            if (xtr->petrs != NULL){
                LMLOG(LDBG_3, "Forwarding packet to PeTR");
                mce = xtr->petrs;
                fe = xtr->fwd_policy->policy_get_fwd_entry(
                        xtr->fwd_policy_dev_parm,
                        map_local_entry_fwd_info(map_loc_e),
                        mcache_entry_routing_info(mce),
                        tuple);
                if (fe == NULL){
                    LMLOG(LDBG_3, "tr_get_fwd_entry: No PETR compatible with local locators afi");
                }
            }else{
                LMLOG(LDBG_3, "tr_get_fwd_entry: No compatible src and dst rlocs. No PeTRs configured");
            }
        }else{
            LMLOG(LDBG_3, "tr_get_fwd_entry: No PETR compatible with local locators afi");
        }
    }

    return (fe);
}


static fwd_entry_t *
tr_get_forwarding_entry(lisp_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    lisp_xtr_t *xtr = NULL;

    xtr = lisp_xtr_cast(dev);

    /* If we are behind a full NAT system, send the message directly to
     * the RTR */
    if (xtr->nat_aware && xtr->nat_status != NO_NAT) {
        //return(get_natt_forwarding_entry(xtr, tuple));
        return NULL;
    } else {
        return(tr_get_fwd_entry(xtr, tuple));
    }
}

/*
 * Return the list of locators from the local mappings containing addr
 * @param local_db Database where to search locators
 * @param addr Address used during the search
 * @return Generic list containg locator_t elements
 */
glist_t *
get_local_locators_with_address(
        local_map_db_t      *local_db,
        lisp_addr_t         *addr)
{
    glist_t *               locators   = NULL;
    locator_t *             locator    = NULL;
    map_local_entry_t *     map_loc_e  = NULL;
    mapping_t *             mapping    = NULL;
    void *                  it         = NULL;

    locators = glist_new();

    local_map_db_foreach_entry(local_db, it) {
        map_loc_e = (map_local_entry_t *)it;
        mapping = map_local_entry_mapping(map_loc_e);
        locator = mapping_get_loct_with_addr(mapping, addr);
        if (locator != NULL){
            glist_add_tail(locator,locators);
        }
    } local_map_db_foreach_end;

    return (locators);
}

map_local_entry_t *
get_map_loc_ent_containing_loct_ptr(
        local_map_db_t      *local_db,
        locator_t           *locator)
{
    map_local_entry_t *     map_loc_e   = NULL;
    mapping_t *             mapping     = NULL;
    void *                  it          = NULL;
    local_map_db_foreach_entry(local_db, it) {
        map_loc_e = (map_local_entry_t *)it;
        mapping = map_local_entry_mapping(map_loc_e);
        if (mapping_has_locator(mapping, locator) == TRUE){
            return (map_loc_e);
        }
    } local_map_db_foreach_end;
    LMLOG(LDBG_2, "get_map_loc_ent_containing_loct_ptr: No mapping has been found with locator %s",
            lisp_addr_to_char(locator_addr(locator)));
    return (NULL);
}



/*
 * Return the list of mappings that has experimented changes in their
 * locators. At the same time iface_locators status is reseted
 * @param xtr
 * @return glist_t with the list of modified mappings (mapping_t *)
 */
glist_t *get_map_local_entry_to_smr(lisp_xtr_t *xtr)
{
    glist_t *           map_loc_e_to_smr        = glist_new();//<map_local_entry_t>
    glist_t *           iface_locators_list    = NULL;
    iface_locators *    if_loct                = NULL;
    glist_entry_t *     it                     = NULL;
    glist_entry_t *     it_loc                 = NULL;
    glist_t *           locators[2]            = {NULL,NULL};
    map_local_entry_t * map_loc_e              = NULL;
    locator_t *         locator                = NULL;
    int                 ctr;

    iface_locators_list = shash_values(xtr->iface_locators_table);

    glist_for_each_entry(it,iface_locators_list){
        if_loct = (iface_locators *)glist_entry_data(it);
        /* Select affected locators */
        if (if_loct->status_changed == TRUE){
            locators[0] = if_loct->ipv4_locators;
            locators[1] = if_loct->ipv6_locators;
        }else{
            if(if_loct->ipv4_prev_addr != NULL){
                locators[0] = if_loct->ipv4_locators;
            }
            if(if_loct->ipv6_prev_addr != NULL){
                locators[1] = if_loct->ipv6_locators;
            }
        }
        /* Reset iface_locators status */
        if_loct->status_changed = FALSE;
        lisp_addr_del(if_loct->ipv4_prev_addr);
        lisp_addr_del(if_loct->ipv6_prev_addr);
        if_loct->ipv4_prev_addr = NULL;
        if_loct->ipv6_prev_addr = NULL;
        /* Select not repeated mappings*/
        for (ctr=0 ; ctr<2 ; ctr++){
            if (locators[ctr] != NULL){
                glist_for_each_entry(it_loc,locators[ctr]){
                    locator = (locator_t *)glist_entry_data(it_loc);
                    map_loc_e = get_map_loc_ent_containing_loct_ptr(xtr->local_mdb, locator);
                    if (map_loc_e != NULL && glist_contain(map_loc_e, map_loc_e_to_smr) == FALSE){
                        glist_add(map_loc_e, map_loc_e_to_smr);
                    }
                }
            }
        }
    }
    glist_destroy(iface_locators_list);
    return (map_loc_e_to_smr);
}


static lisp_addr_t *
get_map_resolver(lisp_xtr_t *xtr)
{
    uint16_t        afi         = AF_UNSPEC;
    glist_entry_t * it          = NULL;
    lisp_addr_t *   addr        = NULL;

    if (default_ctrl_iface_v4 != NULL){
        afi = AF_INET;
    }else if (default_ctrl_iface_v6 != NULL){
        afi = AF_INET6;
    }

    glist_for_each_entry(it,xtr->map_resolvers){
        addr = (lisp_addr_t *)glist_entry_data(it);
        if (lisp_addr_ip_afi(addr) == afi){
            return (addr);
        }
    }
    LMLOG (LDBG_1,"get_map_resolver: No map resolver reachable");
    return (NULL);
}


