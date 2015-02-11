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

#include "iface_locators.h"
#include "lisp_xtr.h"
#include "sockets.h"
#include "util.h"
#include "lmlog.h"

static int mc_entry_expiration_timer_cb(lmtimer_t *t, void *arg);
static void mc_entry_start_expiration_timer(lisp_xtr_t *, mcache_entry_t *);
static int handle_petr_probe_reply(lisp_xtr_t *, mapping_t *, locator_t *,
        uint64_t);
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
static int program_map_register(lisp_xtr_t *xtr, int time);
static int map_register_process(lisp_xtr_t *);
static int rloc_probing(lisp_xtr_t *, mapping_t *, locator_t *loc);
static void program_rloc_probing(lisp_xtr_t *, mapping_t *, locator_t *, int);
static void program_mapping_rloc_probing(lisp_xtr_t *, mapping_t *);
static void program_petr_rloc_probing(lisp_xtr_t *, int time);
static inline lisp_xtr_t *lisp_xtr_cast(lisp_ctrl_dev_t *);

static void proxy_etrs_dump(lisp_xtr_t *, int log_level);
static void map_servers_dump(lisp_xtr_t *, int log_level);

static fwd_entry_t *tr_get_forwarding_entry(lisp_ctrl_dev_t *,
        packet_tuple_t *);

glist_t *get_local_locators_with_address(local_map_db_t *local_db, lisp_addr_t *addr);
mapping_t *get_mapping_containing_locator_ptr(local_map_db_t *local_db, locator_t *locator);
glist_t *get_mappings_to_smr(lisp_xtr_t *xtr);
static lisp_addr_t * get_map_resolver(lisp_xtr_t *xtr);

/* Called when the timer associated with an EID entry expires. */
static int
mc_entry_expiration_timer_cb(lmtimer_t *t, void *arg)
{
    mapping_t *mapping = NULL;
    lisp_addr_t *addr = NULL;

    mapping = mcache_entry_mapping(arg);
    addr = mapping_eid(mapping);
    LMLOG(DBG_1,"Got expiration for EID %s", lisp_addr_to_char(addr));

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

    LMLOG(DBG_1,"The map cache entry of EID %s will expire in %d minutes.",
            lisp_addr_to_char(mapping_eid(mcache_entry_mapping(mce))),
            mapping_ttl(mcache_entry_mapping(mce)));
}


static int
handle_petr_probe_reply(lisp_xtr_t *xtr, mapping_t *m, locator_t *probed,
        uint64_t nonce)
{
    mapping_t *old_map = NULL, *prox_map = NULL;
    glist_t *loct_list = NULL;
    glist_entry_t *it_list = NULL;
    glist_entry_t *it_loct = NULL;
    rmt_locator_extended_info_t *rmt_ext_inf = NULL;
    lisp_addr_t *src_eid = NULL;
    locator_t *loct = NULL, *aux_loct = NULL;

    prox_map = mcache_entry_mapping(xtr->petrs);
    if (xtr->petrs && lisp_addr_cmp(src_eid, mapping_eid(prox_map)) == 0) {
        /* find locator */
        if (glist_size(mapping_locators(m)) == 0){
            return (BAD);
        }
        glist_for_each_entry(it_list,mapping_locators(prox_map)){
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
    }

    if (!loct) {
        LMLOG(DBG_1, "Nonce of Negative Map-Reply Probe doesn't match "
                "any nonce of Proxy-ETR locators");
        return (BAD);
    } else {
        LMLOG(DBG_1, "Map-Reply Probe for %s has not been requested! "
                "Discarding!", lisp_addr_to_char(src_eid));
        return (BAD);
    }

    LMLOG(DBG_1, "Map-Reply probe reachability to the PETR with RLOC %s",
            lisp_addr_to_char(locator_addr(loct)));

    rmt_ext_inf = loct->extended_info;
    if (!rmt_ext_inf->probe_timer){
       LMLOG(DBG_1," Map-Reply Probe was not requested! Discarding!");
       return (BAD);
    }

    /* Reprogramming timers of rloc probing */
    program_rloc_probing(xtr, old_map, probed, xtr->probe_interval);

    return (GOOD);
}

/* Process a record from map-reply probe message */
static int
handle_locator_probe_reply(lisp_xtr_t *xtr, mapping_t *m,
        locator_t *probed, uint64_t nonce)
{
    lisp_addr_t *src_eid = NULL;
    locator_t *loc = NULL;
    mapping_t *old_map = NULL;
    rmt_locator_extended_info_t *rmt_ext_inf = NULL;

    src_eid = mapping_eid(m);

    /* Lookup src EID in map cache */
    old_map = tr_mcache_lookup_mapping(xtr, src_eid);
    if(!old_map) {
        LMLOG(DBG_1, "Source EID %s couldn't be found in the map-cache",
                lisp_addr_to_char(src_eid));
        return(BAD);
    }

    /* Find probed locator in mapping */
    loc = mapping_get_loct_with_addr(old_map, locator_addr(probed));
    if (!loc){
        LMLOG(DBG_2,"Probed locator %s not part of the the mapping %s",
                lisp_addr_to_char(locator_addr(probed)),
                lisp_addr_to_char(mapping_eid(old_map)));
        return (ERR_NO_EXIST);
    }

    /* Compare nonces */
    rmt_ext_inf = loc->extended_info;
    if (!rmt_ext_inf || !rmt_ext_inf->rloc_probing_nonces) {
        LMLOG(DBG_1, "Locator %s has no nonces!",
                lisp_addr_to_char(locator_addr(loc)));
        return(BAD);
    }

    /* Check if the nonce of the message match with the one stored in the
     * structure of the locator */
    if ((nonce_check(rmt_ext_inf->rloc_probing_nonces, nonce)) == GOOD) {
        free(rmt_ext_inf->rloc_probing_nonces);
        rmt_ext_inf->rloc_probing_nonces = NULL;
    } else {
        LMLOG(DBG_1, "Nonce of Map-Reply Probe doesn't match nonce of the "
                "Map-Request Probe. Discarding message ...");
        return (BAD);
    }

    LMLOG(DBG_1," Successfully probed RLOC %s of cache entry with EID %s",
                lisp_addr_to_char(locator_addr(loc)),
                lisp_addr_to_char(mapping_eid(old_map)));


    if (loc->state == DOWN) {
        loc->state = UP;

        LMLOG(DBG_1," Locator %s state changed to UP",
                lisp_addr_to_char(locator_addr(loc)));

        /* [re]Calculate balancing locator vectors if status changed*/
        mapping_compute_balancing_vectors(old_map);
    }

    if (!rmt_ext_inf->probe_timer) {
       LMLOG(DBG_1," Map-Reply Probe was not requested! Discarding!");
       return (BAD);
    }

    /* Reprogramming timers of rloc probing */
    program_rloc_probing(xtr, old_map, loc, xtr->probe_interval);

    return (GOOD);

}

static int
update_mcache_entry(lisp_xtr_t *xtr, mapping_t *m, uint64_t nonce)
{
    mcache_entry_t *mce = NULL;
    mapping_t *old_map;
    lisp_addr_t *eid;

    eid = mapping_eid(m);

    /* Serch map cache entry exist*/
    mce = mcache_lookup_exact(xtr->map_cache, eid);
    if (!mce){
        LMLOG(DBG_2,"No map cache entry for %s", lisp_addr_to_char(eid));
        return (BAD);
    }

    /* Check if map cache entry contains the nonce*/
    if (nonce_check(mce->nonces, nonce) == BAD) {
        LMLOG(DBG_2, " Nonce doesn't match the Map-Request nonce. "
                "Discarding message!");
        return(BAD);
    } else {
        mcache_entry_destroy_nonces(mce);
        mcache_entry_requester_del(mce);
    }

    LMLOG(DBG_2, "Mapping with EID %s already exists, replacing!",
            lisp_addr_to_char(eid));

    old_map = mcache_entry_mapping(mce);

    /* DISCARD all locator state */
    mapping_update_locators(old_map, mapping_locators(m));

    mapping_compute_balancing_vectors(old_map);

    /* Remove Map Request retry timer */
    mcache_entry_stop_req_retry_timer(mce);
    mcache_entry_stop_smr_inv_timer(mce);

    /* Reprogramming timers */
    mc_entry_start_expiration_timer(xtr, mce);

    /* RLOC probing timer */
    program_mapping_rloc_probing(xtr, old_map);

    return (GOOD);
}

static int
tr_recv_map_reply(lisp_xtr_t *xtr, lbuf_t *buf)
{
    void *mrep_hdr;
    int i;
    locator_t *probed = NULL;
    lisp_addr_t *eid;
    mapping_t *m;
    lbuf_t b;
    mcache_entry_t *mce;

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

            mcache_dump_db(xtr->map_cache, DBG_3);

            /*
            if (is_mrsignaling()) {
                mrsignaling_recv_ack();
                continue;
            } */
        } else {
            if (mapping_locator_count(m) > 0) {
                handle_locator_probe_reply(xtr, m, probed,
                        MREP_NONCE(mrep_hdr));
            } else {
                /* If negative probe map-reply, then the probe was for
                 * proxy-ETR (PETR) */
                handle_petr_probe_reply(xtr, m, probed, MREP_NONCE(mrep_hdr));
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
    mcache_entry_t *mce;

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
        LMLOG(DBG_1, "More than one EID record in RLOC probe. Discarding!");
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

        LMLOG(DBG_1, " dst-eid: %s", lisp_addr_to_char(deid));

        /* Check the existence of the requested EID */
        map_loc_e = local_map_db_lookup_eid(xtr->local_mdb, deid);
        if (!map_loc_e) {
            LMLOG(DBG_1,"EID %s not locally configured!",
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
    LMLOG(DBG_1, "Sending %s", lisp_msg_hdr_to_char(mrep));
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
    lisp_addr_t *eid;
    mapping_t *mcache_map;

    eid = mapping_eid(rec_map);

    LMLOG(DBG_1, "Merge-Semantics on, moving returned mapping to "
            "map-cache");

    /* XXX, TODO: done thinking of lisp-re, MUST change to be more general */
    /* Save the mapping returned by the map-notify in the mapping
     * cache */
    mcache_map = tr_mcache_lookup_mapping(xtr, eid);
    if (mcache_map && mapping_cmp(mcache_map, rec_map) != 0) {
        /* UPDATED rlocs */
        LMLOG(DBG_3, "Prefix %s already registered, updating locators",
                lisp_addr_to_char(eid));
        mapping_update_locators(mcache_map,mapping_locators(rec_map));

        mapping_compute_balancing_vectors(mcache_map);
        program_mapping_rloc_probing(xtr, mcache_map);

    } else if (!mcache_map) {
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
    }
    return(GOOD);
}

static int
tr_recv_map_notify(
        lisp_xtr_t      *xtr,
        lbuf_t          *buf)
{
    lisp_addr_t *       eid         = NULL;
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
            LMLOG(DBG_3, "Correct nonce");
            /* Free nonce if authentication is ok */
        } else {
            LMLOG(DBG_1, "No Map Register sent with nonce: %s",
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
        LMLOG(DBG_1, "Map-Notify message is invalid");
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

        local_map = local_map_db_lookup_eid_exact(xtr->local_mdb, eid);
        if (!local_map) {
            LMLOG(DBG_1, "Map-Notify confirms registration of UNKNOWN EID %s."
                    " Dropping!", lisp_addr_to_char(eid));
            continue;
        }

        LMLOG(DBG_1, "Map-Notify message confirms correct registration of %s",
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
    lisp_addr_t *drloc, *srloc;

    /* encap */
    lisp_msg_encap(b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, in_srloc,
            in_drloc);

    /* prepare outer headers */
    drloc = get_map_resolver(xtr);
    srloc = NULL;

    LMLOG(DBG_1, "%s, inner IP: %s -> %s, inner UDP: %d -> %d",
            lisp_msg_ecm_hdr_to_char(b), lisp_addr_to_char(in_srloc),
            lisp_addr_to_char(in_drloc), LISP_CONTROL_PORT,
            LISP_CONTROL_PORT);

    return(send_map_request(&xtr->super, b, srloc, drloc));
}

int
handle_map_cache_miss(lisp_xtr_t *xtr, lisp_addr_t *requested_eid,
        lisp_addr_t *src_eid)
{
    mcache_entry_t *mce = mcache_entry_new();
    mapping_t *m;

    /* install temporary, NOT active, mapping in map_cache
     * TODO: should also build a nonce hash table for faster
     *       nonce lookups*/
    m = mapping_init_remote(requested_eid);
    mcache_entry_init(mce, m);
    if (mcache_add_entry(xtr->map_cache, mapping_eid(m), mce) != GOOD) {
        LMLOG(LWRN, "Couln't install temporary map cache entry for %s!",
                lisp_addr_to_char(requested_eid));
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
    lisp_addr_t *loc_addr;

    if (glist_size(mapping_locators(mapping)) == 0){
        return (rlocs);
    }

    glist_for_each_entry(it_list, mapping_locators(mapping)){
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
    lbuf_t *b;
    lisp_addr_t *seid, *srloc;
    void *hdr;
    glist_t *itr_rlocs;

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

    LMLOG(DBG_1, "%s, itr-rlocs: %s, src-eid: %s, req-eid: %s ", lisp_msg_hdr_to_char(b),
            laddr_list_to_char(itr_rlocs), lisp_addr_to_char(seid), lisp_addr_to_char(deid));
    glist_destroy(itr_rlocs);

    srloc = ctrl_default_rloc(xtr->super.ctrl, lisp_addr_ip_afi(drloc));
    if (!srloc) {
        LMLOG(DBG_2, "No compatible RLOC was found to send SMR Map-Request "
                "for local EID %s", lisp_addr_to_char(seid));
        lisp_msg_destroy(b);
        return(BAD);
    }

    return(send_map_request(&xtr->super, b, srloc, drloc));

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
    lisp_addr_t *deid, *drloc;
    locator_t *loct;

    deid = mapping_eid(dst_map);

    glist_for_each_entry(it_lists,mapping_locators(dst_map)){
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
    mcache_entry_t *    mce             = NULL;
    mapping_t *         mcache_map      = NULL;
    mapping_t *         map             = NULL;
    glist_t *           mapping_list    = NULL;
    glist_entry_t *     it              = NULL;
    glist_entry_t *     it_pitr         = NULL;
    lisp_addr_t *       pitr_addr       = NULL;
    lisp_addr_t *       eid             = NULL;

    LMLOG(DBG_2,"\n*** Re-Register and send SMRs for mappings with updated "
            "RLOCs ***");

    /* Get a list of mappings that require smrs */
    mapping_list = get_mappings_to_smr(xtr);

    /* Send map register and SMR request for each mapping */
    glist_dump(mapping_list,(glist_to_char_fct)mapping_to_char,DBG_1);

    glist_for_each_entry(it, mapping_list) {
        map = (mapping_t *)glist_entry_data(it);

        /* Send map register for all mappings */
        if (nat_aware == FALSE || nat_status == NO_NAT) {
            build_and_send_map_reg(xtr, map);
        } else if (nat_status != UNKNOWN) {
            /* TODO : We suppose one EID and one interface.
             * To be modified when multiple elements */
            map_register_process(xtr);
        }

        eid = mapping_eid(map);

        LMLOG(DBG_1, "Start SMR for local EID %s", lisp_addr_to_char(eid));

        /* For each map cache entry with same afi as local EID mapping */
        if (lisp_addr_lafi(eid) == LM_AFI_IP ) {
            LMLOG(DBG_3, "send_all_smr_and_reg: SMR request for %s. Shouldn't "
                    "receive SMR for IP in mapping?!", lisp_addr_to_char(eid));
        } else if (lisp_addr_lafi(eid) != LM_AFI_IPPREF) {
            LMLOG(DBG_3, "send_all_smr_and_reg: SMR request for %s. SMR "
                    "supported only for IP-prefixes for now!",
                    lisp_addr_to_char(eid));
            continue;
        }

        /* no SMRs for now for multicast */
        if (lisp_addr_is_mc(eid))
            continue;

        glist_dump(mapping_list,(glist_to_char_fct)mapping_to_char,DBG_1);


        /* TODO: spec says SMRs should be sent only to peer ITRs that sent us
         * traffic in the last minute. Should change this in the future*/
        /* XXX: works ONLY with IP */
        mcache_foreach_active_entry_in_ip_eid_db(xtr->map_cache, eid, mce) {
            mcache_map = mcache_entry_mapping(mce);
            build_and_send_smr_mreq_to_map(xtr, map, mcache_map);
        } mcache_foreach_active_entry_in_ip_eid_db_end;

        /* SMR proxy-itr */
        LMLOG(DBG_1, "Sending SMRs to PITRs");
        glist_for_each_entry(it_pitr, xtr->pitrs){
            pitr_addr = (lisp_addr_t *)glist_entry_data(it_pitr);
            build_and_send_smr_mreq(xtr, map, eid, pitr_addr);
        }
    }

    glist_destroy(mapping_list);
    LMLOG(DBG_2,"*** Finished sending notifications ***\n");
}

static int
smr_invoked_map_request_cb(lmtimer_t *t, void *arg)
{
    return(send_smr_invoked_map_request(t->owner, arg));
}

static int
send_smr_invoked_map_request(lisp_xtr_t *xtr, mcache_entry_t *mce)
{
    struct lbuf *b;
    void *hdr;
    nonces_list_t *nonces;
    mapping_t *m;
    lisp_addr_t *deid, empty, *srloc, *drloc;
    lmtimer_t *t;
    glist_t *rlocs;
    int afi;

    m = mcache_entry_mapping(mce);
    deid = mapping_eid(m);
    afi = lisp_addr_lafi(deid);
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
        LMLOG(DBG_1,"SMR: Map-Request for EID: %s (%d retries)",
                lisp_addr_to_char(deid), nonces->retransmits);

        /* BUILD Map-Request */

        /* no source EID and mapping, so put default control rlocs */
        rlocs = ctrl_default_rlocs(xtr->super.ctrl);
        b = lisp_msg_mreq_create(&empty, rlocs, mapping_eid(m));

        hdr = lisp_msg_hdr(b);
        MREQ_SMR_INVOKED(hdr) = 1;
        nonces->nonce[nonces->retransmits] = nonce_build_time();
        MREQ_NONCE(hdr) = nonces->nonce[nonces->retransmits];

        /* we could put anything here. Still, better put something that
         * makes a bit of sense .. */
        srloc = local_map_db_get_main_eid(xtr->local_mdb, afi);
        drloc = deid;

        /* SEND */
        LMLOG(DBG_1, "%s, itr-rlocs:%s src-eid: %s, req-eid: %s",
                lisp_msg_hdr_to_char(b), laddr_list_to_char(rlocs),
                lisp_addr_to_char(&empty), lisp_addr_to_char(mapping_eid(m)));

        if (send_map_request_to_mr(xtr, b, srloc, drloc) != GOOD) {
            return(BAD);
        }

        /* init or delete and init, if needed, the timer */
        t = mcache_entry_init_smr_inv_timer(mce);

        lmtimer_start(t, LISPD_INITIAL_SMR_TIMEOUT,
                smr_invoked_map_request_cb, xtr, mce);
        nonces->retransmits ++;

    } else {
        mcache_entry_stop_smr_inv_timer(mce);
        LMLOG(DBG_1,"SMR: No Map Reply for EID %s. Stopping ...",
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
    lmtimer_t *t;
    nonces_list_t *nonces;
    mapping_t *m;
    lisp_addr_t *deid, *seid, empty = {.lafi = LM_AFI_NO_ADDR};
    glist_t *rlocs;
    lbuf_t *b;
    void *mr_hdr;
    int afi;

    nonces = mcache_entry_nonces(mce);
    m = mcache_entry_mapping(mce);
    deid = mapping_eid(m);

    if (!nonces) {
        mcache_entry_init_nonces(mce);
        nonces = mcache_entry_nonces(mce);
    }

    if (nonces->retransmits - 1 < xtr->map_request_retries) {
        if (nonces->retransmits > 0) {
            LMLOG(DBG_1, "Retransmitting Map Request for EID: %s (%d retries)",
                    lisp_addr_to_char(deid), nonces->retransmits);
        }

        /* BUILD Map-Request */
        afi = lisp_addr_ip_afi(deid);
        seid = local_map_db_get_main_eid(xtr->local_mdb, afi);
        if (!seid) {
            seid = &empty;
        }
        rlocs = ctrl_default_rlocs(xtr->super.ctrl);
        LMLOG(DBG_1, "locators for req: %s", laddr_list_to_char(rlocs));
        b = lisp_msg_mreq_create(seid, rlocs, deid);
        if (!b) {
            return(BAD);
        }

        mr_hdr = lisp_msg_hdr(b);
        nonces->nonce[nonces->retransmits] = nonce_build_time();
        MREQ_NONCE(mr_hdr) = nonces->nonce[nonces->retransmits];

        LMLOG(DBG_1, "%s, itr-rlocs:%s, src-eid: %s, req-eid: %s",
                lisp_msg_hdr_to_char(b), laddr_list_to_char(rlocs),
                lisp_addr_to_char(seid), lisp_addr_to_char(deid));

        /* SEND */
        send_map_request_to_mr(xtr, b, mcache_entry_requester(mce), deid);
        lisp_msg_destroy(b);

        /* prepare callback
         * init or delete and init, if needed, the timer */
        t = mcache_entry_init_req_retry_timer(mce);
        lmtimer_start(t, LISPD_INITIAL_SMR_TIMEOUT,
                send_map_request_retry_cb, xtr, mce);

        nonces->retransmits++;

    } else {
        LMLOG(DBG_1, "No Map-Reply for EID %s after %d retries. Aborting!",
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

        LMLOG(DBG_1, "%s, EID: %s, MS: %s", lisp_msg_hdr_to_char(b),
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

        LMLOG(DBG_1, "%s, Inner IP: %s -> %s, EID: %s, RTR: %s",
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

static int
program_map_register(lisp_xtr_t *xtr, int time)
{
    lmtimer_t *t = xtr->map_register_timer;
    if (!t) {
        xtr->map_register_timer = lmtimer_create(MAP_REGISTER_TIMER);
        t = xtr->map_register_timer;
    }

    /* Configure timer to send the next map register. */
    lmtimer_start(t, time, map_register_cb, xtr, NULL);
    LMLOG(DBG_1, "(Re)programmed Map-Register process in %d seconds", time);
    return(GOOD);
}



static int
map_register_process_default(lisp_xtr_t *xtr)
{
    mapping_t *m;
    void *it = NULL;

    /* TODO
     * - configurable keyid
     * - multiple MSes
     */

    local_map_db_foreach_entry(xtr->local_mdb, it) {
        m = it;
        if (m->locator_count != 0) {
            build_and_send_map_reg(xtr, m);
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
    mapping_t *m = NULL;
    locator_t *loc = NULL;
    lisp_addr_t *nat_rtr = NULL;
    int next_timer_time = 0;
    void *it = NULL;
    nonces_list_t *nemrn;
    lcl_locator_extended_info_t *leinf;

    nemrn = xtr->nat_emr_nonces;
    if (!nemrn) {
        xtr->nat_emr_nonces = nonces_list_new();
        LMLOG(LWRN,"map_register_process_encap: nonces unallocated!"
                " Aborting!");
        exit_cleanup();
    }

    if (nemrn->retransmits <= LISPD_MAX_RETRANSMITS) {

        if (nemrn->retransmits > 0) {
            LMLOG(DBG_1,"No Map Notify received. Retransmitting encapsulated "
                    "map register.");
        }

        local_map_db_foreach_entry(xtr->local_mdb, it) {
            m = it;
            loc = get_locator_behind_nat(m);

            /* If found a locator behind NAT, send
             * Encapsulated Map Register */
            if (loc != NULL) {
                leinf  = loc->extended_info;
                nat_rtr = &leinf->rtr_locators_list->locator->address;
                /* ECM map register only sent to the first Map Server */
                nemrn->nonce[nemrn->retransmits] = nonce_build_time();
                build_and_send_ecm_map_reg(xtr, m, nat_rtr,
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
        exit_cleanup();
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
rloc_probing(lisp_xtr_t *xtr, mapping_t *m, locator_t *loc)
{
    rmt_locator_extended_info_t *einf = NULL;
    nonces_list_t *nonces = NULL;
    lisp_addr_t *deid, empty, *drloc;
    lbuf_t *b;
    glist_t *rlocs;
    lmtimer_t *t;
    void *hdr, *arg;


    deid = mapping_eid(m);

    if (xtr->probe_interval == 0) {
        LMLOG(DBG_2, "rloc_probing: No RLOC Probing for %s cache entry. "
                "RLOC Probing disabled",  lisp_addr_to_char(deid));
        return (GOOD);
    }

    drloc = lisp_addr_get_fwd_ip_addr(locator_addr(loc), ctrl_rlocs(xtr->super.ctrl));
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

        hdr = lisp_msg_hdr(b);
        nonces->nonce[nonces->retransmits] = nonce_build_time() ;
        MREQ_NONCE(hdr) = nonces->nonce[nonces->retransmits];
        MREQ_RLOC_PROBE(hdr) = 1;

        if (nonces->retransmits > 0) {
            LMLOG(DBG_1,"Retry Map-Request Probe for locator %s and "
                    "EID: %s (%d retries)", lisp_addr_to_char(drloc),
                    lisp_addr_to_char(deid), nonces->retransmits);
        } else {
            LMLOG(DBG_1,"Map-Request Probe for locator %s and "
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
            LMLOG(DBG_1,"rloc_probing: No Map-Reply Probe received for locator"
                    " %s and EID: %s -> Locator state changes to DOWN",
                    lisp_addr_to_char(drloc), lisp_addr_to_char(deid));

            /* [re]Calculate balancing loc vectors  if it has been a change
             * of status*/
            mapping_compute_balancing_vectors(m);
        }

        free(einf->rloc_probing_nonces);
        einf->rloc_probing_nonces = NULL;

        /* Reprogram time for next probe interval */
        lmtimer_start(t, xtr->probe_interval, rloc_probing_cb, xtr, arg);
        LMLOG(DBG_2,"Reprogramed RLOC probing of the locator %s of the EID %s "
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
    timer_rloc_probe_argument *arg;

    einf = loc->extended_info;

    /* create timer and arg if needed*/
    if (!einf->probe_timer) {
        einf->probe_timer = lmtimer_create(RLOC_PROBING_TIMER);
        arg = xzalloc(sizeof(timer_rloc_probe_argument));
        LMLOG(DBG_2,"Programming probing of EID's %s locator %s (%d seconds)",
                    lisp_addr_to_char(mapping_eid(m)),
                    lisp_addr_to_char(locator_addr(loc)), time);
    } else {
        arg = einf->probe_timer->cb_argument;
        LMLOG(DBG_2,"Reprogramming probing of EID's %s locator %s (%d seconds)",
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
    glist_for_each_entry(it_list, mapping_locators(map)){
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
    glist_for_each_entry(it_list, mapping_locators(xtr->petrs->mapping)){
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
    mcache_entry_t *mce = mcache_entry_new();
    mcache_entry_init(mce, m);
    if (mcache_add_entry(xtr->map_cache, mapping_eid(m), mce) != GOOD) {
        return(BAD);
    }

    mcache_entry_set_active(mce, ACTIVE);
    /* post installment operations */
    mapping_compute_balancing_vectors(m);

    /* Reprogramming timers */
    mc_entry_start_expiration_timer(xtr, mce);

    /* RLOC probing timer */
    program_mapping_rloc_probing(xtr, m);

    return(GOOD);
}

int
tr_mcache_add_static_mapping(lisp_xtr_t *xtr, mapping_t *m)
{
    mcache_entry_t *mce = mcache_entry_new();
    mcache_entry_init_static(mce, m);

    if (mcache_add_entry(xtr->map_cache, mapping_eid(m), mce) != GOOD) {
        return(BAD);
    }

    program_mapping_rloc_probing(xtr, m);

    return(GOOD);
}

int
tr_mcache_remove_mapping(lisp_xtr_t *xtr, lisp_addr_t *laddr)
{
    void *data;

    data = mcache_remove_entry(xtr->map_cache, laddr);
    mcache_entry_del(data);
    mcache_dump_db(xtr->map_cache, DBG_3);

    return (GOOD);
}

mapping_t *
tr_mcache_lookup_mapping(lisp_xtr_t *xtr, lisp_addr_t *laddr)
{

    mcache_entry_t *mce;

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
    mcache_entry_t *mce;

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
    lisp_xtr_t      *xtr                = lisp_xtr_cast(dev);
    iface_locators  *if_loct            = NULL;
    glist_t         *loct_list          = NULL;
    glist_t         *locators           = NULL;
    locator_t       *locator            = NULL;
    mapping_t       *mapping            = NULL;
    int             afi                 = AF_UNSPEC;
    glist_entry_t   *it                 = NULL;
    glist_entry_t   *it_aux             = NULL;
    glist_entry_t   *it_m               = NULL;
    lisp_addr_t     **prev_addr              = NULL;

    if_loct = (iface_locators *)shash_lookup(xtr->iface_locators_table,iface_name);
    if (if_loct  == NULL){
        LMLOG(DBG_2, "xtr_if_event: Iface %s not found in the list of ifaces for xTR device",
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
            LMLOG(DBG_2, "xtr_if_event: Afi of the new address not known");
            free(iface_name);
            lisp_addr_del(old_addr);
            lisp_addr_del(new_addr);
            return (BAD);
        }
            glist_for_each_entry_safe(it,it_aux,locators){
            locator = (locator_t *)glist_entry_data(it);
            if (lisp_addr_is_no_addr(locator_addr(locator))==TRUE){
                /* If locator was not active, activate it */
                mapping = get_mapping_containing_locator_ptr(xtr->local_mdb,locator);
                if(mapping == NULL){
                    continue;
                }
                /* Check if exists an active locator with the same address.
                 * If it exists, remove not activated locator: Duplicated */
                if (mapping_get_loct_with_addr(mapping,new_addr) != NULL){
                    LMLOG(DBG_2, "xtr_if_event: A non active locator is duplicated. Removing it");
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
        glist_for_each_entry(it_m, if_loct->mappings){
            mapping = (mapping_t *)glist_entry_data(it_m);
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
        /* Recalculate balancing vectors */
        glist_for_each_entry(it_m, if_loct->mappings){
            mapping = (mapping_t *)glist_entry_data(it_m);
            mapping_compute_balancing_vectors(mapping);
        }
    }
    if (xtr->super.mode == RTR_MODE && xtr->all_locs_map) {
        mapping_compute_balancing_vectors(xtr->all_locs_map);
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
        lmlog(LISP_LOG_DEBUG_1, "Info-Request/Info-Reply message");
        if (!process_info_nat_msg(lbuf_data(msg), usk.ra)) {
            return (BAD);
        }
        return (GOOD);*/
        break;
    default:
        LMLOG(DBG_1, "xTR: Unidentified type (%d) control message received",
                type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        LMLOG(DBG_1,"xTR: Failed to process LISP control message");
        return (BAD);
    } else {
        LMLOG(DBG_3, "xTR: Completed processing of LISP control message");
        return (ret);
    }
}

void map_server_elt_del (map_server_elt *map_server)
{
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
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    lisp_addr_t	addr;

    LMLOG(DBG_1, "Creating map cache and local mapping database");

    /* set up databases */
    xtr->local_mdb = local_map_db_new();
    xtr->map_cache = mcache_new();
    xtr->map_servers = glist_new_managed((glist_del_fct)map_server_elt_del);
    xtr->map_resolvers = glist_new_managed((glist_del_fct)lisp_addr_del);
    xtr->pitrs = glist_new_managed((glist_del_fct)lisp_addr_del);
    xtr->petrs = mcache_entry_new();
    lisp_addr_ip_from_char("0.0.0.0", &addr);
    mcache_entry_init_static(xtr->petrs, mapping_init_remote(&addr));

    if (!xtr->local_mdb || !xtr->map_cache) {
        return(BAD);
    }

    //xtr->iface_locators_table = shash_new();
    xtr->iface_locators_table = shash_new_managed((h_key_del_fct)iface_locators_del);

    LMLOG(DBG_1, "Finished Constructing xTR");

    return(GOOD);
}

static void
xtr_ctrl_destruct(lisp_ctrl_dev_t *dev)
{
    mapping_t  *mapping     = NULL;
    void       *it          = NULL;
    lisp_xtr_t *xtr         = lisp_xtr_cast(dev);


    local_map_db_foreach_entry(xtr->local_mdb, it) {
        mapping = (mapping_t *)it;
        ctrl_unregister_eid_prefix(dev,mapping_eid(mapping));
    } local_map_db_foreach_end;

    mcache_del(xtr->map_cache);
    local_map_db_del(xtr->local_mdb);
    glist_destroy(xtr->map_resolvers);
    glist_destroy(xtr->pitrs);
    glist_destroy(xtr->map_servers);
    mapping_del(xtr->all_locs_map);
    lmtimer_stop(xtr->smr_timer);
    LMLOG(DBG_1,"xTR device destroyed");
}

static void
xtr_ctrl_dealloc(lisp_ctrl_dev_t *dev) {
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    free(xtr);
    LMLOG(DBG_1, "Freed xTR ...");
}


static void
xtr_run(lisp_xtr_t *xtr)
{
    mapping_t   *mapping = NULL;
    void        *it      = NULL;

    if (xtr->super.mode == MN_MODE){
        LMLOG(DBG_1, "\nStarting xTR MN ...\n");
    }
    if (xtr->super.mode == xTR_MODE){
        LMLOG(DBG_1, "\nStarting xTR ...\n");
    }

    if (glist_size(xtr->map_servers) == 0) {
        LMLOG(LCRIT, "No Map Server configured. Exiting...");
        exit_cleanup();
    }

    if (glist_size(xtr->map_resolvers) == 0) {
        LMLOG(LCRIT, "No Map Resolver configured. Exiting...");
        exit_cleanup();
    }

    if (xtr->petrs == NULL) {
        LMLOG(LWRN, "No Proxy-ETR defined. Packets to non-LISP destinations "
                "will be forwarded natively (no LISP encapsulation). This "
                "may prevent mobility in some scenarios.");
        sleep(3);
    } else {
        mapping_compute_balancing_vectors(xtr->petrs->mapping);
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

    LMLOG(DBG_1, "****** Summary of the xTR configuration ******");
    local_map_db_dump(xtr->local_mdb, DBG_1);
    mcache_dump_db(xtr->map_cache, DBG_1);

    map_servers_dump(xtr, DBG_1);
    LMLOG(DBG_1, "************* %13s ***************", "Map Resolvers");
        glist_dump(xtr->map_resolvers, (glist_to_char_fct)lisp_addr_to_char, DBG_1);
    proxy_etrs_dump(xtr, DBG_1);
    LMLOG(DBG_1, "************* %13s ***************", "Proxy-ITRs");
    glist_dump(xtr->pitrs, (glist_to_char_fct)lisp_addr_to_char, DBG_1);

    /* Register EIDs prefixes to control */
    local_map_db_foreach_entry(xtr->local_mdb, it) {
        mapping = it;
        ctrl_register_eid_prefix(&(xtr->super),mapping_eid(mapping));
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
    LMLOG(LINF, "\nStarting RTR ...\n");


    if (glist_size(xtr->map_resolvers) == 0) {
        LMLOG(LCRIT, "No Map Resolver configured. Exiting...");
        exit_cleanup();
    }

    if (xtr->all_locs_map) {
    }

    LMLOG(LINF, "****** Summary of the configuration ******");
    local_map_db_dump(xtr->local_mdb, LINF);
    mcache_dump_db(xtr->map_cache, LINF);
    if (xtr->all_locs_map) {
        LMLOG(LINF, "Active interfaces status");
        mapping_compute_balancing_vectors(xtr->all_locs_map);
        LMLOG(LINF, "%s", mapping_to_char(xtr->all_locs_map));
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
	glist_for_each_entry(it_list, mapping_locators(xtr->petrs->mapping)){
		loct_list = (glist_t*)glist_entry_data(it_list);
		glist_for_each_entry(it_loct,loct_list){
			locator = (locator_t *)glist_entry_data(it_loct);
			locator_to_char(locator);
		}

	}
}

static void
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

/* Select 'locp' according to the priority and weight. */
static int
select_rloc_from_bvec(balancing_locators_vecs *blv, packet_tuple_t *tuple,
        locator_t **locp)
{
    int vec_len = 0;
    uint32_t pos = 0;
    uint32_t hash = 0;
    locator_t **loc_vec = NULL;

    if (!blv) {
        return(BAD);
    }

    if (blv->balancing_locators_vec != NULL) {
        loc_vec = blv->balancing_locators_vec;
        vec_len = blv->locators_vec_length;
    } else if (blv->v6_balancing_locators_vec != NULL) {
        loc_vec = blv->v6_balancing_locators_vec;
        vec_len = blv->v6_locators_vec_length;
    } else {
        loc_vec = blv->v4_balancing_locators_vec;
        vec_len = blv->v4_locators_vec_length;
    }
    if (vec_len == 0) {
        LMLOG(DBG_3, "select_rloc_from_bvec: No locators available to send"
                " packet");
        return (BAD);
    }
    hash = pkt_tuple_hash(tuple);
    if (hash == 0) {
        LMLOG(DBG_1, "select_rloc_from_bvec: Couldn't hash tuple to select"
                " the rloc. Using the default rloc");
    }

    /* if hash = 0 then pos = 0 */
    pos = hash % vec_len;
    *locp = loc_vec[pos];

    LMLOG(DBG_3, "select_rloc_from_bvec: src RLOC: %s",
            lisp_addr_to_char(locator_addr(*locp)));

    return (GOOD);
}

/* Select the source and destination RLOC according to the priority and weight.
 * The destination RLOC is selected according to the AFI of the selected source
 * RLOC */
static int
select_locs_from_maps(mapping_t *smap, mapping_t *dmap,
        packet_tuple_t *tuple, locator_t **slocp, locator_t **dlocp)
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

    if (!smap || !dmap || (mapping_locator_count(dmap) == 0)) {
        return(BAD);
    }

    leinf = smap->extended_info;
    reinf = dmap->extended_info;
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
            LMLOG(DBG_2, "select_locs_from_maps: No SRC locators "
                    "available");
        }else if (dst_blv->v4_balancing_locators_vec == NULL
                && dst_blv->v6_balancing_locators_vec == NULL) {
            LMLOG(DBG_2, "select_locs_from_maps: No DST locators "
                    "available");
        } else {
            LMLOG(DBG_2, "select_locs_from_maps: Source and "
                    "destination RLOCs have different afi");
        }
        return (BAD);
    }

    hash = pkt_tuple_hash(tuple);
    if (hash == 0) {
        LMLOG(DBG_1, "select_locs_from_maps: Couldn't get the hash of the tuple "
                "to select the rloc. Using the default rloc");
        //pos = hash%x_vec_len -> 0%x_vec_len = 0;
    }

    pos = hash % src_vec_len;
    *slocp = src_loc_vec[pos];
    loc_addr = locator_addr(*slocp);

    /* decide dst afi based on src afi*/
    lafi = lisp_addr_lafi(loc_addr);
    switch (lafi) {
    case LM_AFI_IP:
        afi = lisp_addr_ip_afi(loc_addr);
        break;
    case LM_AFI_LCAF:
        lcaf = lisp_addr_get_lcaf(loc_addr);
        switch (lcaf_addr_get_type(lcaf)) {
        case LCAF_EXPL_LOC_PATH:
        {
            /* the afi of the first node in the elp */
            elp_node_t *enode = glist_first_data(lcaf_elp_node_list(lcaf));
            afi = lisp_addr_ip_afi(enode->addr);
        }
            break;
        default:
            LMLOG(DBG_2, "select_locs_from_maps:"
                    " LCAF type %d not supported", lcaf_addr_get_type(lcaf));
            return (BAD);
        }
        break;
    default:
        LMLOG(DBG_2, "select_locs_from_maps: LISP addr afi %d not supported",
                lisp_addr_lafi(loc_addr));
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
        LMLOG(DBG_2, "select_locs_from_maps: Unknown IP AFI %d",
                lisp_addr_ip_afi(loc_addr));
        return (BAD);
    }

    pos = hash % dst_vec_len;
    *dlocp = dst_loc_vec[pos];

    LMLOG(DBG_3, "select_locs_from_maps: EID: %s -> %s, protocol: %d, "
            "port: %d -> %d\n  --> RLOC: %s -> %s",
            lisp_addr_to_char(mapping_eid(smap)),
            lisp_addr_to_char(mapping_eid(dmap)), tuple->protocol,
            tuple->src_port, tuple->dst_port,
            lisp_addr_to_char((*slocp)->addr),
            lisp_addr_to_char((*dlocp)->addr));

    return (GOOD);
}

static fwd_entry_t*
get_natt_forwarding_entry(lisp_xtr_t *xtr, packet_tuple_t *tuple) {
    locator_t *srloc = NULL;
    lcl_locator_extended_info_t *loc_leinf;
    fwd_entry_t *fwd_entry = NULL;
    mapping_t *smap = NULL;
    lcl_mapping_extended_info *map_leinf;
    balancing_locators_vecs *src_blv = NULL;


    /* If the packet doesn't have an EID source, forward it natively */
    smap = local_map_db_lookup_eid(xtr->local_mdb, &tuple->src_addr);
    if (!smap) {
        return(NULL);
    }

    map_leinf = smap->extended_info;
    src_blv = &map_leinf->outgoing_balancing_locators_vecs;

    if (select_rloc_from_bvec(src_blv, tuple, &srloc) != GOOD) {
        return (NULL);
    }

    loc_leinf = srloc->extended_info;

    if (!srloc || !loc_leinf || !loc_leinf->rtr_locators_list->locator) {
        LMLOG(DBG_2, "No RTR for the selected src locator (%s).",
                lisp_addr_to_char(srloc->addr));
        return (NULL);
    }

    fwd_entry = xzalloc(sizeof(fwd_entry_t));

    fwd_entry->srloc = srloc->addr;
    fwd_entry->drloc = &loc_leinf->rtr_locators_list->locator->address;
//    fwd_entry->out_socket = *(leinfo->out_socket);

    return (fwd_entry);
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
//        LMLOG(DBG_1, "get_locator_from_lcaf: Type % not supported!, ",
//                lcaf_addr_get_type(lcaf));
//        return (BAD);
//    }
//}

/* Used by ITRs to determine the src IP RLOC if the locator is
 * an LCAF */
static int
get_src_from_lcaf(lisp_xtr_t *xtr, lisp_addr_t *laddr, lisp_addr_t **src)
{
    lcaf_addr_t *lcaf = NULL;
    glist_entry_t *it_elp = NULL;
    glist_entry_t *it_rlocs = NULL;
    elp_node_t *elp_node = NULL;
    lisp_addr_t *addr;
    glist_t *rlocs;
    lcaf = lisp_addr_get_lcaf(laddr);
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_EXPL_LOC_PATH:

        /* lookup in the elp list the first RLOC to also pertain to the device */
        glist_for_each_entry(it_elp, lcaf_elp_node_list(lcaf)) {
            elp_node = (elp_node_t *)glist_entry_data(it_elp);
            rlocs = ctrl_rlocs_with_afi(xtr->super.ctrl,lisp_addr_ip_afi(elp_node->addr));

            glist_for_each_entry(it_rlocs, rlocs) {
                addr = glist_entry_data(it_rlocs);
                if (lisp_addr_cmp(addr, elp_node->addr) == 0) {
                    *src = elp_node->addr;
                    return (GOOD);
                }
            }
        }
        LMLOG(DBG_2, "get_src_from_lcaf: Not found any RLOC from the ELP belonging to the device: %s",
                lisp_addr_to_char(laddr));
        *src = NULL;
        return (BAD);
    default:
        *src = NULL;
        LMLOG(DBG_1, "get_src_from_lcaf: LCAF type %d not supported!, ",
                lcaf_addr_get_type(lcaf));
        return (BAD);
    }
    return (GOOD);
}

/* Used by ITRs to determine the destination IP RLOC if the locator is
 * an LCAF */
static int
get_dst_from_lcaf(lisp_xtr_t *xtr, lisp_addr_t *laddr, lisp_addr_t **dst)
{
    lcaf_addr_t *lcaf = NULL;
    glist_entry_t *it_elp = NULL;
    glist_entry_t *it_rlocs = NULL;
    elp_node_t *elp_node = NULL;
    elp_node_t *next_elp = NULL;
    lisp_addr_t *addr;
    glist_t *rlocs;

    lcaf = lisp_addr_get_lcaf(laddr);
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_EXPL_LOC_PATH:

        /* If the device is a MN or xTR. Destination is the first node */
        if (xtr->super.mode != RTR_MODE){
            elp_node = (elp_node_t *)glist_first_data(lcaf_elp_node_list(lcaf));
            *dst = elp_node->addr;
            return (GOOD);
        }
        /* lookup in the elp list the first RLOC to also pertain to the device */
        glist_for_each_entry(it_elp, lcaf_elp_node_list(lcaf)) {
            elp_node = (elp_node_t *)glist_entry_data(it_elp);
            rlocs = ctrl_rlocs_with_afi(xtr->super.ctrl,lisp_addr_ip_afi(elp_node->addr));
            glist_for_each_entry(it_rlocs, rlocs) {
                addr = glist_entry_data(it_rlocs);
                if (lisp_addr_cmp(addr, elp_node->addr) == 0) {
                    next_elp = glist_entry_data(glist_next(it_elp));
                    *dst = next_elp->addr;
                    return (GOOD);
                }
            }
        }
        LMLOG(DBG_2, "get_dst_from_lcaf: Not found any RLOC from the ELP belonging to the device: %s",
                lisp_addr_to_char(laddr));
        *dst = NULL;
        return (BAD);
    default:
        *dst = NULL;
        LMLOG(DBG_1, "get_dst_from_lcaf: LCAF type %d not supported!, ",
                lcaf_addr_get_type(lcaf));
        return (BAD);
    }
    return (GOOD);
}

static fwd_entry_t *
get_fwd_entry(lisp_xtr_t *xtr, packet_tuple_t *tuple)
{
    mcache_entry_t *mce;
    mapping_t *smap = NULL;
    mapping_t *dmap = NULL;
    locator_t *srloc = NULL;
    locator_t *drloc = NULL;
    fwd_entry_t *fe = NULL;
    int safi, dafi;

    fe = xzalloc(sizeof(fwd_entry_t));

    mce = mcache_lookup(xtr->map_cache, &tuple->dst_addr);

    if (!mce) {
        LMLOG(DBG_1, "No map cache for EID %s. Sending Map-Request!",
                lisp_addr_to_char(&tuple->dst_addr));
        handle_map_cache_miss(xtr, &tuple->dst_addr, &tuple->src_addr);
        return(fe);
    } else if (mce->active == NOT_ACTIVE) {
        LMLOG(DBG_3, "Already sent Map-Request for %s. Waiting for reply!",
                lisp_addr_to_char(&tuple->dst_addr));
        return(fe);
    }

    dmap = mcache_entry_mapping(mce);
    if (mapping_locator_count(dmap) == 0) {
        LMLOG(DBG_3, "Destination %s has a NEGATIVE mapping!",
                lisp_addr_to_char(&tuple->dst_addr));
        return(fe);
    }

    if (xtr->super.mode == xTR_MODE || xtr->super.mode == MN_MODE) {
        /* lookup local mapping for source EID */
        smap = local_map_db_lookup_eid(xtr->local_mdb, &tuple->src_addr);
    } else {
        smap = xtr->all_locs_map;
    }

    if (select_locs_from_maps(smap, dmap, tuple, &srloc, &drloc) != GOOD) {
        /* Try PETRs */
        if (!xtr->petrs) {
            LMLOG(DBG_3, "Trying to forward to PETR but none found ...");
            return (fe);
        }
        if ((select_locs_from_maps(smap, xtr->petrs->mapping, tuple,
                &srloc, &drloc)) != GOOD) {
            LMLOG(DBG_3, "No PETR compatible with local locators afi");
            return (fe);
        }
        LMLOG(DBG_3, "Forwarding packet to PeTR");
    }

    if (!srloc || !drloc) {
        LMLOG(DBG_2, "get_forwarding_entry: No valid source and destination "
                "RLOC pair");
        return(fe);
    }

    safi = lisp_addr_lafi(locator_addr(srloc));
    dafi = lisp_addr_lafi(locator_addr(drloc));

    if (safi == LM_AFI_IP) {
        fe->srloc = locator_addr(srloc);
    } else if (safi == LM_AFI_LCAF) {
        get_src_from_lcaf(xtr,locator_addr(srloc), &fe->srloc);
    }

    if (dafi == LM_AFI_IP) {
        fe->drloc = locator_addr(drloc);
    } else if (dafi == LM_AFI_LCAF) {
        get_dst_from_lcaf(xtr,locator_addr(drloc), &fe->drloc);
    }
    return (fe);
}


static fwd_entry_t *
tr_get_forwarding_entry(lisp_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    lisp_xtr_t *xtr;

    xtr = lisp_xtr_cast(dev);

    /* If we are behind a full NAT system, send the message directly to
     * the RTR */
    if (xtr->nat_aware && xtr->nat_status == FULL_NAT) {
        return(get_natt_forwarding_entry(xtr, tuple));
    } else {
        return(get_fwd_entry(xtr, tuple));
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
    glist_t     *locators   = NULL;
    locator_t   *locator    = NULL;
    mapping_t   *mapping    = NULL;
    void        *it         = NULL;

    locators = glist_new();

    local_map_db_foreach_entry(local_db, it) {
        mapping = (mapping_t *)it;
        locator = mapping_get_loct_with_addr(mapping, addr);
        if (locator != NULL){
            glist_add_tail(locator,locators);
        }
    } local_map_db_foreach_end;

    return (locators);
}

mapping_t *
get_mapping_containing_locator_ptr(
        local_map_db_t      *local_db,
        locator_t           *locator)
{
    mapping_t   *mapping        = NULL;
    void        *it             = NULL;
    local_map_db_foreach_entry(local_db, it) {
        mapping = (mapping_t *)it;
        if (mapping_has_locator(mapping, locator) == TRUE){
            return (mapping);
        }
    } local_map_db_foreach_end;
    LMLOG(DBG_2, "get_mapping_with_locator: No mapping has been found with locator %s",
            lisp_addr_to_char(locator_addr(locator)));
    return (NULL);
}



/*
 * Return the list of mappings that has experimented changes in their
 * locators. At the same time iface_locators status is reseted
 * @param xtr
 * @return glist_t with the list of modified mappings (mapping_t *)
 */
glist_t *get_mappings_to_smr(lisp_xtr_t *xtr)
{
    glist_t         *mappings_to_smr        = glist_new();
    glist_t         *iface_locators_list    = NULL;
    iface_locators  *if_loct                = NULL;
    glist_entry_t   *it                     = NULL;
    glist_entry_t   *it_loc                 = NULL;
    glist_t         *locators[2]            = {NULL,NULL};
    mapping_t       *mapping                = NULL;
    locator_t       *locator                = NULL;
    int             ctr;

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
                    mapping = get_mapping_containing_locator_ptr(xtr->local_mdb, locator);
                    if (mapping != NULL && glist_contain(mapping, mappings_to_smr) == FALSE){
                        glist_add(mapping, mappings_to_smr);
                    }
                }
            }
        }
    }
    return (mappings_to_smr);
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
    LMLOG (DBG_1,"get_map_resolver: No map resolver reachable");
    return (NULL);
}


