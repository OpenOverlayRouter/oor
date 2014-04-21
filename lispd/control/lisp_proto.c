/*
 * lisp_proto.c
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

#include "lisp_proto.h"
#include <defs.h>


/* Process a record from map-reply probe message */
static int
process_map_reply_probe(mapping_t *m, locator_t *probed, uint64_t nonce)
{
    lisp_addr_t *src_eid = NULL;
    locator_t *loc = NULL, *aux_loc = NULL;
    mapping_t *old_map = NULL, *pmap = NULL;
    locators_list_t *loc_list[2] = {NULL, NULL};
    rmt_locator_extended_info *rmt_ext_inf = NULL;
    int ctr = 0;

    src_eid = maping_eid(m);
    if (mapping_locator_count(m) > 0) {
        /* Lookup src EID in map cache */
        old_map = mcache_lookup_mapping(src_eid);
        if(!old_map) {
            lmlog(DBG_1, "Source EID %s couldn't be found in the map-cache",
                    lisp_addr_to_char(src_eid));
            return(BAD);
        }

        /* Find probed locator in mapping */
        loc = mapping_get_locator(old_map, locator_addr(probed));
        if (!loc){
            lmlog(DBG_2,"Probed locator %s not part of the the mapping %s",
                    lisp_addr_to_char(locator_addr(probed)),
                    lisp_addr_to_char(mapping_eid(old_map)));
            return (ERR_NO_EXIST);
        }

        /* Compare nonces */
        rmt_ext_inf = (rmt_locator_extended_info *)(loc->extended_info);
        if (!rmt_ext_inf || !rmt_ext_inf->rloc_probing_nonces) {
            lmlog(DBG_1, "Locator %s has no nonces!",
                    lisp_addr_to_char(locator_addr(loc)));
            return(BAD);
        }

        /* Check if the nonce of the message match with the one stored in the
         * structure of the locator */
        if ((nonce_check(rmt_ext_inf->rloc_probing_nonces, nonce)) == GOOD){
            free(rmt_ext_inf->rloc_probing_nonces);
            rmt_ext_inf->rloc_probing_nonces = NULL;
        }else{
            lmlog(DBG_1,"Nonce of Map-Reply Probe doesn't match nonce of the "
                    "Map-Request Probe. Discarding message ...");
            return (BAD);
        }

        lmlog(DBG_1," Successfully pobed RLOC %s of cache entry with EID %s",
                    lisp_addr_to_char(locator_addr(probed)),
                    lisp_addr_to_char(mapping_eid(old_map)));

    /* If negative probe map-reply, then the probe was for proxy-ETR (PETR) */
    } else {
        pmap = mcache_entry_mapping(proxy_etrs);
        if (proxy_etrs
            && lisp_addr_cmp(src_eid, mapping_eid(pmap)) == 0) {

            /* find locator */
            old_map = mcache_entry_mapping(proxy_etrs);
            loc_list[0] = pmap->head_v4_locators_list;
            loc_list[1] = pmap->head_v6_locators_list;
            for (ctr=0 ; ctr < 2 ; ctr++) {
                while (loc_list[ctr]!=NULL) {
                    aux_loc = loc_list[ctr]->locator;
                    rmt_ext_inf = (rmt_locator_extended_info *)(aux_loc->extended_info);
                    if ((nonce_check(rmt_ext_inf->rloc_probing_nonces,nonce)) == GOOD){
                        free (rmt_ext_inf->rloc_probing_nonces);
                        rmt_ext_inf->rloc_probing_nonces = NULL;
                        loc = aux_loc;
                        break;
                    }
                    loc_list[ctr] = loc_list[ctr]->next;
                }
                if (loc) {
                    break;
                }
            }
            if (!loc) {
                lmlog(DBG_1,"Nonce of Negative Map-Reply Probe doesn't match "
                        "any nonce of Proxy-ETR locators");
                return (BAD);
            }
        } else {
            lmlog(DBG_1,"Map-Reply Probe for %s has not been requested! "
                    "Discarding!", lisp_addr_to_char(src_eid));
            return (BAD);
        }

        lmlog(DBG_1,"Map-Reply probe reachability to the PETR with RLOC %s",
                    lisp_addr_to_char(locator_addr(loc)));
    }

    if (*(loc->state) == DOWN) {
        *(loc->state) = UP;

        lmlog(DBG_1," Locator %s state changed to UP",
                lisp_addr_to_char(locator_addr(loc)));

        /* [re]Calculate balancing locator vectors if status changed*/
        mapping_compute_balancing_vectors(old_map);
    }

    /* Reprogramming timers of rloc probing */
    rmt_ext_inf = (rmt_locator_extended_info *)(loc->extended_info);
    if (!rmt_ext_inf->probe_timer){
       lmlog(DBG_1," Map-Reply Probe was not requested! Discarding!");
       return (BAD);
    }

    start_timer(rmt_ext_inf->probe_timer, RLOC_PROBING_INTERVAL,
            (timer_callback)rloc_probing, rmt_ext_inf->probe_timer->cb_argument);

    if (mapping_locator_count(m) != 0 ){
        lmlog(DBG_2,"Reprogrammed probing of EID's %s locator %s (%d seconds)",
                lisp_addr_to_char(mapping_eid(old_map)),
                lisp_addr_to_char(locator_addr(loc)),
                RLOC_PROBING_INTERVAL);
    } else {
        lmlog(DBG_2,"Reprogrammed RLOC probing of PETR locator %s in %d seconds",
                lisp_addr_to_char(locator_addr(loc)), RLOC_PROBING_INTERVAL);
    }

    return (GOOD);

}


int
process_map_reply_msg(lisp_ctrl_dev_t *dev, lbuf_t *buf)
{
    void *mrep_hdr, *mrec_hdr, loc_hdr;
    int i, j, ret;
    glist_t locs;
    locator_t *loc, *probed;
    lisp_addr_t *seid;
    mapping_t *m;
    lbuf_t b;
    mcache_entry_t *mce;

    /* local copy */
    b = *buf;
    seid = lisp_addr_new();

    mrep_hdr = lisp_msg_pull_hdr(b);
    lmlog(DBG_1, "%s", lisp_msg_hdr_to_char(mrep_hdr));

    for (i = 0; i <= MREP_REC_COUNT(mrep_hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(b, m, probed) != GOOD) {
            goto err;
        }

        if (!MREP_RLOC_PROBE(mrep_hdr)) {
            /* Check if the map reply corresponds to a not active map cache */
            mce = lookup_nonce_in_no_active_map_caches(mapping_eid(m), MREP_NONCE(mrep_hdr));

            if (mce) {
                /* delete placeholder/dummy mapping and install the new one */
                mcache_del_mapping(mapping_eid(mcache_entry_mapping(mce)));

                /* DO NOT free mapping in this case */
                mcache_add_mapping(m);
            } else {

                /* the reply might be for an active mapping (SMR)*/
                mcache_update_entry(m, MREP_NONCE(mrep_hdr));
                mapping_del(m);
            }

            map_cache_dump_db(DBG_3);

            /*
            if (is_mrsignaling()) {
                mrsignaling_recv_ack();
                continue;
            } */
        } else {
            process_map_reply_probe(m, probed, MREP_NONCE(mrep_hdr));
            mapping_del(m);
        }

    }

    return(GOOD);


done:
    lisp_addr_del(seid);
    return(GOOD);
err:
    lisp_addr_del(seid);
    mapping_del(m);
    return(BAD);
}

int
process_map_notify(lisp_ctrl_dev_t *dev, lbuf_t *b)
{
    lisp_addr_t *eid;
    mapping_t *m, *local_mapping, *mcache_mapping;
    mcache_entry_t *mce;
    void *hdr;
    int i;
    locator_t *probed;

    hdr = lisp_msg_pull_hdr(b);

    /* TODO: compare nonces in all cases not only NAT */
    if (MNTF_XTR_ID_PRESENT(hdr) == TRUE) {
        if (nonce_check(nat_emr_nonce, MNTF_NONCE(hdr)) == GOOD){
            lmlog(DBG_3, "Correct nonce");
            /* Free nonce if authentication is ok */
        } else {
            lmlog(DBG_1, "No (Encapsulated) Map Register sent with nonce: %s",
                    nonce_to_char(MNTF_NONCE(hdr)));
            return (BAD);
        }
    }

    /* TODO: match eid/nonce to ms-key */
    if (lisp_msg_check_auth_field(b, map_servers->key) != GOOD) {
        lmlog(DBG_1, "Map-Notify message is invalid");
        program_map_register(dev, LISPD_INITIAL_EMR_TIMEOUT);
        return(BAD);
    }

    lisp_msg_pull_auth_field(b);

    for (i = 0; i <= MNTF_REC_COUNT(hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(b, m, probed) != GOOD) {
            mapping_del(m);
            return(BAD);
        }

        eid = mapping_eid(m);

        local_mapping = local_map_db_lookup_eid_exact(eid);
        if (!local_mapping) {
            lmlog(DBG_1, "Map-Notify confirms registration of UNKNOWN EID %s. "
                    "Dropping!", lisp_addr_to_char(mapping_eid(m)));
            continue;
        }

        lmlog(DBG_1, "Map-Notify message confirms correct registration of %s",
                lisp_addr_to_char(eid));

        /* === merge semantics on === */
        if (mapping_cmp(local_mapping, m) != 0 || lisp_addr_is_mc(eid)) {
            lmlog(DBG_1, "Merge-Semantics on, moving returned mapping to map-cache");

            /* Save the mapping returned by the map-notify in the mapping cache */
            mcache_mapping = mcache_lookup_mapping(eid);
            if (mcache_mapping && mapping_cmp(mcache_mapping, m) != 0) {
                /* UPDATED rlocs */
                lmlog(DBG_3, "Prefix %s already registered, updating locators",
                        lisp_addr_to_char(eid));
                mapping_update_locators(mcache_mapping,
                        m->head_v4_locators_list,
                        m->head_v6_locators_list,
                        m->locator_count);

                mapping_compute_balancing_vectors(mcache_mapping);
                mapping_program_rloc_probing(mcache_mapping);

                /* cheap hack to avoid cloning */
                m->head_v4_locators_list = NULL;
                m->head_v6_locators_list = NULL;
                mapping_del(m);
            } else if (!mcache_mapping) {
                /* FIRST registration */
                if (mcache_add_mapping(m) != GOOD) {
                    mapping_del(m);
                    return(BAD);
                }

                /* for MC initialize the JIB */
                if (lisp_addr_is_mc(eid)
                        && !mapping_get_re_data(mcache_entry_mapping(mce))) {
                    mapping_init_re_data(mcache_entry_mapping(mce));
                }
            }
        }

        free(nat_emr_nonce);
        nat_emr_nonce = NULL;
        program_map_register(dev, MAP_REGISTER_INTERVAL);

    }

    return(GOOD);
}

int
mcache_update_entry(mapping_t *m, uint64_t nonce) {

    mcache_entry_t *mce = NULL;
    mapping_t *old_map, *new_map;
    lisp_addr_t *eid;
    locators_list_t *llist[2];
    int ctr;

    eid = mapping_eid(m);

    /* Serch map cache entry exist*/
    mce = map_cache_lookup_exact(eid);
    if (!mce){
        lmlog(DBG_2,"No map cache entry for %s", lisp_addr_to_char(eid));
        return (BAD);
    }
    /* Check if map cache entry contains the nonce*/
    if (nonce_check(mce->nonces, nonce) == BAD) {
        lmlog(DBG_2, " Nonce doesn't match nonce of the Map-Request. "
                "Discarding message ...");
        return(BAD);
    } else {
        mcache_entry_destroy_nonces(mce);
    }

    lmlog(DBG_2, "Mapping with EID %s already exists, replacing!",
            lisp_addr_to_char(eid));
    old_map = mcache_entry_mapping(mce);
    mapping_del(old_map);

    mcache_entry_set_mapping(mce, mapping_clone(m));
    new_map = mcache_entry_mapping(mce);

    mapping_compute_balancing_vectors(new_map);

    /* Reprogramming timers */
    map_cache_entry_start_expiration_timer(mce);

    /* RLOC probing timer */
    mapping_program_rloc_probing(new_map);

    return (GOOD);
}

int
send_map_request_to_mr(lisp_ctrl_dev_t *dev, lbuf_t *b, uconn_t *uc)
{
    int afi = lisp_addr_ip_afi(&uc->ra);
    lisp_addr_copy(uc->ra, dev->tr_class->get_map_resolver(dev));
    lisp_addr_copy(uc->la, dev->tr_class->get_default_rloc(dev, afi));
    uc->rp = LISP_CONTROL_PORT;
    uc->lp = LISP_CONTROL_PORT;

    if (send_msg(dev, b, uc) != GOOD) {
        lmlog(DBG_1,"Couldn't send Map-Request!");
    }

    return(GOOD);
}

static int
build_and_send_smr_mreq(lisp_ctrl_dev_t *dev, mapping_t *m, lisp_addr_t *dst)
{
    lbuf_t *b;
    void *hdr;
    uconn_t uc;
    int ret;
    lisp_addr_t *src;

    b = lisp_msg_create(LISP_MAP_REQUEST);
    hdr = lisp_msg_hdr(b);

    MREQ_SMR(hdr) = 1;
    lisp_msg_put_mapping(b, m, NULL);

    src = dev->tr_class->get_default_rloc(dev, lisp_addr_ip_afi(dst));
    if (!src) {
        lmlog(DBG_1, "No compatible RLOC was found to send SMR Map-Request "
                "for %s", lisp_addr_to_char(mapping_eid(m)));
        return(BAD);
    }

    lisp_addr_copy(&uc->ra, dst);
    lisp_addr_copy(&uc->la, src);
    uc->rp = LISP_CONTROL_PORT;
    uc->lp = LISP_CONTROL_PORT;

    ret = send_msg(dev, b, &uc);
    lisp_msg_destroy(b);

    if (ret != GOOD) {
        return(BAD);
    }
    return(GOOD);
}

static int
send_all_smr_cb(timer *t, void *arg)
{
    timer_arg_t *ta = arg;
    send_all_smr(ta->dev);
    return(GOOD);
}

/* Send a solicit map request for each rloc of all eids in the map cache
 * database */
static void
send_all_smr(lisp_ctrl_dev_t *dev)
{
    locators_list_t *loc_lists[2] = {NULL, NULL};
    mcache_entry_t *mce = NULL;
    locators_list_t *lit = NULL;
    locator_t *loc = NULL;
    mapping_t **mlist = NULL;
    lisp_addr_list_t *pitr_elt = NULL;
    lisp_addr_t *eid = NULL;
    int mcount = 0;
    int i, j, nb_mappings;



    lmlog(DBG_2,"*** Init SMR notification ***");

    /* Get a list of mappings that require smrs */
    nb_mappings = local_map_db_n_mappings(local_mdb);
    if (!(mlist = calloc(1, nb_mappings*sizeof(mapping_t *)))) {
        lmlog(LWRN, "ctrl_dev_send_smr: Unable to allocate memory: %s",
                strerror(errno));
        return;
    }

    mlist = ctrl_get_mappings_to_smr(dev->ctrl, mlist, &mcount);

    /* Send map register and SMR request for each mapping */
    for (i = 0; i < mcount; i++) {
        /* Send map register for all mappings */
        if (nat_aware == FALSE || nat_status == NO_NAT) {
            build_and_send_map_register_msg(mlist[i]);
        }else if (nat_status != UNKNOWN){
            /* TODO : We suppose one EID and one interface.
             * To be modified when multiple elements */
            map_register_process();
        }

        eid = mapping_eid(mlist[i]);

        lmlog(DBG_1, "Start SMR for local EID %s", lisp_addr_to_char(eid));

        /* For each map cache entry with same afi as local EID mapping */

        if (lisp_addr_afi(eid) == LM_AFI_IP ) {
            lmlog(DBG_3, "init_smr: SMR request for %s. Shouldn't receive SMR "
                    "for IP in mapping?!", lisp_addr_to_char(eid));
        } else if (lisp_addr_afi(eid) != LM_AFI_IPPREF) {
            lmlog(DBG_3, "init_smr: SMR request for %s. SMR supported only for "
                    "IP-prefixes for now!",  lisp_addr_to_char(eid));
            continue;
        }

        /* no SMRs for now for multicast */
        if (lisp_addr_is_mc(eid))
            continue;


        /* TODO: spec says SMRs should be sent only to peer ITRs that sent us
         * traffic in the last minute. Should change this in the future*/
        /* XXX: works ONLY with IP */
        mcache_foreach_active_entry_in_ip_eid_db(eid, mce) {
            loc_lists[0] = mce->mapping->head_v4_locators_list;
            loc_lists[1] = mce->mapping->head_v6_locators_list;
            for (j = 0; j < 2; j++) {
                if (loc_lists[j]) {
                    lit = loc_lists[j];
                    while (lit) {
                        loc = lit->locator;
                        if (build_and_send_smr_mreq(dev, mce->mapping,
                                locator_addr(loc)) == GOOD) {
                            lmlog(DBG_1, "  SMR'ing RLOC %s from EID %s",
                                    lisp_addr_to_char(locator_addr(loc)),
                                    lisp_addr_to_char(eid));
                        }

                        lit = lit->next;
                    }
                }
            }
        } mcache_foreach_active_entry_in_ip_eid_db_end;

        /* SMR proxy-itr */
        pitr_elt = proxy_itrs;

        while (pitr_elt) {
            if (build_and_send_smr_mreq(dev, mlist[i], pitr_elt->address)
                    == GOOD) {
                lmlog(DBG_1, "  SMR'ing Proxy ITR %s for EID %s",
                        lisp_addr_to_char(pitr_elt->address),
                        lisp_addr_to_char(eid));
            } else {
                lmlog(DBG_1, "  Coudn't SMR Proxy ITR %s for EID %s",
                        lisp_addr_to_char(pitr_elt->address),
                        lisp_addr_to_char(eid));
            }
            pitr_elt = pitr_elt->next;
        }

    }

    free (mlist);
    lmlog(DBG_2,"*** Finish SMR notification ***");
}

int
program_smr(lisp_ctrl_dev_t *dev, int time) {
    timer *t;
    timer_arg_t *arg;
    t = dev->tr_class->smr_timer(dev);

    arg->dev = dev;
    start_timer(t, LISPD_SMR_TIMEOUT, send_all_smr_cb, arg);
    return(GOOD);
}


static int
smr_invoked_map_request_cb(timer *t, void *arg)
{
    return(send_smr_invoked_map_request(arg));
}

int
send_smr_invoked_map_request(lisp_ctrl_dev_t *dev, mcache_entry_t *mce)
{
    struct lbuf *mr;
    void *mr_hdr;
    uconn_t uc;
    nonces_list_t *nonces;
    mapping_t *m;
    lisp_addr_t *eid, empty;
    timer_arg_t *arg;
    timer *t;

    m = mcache_entry_mapping(mce);
    eid = mapping_eid(m);
    lisp_addr_set_afi(&empty, LM_AFI_NO_ADDR);

    /* Sanity Check */
    if (!nonces) {
        mcache_entry_init_nonces(mce);
        if (!(nonces = mcache_entry_nonces(mce))) {
            lmlog(LWRN, "send_smr_invoked_map_request: Unable to allocate"
                    " memory for nonces.");
            return (BAD);
        }
    }

    if (nonces->retransmits - 1 < LISPD_MAX_SMR_RETRANSMIT) {
        lmlog(DBG_1,"SMR: Map-Request for EID: %s (%d retries)",
                lisp_addr_to_char(eid), nonces->retransmits);

        /* build Map-Request */
        mr = lisp_msg_create(LISP_MAP_REQUEST);

        /* no source EID and mapping, so put default control rlocs */
        lisp_msg_put_addr(mr, &empty);
        lisp_msg_put_itr_rlocs(mr, dev->tr_class->get_default_rlocs(dev));
        lisp_msg_put_eid_rec(mr, mapping_eid(m));

        mr_hdr = lisp_msg_hdr(mr);
        MREQ_SMR_INVOKED(mr_hdr) = 1;
        MREQ_NONCE(mr_hdr) = nonces->nonce[nonces->retransmits];

        lisp_addr_copy(&uc.la, dev->tr_class->get_main_eid(dev));
        lisp_addr_copy(&uc.ra, eid);
        uc.lp = LISP_CONTROL_PORT;
        uc.rp = LISP_CONTROL_PORT;
        if (send_map_request_to_mr(dev, mr, &uc) != GOOD) {
            return(BAD);
        }

        /* init or delete and init, if needed, the timer */
        t = mcache_entry_init_smr_inv_timer(mce);
        arg = mcache_entry_smr_inv_timer_arg(mce);
        *arg = (timer_arg_t){dev, mce};

        start_timer(t, LISPD_INITIAL_SMR_TIMEOUT,
                smr_invoked_map_request_cb, arg);
        nonces->retransmits ++;

    } else {
        mcache_entry_stop_smr_inv_timer(mce);
        lmlog(DBG_1,"SMR: No Map Reply for EID %s. Stopping ...",
                lisp_addr_to_char(eid));
    }
    return (GOOD);

}


/* build and send generic map-register with one record */
static int
build_and_send_map_reg(lisp_ctrl_dev_t *dev, mapping_t *m, char *key,
        lisp_key_type_t keyid)
{
    lbuf_t *b;
    void *hdr;

    b = lisp_msg_create(LISP_MAP_REGISTER);

    if (lisp_msg_put_empty_auth_record(*b, keyid) != GOOD) {
        return(BAD);
    }
    if (lisp_msg_put_mapping(b, m) != GOOD) {
        return(BAD);
    }
    if (lisp_msg_fill_auth_data(b, key, keyid) != GOOD) {
        return(BAD);
    }

    hdr = lisp_msg_hdr(b);
    /* XXX Quick hack */
    /* Cisco IOS RTR implementation drops Data-Map-Notify if ECM Map Register
     * nonce = 0 */
    MREG_NONCE(hdr) = nonce_build((unsigned int) time(NULL));

    send_msg(dev, b);
    lisp_msg_destroy(b);
    return(GOOD);
}

int
handle_map_cache_miss(lisp_ctrl_dev_t *dev, lisp_addr_t *requested_eid,
        lisp_addr_t *src_eid)
{
    mcache_entry_t *mce = NULL;
    mapping_t *m;

    /* install temporary, NOT active, mapping in map_cache
     * TODO: should also build a nonce hash table for faster
     *       nonce lookups*/
    m = mapping_init_remote(requested_eid);
    mce = mcache_entry_init(m);
    if (map_cache_add_entry(mce) != GOOD) {
        lmlog(LWRN, "Couln't install temporary map cache entry for %s!",
                lisp_addr_to_char(requested_eid));
        return(BAD);
    }

    if (src_eid) {
        mcache_entry_set_requester(mce, lisp_addr_clone(src_eid));
    } else {
        mcache_entry_set_requester(mce, NULL);
    }
    return(send_map_request_retry(dev, mce));
}

static int
send_map_request_retry_cb(timer *t, void *arg) {
    timer_arg_t *ta = arg;
    int ret;

    free(ta);
    ret = send_map_request_retry(ta->dev, ta->data);
    return(ret);
}


/* Sends a Map-Request for EID in 'mce' and sets-up a retry timer */
int
send_map_request_retry(lisp_ctrl_dev_t *dev, mcache_entry_t *mce)
{
    timer *t;
    nonces_list_t *nonces;
    mapping_t *m;
    lisp_addr_t *eid;
    uconn_t uc;
    lbuf_t *b;
    void *mr_hdr;
    timer_arg_t *arg;

    nonces = mcache_entry_nonces(mce);
    m = mcache_entry_mapping(mce);
    eid = mapping_eid(m);

    if (!nonces) {
        mcache_entry_init_nonces(mce);
        if (!(nonces = mcache_entry_nonces(mce))) {
            lmlog(LWRN, "Send_map_request_miss: Unable to allocate memory for "
                    "nonces.");
            return (BAD);
        }
    }

    if (nonces->retransmits - 1 < map_request_retries) {
        if (nonces->retransmits > 0) {
            lmlog(DBG_1, "Retransmiting Map Request for EID: %s (%d retries)",
                    lisp_addr_to_char(eid), nonces->retransmits);
        }

        /* build Map-Request */
        b = lisp_msg_create(LISP_MAP_REQUEST);

        lisp_msg_put_addr(b, eid);
        lisp_msg_put_itr_rlocs(b, dev->tr_class->get_default_rlocs(dev));
        lisp_msg_put_eid_rec(b, mapping_eid(m));

        mr_hdr = lisp_msg_hdr(b);
        MREQ_NONCE(mr_hdr) = nonces->nonce[nonces->retransmits];

        /* udp connection parameters (inner headers) */
        lisp_addr_copy(&uc.la, mcache_entry_requester(mce));
        lisp_addr_copy(&uc.ra, eid);
        uc.lp = LISP_CONTROL_PORT;
        uc.rp = LISP_CONTROL_PORT;

        /* send to ctrl */
        send_map_request_to_mr(dev, b, uc);

        /* prepare callback */
        /* init or delete and init, if needed, the timer */
        t = mcache_entry_init_req_retry_timer(mce);
        arg = mcache_entry_req_retry_timer_arg(mce);
        *arg = (timer_arg_t){dev, mce};

        start_timer(t, LISPD_INITIAL_SMR_TIMEOUT,
                send_map_request_retry_cb, arg);

        nonces->retransmits++;

        lisp_msg_destroy(b);

    } else {
        lmlog(DBG_1, "No Map-Reply for EID %s after %d retries. Aborting!",
                lisp_addr_to_char(eid), nonces->retransmits - 1);
        mcache_del_mapping(eid);
    }

    return(GOOD);
}


static int
map_register_cb(timer *t, void *arg)
{
    return(map_register_process(arg));
}

int
program_map_register(lisp_ctrl_dev_t *dev, int time) {
    timer *t = dev->tr_class->map_register_timer(dev);

    /* Configure timer to send the next map register. */
    start_timer(t, time, map_register_cb, dev);
    lmlog(DBG_1, "(Re)programmed Map-Register process in %d seconds", time);
    return(GOOD);
}



static int
map_register_process_default(lisp_ctrl_dev_t *dev)
{
    mapping_t *m;
    void *it = NULL;
    lbuf_t *mreg;
    lisp_key_type_t keyid = HMAC_SHA_1_96;

    /* TODO
     * - configurable keyid
     * - multiple MSes
     */

    local_map_db_foreach_entry(it) {
        m = it;
        if (m->locator_count != 0) {
            err = build_and_send_map_reg(dev, &mreg, m,
                    map_servers->key, keyid);
            if (err != GOOD) {
                lmlog(LERR, "Coudn't send Map-Register for EID  %s!",
                        lisp_addr_to_char(mapping_eid(m)));
            }
        }
    } local_map_db_foreach_end;

    program_map_register(dev, MAP_REGISTER_INTERVAL);

    return(GOOD);
}

static int
map_register_process_encap(lisp_ctrl_dev_t *dev)
{
    mapping_t *m = NULL;
    locators_list_t *loc_list[2] = { NULL, NULL };
    locator_t *loc = NULL;
    lisp_addr_t *nat_rtr = NULL;
    int next_timer_time = 0;
    int ctr1 = 0;
    void *it = NULL;
    nonces_list_t *nemrn;

    nemrn = dev->tr_class->nat_emr_nonce(dev);
    if (!nemrn) {
        lmlog(LWRN,"map_register_process_encap: nonces unallocated!"
                " Aborting!");
        exit_cleanup();
    }

    if (nemrn->retransmits <= LISPD_MAX_RETRANSMITS) {

        if (nemrn->retransmits > 0) {
            lmlog(DBG_1,"No Map Notify received. Retransmitting encapsulated "
                    "map register.");
        }

        local_map_db_foreach_entry(it) {
            m = it;
            if (m->locator_count != 0) {

                /* Find the locator behind NAT */
                loc_list[0] = m->head_v4_locators_list;
                loc_list[1] = m->head_v6_locators_list;
                for (ctr1 = 0 ; ctr1 < 2 ; ctr1++) {
                    while (loc_list[ctr1] != NULL) {
                        loc = loc_list[ctr1]->locator;
                        if ((((lcl_locator_extended_info *)loc->extended_info)->rtr_locators_list) != NULL) {
                            break;
                        }
                        loc = NULL;
                        loc_list[ctr1] = loc_list[ctr1]->next;
                    }
                    if (loc != NULL){
                        break;
                    }
                }
                /* If found a locator behind NAT, send
                 * Encapsulated Map Register */
                if (loc != NULL) {
                    nat_rtr = &(((lcl_locator_extended_info *)loc->extended_info)->rtr_locators_list->locator->address);
                    /* ECM map register only sent to the first Map Server */
                    err = build_and_send_ecm_map_register(m,
                            map_servers,
                            nat_rtr,
                            default_ctrl_iface_v4,
                            &site_ID,
                            &xTR_ID,
                            &(nemrn->nonce[nemrn->retransmits]));
                    if (err != GOOD){
                        lmlog(LERR,"encapsulated_map_register_process: "
                                "Couldn't send encapsulated map register.");
                    }
                    nemrn->retransmits++;
                }else{
                    if (loc == NULL){
                        lmlog(LERR,"encapsulated_map_register_process: "
                                "Couldn't send encapsulated map register. "
                                "No RTR found");
                    }else{
                        lmlog(LERR,"encapsulated_map_register_process: "
                                "Couldn't send encapsulated map register. "
                                "No output interface found");
                    }
                }
                next_timer_time = LISPD_INITIAL_EMR_TIMEOUT;
            }
        } local_map_db_foreach_end;

    }else{
        free (nemrn);
        nemrn = NULL;
        lmlog(LERR,"encapsulated_map_register_process: Communication error "
                "between LISPmob and RTR/MS. Retry after %d seconds",
                MAP_REGISTER_INTERVAL);
        next_timer_time = MAP_REGISTER_INTERVAL;
    }

    program_map_register(dev, next_timer_time);

    return(GOOD);
}


int map_register_process(lisp_ctrl_dev_t *dev)
{
    int ret = 0;
    lispd_map_server_list_t *ms;
    int nat_aw, nat_stat;

    ms = dev->tr_class->get_map_servers(dev);
    if (!ms) {
        lmlog(LISP_LOG_CRIT, "map_register: No Map Servers configured!");
        exit_cleanup();
    }

    nat_aw = dev->tr_class->nat_aware(dev);
    nat_stat = dev->tr_class->nat_status(dev);

    if (nat_aw == TRUE) {
        /* NAT procedure instead of the standard one */
        /* TODO: if possible move info_request_process out */
        if (nat_stat == UNKNOWN) {
            ret = initial_info_request_process();
        }

        if (nat_stat == FULL_NAT) {
            ret = map_register_process_encap(dev);
        }
    }

    /* Standard Map-Register mechanism */
    if ((nat_aw == FALSE) || ((nat_aw == TRUE) && (nat_stat == NO_NAT))) {
        ret = map_register_process_default(dev);
    }

    return (ret);
}

