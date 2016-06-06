/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <unistd.h>

#include "../lib/iface_locators.h"
#include "../lib/sockets.h"
#include "../lib/mem_util.h"
#include "../lib/oor_log.h"
#include "../lib/timers_utils.h"
#include "../lib/util.h"
#include "lisp_xtr.h"

static int mc_entry_expiration_timer_cb(oor_timer_t *t);
static void mc_entry_start_expiration_timer(lisp_xtr_t *, mcache_entry_t *);
static int handle_locator_probe_reply(lisp_xtr_t *, mcache_entry_t *, lisp_addr_t *);
static int update_mcache_entry(lisp_xtr_t *, mapping_t *);
static int tr_recv_map_reply(lisp_xtr_t *, lbuf_t *, uconn_t *);
static int tr_reply_to_smr(lisp_xtr_t *xtr, lisp_addr_t *src_eid, lisp_addr_t *req_eid);
static int tr_recv_map_request(lisp_xtr_t *, lbuf_t *, uconn_t *);
static int tr_recv_map_notify(lisp_xtr_t *, lbuf_t *);
static int tr_recv_info_nat(lisp_xtr_t *xtr, lbuf_t *buf, uconn_t *uc);
int tr_update_nat_info(lisp_xtr_t *xtr, map_local_entry_t *mle, locator_t *loct,
        glist_t *rtr_list);
void tr_update_fwd_info_rtrs(lisp_xtr_t *xtr);
glist_t *nat_select_rtrs(glist_t * rtr_list);

static glist_t *build_rloc_list(mapping_t *m);
static int build_and_send_smr_mreq(lisp_xtr_t *, mapping_t *, lisp_addr_t *,
        lisp_addr_t *);
static int build_and_send_smr_mreq_to_map(lisp_xtr_t *, mapping_t *,
        mapping_t *);
static int send_all_smr_cb(oor_timer_t *);
static void send_all_smr_and_reg(lisp_xtr_t *);
static int smr_invoked_map_request_cb(oor_timer_t *timer);
static int send_smr_invoked_map_request(lisp_xtr_t *xtr, lisp_addr_t *src_eid,
        mcache_entry_t *mce, uint64_t nonce);
static int program_smr(lisp_xtr_t *, int time);
static int send_map_request_retry_cb(oor_timer_t *timer);
static int build_and_send_encap_map_request(lisp_xtr_t *xtr, lisp_addr_t *src_eid,
        mcache_entry_t *mce, uint64_t nonce);
static int build_and_send_map_reg(lisp_xtr_t *, mapping_t *, map_server_elt *,
        uint64_t);
int program_map_register_for_mapping(lisp_xtr_t *xtr, map_local_entry_t *mle);
static int encap_map_register_cb(oor_timer_t *timer);
int program_encap_map_reg_of_loct_for_map(lisp_xtr_t *xtr, map_local_entry_t *mle,
        locator_t *src_loct);
static int rloc_probing(lisp_xtr_t *, mapping_t *, locator_t *loc, uint64_t nonce);
static void program_rloc_probing(lisp_xtr_t *, mcache_entry_t *, locator_t *, int);
static void program_mce_rloc_probing(lisp_xtr_t *, mcache_entry_t *);
static inline lisp_xtr_t *lisp_xtr_cast(oor_ctrl_dev_t *);
int map_reply_fill_uconn(lisp_xtr_t *xtr, glist_t *itr_rlocs, uconn_t *uc);

static void proxy_etrs_dump(lisp_xtr_t *, int log_level);

static fwd_info_t *tr_get_forwarding_entry(oor_ctrl_dev_t *,
        packet_tuple_t *);

glist_t *get_local_locators_with_address(local_map_db_t *local_db, lisp_addr_t *addr);
map_local_entry_t *get_map_loc_ent_containing_loct_ptr(local_map_db_t *local_db,
        locator_t *locator);
glist_t *get_map_local_entry_to_smr(lisp_xtr_t *xtr);
static lisp_addr_t * get_map_resolver(lisp_xtr_t *xtr);

static int mapping_has_elp_with_l_bit(mapping_t *map);
/* Funtions related to timer_rloc_probe_argument */
timer_rloc_probe_argument *timer_rloc_probe_argument_new_init(mcache_entry_t *mce,
        locator_t *locator);
int xtr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t status);
int xtr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name,
        lisp_addr_t *old_addr, lisp_addr_t *new_addr, uint8_t status);
int xtr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,
        lisp_addr_t *src_pref, lisp_addr_t *dst_pref, lisp_addr_t *gateway);
int xtr_iface_event_signaling(lisp_xtr_t * xtr, iface_locators * if_loct);

void timer_rloc_probe_argument_free(timer_rloc_probe_argument *timer_arg);
/* Funtions related to timer_map_req_argument */
timer_map_req_argument *timer_map_req_arg_new_init(mcache_entry_t *mce,
        lisp_addr_t *src_eid);
void timer_map_req_arg_free(timer_map_req_argument * timer_arg);
/* Funtions related to timer_map_reg_argument */
timer_map_reg_argument * timer_map_reg_argument_new_init(map_local_entry_t *mle,
        map_server_elt *ms);
void timer_map_reg_arg_free(timer_map_reg_argument * timer_arg);
timer_encap_map_reg_argument *timer_encap_map_reg_argument_new_init(map_local_entry_t *mle,
        map_server_elt *ms, locator_t *src_loct, lisp_addr_t *rtr_addr);
void timer_encap_map_reg_arg_free(timer_encap_map_reg_argument * timer_arg);
void timer_encap_map_reg_stop_using_locator(map_local_entry_t *mle, locator_t *loct);
timer_inf_req_argument * timer_inf_req_argument_new_init(map_local_entry_t *mle,
        locator_t *loct, map_server_elt *ms);
void timer_inf_req_arg_free(timer_inf_req_argument * timer_arg);
void timer_inf_req_stop_using_locator(map_local_entry_t *mle, locator_t *loct);


inline oor_encap_t tr_get_encap_type(lisp_xtr_t *tr)
{
    return (tr->encap_type);
}

/* Called when the timer associated with an EID entry expires. */
static int
mc_entry_expiration_timer_cb(oor_timer_t *timer)
{
    mcache_entry_t *mce = oor_timer_cb_argument(timer);
    mapping_t *map = mcache_entry_mapping(mce);
    lisp_addr_t *addr = mapping_eid(map);
    lisp_xtr_t *xtr = oor_timer_owner(timer);

    OOR_LOG(LDBG_1,"Got expiration for EID %s", lisp_addr_to_char(addr));
    tr_mcache_remove_entry(xtr, mce);
    return(GOOD);
}

static void
mc_entry_start_expiration_timer(lisp_xtr_t *xtr, mcache_entry_t *mce)
{
    /* Expiration cache timer */
    oor_timer_t *timer;

    timer = oor_timer_create(EXPIRE_MAP_CACHE_TIMER);
    oor_timer_init(timer,xtr,mc_entry_expiration_timer_cb,mce,NULL,NULL);
    htable_ptrs_timers_add(ptrs_to_timers_ht, mce, timer);

    oor_timer_start(timer, mapping_ttl(mcache_entry_mapping(mce))*60);

    OOR_LOG(LDBG_1,"The map cache entry of EID %s will expire in %d minutes.",
            lisp_addr_to_char(mapping_eid(mcache_entry_mapping(mce))),
            mapping_ttl(mcache_entry_mapping(mce)));
}

/* Process a record from map-reply probe message */
static int
handle_locator_probe_reply(lisp_xtr_t *xtr, mcache_entry_t *mce,
        lisp_addr_t *probed_addr)
{
    locator_t * loct = NULL;
    mapping_t * map = NULL;

    map = mcache_entry_mapping(mce);
    loct = mapping_get_loct_with_addr(map, probed_addr);


    if (!loct){
        OOR_LOG(LDBG_2,"Probed locator %s not part of the the mapping %s",
                lisp_addr_to_char(probed_addr),
                lisp_addr_to_char(mapping_eid(map)));
        return (ERR_NO_EXIST);
    }


    OOR_LOG(LDBG_1," Successfully probed RLOC %s of cache entry with EID %s",
                lisp_addr_to_char(locator_addr(loct)),
                lisp_addr_to_char(mapping_eid(map)));


    if (loct->state == DOWN) {
        loct->state = UP;

        OOR_LOG(LDBG_1," Locator %s state changed to UP",
                lisp_addr_to_char(locator_addr(loct)));

        /* [re]Calculate forwarding info if status changed*/
        xtr->fwd_policy->updated_map_cache_inf(xtr->fwd_policy_dev_parm,mce);
    }

    /* Reprogramming timers of rloc probing */
    program_rloc_probing(xtr, mce, loct, xtr->probe_interval);

    return (GOOD);

}

static int
update_mcache_entry(lisp_xtr_t *xtr, mapping_t *recv_map)
{
    mcache_entry_t *mce = NULL;
    mapping_t *map = NULL;
    lisp_addr_t *eid = NULL;


    eid = mapping_eid(recv_map);

    /* Serch map cache entry exist*/
    mce = mcache_lookup_exact(xtr->map_cache, eid);
    if (!mce){
        OOR_LOG(LDBG_2,"No map cache entry for %s", lisp_addr_to_char(eid));
        return (BAD);
    }

    OOR_LOG(LDBG_2, "Mapping with EID %s already exists, replacing!",
            lisp_addr_to_char(eid));

    map = mcache_entry_mapping(mce);

    /* DISCARD all locator state */
    mapping_update_locators(map, mapping_locators_lists(recv_map));

    /* Update forwarding info */
    xtr->fwd_policy->updated_map_cache_inf(xtr->fwd_policy_dev_parm,mce);

    /* Reprogramming timers */
    mc_entry_start_expiration_timer(xtr, mce);

    /* RLOC probing timer */
    program_mce_rloc_probing(xtr, mce);

    return (GOOD);
}

static int
tr_recv_map_reply(lisp_xtr_t *xtr, lbuf_t *buf, uconn_t *udp_con)
{
    void *mrep_hdr;
    locator_t *probed;
    lisp_addr_t *probed_addr;
    mapping_t *m, *aux_m;
    lbuf_t b;
    mcache_entry_t *mce;
    nonces_list_t *nonces_lst;
    oor_timer_t *timer;
    timer_map_req_argument *t_mr_arg;
    int records,active_entry,i;

    /* local copy */
    b = *buf;

    mrep_hdr = lisp_msg_pull_hdr(&b);

    /* Check NONCE */
    nonces_lst = htable_nonces_lookup(nonces_ht, MREP_NONCE(mrep_hdr));
    if (!nonces_lst){
        OOR_LOG(LDBG_2, " Nonce %"PRIx64" doesn't match any Map-Request nonce. "
                "Discarding message!", MREP_NONCE(mrep_hdr));
        return(BAD);
    }
    timer = nonces_list_timer(nonces_lst);
    /* If it is not a Map Reply Probe */
    if (!MREP_RLOC_PROBE(mrep_hdr)){
        t_mr_arg = (timer_map_req_argument *)oor_timer_cb_argument(timer);
        /* We only accept one record except when the nonce is generated by a not active entry */
        mce = t_mr_arg->mce;


        active_entry = mcache_entry_active(mce);
        if (!active_entry){
            records = MREP_REC_COUNT(mrep_hdr);
            /* delete placeholder/dummy mapping inorder to install the new one */
            tr_mcache_remove_entry(xtr, mce);
            /* Timers are removed during the process of deleting the mce*/
            timer = NULL;
        }else{
            if (MREP_REC_COUNT(mrep_hdr) >1){
                OOR_LOG(LINF,"Received Map Reply with multiple records. Only first one will be processed");
            }
            records = 1;
        }

        for (i = 0; i < records; i++) {
            m = mapping_new();
            if (lisp_msg_parse_mapping_record(&b, m, &probed) != GOOD) {
                goto err;
            }
            if (mapping_has_elp_with_l_bit(m)){
                OOR_LOG(LDBG_1,"Received a Map Reply with an ELP with the L bit set. "
                        "Not supported -> Discrding map reply");
                goto err;
            }

            /* Mapping is NOT ACTIVE */
            if (!active_entry) {
                /* DO NOT free mapping in this case */
                tr_mcache_add_mapping(xtr, m);
                /* Mapping is ACTIVE */
            } else {
                /* the reply might be for an active mapping (SMR)*/
                update_mcache_entry(xtr, m);
                mapping_del(m);
            }

            mcache_dump_db(xtr->map_cache, LDBG_3);
        }
    }else{
        if (MREP_REC_COUNT(mrep_hdr) >1){
            OOR_LOG(LDBG_1,"Received Map Reply Probe with multiple records. Only first one will be processed");
        }
        records = 1;
        for (i = 0; i < records; i++) {
            m = mapping_new();
            if (lisp_msg_parse_mapping_record(&b, m, &probed) != GOOD) {
                goto err;
            }
            if (mapping_has_elp_with_l_bit(m)){
                OOR_LOG(LDBG_1,"Received a Map Reply with an ELP with the L bit set. "
                        "Not supported -> Discrding map reply");
                goto err;
            }

            if (probed != NULL){
                probed_addr = locator_addr(probed);
            }else{
                probed_addr = &(udp_con->ra);
            }

            mce = mcache_lookup_exact(xtr->map_cache, mapping_eid(m));
            if (!mce){
                /* Check if the map reply probe is from a proxy */
                mce = xtr->petrs;
                aux_m = mcache_entry_mapping(mce);
                if (lisp_addr_cmp(mapping_eid(m),mapping_eid(aux_m)) != 0){
                    OOR_LOG(LDBG_2,"Received a non requested Map Reply probe");
                    return (BAD);
                }
            }

            handle_locator_probe_reply(xtr, mce, probed_addr);

            /* No need to free 'probed' since it's a pointer to a locator in
             * of m's */
            mapping_del(m);
        }
    }
    if (timer != NULL){
        /* Remove nonces_lst and associated timer*/
        stop_timer_from_obj(mce,timer,ptrs_to_timers_ht,nonces_ht);
    }

    return(GOOD);
err:
    locator_del(probed);
    mapping_del(m);
    return(BAD);
}


static int
tr_reply_to_smr(lisp_xtr_t *xtr, lisp_addr_t *src_eid, lisp_addr_t *req_eid)
{
    mcache_entry_t *mce;
    oor_timer_t *timer;
    timer_map_req_argument *timer_arg;

    /* Lookup the map cache entry that match with the requested EID prefix */
    if (!(mce = mcache_lookup(xtr->map_cache, req_eid))) {
        OOR_LOG(LDBG_2,"tr_reply_to_smr: Received a solicited SMR from %s but it "
                "doesn't exist in cache", lisp_addr_to_char(req_eid));
        return(BAD);
    }

    /* Creat timer responsible of retries */
    timer_arg = timer_map_req_arg_new_init(mce,src_eid);
    timer = oor_timer_with_nonce_new(SMR_INV_RETRY_TIMER, xtr, smr_invoked_map_request_cb,
            timer_arg,(oor_timer_del_cb_arg_fn)timer_map_req_arg_free);

    htable_ptrs_timers_add(ptrs_to_timers_ht, mce, timer);

    smr_invoked_map_request_cb(timer);

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


    if (MREQ_RLOC_PROBE(mreq_hdr) && MREQ_REC_COUNT(mreq_hdr) > 1) {
        OOR_LOG(LDBG_1, "More than one EID record in RLOC probe. Discarding!");
        goto err;
    }

    if (MREQ_SMR(mreq_hdr) && MREQ_REC_COUNT(mreq_hdr) > 1) {
        OOR_LOG(LDBG_1, "More than one EID record in SMR request. Discarding!");
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


        OOR_LOG(LDBG_1, " dst-eid: %s", lisp_addr_to_char(deid));


        if (xtr->super.mode == xTR_MODE || xtr->super.mode == MN_MODE) {
            /* Check the existence of the requested EID */
            map_loc_e = local_map_db_lookup_eid(xtr->local_mdb, deid, TRUE);
            if (!map_loc_e) {
                OOR_LOG(LDBG_1,"EID %s not locally configured!",
                        lisp_addr_to_char(deid));
                continue;
            }
            map = map_local_entry_mapping(map_loc_e);
            lisp_msg_put_mapping(mrep, map, MREQ_RLOC_PROBE(mreq_hdr)
                    ? &uc->la: NULL);
        }else if (xtr->super.mode == RTR_MODE &&
                (MREQ_SMR(mreq_hdr) || MREQ_RLOC_PROBE(mreq_hdr))){
            lisp_msg_put_neg_mapping(mrep, deid, 0, ACT_NO_ACTION, A_NO_AUTHORITATIVE);
        }else{
            continue;
        }
        /* If packet is a Solicit Map Request, process it */
        if (lisp_addr_lafi(seid) != LM_AFI_NO_ADDR && MREQ_SMR(mreq_hdr)) {
            if(tr_reply_to_smr(xtr,deid,seid) != GOOD) {
                goto err;
            }
            /* Return if RLOC probe bit is not set */
            if (!MREQ_RLOC_PROBE(mreq_hdr)) {
                goto done;
            };
        }
    }
    mrep_hdr = lisp_msg_hdr(mrep);
    MREP_RLOC_PROBE(mrep_hdr) = MREQ_RLOC_PROBE(mreq_hdr);
    MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);

    /* SEND MAP-REPLY */
    if (map_reply_fill_uconn(xtr, itr_rlocs, uc) != GOOD){
        OOR_LOG(LDBG_1, "Couldn't send Map Reply, no itr_rlocs reachable");
        goto err;
    }
    OOR_LOG(LDBG_1, "Sending %s", lisp_msg_hdr_to_char(mrep));
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
tr_recv_info_nat(lisp_xtr_t *xtr, lbuf_t *buf, uconn_t *uc)
{
    lisp_addr_t *inf_reply_eid, *inf_req_eid, *nat_lcaf_addr;
    void *info_nat_hdr, *info_nat_hdr_2;
    lbuf_t  b;
    nonces_list_t *nonces_lst;
    timer_inf_req_argument *timer_arg;
    int len, ttl;
    glist_t *rtr_lst;
    map_local_entry_t *mle;

    /* local copy of the buf that can be modified */
    b = *buf;
    info_nat_hdr = lisp_msg_pull_hdr(&b);

    if (INF_REQ_R_bit(info_nat_hdr) == INFO_REQUEST){
        OOR_LOG(LDBG_1, "XTR received an Info Request. Discarting message");
        return(BAD);
    }

    /* Check NONCE */
    nonces_lst = htable_nonces_lookup(nonces_ht, INF_REQ_NONCE(info_nat_hdr));
    if (!nonces_lst){
        OOR_LOG(LDBG_2, " Nonce %"PRIx64" doesn't match any Info Request nonce. "
                "Discarding message!", INF_REQ_NONCE(info_nat_hdr));
        return(BAD);
    }

    timer_arg = oor_timer_cb_argument(nonces_list_timer(nonces_lst));
    mle = timer_arg->mle;

    lisp_msg_pull_auth_field(&b);

    info_nat_hdr_2 = lbuf_pull(&b, sizeof(info_nat_hdr_2_t));

    /* Get EID prefix for the info reply and compare with the one of the info request*/
    inf_reply_eid = lisp_addr_new();
    len = lisp_addr_parse(lbuf_data(&b), inf_reply_eid);
    if (len <= 0) {
        lisp_addr_del(inf_reply_eid);
        return(BAD);
    }
    lbuf_pull(&b, len);
    lisp_addr_set_plen(inf_reply_eid, INF_REQ_2_EID_MASK(info_nat_hdr_2));

    inf_req_eid = map_local_entry_eid(mle);

    if (lisp_addr_cmp(inf_reply_eid,inf_req_eid)!=0){
        OOR_LOG(LDBG_2, "EID from info request and info reply are different (%s - %s)",
                lisp_addr_to_char(inf_req_eid),lisp_addr_to_char(inf_reply_eid));
        lisp_addr_del(inf_reply_eid);
        return (BAD);
    }
    lisp_addr_del(inf_reply_eid);

    /* We obtain the key to use in the authentication process from the argument of the timer */

    if (lisp_msg_check_auth_field(buf, timer_arg->ms->key) != GOOD) {
        OOR_LOG(LDBG_1, "Info Reply Message validation failed for EID %s with key "
                "%s. Stopping processing!", lisp_addr_to_char(inf_req_eid),
                timer_arg->ms->key);
        return (BAD);
    }

    nat_lcaf_addr = lisp_addr_new();
    len = lisp_addr_parse(lbuf_data(&b), nat_lcaf_addr);
    if (len <= 0) {
        lisp_addr_del(nat_lcaf_addr);
        OOR_LOG(LDBG_2, "tr_recv_info_nat: Can not parse nat lcaf address");
        return(BAD);
    }

    rtr_lst = nat_type_get_rtr_addr_lst(lcaf_addr_get_nat(lisp_addr_get_lcaf(nat_lcaf_addr)));

    if (tr_update_nat_info(xtr,mle,timer_arg->loct,rtr_lst) == GOOD){
        /* Configure Encap Map Register */
        program_encap_map_reg_of_loct_for_map(xtr, mle,timer_arg->loct);
        /* Reprogram time for next Info Request interval */
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        ttl = ntohl(INF_REQ_2_TTL(info_nat_hdr_2));
        oor_timer_start(nonces_lst->timer, ttl*60);
        OOR_LOG(LDBG_1,"Info Request of %s to %s from locator %s programmed in %d minutes.",
                lisp_addr_to_char(map_local_entry_eid(mle)), lisp_addr_to_char(timer_arg->ms->address),
                lisp_addr_to_char(locator_addr(timer_arg->loct)), ttl);
    }

    lisp_addr_del(nat_lcaf_addr);
    return (GOOD);
}

int
tr_update_nat_info(lisp_xtr_t *xtr, map_local_entry_t *mle, locator_t *loct,
        glist_t *rtr_list)
{
    glist_t *final_rtr_list;

    final_rtr_list = nat_select_rtrs(rtr_list);
    if (glist_size(final_rtr_list) == 0){
        OOR_LOG(LDBG_1, "Info Reply Message doesn't have any compatible RTR");
        glist_destroy(final_rtr_list);
        return (BAD);
    }

    mle_nat_info_update(mle, loct, final_rtr_list);

    /* Update forwarding info of the local entry*/
    xtr->fwd_policy->updated_map_loc_inf(xtr->fwd_policy_dev_parm,mle);

    /* Update forwarding info of rtrs */
    tr_update_fwd_info_rtrs(xtr);

    glist_destroy(final_rtr_list);
    return (GOOD);
}

void
tr_update_fwd_info_rtrs(lisp_xtr_t *xtr)
{
    lisp_addr_t *rtr_addr;
    map_local_entry_t *mle;
    mapping_t *map;
    locator_t *rtr_loct;
    glist_t *rtr_addr_list;
    glist_entry_t *addr_it;

    map = mcache_entry_mapping(xtr->rtrs);
    /* Remove the list of rtr locators */
    mapping_remove_locators(map);

    /* Regenerate rtr list using the information of local map entries */
    local_map_db_foreach_entry(xtr->local_mdb,mle){
        rtr_addr_list = mle_rtr_addr_list(mle);
        glist_for_each_entry(addr_it, rtr_addr_list){
            rtr_addr = (lisp_addr_t *)glist_entry_data(addr_it);
            rtr_loct = locator_new_init(rtr_addr,UP,0,1,1,100,255,0);
            mapping_add_locator(map,rtr_loct);
        }
        glist_destroy(rtr_addr_list);
    }local_map_db_foreach_end;

    /* Update forwarding info of rtrs */
    xtr->fwd_policy->updated_map_cache_inf(xtr->fwd_policy_dev_parm,xtr->rtrs);
}

glist_t *
nat_select_rtrs(glist_t * rtr_list)
{
    glist_t *final_rtr_list = glist_new_managed((glist_del_fct)lisp_addr_del);
    lisp_addr_t *rtr_addr;

    addr_list_rm_not_compatible_addr(rtr_list, IPv4_SUPPORT);

    //TODO Select RTR process
    rtr_addr = (lisp_addr_t *)glist_first_data(rtr_list);
    if (rtr_addr){
        glist_add(lisp_addr_clone(rtr_addr), final_rtr_list);
    }
    return (final_rtr_list);
}



int
map_reply_fill_uconn(lisp_xtr_t *xtr, glist_t *itr_rlocs, uconn_t *uc)
{
    lisp_addr_t *src_loc;
    int afi;

    if (laddr_list_get_addr(itr_rlocs, lisp_addr_ip_afi(&uc->la), &uc->ra) == GOOD){
        return (GOOD);
    }

    if (lisp_addr_ip_afi(&uc->la) == AF_INET){
        afi = AF_INET6;
    }else{
        afi = AF_INET;
    }
    src_loc = ctrl_default_rloc(xtr->super.ctrl, afi);
    if (src_loc == NULL){
        return (BAD);
    }
    if (laddr_list_get_addr(itr_rlocs, afi, &uc->ra) != GOOD){
        return (BAD);
    }
    lisp_addr_copy(&uc->la, src_loc);

    return (GOOD);
}



static int
handle_merge_semantics(lisp_xtr_t *xtr, mapping_t *rec_map)
{
    lisp_addr_t *eid = NULL;
    mcache_entry_t *mce = NULL;
    mapping_t *map = NULL;

    eid = mapping_eid(rec_map);

    OOR_LOG(LDBG_1, "Merge-Semantics on, moving returned mapping to "
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
    map = mcache_entry_mapping(mce);
    if (mapping_cmp(map, rec_map) != 0) {
        /* UPDATED rlocs */
        OOR_LOG(LDBG_3, "Prefix %s already registered, updating locators",
                lisp_addr_to_char(eid));
        mapping_update_locators(map,mapping_locators_lists(rec_map));

        /* Update forward info*/
        xtr->fwd_policy->updated_map_cache_inf(xtr->fwd_policy_dev_parm,mce);

        program_mce_rloc_probing(xtr, mce);

    }
    return(GOOD);
}

static int
tr_recv_map_notify(lisp_xtr_t *xtr, lbuf_t *buf)
{
    lisp_addr_t *eid;
    map_local_entry_t *map_loc_e;
    mapping_t *m, *local_map;
    void *hdr;
    locator_t *probed ;
    map_server_elt *ms;
    nonces_list_t *nonces_lst;
    oor_timer_t *timer;
    timer_map_reg_argument *timer_arg_mn;
    timer_encap_map_reg_argument *timer_arg_emn;
    int i, res = BAD;
    lbuf_t b;

    /* local copy */
    b = *buf;
    hdr = lisp_msg_pull_hdr(&b);

    /* Check NONCE */
    nonces_lst = htable_nonces_lookup(nonces_ht, MNTF_NONCE(hdr));
    if (!nonces_lst){
        OOR_LOG(LDBG_1, "No Map Register sent with nonce: %"PRIx64
                " Discarding message!", MNTF_NONCE(hdr));
        return(BAD);
    }
    timer = nonces_list_timer(nonces_lst);

    if (MNTF_I_BIT(hdr)==1){
        OOR_LOG(LDBG_1,"Received Data Map Notify");
        timer_arg_emn = (timer_encap_map_reg_argument *)oor_timer_cb_argument(timer);
        ms = timer_arg_emn->ms;
        if (MNTF_R_BIT(hdr)==1){
            /* We subtract the RTR authentication field. Is not used in the authentication
             * calculation of the map notify.*/
            // XXX Speculate that this field is removed by RTR so length is 0
            lbuf_set_size(buf, lbuf_size(buf) - sizeof(auth_record_hdr_t));
        }
    }else{
        timer_arg_mn = (timer_map_reg_argument *)oor_timer_cb_argument(timer);
        ms = timer_arg_mn->ms;
    }



    res = lisp_msg_check_auth_field(buf, ms->key);

    if (res != GOOD){
        OOR_LOG(LDBG_1, "Map-Notify message is invalid");
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
        if (!map_loc_e) {
            OOR_LOG(LDBG_1, "Map-Notify confirms registration of UNKNOWN EID %s."
                    " Dropping!", lisp_addr_to_char(eid));
            continue;
        }
        local_map = map_local_entry_mapping(map_loc_e);

        OOR_LOG(LDBG_1, "Map-Notify message confirms correct registration of %s."
                "Programing next Map-Register in %d seconds",lisp_addr_to_char(eid),
                MAP_REGISTER_INTERVAL);

        /* MULTICAST MERGE SEMANTICS */
        if (lisp_addr_is_mc(eid) && mapping_cmp(local_map, m) != 0) {
            handle_merge_semantics(xtr, m);
        }


        mapping_del(m);
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        oor_timer_start(timer,MAP_REGISTER_INTERVAL);
    }

    return(GOOD);
}


int
handle_map_cache_miss(lisp_xtr_t *xtr, lisp_addr_t *requested_eid,
        lisp_addr_t *src_eid)
{
    mcache_entry_t *mce = mcache_entry_new();
    mapping_t *m = NULL;
    oor_timer_t *timer;
    timer_map_req_argument *timer_arg;

    /* Install temporary, NOT active, mapping in map_cache */
    m = mapping_new_init(requested_eid);
    mcache_entry_init(mce, m);
    /* Precalculate routing information */
    if (xtr->fwd_policy->init_map_cache_policy_inf(xtr->fwd_policy_dev_parm,mce,
            xtr->fwd_policy->del_map_cache_policy_inf) != GOOD){
        OOR_LOG(LWRN, "handle_map_cache_miss: Couldn't initiate routing info for map cache entry %s!. Discarding it.",
                lisp_addr_to_char(requested_eid));
        mcache_entry_del(mce);
        return(BAD);
    }

    if (mcache_add_entry(xtr->map_cache, requested_eid, mce) != GOOD) {
        OOR_LOG(LWRN, "Couln't install temporary map cache entry for %s!",
                lisp_addr_to_char(requested_eid));
        mcache_entry_del(mce);
        return(BAD);
    }
    timer_arg = timer_map_req_arg_new_init(mce,src_eid);
    timer = oor_timer_with_nonce_new(MAP_REQUEST_RETRY_TIMER,xtr,send_map_request_retry_cb,
            timer_arg,(oor_timer_del_cb_arg_fn)timer_map_req_arg_free);
    htable_ptrs_timers_add(ptrs_to_timers_ht,mce,timer);

    return(send_map_request_retry_cb(timer));
}

static glist_t *
build_rloc_list(mapping_t *mapping)
{
    glist_t *rlocs = glist_new();
    locator_t *locator = NULL;
    lisp_addr_t *loc_addr = NULL;

    if (glist_size(mapping_locators_lists(mapping)) == 0){
        return (rlocs);
    }

    mapping_foreach_active_locator(mapping, locator){
        loc_addr = locator_addr(locator);
        glist_add_tail(loc_addr,rlocs);
    }mapping_foreach_active_locator_end;

    return(rlocs);
}

static int
build_and_send_smr_mreq(lisp_xtr_t *xtr, mapping_t *smap,
        lisp_addr_t *deid, lisp_addr_t *drloc)
{
    uconn_t uc;
    lbuf_t * b = NULL;
    lisp_addr_t *seid = NULL;
    lisp_addr_t *srloc = NULL;
    void *hdr = NULL;
    glist_t *itr_rlocs = NULL;
    int res = GOOD;

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
    OOR_LOG(LDBG_1, "%s, itr-rlocs: %s, src-eid: %s, req-eid: %s ", lisp_msg_hdr_to_char(b),
            laddr_list_to_char(itr_rlocs), lisp_addr_to_char(seid), lisp_addr_to_char(deid));
    glist_destroy(itr_rlocs);

    srloc = ctrl_default_rloc(xtr->super.ctrl, lisp_addr_ip_afi(drloc));
    if (!srloc) {
        OOR_LOG(LDBG_2, "No compatible RLOC was found to send SMR Map-Request "
                "for local EID %s", lisp_addr_to_char(seid));
        lisp_msg_destroy(b);
        return(BAD);
    }

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, srloc, drloc);
    res = send_msg(&xtr->super, b, &uc);
    lisp_msg_destroy(b);

    return(res);
}

/* solicit SMRs for 'src_map' to all locators of 'dst_map'*/
static int
build_and_send_smr_mreq_to_map(lisp_xtr_t  *xtr, mapping_t *src_map,
        mapping_t *dst_map)
{
    lisp_addr_t *deid = NULL, *drloc = NULL;
    locator_t *loct = NULL;

    deid = mapping_eid(dst_map);

    mapping_foreach_active_locator(dst_map, loct){
        if (loct->state == UP){
            drloc = locator_addr(loct);
            build_and_send_smr_mreq(xtr, src_map, deid, drloc);
        }
    }mapping_foreach_active_locator_end;

    return(GOOD);
}

static int
send_all_smr_cb(oor_timer_t *timer)
{
    send_all_smr_and_reg((lisp_xtr_t *)oor_timer_cb_argument(timer));
    return(GOOD);
}

/* Send a solicit map request for each rloc of all eids in the map cache
 * database */
static void
send_all_smr_and_reg(lisp_xtr_t *xtr)
{
    map_local_entry_t * map_loc_e = NULL;
    mcache_entry_t * mce = NULL;
    mapping_t * mcache_map = NULL;
    mapping_t * map = NULL;
    glist_t * map_loc_e_list = NULL; //<map_local_entry_t *>
    glist_entry_t * it = NULL;
    glist_entry_t * it_pitr = NULL;
    lisp_addr_t * pitr_addr = NULL;
    lisp_addr_t * eid = NULL;

    OOR_LOG(LDBG_1,"\n**** Re-Register and send SMRs for mappings with updated "
            "RLOCs ****");

    /* Get a list of mappings that require smrs */
    map_loc_e_list = get_map_local_entry_to_smr(xtr);

    /* Send map register and SMR request for each mapping */
    //glist_dump(map_loc_e_list,(glist_to_char_fct)map_local_entry_to_char,LDBG_1);

    glist_for_each_entry(it, map_loc_e_list) {
        map_loc_e = (map_local_entry_t *)glist_entry_data(it);
        map = map_local_entry_mapping(map_loc_e);
        eid = mapping_eid(map);

        program_map_register_for_mapping(xtr, map_loc_e);

        OOR_LOG(LDBG_1, "Start SMR for local EID %s", lisp_addr_to_char(eid));

        /* no SMRs for now for multicast */
        if (lisp_addr_is_mc(eid))
            continue;

        /* TODO: spec says SMRs should be sent only to peer ITRs that sent us
         * traffic in the last minute. Should change this in the future*/
        /* XXX: works ONLY with IP */
        mcache_foreach_active_entry_in_ip_eid_db(xtr->map_cache, eid, mce) {
            mcache_map = mcache_entry_mapping(mce);
            build_and_send_smr_mreq_to_map(xtr, map, mcache_map);
        } mcache_foreach_active_entry_in_ip_eid_db_end;

        /* SMR proxy-itr */
        OOR_LOG(LDBG_1, "Sending SMRs to PITRs");
        glist_for_each_entry(it_pitr, xtr->pitrs){
            pitr_addr = (lisp_addr_t *)glist_entry_data(it_pitr);
            build_and_send_smr_mreq(xtr, map, eid, pitr_addr);
        }
    }

    glist_destroy(map_loc_e_list);
    OOR_LOG(LDBG_2,"*** Finished sending notifications ***\n");
}


static int
smr_invoked_map_request_cb(oor_timer_t *timer)
{
    timer_map_req_argument *timer_arg = (timer_map_req_argument *)oor_timer_cb_argument(timer);
    nonces_list_t *nonces_list = oor_timer_nonces(timer);
    lisp_xtr_t *xtr = oor_timer_owner(timer);
    uint64_t nonce;
    lisp_addr_t *deid;

    if (nonces_list_size(nonces_list) - 1 < OOR_MAX_SMR_RETRANSMIT) {
        nonce = nonce_new();
        if (send_smr_invoked_map_request(xtr, timer_arg->src_eid, timer_arg->mce, nonce) != GOOD){
            return (BAD);
        }
        htable_nonces_insert(nonces_ht, nonce, nonces_list);
        oor_timer_start(timer, OOR_INITIAL_SMR_TIMEOUT);
        return (GOOD);
    } else {
        deid = mapping_eid(mcache_entry_mapping(timer_arg->mce));
        OOR_LOG(LDBG_1,"SMR: No Map Reply for EID %s. Removing entry ...",
                lisp_addr_to_char(deid));
        tr_mcache_remove_entry(xtr,timer_arg->mce);
        return (BAD);
    }
}

static int
send_smr_invoked_map_request(lisp_xtr_t *xtr, lisp_addr_t *src_eid,
        mcache_entry_t *mce, uint64_t nonce)
{
    uconn_t uc;
    lisp_addr_t *drloc, *srloc;
    struct lbuf *b = NULL;
    void *hdr = NULL;
    mapping_t *m = NULL;
    lisp_addr_t *deid = NULL, *s_in_addr = NULL, *d_in_addr = NULL;
    glist_t *rlocs = NULL;
    int afi, ret ;

    m = mcache_entry_mapping(mce);
    deid = mapping_eid(m);
    afi = lisp_addr_ip_afi(deid);

    OOR_LOG(LDBG_1,"SMR: Map-Request for EID: %s",lisp_addr_to_char(deid));

    /* BUILD Map-Request */

    /* no source EID and mapping, so put default control rlocs */
    rlocs = ctrl_default_rlocs(xtr->super.ctrl);
    b = lisp_msg_mreq_create(src_eid, rlocs, mapping_eid(m));
    if (b == NULL){
        OOR_LOG(LWRN, "send_smr_invoked_map_request: Couldn't create map request message");
        glist_destroy(rlocs);
        return (BAD);
    }

    hdr = lisp_msg_hdr(b);
    MREQ_SMR_INVOKED(hdr) = 1;
    MREQ_NONCE(hdr) = nonce;

    /* we could put anything here. Still, better put something that
     * makes a bit of sense .. */
    s_in_addr = local_map_db_get_main_eid(xtr->local_mdb, afi);
    d_in_addr = deid;
    /* If we don't have a source EID as an RTR, we use an RLOC. May be, RTR could have a loopback EID address */
    if (s_in_addr == NULL){
        s_in_addr = ctrl_default_rloc(lisp_ctrl_dev_get_ctrl_t(&(xtr->super)),afi);
        if (s_in_addr == NULL){
            OOR_LOG(LDBG_1,"SMR: Couldn't generate Map-Request for EID: %s. No source inner ip address available)",
                    lisp_addr_to_char(deid));
            return (BAD);
        }
    }

    /* SEND */
    OOR_LOG(LDBG_1, "%s, itr-rlocs:%s src-eid: %s, req-eid: %s",
            lisp_msg_hdr_to_char(b), laddr_list_to_char(rlocs),
            lisp_addr_to_char(src_eid), lisp_addr_to_char(deid));

    /* Encapsulate messgae and send it to the map resolver */
    lisp_msg_encap(b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, s_in_addr,
            d_in_addr);

    srloc = NULL;
    drloc = get_map_resolver(xtr);
    if (!drloc){
        glist_destroy(rlocs);
        lisp_msg_destroy(b);
        return (BAD);
    }

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, srloc, drloc);
    ret = send_msg(&xtr->super, b, &uc);

    glist_destroy(rlocs);
    lisp_msg_destroy(b);

    return (ret);
}

static int
program_smr(lisp_xtr_t *xtr, int time)
{

    OOR_LOG(LDBG_1,"Reprograming SMR in %d seconds",time);

    if (!xtr->smr_timer) {
        xtr->smr_timer = oor_timer_create(SMR_TIMER);
        oor_timer_init(xtr->smr_timer, xtr, send_all_smr_cb, xtr, NULL,NULL);
    }

    oor_timer_start(xtr->smr_timer, time);
    return(GOOD);
}


static int
send_map_request_retry_cb(oor_timer_t *timer)
{
    timer_map_req_argument *timer_arg = (timer_map_req_argument *)oor_timer_cb_argument(timer);
    nonces_list_t *nonces_list = oor_timer_nonces(timer);
    lisp_xtr_t *xtr = oor_timer_owner(timer);
    uint64_t nonce;
    lisp_addr_t *deid;
    int retries = nonces_list_size(nonces_list);

    deid = mapping_eid (mcache_entry_mapping(timer_arg->mce));
    if (retries - 1 < xtr->map_request_retries) {

        if (retries > 0) {
            OOR_LOG(LDBG_1, "Retransmitting Map Request for EID: %s (%d retries)",
                    lisp_addr_to_char(deid), retries);
        }
        nonce = nonce_new();
        if (build_and_send_encap_map_request(xtr, timer_arg->src_eid, timer_arg->mce, nonce) != GOOD){
            return (BAD);
        }
        htable_nonces_insert(nonces_ht, nonce, nonces_list);
        oor_timer_start(timer, OOR_INITIAL_MRQ_TIMEOUT);
        return (GOOD);
    } else {
        OOR_LOG(LDBG_1, "No Map-Reply for EID %s after %d retries. Aborting!",
                lisp_addr_to_char(deid), retries -1 );
        /* When removing mce, all timers associated to it are canceled */
        tr_mcache_remove_entry(xtr,timer_arg->mce);

        return (BAD);
    }
}


/* Sends Encap Map-Request for EID in 'mce' and sets-up a retry timer */
static int
build_and_send_encap_map_request(lisp_xtr_t *xtr, lisp_addr_t *seid,
        mcache_entry_t *mce, uint64_t nonce)
{
    uconn_t uc;
    mapping_t *m = NULL;
    lisp_addr_t *deid = NULL;
    lisp_addr_t *drloc, *srloc;
    glist_t *rlocs = NULL;
    lbuf_t *b = NULL;
    void *mr_hdr = NULL;

    if (glist_size(xtr->map_resolvers) == 0){
        OOR_LOG(LDBG_1, "Couldn't send encap map request: No map resolver configured");
        return (BAD);
    }

    m = mcache_entry_mapping(mce);
    deid = mapping_eid(m);

    /* BUILD Map-Request */

    // Rlocs to be used as ITR of the map req.
    rlocs = ctrl_default_rlocs(xtr->super.ctrl);
    OOR_LOG(LDBG_1, "locators for req: %s", laddr_list_to_char(rlocs));
    b = lisp_msg_mreq_create(seid, rlocs, deid);
    if (b == NULL) {
        OOR_LOG(LDBG_1, "build_and_send_encap_map_request: Couldn't create map request message");
        glist_destroy(rlocs);
        return(BAD);
    }

    mr_hdr = lisp_msg_hdr(b);
    MREQ_NONCE(mr_hdr) = nonce;
    OOR_LOG(LDBG_1, "%s, itr-rlocs:%s, src-eid: %s, req-eid: %s",
            lisp_msg_hdr_to_char(b), laddr_list_to_char(rlocs),
            lisp_addr_to_char(seid), lisp_addr_to_char(deid));
    glist_destroy(rlocs);


    /* Encapsulate message and send it to the map resolver */

    lisp_msg_encap(b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, seid, deid);

    srloc = NULL;
    drloc = get_map_resolver(xtr);
    if (!drloc){
        lisp_msg_destroy(b);
        return (BAD);
    }

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, srloc, drloc);
    send_msg(&xtr->super, b, &uc);

    lisp_msg_destroy(b);

    return(GOOD);
}

/* build and send generic map-register with one record
 * for each map server */
static int
build_and_send_info_req(lisp_xtr_t * xtr, mapping_t * m, locator_t *loct,
        map_server_elt *ms, uint64_t nonce)
{
    lbuf_t * b = NULL;
    void *hdr;
    lisp_addr_t *srloc, *drloc;
    uconn_t uc;


    b = lisp_msg_inf_req_create(m, ms->key_type);

    if (!b) {
        return(BAD);
    }
    hdr = lisp_msg_hdr(b);
    INF_REQ_NONCE(hdr) = nonce;

    if (lisp_msg_fill_auth_data(b, ms->key_type,
            ms->key) != GOOD) {
        return(BAD);
    }
    srloc = locator_addr(loct);
    drloc =  ms->address;
    OOR_LOG(LDBG_1, "%s, EID: %s, MS: %s", lisp_msg_hdr_to_char(b),
            lisp_addr_to_char(mapping_eid(m)), lisp_addr_to_char(drloc));

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, srloc, drloc);
    send_msg(&xtr->super, b, &uc);

    lisp_msg_destroy(b);

    return(GOOD);
}


/* build and send generic map-register with one record
 * for each map server */
static int
build_and_send_map_reg(lisp_xtr_t * xtr, mapping_t * m, map_server_elt *ms,
        uint64_t nonce)
{
    lbuf_t * b = NULL;
    void * hdr = NULL;
    lisp_addr_t * drloc = NULL;
    uconn_t uc;

    b = lisp_msg_mreg_create(m, ms->key_type);

    if (!b) {
        return(BAD);
    }

    hdr = lisp_msg_hdr(b);
    MREG_PROXY_REPLY(hdr) = ms->proxy_reply;
    MREG_NONCE(hdr) = nonce;

    if (lisp_msg_fill_auth_data(b, ms->key_type,
            ms->key) != GOOD) {
        return(BAD);
    }
    drloc =  ms->address;
    OOR_LOG(LDBG_1, "%s, EID: %s, MS: %s", lisp_msg_hdr_to_char(b),
            lisp_addr_to_char(mapping_eid(m)), lisp_addr_to_char(drloc));

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
    send_msg(&xtr->super, b, &uc);

    lisp_msg_destroy(b);

    return(GOOD);
}

static int
build_and_send_encap_map_reg(lisp_xtr_t * xtr, mapping_t * m, map_server_elt *ms,
        lisp_addr_t *etr_addr, lisp_addr_t *rtr_addr, uint64_t nonce)
{
    lbuf_t * b;
    void * hdr;
    uconn_t uc;

    b = lisp_msg_nat_mreg_create(m, xtr->site_id, &xtr->xtr_id, ms->key_type);
    hdr = lisp_msg_hdr(b);

    MREG_NONCE(hdr) = nonce;
    MREG_PROXY_REPLY(hdr) = 1;
    MREG_IBIT(hdr) = 1;
    MREG_RBIT(hdr) = 1;

    if (lisp_addr_ip_afi(ms->address) != lisp_addr_ip_afi(etr_addr)){
        OOR_LOG(LDBG_1, "build_and_send_ecm_map_reg: Map Server afi not compatible with selected"
                " local rloc (%s)", lisp_addr_to_char(etr_addr));
        lisp_msg_destroy(b);
        return (BAD);
    }

    if (lisp_msg_fill_auth_data(b, ms->key_type, ms->key) != GOOD) {
        OOR_LOG(LDBG_2, "build_and_send_ecm_map_reg: Error filling the authentication data");
        return(BAD);
    }

    lisp_msg_encap(b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, etr_addr,ms->address);
    hdr = lisp_msg_ecm_hdr(b);

    /* TODO To use when implementing draft version 4 or higher */
    //ECM_RTR_PROCESS_BIT(hdr) = 1;

    OOR_LOG(LDBG_1, "%s, Inner IP: %s -> %s, EID: %s, RTR: %s",
             lisp_msg_hdr_to_char(b), lisp_addr_to_char(etr_addr),
             lisp_addr_to_char(ms->address), lisp_addr_to_char(mapping_eid(m)),
             lisp_addr_to_char(rtr_addr));



    uconn_init(&uc, LISP_DATA_PORT, LISP_CONTROL_PORT, etr_addr, rtr_addr);
    send_msg(&xtr->super, b, &uc);

    lisp_msg_destroy(b);
    return(GOOD);
}

static int
map_register_cb(oor_timer_t *timer)
{
    timer_map_reg_argument *timer_arg = oor_timer_cb_argument(timer);
    nonces_list_t *nonces_lst = oor_timer_nonces(timer);
    lisp_xtr_t *xtr = oor_timer_owner(timer);
    mapping_t *map = map_local_entry_mapping(timer_arg->mle);
    map_server_elt *ms = timer_arg->ms;
    uint64_t nonce;

    if ((nonces_list_size(nonces_lst) -1) < xtr->probe_retries){
        nonce = nonce_new();
        if (build_and_send_map_reg(xtr, map, ms, nonce) != GOOD){
            return (BAD);
        }
        if (nonces_list_size(nonces_lst) > 0) {
            OOR_LOG(LDBG_1,"Sent Retry Map-Register for mapping %s to %s "
                    "(%d retries)", lisp_addr_to_char(mapping_eid(map)),
                    lisp_addr_to_char(ms->address), nonces_list_size(nonces_lst));
        } else {
            OOR_LOG(LDBG_1,"Sent Map-Register for mapping %s to %s "
                    , lisp_addr_to_char(mapping_eid(map)),
                    lisp_addr_to_char(ms->address));
        }
        htable_nonces_insert(nonces_ht, nonce,nonces_lst);
        oor_timer_start(timer, OOR_INITIAL_MREG_TIMEOUT);
        return (GOOD);
    }else{
        /* If we have reached maximum number of retransmissions, change remote
         *  locator status */

        /* Reprogram time for next Map Register interval */
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        oor_timer_start(timer, MAP_REGISTER_INTERVAL);
        OOR_LOG(LWRN,"Map Register of %s to %s not received reply. Retry in %d seconds",
                lisp_addr_to_char(mapping_eid(map)), lisp_addr_to_char(ms->address),
                MAP_REGISTER_INTERVAL);

        return (BAD);
    }
}

int
program_map_register(lisp_xtr_t *xtr)
{
    void *map_local_entry_it;
    map_local_entry_t *mle;
    oor_timer_t *timer;
    timer_map_reg_argument *timer_arg;
    map_server_elt *ms;
    glist_entry_t *ms_it;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }

    local_map_db_foreach_entry(xtr->local_mdb, map_local_entry_it) {
        mle = (map_local_entry_t *)map_local_entry_it;
        /* Cancel timers associated to the map register of the local map entry */
        stop_timers_of_type_from_obj(mle,MAP_REGISTER_TIMER,ptrs_to_timers_ht, nonces_ht);
        /* Configure map register for each map server */
        glist_for_each_entry(ms_it,xtr->map_servers){
            ms = (map_server_elt *)glist_entry_data(ms_it);
            timer_arg = timer_map_reg_argument_new_init(mle,ms);
            timer = oor_timer_with_nonce_new(MAP_REGISTER_TIMER, xtr, map_register_cb,
                    timer_arg,(oor_timer_del_cb_arg_fn)timer_map_reg_arg_free);
            htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
            map_register_cb(timer);
        }
    } local_map_db_foreach_end;

    return(GOOD);
}

int
program_map_register_for_mapping(lisp_xtr_t *xtr, map_local_entry_t *mle)
{
    oor_timer_t *timer;
    timer_map_reg_argument *timer_arg;
    map_server_elt *ms;
    glist_entry_t *ms_it;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }

    /* Cancel timers associated to the map register of the local map entry */
    stop_timers_of_type_from_obj(mle,MAP_REGISTER_TIMER,ptrs_to_timers_ht, nonces_ht);
    /* Configure map register for each map server */
    glist_for_each_entry(ms_it,xtr->map_servers){
        ms = (map_server_elt *)glist_entry_data(ms_it);
        timer_arg = timer_map_reg_argument_new_init(mle,ms);
        timer = oor_timer_with_nonce_new(MAP_REGISTER_TIMER, xtr, map_register_cb,
                timer_arg,(oor_timer_del_cb_arg_fn)timer_map_reg_arg_free);
        htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
        map_register_cb(timer);
    }

    return(GOOD);
}

static int
encap_map_register_cb(oor_timer_t *timer)
{
    timer_encap_map_reg_argument *timer_arg = oor_timer_cb_argument(timer);
    nonces_list_t *nonces_lst = oor_timer_nonces(timer);
    lisp_xtr_t *xtr = oor_timer_owner(timer);
    mapping_t *map = map_local_entry_mapping(timer_arg->mle);
    map_server_elt *ms = timer_arg->ms;
    lisp_addr_t *etr_addr = locator_addr(timer_arg->src_loct);
    lisp_addr_t *rtr_addr = timer_arg->rtr_rloc;
    uint64_t nonce;

    if ((nonces_list_size(nonces_lst) -1) < xtr->probe_retries){
        nonce = nonce_new();
        if (build_and_send_encap_map_reg(xtr, map, ms, etr_addr, rtr_addr, nonce) != GOOD){
            return (BAD);
        }
        if (nonces_list_size(nonces_lst) > 0) {
            OOR_LOG(LDBG_1,"Sent Retry Encap Map-Register for mapping %s to MS %s from RLOC %s through RTR %s"
                    "(%d retries)", lisp_addr_to_char(mapping_eid(map)), lisp_addr_to_char(ms->address),
                    lisp_addr_to_char(etr_addr),lisp_addr_to_char(rtr_addr),nonces_list_size(nonces_lst));
        } else {
            OOR_LOG(LDBG_1,"Sent Encap Map-Register for mapping %s to MS %s from RLOC %s through RTR %s"
                    , lisp_addr_to_char(mapping_eid(map)),lisp_addr_to_char(ms->address),
                    lisp_addr_to_char(etr_addr),lisp_addr_to_char(rtr_addr));
        }
        htable_nonces_insert(nonces_ht, nonce,nonces_lst);
        oor_timer_start(timer, OOR_INITIAL_MREG_TIMEOUT);
        return (GOOD);
    }else{
        /* If we have reached maximum number of retransmissions, change remote
         *  locator status */

        /* Reprogram time for next Map Register interval */
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        oor_timer_start(timer, MAP_REGISTER_INTERVAL);
        OOR_LOG(LDBG_1,"Encap Map-Register for mapping %s to MS %s from RLOC %s through RTR %s not received reply."
                " Retry in %d seconds", lisp_addr_to_char(mapping_eid(map)),lisp_addr_to_char(ms->address),
                lisp_addr_to_char(etr_addr),lisp_addr_to_char(rtr_addr), MAP_REGISTER_INTERVAL);

        return (BAD);
    }
}


int
program_encap_map_reg_of_loct_for_map(lisp_xtr_t *xtr, map_local_entry_t *mle,
        locator_t *src_loct)
{
    oor_timer_t *timer;
    timer_encap_map_reg_argument *timer_arg;
    map_server_elt *ms;
    glist_t *timers_lst, *rtr_addr_lst;
    glist_entry_t *ms_it, *timers_it, *rtr_it;
    lisp_addr_t *rtr_addr;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }
    /*
     * We configure the timers using the map_local_entry_t pointer instead of locator
     * as we want to isolate locatars form timers
     */

    /* Cancel timers associated to encap map register associated to the locator */
    timers_lst = htable_ptrs_timers_get_timers_of_type_from_obj(ptrs_to_timers_ht, mle, ENCAP_MAP_REGISTER_TIMER);

    glist_for_each_entry(timers_it,timers_lst){
        timer = (oor_timer_t *)glist_entry_data(timers_it);
        timer_arg = oor_timer_cb_argument(timer);
        if(src_loct == timer_arg->src_loct){
            stop_timer_from_obj(mle,timer,ptrs_to_timers_ht, nonces_ht);
            // Continue processing as it could be more than one map server, RTR
        }
    }
    glist_destroy(timers_lst);
    /* Configure encap map register for each RTR  and MS*/
    rtr_addr_lst = mle_rtr_addr_list(mle);
    glist_for_each_entry(rtr_it,rtr_addr_lst){
        rtr_addr = (lisp_addr_t *)glist_entry_data(rtr_it);
        glist_for_each_entry(ms_it,xtr->map_servers){
            ms = (map_server_elt *)glist_entry_data(ms_it);
            timer_arg = timer_encap_map_reg_argument_new_init(mle,ms,src_loct,rtr_addr);
            timer = oor_timer_with_nonce_new(ENCAP_MAP_REGISTER_TIMER, xtr, encap_map_register_cb,
                    timer_arg,(oor_timer_del_cb_arg_fn)timer_encap_map_reg_arg_free);
            htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
            encap_map_register_cb(timer);
        }
    }
    glist_destroy(rtr_addr_lst);
    return(GOOD);
}

static int
info_request_cb(oor_timer_t *timer)
{
    timer_inf_req_argument *timer_arg = oor_timer_cb_argument(timer);
    nonces_list_t *nonces_lst = oor_timer_nonces(timer);
    lisp_xtr_t *xtr = oor_timer_owner(timer);
    mapping_t *map = map_local_entry_mapping(timer_arg->mle);
    locator_t *loct = timer_arg->loct;
    map_server_elt *ms = timer_arg->ms;
    uint64_t nonce;

    if ((nonces_list_size(nonces_lst) -1) < xtr->map_request_retries){
        nonce = nonce_new();
        if (nonces_list_size(nonces_lst) > 0) {
            OOR_LOG(LDBG_1,"Sent Info Request retry for mapping %s to %s from locator %s"
                    "(%d retries)", lisp_addr_to_char(mapping_eid(map)),
                    lisp_addr_to_char(ms->address), lisp_addr_to_char(locator_addr(loct)),
                    nonces_list_size(nonces_lst));
        } else {
            timer_encap_map_reg_stop_using_locator(timer_arg->mle, loct);
            OOR_LOG(LDBG_1,"Sent Info Request for mapping %s to %s from locator %s",
                    lisp_addr_to_char(mapping_eid(map)),lisp_addr_to_char(ms->address),
                    lisp_addr_to_char(locator_addr(loct)));
        }

        if (build_and_send_info_req(xtr, map, loct, ms, nonce) != GOOD){
            return (BAD);
        }

        htable_nonces_insert(nonces_ht, nonce,nonces_lst);
        oor_timer_start(timer, OOR_INITIAL_INF_REQ_TIMEOUT);
        return (GOOD);
    }else{
        /* We reached maximum number of retransmissions */

        /* Reprogram time for next Info Request interval */
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        oor_timer_start(timer, OOR_SLEEP_INF_REQ_TIMEOUT);
        OOR_LOG(LWRN,"Info Request of %s to %s from locator %s not received reply. Retry in %d seconds",
                lisp_addr_to_char(mapping_eid(map)), lisp_addr_to_char(ms->address),
                lisp_addr_to_char(locator_addr(loct)), OOR_SLEEP_INF_REQ_TIMEOUT);

        return (BAD);
    }
}

int
program_info_req_per_loct(lisp_xtr_t *xtr, map_local_entry_t *mle, locator_t *loct)
{
    oor_timer_t *timer;
    timer_inf_req_argument *timer_arg;
    map_server_elt *ms;
    glist_entry_t *ms_it;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }
    /* Program info request for each Map Server */
    glist_for_each_entry(ms_it,xtr->map_servers){
        ms = (map_server_elt *)glist_entry_data(ms_it);
        timer_arg = timer_inf_req_argument_new_init(mle,loct,ms);
        timer = oor_timer_with_nonce_new(INFO_REQUEST_TIMER, xtr, info_request_cb,
                timer_arg,(oor_timer_del_cb_arg_fn)timer_inf_req_arg_free);
        htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
        oor_timer_start(timer, OOR_INF_REQ_HANDOVER_TIMEOUT);
    }

    return(GOOD);
}

int
program_initial_info_request_process(lisp_xtr_t *xtr)
{
    void *map_local_entry_it;
    oor_timer_t *timer;
    timer_inf_req_argument *timer_arg;
    map_local_entry_t *mle;
    mapping_t *map;
    locator_t *loct;
    map_server_elt *ms;
    glist_entry_t *ms_it;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }

    local_map_db_foreach_entry(xtr->local_mdb, map_local_entry_it) {
        mle = (map_local_entry_t *)map_local_entry_it;
        map = map_local_entry_mapping(mle);
        /* Cancel timers associated to the info request process of the local map entry */
        stop_timers_of_type_from_obj(mle,INFO_REQUEST_TIMER,ptrs_to_timers_ht, nonces_ht);
        mapping_foreach_active_locator(map,loct){
            glist_for_each_entry(ms_it,xtr->map_servers){
                ms = (map_server_elt *)glist_entry_data(ms_it);
                timer_arg = timer_inf_req_argument_new_init(mle,loct,ms);
                timer = oor_timer_with_nonce_new(INFO_REQUEST_TIMER, xtr, info_request_cb,
                        timer_arg,(oor_timer_del_cb_arg_fn)timer_inf_req_arg_free);
                htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
                info_request_cb(timer);
            }
        }mapping_foreach_active_locator_end;
    } local_map_db_foreach_end;

    return(GOOD);
}

static int
rloc_probing_cb(oor_timer_t *timer)
{
    timer_rloc_probe_argument *rparg = oor_timer_cb_argument(timer);
    nonces_list_t *nonces_lst = oor_timer_nonces(timer);
    lisp_xtr_t *xtr = oor_timer_owner(timer);
    mapping_t *map = mcache_entry_mapping(rparg->mce);
    locator_t *loct = rparg->locator;
    lisp_addr_t * drloc;
    uint64_t nonce;
    mcache_entry_t * mce;

    // XXX alopez -> What we have to do with ELP and probe bit
    drloc = xtr->fwd_policy->get_fwd_ip_addr(locator_addr(loct), ctrl_rlocs(xtr->super.ctrl));

    if ((nonces_list_size(nonces_lst) -1) < xtr->probe_retries){
        nonce = nonce_new();
        if (rloc_probing(xtr, map,loct,nonce) != GOOD){
                   return (BAD);
        }
        if (nonces_list_size(nonces_lst) > 0) {
            OOR_LOG(LDBG_1,"Retry Map-Request Probe for locator %s and "
                    "EID: %s (%d retries)", lisp_addr_to_char(drloc),
                    lisp_addr_to_char(mapping_eid(map)), nonces_list_size(nonces_lst));
        } else {
            OOR_LOG(LDBG_1,"Map-Request Probe for locator %s and "
                    "EID: %s", lisp_addr_to_char(drloc),
                    lisp_addr_to_char(mapping_eid(map)));
        }
        htable_nonces_insert(nonces_ht, nonce,nonces_lst);
        oor_timer_start(timer, xtr->probe_retries_interval);
        return (GOOD);
    }else{
        /* If we have reached maximum number of retransmissions, change remote
         *  locator status */
        if (locator_state(loct) == UP) {
            locator_set_state(loct, DOWN);
            OOR_LOG(LDBG_1,"rloc_probing: No Map-Reply Probe received for locator"
                    " %s and EID: %s -> Locator state changes to DOWN",
                    lisp_addr_to_char(drloc), lisp_addr_to_char(mapping_eid(map)));

            /* [re]Calculate forwarding info  if it has been a change
             * of status*/
            mce = mcache_lookup_exact(xtr->map_cache,mapping_eid(map));
            if (mce == NULL){
                /* It is a PeTR RLOC */
                if ( mcache_entry_mapping(xtr->petrs) != map ){
                    OOR_LOG(LERR,"rloc_probing: No map cache entry for EID %s. It should never happend",
                            lisp_addr_to_char(mapping_eid(map)));
                    return (BAD);
                }
                mce = xtr->petrs;
            }

            xtr->fwd_policy->updated_map_cache_inf(xtr->fwd_policy_dev_parm,mce);
        }

        /* Reprogram time for next probe interval */
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        oor_timer_start(timer, xtr->probe_interval);
        OOR_LOG(LDBG_2,"Reprogramed RLOC probing of the locator %s of the EID %s "
                "in %d seconds", lisp_addr_to_char(drloc),
                lisp_addr_to_char(mapping_eid(map)), xtr->probe_interval);

        return (BAD);
    }
}

/* Send a Map-Request probe to check status of 'loc'. If the number of
 * retries without answer is higher than rloc_probe_retries. Change the status
 * of the 'loc' to down */
static int
rloc_probing(lisp_xtr_t *xtr, mapping_t *map, locator_t *loc, uint64_t nonce)
{
    uconn_t uc;
    lisp_addr_t * deid = NULL;
    lisp_addr_t * drloc = NULL;
    lisp_addr_t empty;
    lbuf_t * b = NULL;
    glist_t * rlocs = NULL;
    void * hdr = NULL;
    int ret;

    deid = mapping_eid(map);

    // XXX alopez -> What we have to do with ELP and probe bit
    drloc = xtr->fwd_policy->get_fwd_ip_addr(locator_addr(loc), ctrl_rlocs(xtr->super.ctrl));
    lisp_addr_set_lafi(&empty, LM_AFI_NO_ADDR);

    rlocs = ctrl_default_rlocs(xtr->super.ctrl);
    b = lisp_msg_mreq_create(&empty, rlocs, deid);
    glist_destroy(rlocs);
    if (b == NULL){
        return (BAD);
    }

    hdr = lisp_msg_hdr(b);
    MREQ_NONCE(hdr) = nonce;
    MREQ_RLOC_PROBE(hdr) = 1;

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
    ret = send_msg(&xtr->super, b, &uc);
    lisp_msg_destroy(b);

    return (ret);
}

static void
program_rloc_probing(lisp_xtr_t *xtr, mcache_entry_t *mce, locator_t *loc, int time)
{
    oor_timer_t *timer;
    timer_rloc_probe_argument *arg;


    arg = timer_rloc_probe_argument_new_init(mce,loc);
    timer = oor_timer_with_nonce_new(RLOC_PROBING_TIMER,xtr,rloc_probing_cb,
            arg,(oor_timer_del_cb_arg_fn)timer_rloc_probe_argument_free);
    htable_ptrs_timers_add(ptrs_to_timers_ht, mce, timer);

    oor_timer_start(timer, time);
    OOR_LOG(LDBG_2,"Programming probing of EID's %s locator %s (%d seconds)",
            lisp_addr_to_char(mapping_eid(mcache_entry_mapping(mce))),
            lisp_addr_to_char(locator_addr(loc)), time);

}

/* Program RLOC probing for each locator of the mapping */
static void
program_mce_rloc_probing(lisp_xtr_t *xtr, mcache_entry_t *mce)
{
	mapping_t *map;
    locator_t *locator;

    if (xtr->probe_interval == 0) {
        return;
    }
    /* Cancel previous RLOCs Probing associated to this mce */
    stop_timers_of_type_from_obj(mce,RLOC_PROBING_TIMER,ptrs_to_timers_ht, nonces_ht);

    map = mcache_entry_mapping(mce);
    /* Start rloc probing for each locator of the mapping */
    mapping_foreach_active_locator(map,locator){
    		// XXX alopez: Check if RLOB probing available for all LCAF. ELP RLOC Probing bit
    		program_rloc_probing(xtr, mce, locator, xtr->probe_interval);
    }mapping_foreach_active_locator_end;
}


int
tr_mcache_add_mapping(lisp_xtr_t *xtr, mapping_t *m)
{
    mcache_entry_t *mce;

    mce = mcache_entry_new();
    if (mce == NULL){
        return (BAD);
    }

    mcache_entry_init(mce, m);

    /* Precalculate routing information */
    if (xtr->fwd_policy->init_map_cache_policy_inf(xtr->fwd_policy_dev_parm,mce,
            xtr->fwd_policy->del_map_cache_policy_inf) != GOOD){
        OOR_LOG(LWRN, "tr_mcache_add_mapping: Couldn't initiate routing info for map cache entry %s!. Discarding it.",
                lisp_addr_to_char(mapping_eid(m)));
        mcache_entry_del(mce);
        return(BAD);
    }

    if (mcache_add_entry(xtr->map_cache, mapping_eid(m), mce) != GOOD) {
        OOR_LOG(LDBG_1, "tr_mcache_add_mapping: Couldn't add map cache entry %s to data base!. Discarding it.",
                lisp_addr_to_char(mapping_eid(m)));
        mcache_entry_del(mce);
        return(BAD);
    }

    mcache_entry_set_active(mce, ACTIVE);

    /* Reprogramming timers */
    mc_entry_start_expiration_timer(xtr, mce);

    /* RLOC probing timer */
    program_mce_rloc_probing(xtr, mce);

    return(GOOD);
}

int
tr_mcache_add_static_mapping(lisp_xtr_t *xtr, mapping_t *m)
{
    mcache_entry_t *mce = NULL;

    mce = mcache_entry_new();
    if (mce == NULL){
        return(BAD);
    }
    mcache_entry_init_static(mce, m);

    /* Precalculate routing information */
    if (xtr->fwd_policy->init_map_cache_policy_inf(xtr->fwd_policy_dev_parm,mce,
            xtr->fwd_policy->del_map_cache_policy_inf) != GOOD){
        OOR_LOG(LWRN, "tr_mcache_add_static_mapping: Couldn't initiate routing info for map cache entry %s!. Discarding it.",
                lisp_addr_to_char(mapping_eid(m)));
        mcache_entry_del(mce);
        return(BAD);
    }

    if (mcache_add_entry(xtr->map_cache, mapping_eid(m), mce) != GOOD) {
        OOR_LOG(LDBG_1, "tr_mcache_add_static_mapping: Couldn't add static map cache entry %s to data base!. Discarding it.",
                        lisp_addr_to_char(mapping_eid(m)));
        return(BAD);
    }

    program_mce_rloc_probing(xtr, mce);

    return(GOOD);
}

int
tr_mcache_remove_entry(lisp_xtr_t *xtr, mcache_entry_t *mce)
{
    void *data = NULL;
    lisp_addr_t *eid = mapping_eid(mcache_entry_mapping(mce));

    data = mcache_remove_entry(xtr->map_cache, eid);
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
int
xtr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t status)
{
    lisp_xtr_t * xtr = lisp_xtr_cast(dev);
    iface_locators * if_loct = NULL;
    locator_t * locator = NULL;
    map_local_entry_t * map_loc_e = NULL;
    glist_entry_t * it = NULL;
    glist_entry_t * it_m = NULL;

    if_loct = (iface_locators *)shash_lookup(xtr->iface_locators_table,iface_name);
    if (if_loct  == NULL){
        OOR_LOG(LDBG_2, "xtr_if_status_change: Iface %s not found in the list of ifaces for xTR device",
                iface_name);
        return (BAD);
    }
    /* Change the status of the affected locators */
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
        xtr->fwd_policy->updated_map_loc_inf(xtr->fwd_policy_dev_parm,map_loc_e);
    }

    if (xtr->super.mode == RTR_MODE && xtr->all_locs_map) {
        xtr->fwd_policy->updated_map_loc_inf(xtr->fwd_policy_dev_parm,xtr->all_locs_map);
    }

    xtr_iface_event_signaling(xtr, if_loct);

    return (GOOD);
}

int
xtr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status)
{
    lisp_xtr_t * xtr = lisp_xtr_cast(dev);
    iface_locators * if_loct = NULL;
    glist_t * loct_list = NULL;
    glist_t * locators = NULL;
    locator_t * locator = NULL;
    map_local_entry_t * map_loc_e = NULL;
    mapping_t * mapping = NULL;
    int afi = AF_UNSPEC;
    glist_entry_t * it = NULL;
    glist_entry_t * it_aux = NULL;
    glist_entry_t * it_m = NULL;
    lisp_addr_t ** prev_addr = NULL;

    if_loct = (iface_locators *)shash_lookup(xtr->iface_locators_table,iface_name);
    if (if_loct  == NULL){
        OOR_LOG(LDBG_2, "xtr_if_addr_update: Iface %s not found in the list of ifaces for xTR device",
                iface_name);
        return (BAD);
    }

    if (old_addr != NULL && lisp_addr_cmp(old_addr, new_addr) == 0){
        return (GOOD);
    }

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
        OOR_LOG(LDBG_2, "xtr_if_addr_update: Afi of the new address not known");
        return (BAD);
    }
    /* Update the address of the affected locators */
    glist_for_each_entry_safe(it,it_aux,locators){
        locator = (locator_t *)glist_entry_data(it);
        /* The locator was not active during init process */
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
                OOR_LOG(LDBG_2, "xtr_if_addr_change: A non active locator is duplicated. Removing it");
                loct_list = mapping_get_loct_lst_with_afi(mapping,LM_AFI_NO_ADDR,0);
                iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                glist_remove_obj_with_ptr(locator,loct_list);
                continue;
            }
            /* Activate locator */
            mapping_activate_locator(mapping,locator,new_addr);
            /* Recalculate forwarding info of the mappings with activated locators */
            xtr->fwd_policy->updated_map_loc_inf(xtr->fwd_policy_dev_parm,map_loc_e);

        }else{
            locator_clone_addr(locator,new_addr);
        }

    }
    /* Transition check */
    /* prev_addr is the previous address before starting the transition process */
    if (*prev_addr != NULL){
        if (lisp_addr_cmp(*prev_addr, new_addr) == 0){
            lisp_addr_del(*prev_addr);
            *prev_addr = NULL;
        }
    }else{
        if (old_addr != NULL){
            *prev_addr = lisp_addr_clone(old_addr);
        }else{
            *prev_addr = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
        }
    }
    /* Reorder locators */
    glist_for_each_entry(it_m, if_loct->map_loc_entries){
        map_loc_e = (map_local_entry_t *)glist_entry_data(it_m);
        mapping = map_local_entry_mapping(map_loc_e);
        mapping_sort_locators(mapping, new_addr);
    }

    if (xtr->super.mode == RTR_MODE && xtr->all_locs_map) {
        xtr->fwd_policy->updated_map_loc_inf(xtr->fwd_policy_dev_parm,xtr->all_locs_map);
    }

    xtr_iface_event_signaling(xtr, if_loct);

    return (GOOD);
}

int
xtr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    lisp_xtr_t * xtr = lisp_xtr_cast(dev);
    iface_locators * if_loct = NULL;

    if_loct = (iface_locators *)shash_lookup(xtr->iface_locators_table,iface_name);
    xtr_iface_event_signaling(xtr, if_loct);
    return (GOOD);
}

int
xtr_iface_event_signaling(lisp_xtr_t * xtr, iface_locators * if_loct)
{
    locator_t *loct;
    lisp_addr_t *loct_addr;
    map_local_entry_t *mle;
    glist_t *timers_lst;
    glist_entry_t *mle_it, *timer_it;
    mapping_t *map;
    oor_timer_t *timer;


    if(xtr->nat_aware == TRUE){
        if (glist_size(if_loct->ipv4_locators) == 0){
            return (GOOD);
        }
        loct = glist_first_data(if_loct->ipv4_locators);
        loct_addr = locator_addr(loct);
        if (lisp_addr_is_no_addr(loct_addr)==TRUE){
            return (GOOD);
        }
        glist_for_each_entry(mle_it,if_loct->map_loc_entries){
            mle = (map_local_entry_t *)glist_entry_data(mle_it);
            map = map_local_entry_mapping(mle);
            loct = mapping_get_loct_with_addr(map,loct_addr);

            /* Stop timers associtated with the locator */
            timer_inf_req_stop_using_locator(mle, loct);
            timer_encap_map_reg_stop_using_locator(mle, loct);

            if (locator_state(loct) == UP){
                OOR_LOG(LDBG_2,"xtr_if_event: Reconfiguring Info Request process for locator %s of "
                        "the mapping %s.", lisp_addr_to_char(loct_addr),
                        lisp_addr_to_char(mapping_eid(map)));
                program_info_req_per_loct(xtr, mle, loct);
            }else{
                /* Reprogram all the Encap Map Registers of the other interfaces associated to the mapping
                 * If status is up this process will be done when receiving the Info Reply*/
                timers_lst = htable_ptrs_timers_get_timers_of_type_from_obj(ptrs_to_timers_ht,
                           mle, ENCAP_MAP_REGISTER_TIMER);
                glist_for_each_entry(timer_it, timers_lst){
                    timer = (oor_timer_t *)glist_entry_data(timer_it);
                    oor_timer_start(timer, OOR_INF_REQ_HANDOVER_TIMEOUT);
                }
                glist_destroy(timers_lst);
            }
        }
    }else{
        program_smr(xtr, OOR_SMR_TIMEOUT);
    }
    return (GOOD);
}


static int
xtr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc)
{
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
        ret = tr_recv_map_reply(xtr, msg, uc);
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
        ret = tr_recv_info_nat(xtr, msg, uc);
        break;
    default:
        OOR_LOG(LDBG_1, "xTR: Unidentified type (%d) control message received",
                type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        OOR_LOG(LDBG_1,"xTR: Failed to process LISP control message");
        return (BAD);
    } else {
        OOR_LOG(LDBG_3, "xTR: Completed processing of LISP control message");
        return (ret);
    }
}

map_server_elt *
map_server_elt_new_init(lisp_addr_t *address,uint8_t key_type, char *key,
        uint8_t proxy_reply)
{
    map_server_elt *ms = NULL;
    ms = xzalloc(sizeof(map_server_elt));
    if (ms == NULL){
        OOR_LOG(LWRN,"Couldn't allocate memory for a map_server_elt structure");
        return (NULL);
    }
    ms->address     = lisp_addr_clone(address);
    ms->key_type    = key_type;
    ms->key         = strdup(key);
    ms->proxy_reply = proxy_reply;

    return (ms);
}

void
map_server_elt_del (map_server_elt *map_server)
{
    if (map_server == NULL){
        return;
    }
    lisp_addr_del (map_server->address);
    free(map_server->key);
    free(map_server);
}

static inline lisp_xtr_t *
lisp_xtr_cast(oor_ctrl_dev_t *dev)
{
    /* make sure */
    lm_assert(dev->ctrl_class == &xtr_ctrl_class);
    return(CONTAINER_OF(dev, lisp_xtr_t, super));
}

static oor_ctrl_dev_t *
xtr_ctrl_alloc()
{
    lisp_xtr_t *xtr;
    xtr = xzalloc(sizeof(lisp_xtr_t));
    return(&xtr->super);
}

static int
xtr_ctrl_construct(oor_ctrl_dev_t *dev)
{
    lisp_xtr_t *    xtr         = lisp_xtr_cast(dev);
    lisp_addr_t	    addr;
    mapping_t *     pxtr_map, *rtr_map;


    OOR_LOG(LDBG_1, "Creating map cache and local mapping database");

    /* set up databases */
    xtr->local_mdb = local_map_db_new();
    xtr->map_cache = mcache_new();
    xtr->map_servers = glist_new_managed((glist_del_fct)map_server_elt_del);
    xtr->map_resolvers = glist_new_managed((glist_del_fct)lisp_addr_del);
    xtr->pitrs = glist_new_managed((glist_del_fct)lisp_addr_del);
    xtr->petrs = mcache_entry_new();
    xtr->rtrs = mcache_entry_new();
    xtr->iface_locators_table = shash_new_managed((free_value_fn_t)iface_locators_del);

    if (!xtr->local_mdb || !xtr->map_cache || !xtr->map_servers ||
            !xtr->map_resolvers || !xtr->pitrs || !xtr->petrs ||
            !xtr->rtrs || !xtr->iface_locators_table) {
        return(BAD);
    }

    lisp_addr_ip_from_char("0.0.0.0", &addr);
    pxtr_map = mapping_new_init(&addr);
    mcache_entry_init_static(xtr->petrs, pxtr_map);
    rtr_map = mapping_new_init(&addr);
    mcache_entry_init_static(xtr->rtrs, rtr_map);

    OOR_LOG(LDBG_1, "Finished Constructing xTR");

    return(GOOD);
}

static void
xtr_ctrl_destruct(oor_ctrl_dev_t *dev)
{
    map_local_entry_t * map_loc_e = NULL;
    void *it = NULL;
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);

    local_map_db_foreach_entry(xtr->local_mdb, it) {
        map_loc_e = (map_local_entry_t *)it;
        ctrl_unregister_eid_prefix(dev,map_local_entry_eid(map_loc_e));
    } local_map_db_foreach_end;

    if (xtr->fwd_policy_dev_parm != NULL){
        xtr->fwd_policy->del_dev_policy_inf(xtr->fwd_policy_dev_parm);
    }

    shash_destroy(xtr->iface_locators_table);
    mcache_del(xtr->map_cache);
    mcache_entry_del(xtr->petrs);
    mcache_entry_del(xtr->rtrs);
    local_map_db_del(xtr->local_mdb);
    glist_destroy(xtr->map_resolvers);
    glist_destroy(xtr->pitrs);
    glist_destroy(xtr->map_servers);
    if (xtr->super.mode == RTR_MODE){
        map_local_entry_del(xtr->all_locs_map);
    }
    oor_timer_stop(xtr->smr_timer);
    OOR_LOG(LDBG_1,"xTR device destroyed");
}

static void
xtr_ctrl_dealloc(oor_ctrl_dev_t *dev) {
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    free(xtr);
    OOR_LOG(LDBG_1, "Freed xTR ...");
}

static void
xtr_run(lisp_xtr_t *xtr)
{
    map_local_entry_t *map_loc_e;
    locator_t *loct;
    void *it;
    int num_eids = 0;

    if (xtr->super.mode == MN_MODE){
        OOR_LOG(LDBG_1, "\nStarting xTR MN ...\n");
    }
    if (xtr->super.mode == xTR_MODE){
        OOR_LOG(LDBG_1, "\nStarting xTR ...\n");
    }

    if (glist_size(xtr->map_servers) == 0) {
        OOR_LOG(LCRIT, "**** NO MAP SERVER CONFIGURED. Your EID will not be registered in the Mapping System.");
        sleep(3);
    }

    if (glist_size(xtr->map_resolvers) == 0) {
        OOR_LOG(LCRIT, "**** NO MAP RESOLVER CONFIGURED. You can not request mappings to the mapping system");
        sleep(3);
    }

    if (mcache_has_locators(xtr->petrs) == FALSE) {
        OOR_LOG(LWRN, "No Proxy-ETR defined. Packets to non-LISP destinations "
                "will be forwarded natively (no LISP encapsulation). This "
                "may prevent mobility in some scenarios.");
        sleep(3);
    } else {
        xtr->fwd_policy->updated_map_cache_inf(xtr->fwd_policy_dev_parm,xtr->petrs);
    }

    /* Check configured parameters when NAT-T activated. */
    if (xtr->nat_aware == TRUE) {
        if (glist_size(xtr->map_servers) > 1
                || lisp_addr_ip_afi(((map_server_elt *)glist_first_data(xtr->map_servers))->address) != AF_INET) {
            OOR_LOG(LERR, "NAT aware on -> This version of OOR is limited to one IPv4 Map Server.");
            exit_cleanup();
        }

        if (glist_size(xtr->map_resolvers) > 0) {
            OOR_LOG(LINF, "NAT aware on -> No Map Resolver will be used.");
            glist_remove_all(xtr->map_resolvers);
        }
        if (xtr->probe_interval > 0) {
            xtr->probe_interval = 0;
            OOR_LOG(LINF, "NAT aware on -> disabling RLOC Probing");
        }
        /* Set local locators to unreachable*/
        local_map_db_foreach_entry(xtr->local_mdb, it) {
            map_loc_e = (map_local_entry_t *)it;
            num_eids++;
            if (num_eids > 1){
                OOR_LOG(LERR, "NAT aware on -> Only one EID prefix supported.");
                exit_cleanup();
            }
            mapping_foreach_locator(map_local_entry_mapping(map_loc_e),loct){
                locator_set_R_bit(loct,0);
                /* We don't support LCAF in NAT */
                if (lisp_addr_lafi(locator_addr(loct)) == LM_AFI_LCAF){
                    OOR_LOG(LERR, "NAT aware on -> This version of OOR doesn't support LCAF when NAT is enabled.");
                    exit_cleanup();
                }
            }mapping_foreach_locator_end;
        } local_map_db_foreach_end;

        xtr->fwd_policy->init_map_cache_policy_inf(xtr->fwd_policy_dev_parm,xtr->rtrs,
                xtr->fwd_policy->del_map_cache_policy_inf);

    }

    if (xtr->super.mode == MN_MODE){
        /* Check number of EID prefixes */

        if (local_map_db_num_ip_eids(xtr->local_mdb, AF_INET) > 1) {
            OOR_LOG(LERR, "OOR in mobile node mode only supports one IPv4 EID "
                    "prefix and one IPv6 EID prefix");
            exit_cleanup();
        }
        if (local_map_db_num_ip_eids(xtr->local_mdb, AF_INET6) > 1) {
            OOR_LOG(LERR, "OOR in mobile node mode only supports one IPv4 EID "
                    "prefix and one IPv6 EID prefix");
            exit_cleanup();
        }
    }

    OOR_LOG(LDBG_1, "****** Summary of the xTR configuration ******");
    local_map_db_dump(xtr->local_mdb, LDBG_1);
    mcache_dump_db(xtr->map_cache, LDBG_1);

    map_servers_dump(xtr, LDBG_1);
    OOR_LOG(LDBG_1, "************* %13s ***************", "Map Resolvers");
        glist_dump(xtr->map_resolvers, (glist_to_char_fct)lisp_addr_to_char, LDBG_1);
    proxy_etrs_dump(xtr, LDBG_1);
    OOR_LOG(LDBG_1, "************* %13s ***************", "Proxy-ITRs");
    glist_dump(xtr->pitrs, (glist_to_char_fct)lisp_addr_to_char, LDBG_1);

    local_map_db_foreach_entry(xtr->local_mdb, it) {
        /* Register EID prefix to control */
        map_loc_e = (map_local_entry_t *)it;
        ctrl_register_eid_prefix(&(xtr->super),map_local_entry_eid(map_loc_e));
        /* Update forwarding info of the local mappings. When it is created during conf file process,
         * the local rlocs are not set. For this reason should be calculated again. It can not be removed
         * from the conf file process -> In future could appear fwd_map_info parameters*/
        xtr->fwd_policy->updated_map_loc_inf(xtr->fwd_policy_dev_parm,map_loc_e);

    } local_map_db_foreach_end;


    if (xtr->nat_aware){
        program_initial_info_request_process(xtr);
    }else{
        /*  Register to the Map-Server(s) */
        program_map_register(xtr);
        /* SMR proxy-ITRs list to be updated with new mappings */
        program_smr(xtr, 1);
    }

    /* RLOC Probing proxy ETRs */
    program_mce_rloc_probing(xtr, xtr->petrs);
}

static void
rtr_run(lisp_xtr_t *xtr)
{
    mapping_t * mapping = NULL;

    OOR_LOG(LINF, "\nStarting RTR ...\n");

    if (xtr->nat_aware == TRUE){
        OOR_LOG(LERR, "An RTR cannot be behind a NAT box. Disable nat_traversal_support ...");
        exit_cleanup();
    }


    if (glist_size(xtr->map_resolvers) == 0) {
        OOR_LOG(LCRIT, "**** NO MAP RESOLVER CONFIGURES. You can not request mappings to the mapping system");
        sleep(3);
    }

    OOR_LOG(LINF, "****** Summary of the configuration ******");
    local_map_db_dump(xtr->local_mdb, LINF);
    mcache_dump_db(xtr->map_cache, LINF);
    if (xtr->all_locs_map) {
        mapping = map_local_entry_mapping(xtr->all_locs_map);
        OOR_LOG(LINF, "Active interfaces status");
        xtr->fwd_policy->updated_map_loc_inf(xtr->fwd_policy_dev_parm,xtr->all_locs_map);
        OOR_LOG(LINF, "%s", mapping_to_char(mapping));
    }
}

static void
xtr_ctrl_run(oor_ctrl_dev_t *dev)
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
        .if_link_update = xtr_if_link_update,
        .if_addr_update = xtr_if_addr_update,
        .route_update = xtr_route_update,
        .get_fwd_entry = tr_get_forwarding_entry
};


static void
proxy_etrs_dump(lisp_xtr_t *xtr, int log_level)
{
	locator_t *locator = NULL;

    OOR_LOG(log_level, "************************* Proxy ETRs List ****************************");
    OOR_LOG(log_level, "|               Locator (RLOC)            | Status | Priority/Weight |");

	/* Start rloc probing for each locator of the mapping */
	mapping_foreach_active_locator(mcache_entry_mapping(xtr->petrs),locator){
			locator_to_char(locator);
	}mapping_foreach_active_locator_end;
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

    OOR_LOG(log_level, "******************* Map-Servers list ********************************");
    OOR_LOG(log_level, "|               Locator (RLOC)            |       Key Type          |");

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
        OOR_LOG(log_level, "%s", str);
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
//

static fwd_info_t *
tr_get_fwd_entry(lisp_xtr_t *xtr, packet_tuple_t *tuple)
{
    fwd_info_t  *fwd_info;
    mcache_entry_t *mce = NULL;
    map_local_entry_t *map_loc_e = NULL;
    mapping_t *dmap = NULL;
    lisp_addr_t *eid;
    lisp_addr_t *src_eid, *dst_eid;
    int iidmlen;

    fwd_info = fwd_info_new();
    if(fwd_info == NULL){
        OOR_LOG(LWRN, "tr_get_fwd_entry: Couldn't allocate memory for fwd_info_t");
        return (NULL);
    }

    if (xtr->super.mode == xTR_MODE || xtr->super.mode == MN_MODE) {
        /* lookup local mapping for source EID */
        map_loc_e = local_map_db_lookup_eid(xtr->local_mdb, &tuple->src_addr, FALSE);
        if (map_loc_e == NULL){
            OOR_LOG(LDBG_3, "The source address %s is not a local EID", lisp_addr_to_char(&tuple->src_addr));
            return (fwd_info);
        }
        eid = map_local_entry_eid(map_loc_e);

        if (lisp_addr_is_iid(eid)){
            tuple->iid = lcaf_iid_get_iid(lisp_addr_get_lcaf(eid));
        }else{
            tuple->iid = 0;
        }
    }else {
        /* When RTR, iid is obtained from the desencapsulated packet */
        map_loc_e = xtr->all_locs_map;
    }
    if (tuple->iid > 0){
        iidmlen = (lisp_addr_ip_afi(&tuple->src_addr) == AF_INET) ? 32: 128;
        src_eid = lisp_addr_new_init_iid(tuple->iid, &tuple->src_addr, iidmlen);
        dst_eid = lisp_addr_new_init_iid(tuple->iid, &tuple->dst_addr, iidmlen);
    }else{
        src_eid = lisp_addr_clone(&tuple->src_addr);
        dst_eid = lisp_addr_clone(&tuple->dst_addr);
    }

    if (xtr->nat_aware){
        mce = xtr->rtrs;
    }else{
        mce = mcache_lookup(xtr->map_cache, dst_eid);
    }
    if (!mce) {
        /* No map cache entry, initiate map cache miss process */
        fwd_info->temporal = TRUE;
        OOR_LOG(LDBG_1, "No map cache for EID %s. Sending Map-Request!",
                lisp_addr_to_char(dst_eid));
        handle_map_cache_miss(xtr, dst_eid, src_eid);
        /* If the EID is not from a iid net, try to fordward to the PeTR */
        if (lisp_addr_is_iid(dst_eid) == FALSE){
            if (mcache_has_locators(xtr->petrs) == FALSE){
                OOR_LOG(LDBG_3, "Trying to forward to PETR but none found ...");
                lisp_addr_del(src_eid);
                lisp_addr_del(dst_eid);
                return (fwd_info);
            }
            OOR_LOG(LDBG_3, "Forwarding packet to PeTR");
            fwd_info->neg_map_reply_act = ACT_NATIVE_FWD;
            mce = xtr->petrs;
        }else{
            lisp_addr_del(src_eid);
            lisp_addr_del(dst_eid);
            fwd_info->neg_map_reply_act = ACT_NO_ACTION;
            return (fwd_info);
        }
    } else if (mce->active == NOT_ACTIVE) {
        fwd_info->temporal = TRUE;
        OOR_LOG(LDBG_2, "Already sent Map-Request for %s. Waiting for reply!",
                lisp_addr_to_char(dst_eid));
        /* If the EID is not from a iid net, try to fordward to the PeTR */
        if (lisp_addr_is_iid(dst_eid) == FALSE){
            if (mcache_has_locators(xtr->petrs) == FALSE){
                OOR_LOG(LDBG_3, "Trying to forward to PETR but none found ...");
                lisp_addr_del(src_eid);
                lisp_addr_del(dst_eid);
                return (fwd_info);
            }
            OOR_LOG(LDBG_3, "Forwarding packet to PeTR");
            fwd_info->neg_map_reply_act = ACT_NATIVE_FWD;
            mce = xtr->petrs;
        }else{
            lisp_addr_del(src_eid);
            lisp_addr_del(dst_eid);
            fwd_info->neg_map_reply_act = ACT_NO_ACTION;
            return (fwd_info);
        }
    }

    dmap = mcache_entry_mapping(mce);
    if (mapping_locator_count(dmap) == 0) {
        OOR_LOG(LDBG_3, "Destination %s has a NEGATIVE mapping!",
                lisp_addr_to_char(dst_eid));
        switch (mapping_action(dmap)){
        case ACT_NO_ACTION:
            lisp_addr_del(src_eid);
            lisp_addr_del(dst_eid);
            fwd_info->neg_map_reply_act = ACT_NO_ACTION;
            return (fwd_info);
        case ACT_NATIVE_FWD:
            if (mcache_has_locators(xtr->petrs) == FALSE){
                OOR_LOG(LDBG_3, "Trying to forward to PETR but none found ...");
                lisp_addr_del(src_eid);
                lisp_addr_del(dst_eid);
                return (fwd_info);
            }
            OOR_LOG(LDBG_3, "Forwarding packet to PeTR");
            fwd_info->neg_map_reply_act = ACT_NATIVE_FWD;
            mce = xtr->petrs;
            break;
        case ACT_SEND_MREQ:
            // TODO: To be implemented. Now drop paquet
            OOR_LOG(LDBG_2, "Recived a packet of an entry with ACT send map req. Drop packet");
            lisp_addr_del(src_eid);
            lisp_addr_del(dst_eid);
            fwd_info->neg_map_reply_act = ACT_NO_ACTION;
            return (fwd_info);
        case ACT_DROP:
            lisp_addr_del(src_eid);
            lisp_addr_del(dst_eid);
            fwd_info->neg_map_reply_act = ACT_DROP;
            return (fwd_info);
        }
    }


    xtr->fwd_policy->policy_get_fwd_info(
            xtr->fwd_policy_dev_parm,
            map_local_entry_fwd_info(map_loc_e),
            mcache_entry_routing_info(mce),
            tuple, fwd_info);


    /* Problems obtaining fwd entry */
    if (!fwd_info->fwd_info){
        /* If we didn't try to send to a PeTR, try now */
        if (mce != xtr->petrs){
            if (lisp_addr_is_iid(dst_eid) == FALSE){
                if (mcache_has_locators(xtr->petrs) == TRUE){
                    OOR_LOG(LDBG_3, "Forwarding packet to PeTR");
                    mce = xtr->petrs;
                    xtr->fwd_policy->policy_get_fwd_info(
                            xtr->fwd_policy_dev_parm,
                            map_local_entry_fwd_info(map_loc_e),
                            mcache_entry_routing_info(mce),
                            tuple, fwd_info);
                    if (!fwd_info->fwd_info){
                        OOR_LOG(LDBG_3, "tr_get_fwd_entry: No PETR compatible with local locators afi");
                        fwd_info->neg_map_reply_act = ACT_NATIVE_FWD;
                    }
                }else{
                    OOR_LOG(LDBG_3, "tr_get_fwd_entry: No compatible src and dst rlocs. No PeTRs configured");
                    fwd_info->neg_map_reply_act = ACT_NATIVE_FWD;
                }
            }else{
                fwd_info->neg_map_reply_act = ACT_NO_ACTION;
            }
        }else{
            OOR_LOG(LDBG_3, "tr_get_fwd_entry: No PETR compatible with local locators afi");
            fwd_info->neg_map_reply_act = ACT_NATIVE_FWD;
        }
    }
    /* Assign encapsulated that should be used */
    fwd_info->encap = xtr->encap_type;
    lisp_addr_del(src_eid);
    lisp_addr_del(dst_eid);
    return (fwd_info);
}


static fwd_info_t *
tr_get_forwarding_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    lisp_xtr_t *xtr;

    xtr = lisp_xtr_cast(dev);

    return(tr_get_fwd_entry(xtr, tuple));
}

/*
 * Return the list of locators from the local mappings containing addr
 * @param local_db Database where to search locators
 * @param addr Address used during the search
 * @return Generic list containg locator_t elements
 */
glist_t *
get_local_locators_with_address(local_map_db_t *local_db, lisp_addr_t *addr)
{
    glist_t * locators = NULL;
    locator_t * locator = NULL;
    map_local_entry_t * map_loc_e = NULL;
    mapping_t * mapping = NULL;
    void * it = NULL;

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
get_map_loc_ent_containing_loct_ptr(local_map_db_t *local_db, locator_t *locator)
{
    map_local_entry_t *map_loc_e;
    map_local_entry_t *map_loc_e_res = NULL;
    mapping_t *mapping = NULL;
    uint8_t found = FALSE;
    void *it = NULL;
    local_map_db_foreach_entry_with_break(local_db, it, found) {
        map_loc_e = (map_local_entry_t *)it;
        mapping = map_local_entry_mapping(map_loc_e);
        if (mapping_has_locator(mapping, locator) == TRUE){
            found = TRUE;
            map_loc_e_res = map_loc_e;
        }
    } local_map_db_foreach_with_break_end(found);
    if (!map_loc_e_res){
        OOR_LOG(LDBG_2, "get_map_loc_ent_containing_loct_ptr: No mapping has been found with locator %s",
                lisp_addr_to_char(locator_addr(locator)));
    }
    return (map_loc_e_res);

}



/*
 * Return the list of mappings that has experimented changes in their
 * locators. At the same time iface_locators status is reseted
 * @param xtr
 * @return glist_t with the list of modified mappings (mapping_t *)
 */
glist_t *
get_map_local_entry_to_smr(lisp_xtr_t *xtr)
{
    glist_t * map_loc_e_to_smr = glist_new();//<map_local_entry_t>
    glist_t * iface_locators_list = NULL;
    iface_locators * if_loct = NULL;
    glist_entry_t * it = NULL;
    glist_entry_t * it_loc = NULL;
    glist_t * locators[2] = {NULL,NULL};
    map_local_entry_t * map_loc_e = NULL;
    locator_t * locator = NULL;
    int ctr;

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
    glist_entry_t * it = NULL;
    lisp_addr_t * addr = NULL;
    oor_ctrl_t * ctrl = NULL;
    int supported_afis;

    ctrl = xtr->super.ctrl;
    supported_afis = ctrl_supported_afis(ctrl);

    if ((supported_afis & IPv6_SUPPORT) != 0){
        glist_for_each_entry(it,xtr->map_resolvers){
            addr = (lisp_addr_t *)glist_entry_data(it);
            if (lisp_addr_ip_afi(addr) == AF_INET6){
                return (addr);
            }
        }
    }

    if ((supported_afis & IPv4_SUPPORT) != 0){
        glist_for_each_entry(it,xtr->map_resolvers){
            addr = (lisp_addr_t *)glist_entry_data(it);
            if (lisp_addr_ip_afi(addr) == AF_INET){
                return (addr);
            }
        }
    }

    OOR_LOG (LDBG_1,"get_map_resolver: No map resolver reachable");
    return (NULL);
}

// XXX This function is only used while we don't have support of L bit of ELPs
static int
mapping_has_elp_with_l_bit(mapping_t *map)
{
    glist_t *loct_list;
    locator_t *loct;
    lisp_addr_t *addr;
    elp_t * elp;
    elp_node_t *elp_node;
    glist_entry_t *loct_it;
    glist_entry_t *elp_n_it;

    loct_list = mapping_get_loct_lst_with_afi(map,LM_AFI_LCAF,LCAF_EXPL_LOC_PATH);
    if (loct_list == NULL){
        return (FALSE);
    }
    glist_for_each_entry(loct_it,loct_list){
        loct = (locator_t *)glist_entry_data(loct_it);
        addr = locator_addr(loct);
        elp = (elp_t *)lisp_addr_lcaf_addr(addr);
        glist_for_each_entry(elp_n_it,elp->nodes){
            elp_node = (elp_node_t *)glist_entry_data(elp_n_it);
            if (elp_node->L == true){
                return (TRUE);
            }
        }
    }

    return (FALSE);
}

timer_rloc_probe_argument *
timer_rloc_probe_argument_new_init(mcache_entry_t *mce,locator_t *locator)
{
    timer_rloc_probe_argument *timer_arg = xmalloc(sizeof(timer_rloc_probe_argument));
    timer_arg->mce = mce;
    timer_arg->locator = locator;
    return (timer_arg);
}

void
timer_rloc_probe_argument_free(timer_rloc_probe_argument *timer_arg){
    free (timer_arg);
}

timer_map_req_argument *
timer_map_req_arg_new_init(mcache_entry_t *mce,lisp_addr_t *src_eid)
{
    timer_map_req_argument *timer_arg = xmalloc(sizeof(timer_map_req_argument));
    timer_arg->mce = mce;
    timer_arg->src_eid = lisp_addr_clone(src_eid);

    return(timer_arg);
}

void
timer_map_req_arg_free(timer_map_req_argument * timer_arg)
{
    lisp_addr_del(timer_arg->src_eid);
    free(timer_arg);
}

timer_map_reg_argument *
timer_map_reg_argument_new_init(map_local_entry_t *mle,
        map_server_elt *ms)
{
    timer_map_reg_argument *timer_arg = xmalloc(sizeof(timer_map_reg_argument));
    timer_arg->mle = mle;
    timer_arg->ms = ms;

    return(timer_arg);
}

void
timer_map_reg_arg_free(timer_map_reg_argument * timer_arg)
{
    free(timer_arg);
}

timer_encap_map_reg_argument *
timer_encap_map_reg_argument_new_init(map_local_entry_t *mle,
        map_server_elt *ms, locator_t *src_loct, lisp_addr_t *rtr_addr)
{
    timer_encap_map_reg_argument *timer_arg = xmalloc(sizeof(timer_encap_map_reg_argument));
    timer_arg->mle = mle;
    timer_arg->ms = ms;
    timer_arg->src_loct = src_loct;
    timer_arg->rtr_rloc = lisp_addr_clone(rtr_addr);
    return(timer_arg);
}

void
timer_encap_map_reg_arg_free(timer_encap_map_reg_argument * timer_arg)
{
    lisp_addr_del(timer_arg->rtr_rloc);
    free(timer_arg);
}

/*
 * Stop all the timers of type ENCAP_MAP_REGISTER_TIMER associated with the map local entry
 * introduced as a parameter and using the specified locator.
 */
void
timer_encap_map_reg_stop_using_locator(map_local_entry_t *mle, locator_t *loct)
{
    glist_t *timers_lst;
    glist_entry_t *timer_it;
    oor_timer_t *timer;
    timer_encap_map_reg_argument * timer_arg;

    timers_lst = htable_ptrs_timers_get_timers_of_type_from_obj(ptrs_to_timers_ht,
            mle, ENCAP_MAP_REGISTER_TIMER);
    glist_for_each_entry(timer_it,timers_lst){
        timer = (oor_timer_t *)glist_entry_data(timer_it);
        timer_arg = (timer_encap_map_reg_argument *)oor_timer_cb_argument(timer);
        if (timer_arg->src_loct == loct){
            stop_timer_from_obj(mle,timer,ptrs_to_timers_ht,nonces_ht);
        }
    }
    glist_destroy(timers_lst);
}

timer_inf_req_argument *
timer_inf_req_argument_new_init(map_local_entry_t *mle, locator_t *loct,
        map_server_elt *ms)
{
    timer_inf_req_argument *timer_arg = xmalloc(sizeof(timer_inf_req_argument));
    timer_arg->mle = mle;
    timer_arg->loct = loct;
    timer_arg->ms = ms;
    return (timer_arg);
}

void
timer_inf_req_arg_free(timer_inf_req_argument * timer_arg)
{
    free(timer_arg);
}

/*
 * Stop all the timers of type INFO_REQUEST_TIMER associated with the map local entry
 * introduced as a parameter and using the specified locator.
 */
void
timer_inf_req_stop_using_locator(map_local_entry_t *mle, locator_t *loct)
{
    glist_t *timers_lst;
    glist_entry_t *timer_it;
    oor_timer_t *timer;
    timer_inf_req_argument * timer_arg;

    timers_lst = htable_ptrs_timers_get_timers_of_type_from_obj(ptrs_to_timers_ht,
            mle, INFO_REQUEST_TIMER);
    glist_for_each_entry(timer_it,timers_lst){
        timer = (oor_timer_t *)glist_entry_data(timer_it);
        timer_arg = (timer_inf_req_argument *)oor_timer_cb_argument(timer);
        if (timer_arg->loct == loct){
            stop_timer_from_obj(mle,timer,ptrs_to_timers_ht,nonces_ht);
        }
    }
    glist_destroy(timers_lst);
}
