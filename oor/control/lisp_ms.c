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

#include "lisp_ms.h"
#include "../defs.h"
#include "../lib/cksum.h"
#include "../lib/oor_log.h"
#include "../lib/prefixes.h"
#include "../lib/timers_utils.h"
#include "../lib/util.h"


static int ms_recv_map_request(lisp_ms_t *, lbuf_t *, void *, uconn_t*, uconn_t *);
static int ms_recv_map_register(lisp_ms_t *, lbuf_t *, void *, uconn_t*, uconn_t *);
static int ms_recv_enc_ctrl_msg(lisp_ms_t *ms, lbuf_t *msg, void **ecm_hdr, uconn_t *int_uc);
static int ms_recv_map_request(lisp_ms_t *ms, lbuf_t *buf,  void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc);
static int ms_recv_map_register(lisp_ms_t *, lbuf_t *,void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc);
static int ms_recv_msg(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);



static locator_t *
get_locator_with_afi(mapping_t *m, int afi)
{
	glist_t *loct_list = NULL;
	glist_entry_t *it_list = NULL;
	glist_entry_t *it_loct = NULL;
    locator_t *loct = NULL;
    lisp_addr_t *addr = NULL;
    int lafi = 0;
    int afi_type = 0;

    glist_for_each_entry(it_list,mapping_locators_lists(m)){
    	loct_list = (glist_t *)glist_entry_data(it_list);
    	locator_list_lafi_type(loct_list,&lafi,&afi_type);
    	if (lafi == LM_AFI_NO_ADDR || (lafi == LM_AFI_IP && afi_type != afi)){
    		continue;
    	}
    	glist_for_each_entry(it_loct,loct_list){
    		loct = (locator_t *)glist_entry_data(it_loct);
    		if (locator_state(loct) == DOWN){
    			continue;
    		}
    		addr = locator_addr(loct);
    		addr = lisp_addr_get_ip_addr(addr);
    		if (lisp_addr_ip_afi (addr) == afi){
    			return (loct);
    		}
    	}
    }

    return(NULL);
}

static int
get_etr_from_lcaf(lisp_addr_t *laddr, lisp_addr_t **dst)
{
    lcaf_addr_t *lcaf = NULL;
    elp_node_t *enode;

    lcaf = lisp_addr_get_lcaf(laddr);
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_EXPL_LOC_PATH:
        /* we're looking for the ETR, so the destination is the last elp hop */
        enode = glist_last_data(lcaf_elp_node_list(lcaf));
        *dst = enode->addr;
        break;
    default:
        *dst = NULL;
        OOR_LOG(LDBG_1, "get_locator_from_lcaf: Type % not supported!, ",
                lcaf_addr_get_type(lcaf));
        return (BAD);
    }
    return (GOOD);
}

/* forward encapsulated Map-Request to ETR */
static int
forward_mreq(lisp_ms_t *ms, lbuf_t *b, mapping_t *m)
{
	oor_ctrl_t *ctrl = NULL;
    lisp_addr_t *drloc = NULL;
    locator_t *loct = NULL;
    uconn_t fwd_uc;

    ctrl = ctrl_dev_get_ctrl_t(&(ms->super));

    if ((ctrl_supported_afis(ctrl) & IPv4_SUPPORT) != 0){
    	loct = get_locator_with_afi(m, AF_INET);
    }
    if (loct == NULL && (ctrl_supported_afis(ctrl) & IPv6_SUPPORT) != 0){
    	loct = get_locator_with_afi(m, AF_INET6);
    }
    if (loct == NULL){
    	OOR_LOG(LDBG_1, "Can't find valid RLOC to forward Map-Request to "
    	                "ETR. Discarding!");
    	return(BAD);
    }

    drloc = lisp_addr_get_ip_addr(locator_addr(loct));

    if (lisp_addr_lafi(drloc) == LM_AFI_LCAF) {
        get_etr_from_lcaf(drloc, &drloc);
    }

    OOR_LOG(LDBG_3, "Found xTR with locator %s to forward Encap Map-Request",
            lisp_addr_to_char(drloc));

    /* Set buffer to forward the encapsulated message*/
    lbuf_point_to_lisp_hdr(b);

    uconn_init(&fwd_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
    return(send_msg(&ms->super, b, &fwd_uc));
}


/* Called when the timer associated with a registered lisp site expires. */
static int
lsite_entry_expiration_timer_cb(oor_timer_t *t)
{
    lisp_reg_site_t *rsite = NULL;
    lisp_addr_t *addr = NULL;
    lisp_ms_t *ms = t->owner;

    rsite = oor_timer_cb_argument(t);
    addr = mapping_eid(rsite->site_map);
    OOR_LOG(LDBG_1,"Registration of site with EID %s timed out",
            lisp_addr_to_char(addr));

    mdb_remove_entry(ms->reg_sites_db, addr);
    lisp_reg_site_del(rsite);
    ms_dump_registered_sites(ms, LDBG_3);
    return(GOOD);
}

static void
lsite_entry_start_expiration_timer(lisp_ms_t *ms, lisp_reg_site_t *rsite)
{
    oor_timer_t *timer;


    timer = oor_timer_without_nonce_new(REG_SITE_EXPRY_TIMER, ms, lsite_entry_expiration_timer_cb,
            rsite, NULL);
    htable_ptrs_timers_add(ptrs_to_timers_ht,rsite, timer);

    /* Give a 2s margin before purging the registered site */
    oor_timer_start(timer, MS_SITE_EXPIRATION + 2);

    OOR_LOG(LDBG_2,"The map cache entry of EID %s will expire in %ld seconds.",
            lisp_addr_to_char(mapping_eid(rsite->site_map)),
            MS_SITE_EXPIRATION);
}

static void
lsite_entry_update_expiration_timer(lisp_ms_t *ms, lisp_reg_site_t *rsite)
{
    oor_timer_t *timer;
    glist_t *timer_lst;

    timer_lst = htable_ptrs_timers_get_timers_of_type_from_obj(ptrs_to_timers_ht,rsite,
            REG_SITE_EXPRY_TIMER);

    if (glist_size(timer_lst) != 1){
        OOR_LOG(LDBG_1,"lsite_entry_start_expiration_timer: %d timers for same site."
                "It should never happen", glist_size(timer_lst));
        glist_destroy(timer_lst);
        return;
    }
    timer = (oor_timer_t *)glist_first_data(timer_lst);
    glist_destroy(timer_lst);

    /* Give a 2s margin before purging the registered site */
    oor_timer_start(timer, MS_SITE_EXPIRATION + 2);

    OOR_LOG(LDBG_2,"The map cache entry of EID %s will expire in %ld seconds.",
            lisp_addr_to_char(mapping_eid(rsite->site_map)),
            MS_SITE_EXPIRATION);
}

static int
ms_recv_enc_ctrl_msg(lisp_ms_t *ms, lbuf_t *msg, void **ecm_hdr, uconn_t *int_uc)
{
    packet_tuple_t inner_tuple;

    *ecm_hdr = lisp_msg_pull_ecm_hdr(msg);
    if (ECM_SECURITY_BIT(*ecm_hdr)){
        switch (lisp_ecm_auth_type(msg)){
        default:
            OOR_LOG(LDBG_2, "Not supported ECM auth type %d",lisp_ecm_auth_type(msg));
            return (BAD);
        }
    }
    if (lisp_msg_parse_int_ip_udp(msg) != GOOD) {
        return (BAD);
    }
    pkt_parse_inner_5_tuple(msg, &inner_tuple);
    uconn_init(int_uc, inner_tuple.dst_port, inner_tuple.src_port, &inner_tuple.dst_addr,&inner_tuple.src_addr);
    *ecm_hdr = lbuf_lisp_hdr(msg);

    return (GOOD);
}


static int
ms_recv_map_request(lisp_ms_t *ms, lbuf_t *buf,  void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{

    lisp_addr_t *   seid        = NULL;
    lisp_addr_t *   deid        = NULL;
    lisp_addr_t *   neg_pref    = NULL;
    lisp_addr_t *   aux_deid    = NULL;
    mapping_t *     map         = NULL;
    mref_mapping_t * mref_map   = NULL;
    glist_t *       itr_rlocs   = NULL;
    void *          mreq_hdr    = NULL;
    void *          mrep_hdr    = NULL;
    void *          mref_hdr    = NULL;
    mapping_record_hdr_t *  rec            = NULL;
    int             i           = 0;
    int             d           = 0;
    lbuf_t *        mref        = NULL;
    lbuf_t *        mrep        = NULL;
    lbuf_t  b;
    lisp_site_prefix_t *    site            = NULL;
    lisp_reg_site_t *       rsite           = NULL;
    uint8_t act_flag;
    uconn_t send_uc;

    if (!ecm_hdr){
        OOR_LOG(LDBG_1, "Received a not encapsulated Map Request. Discarding!");
        return(BAD);
    }

    /* local copy of the buf that can be modified */
    b = *buf;

    d = ECM_DDT_BIT(ecm_hdr);

    seid = lisp_addr_new();


    mreq_hdr = lisp_msg_pull_hdr(&b);

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }

    if (MREQ_RLOC_PROBE(mreq_hdr)) {
        OOR_LOG(LDBG_2, "Probe bit set. Discarding!");
        return(BAD);
    }

    if (MREQ_SMR(mreq_hdr)) {
        OOR_LOG(LDBG_2, "SMR bit set. Discarding!");
        return(BAD);
    }

    /* PROCESS ITR RLOCs */
    itr_rlocs = laddr_list_new();
    lisp_msg_parse_itr_rlocs(&b, itr_rlocs);

    for (i = 0; i < MREQ_REC_COUNT(mreq_hdr); i++) {
        deid = lisp_addr_new();

        /* PROCESS EID REC */
        if (lisp_msg_parse_eid_rec(&b, deid) != GOOD) {
            goto err;
        }

        /* CHECK IF WE NEED TO PROXY REPLY */
        site = mdb_lookup_entry(ms->lisp_sites_db, deid);
        rsite = mdb_lookup_entry(ms->reg_sites_db, deid);
        /* Static entries will have null site and not null rsite */
        if (!site && !rsite) {
            if(d==1){
                // send NOT_AUTHORITATIVE map-referral with Incomplete = 1
                // and TTL = 0
                mref = lisp_msg_neg_mref_create(deid, 0, LISP_ACTION_NOT_AUTHORITATIVE, A_NO_AUTHORITATIVE,
                        1, MREQ_NONCE(mreq_hdr));
                OOR_LOG(LDBG_1,"The node is not authoritative for the requested EID %s, sending NOT_AUTHORITATIVE message",
                        lisp_addr_to_char(deid));
                OOR_LOG(LDBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mref),
                        lisp_addr_to_char(deid));
                send_msg(&ms->super, mref, ext_uc);
                lisp_msg_destroy(mref);
            }else{
                /* send negative map-reply with TTL 15 min */
                neg_pref = mdb_get_shortest_negative_prefix(ms->lisp_sites_db, deid);
                if (lisp_addr_is_iid(deid)){
                    act_flag = ACT_NO_ACTION;
                }else{
                    act_flag = ACT_NATIVE_FWD;
                }
                mrep = lisp_msg_neg_mrep_create(neg_pref, 15, act_flag,A_AUTHORITATIVE,
                        MREQ_NONCE(mreq_hdr));
                OOR_LOG(LDBG_1,"The requested EID %s doesn't belong to this Map Server",
                        lisp_addr_to_char(deid));
                OOR_LOG(LDBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mrep),
                        lisp_addr_to_char(deid));
                if (map_reply_fill_uconn(&ms->super, itr_rlocs, int_uc, ext_uc, &send_uc) != GOOD){
                    OOR_LOG(LDBG_1, "Couldn't send Map Reply, no itr_rlocs reachable");
                    goto err;
                }
                if (send_msg(&ms->super, mrep, &send_uc) != GOOD) {
                    OOR_LOG(LDBG_1, "Couldn't send Map-Reply!");
                }
                lisp_msg_destroy(mrep);
                lisp_addr_del(neg_pref);
            }
            lisp_addr_del(deid);

            continue;
        }

        /* Find if the site actually registered */
        if (!rsite) {
            if (site->accept_more_specifics == FALSE){
                aux_deid = site->eid_prefix;
            }else{
                aux_deid = deid;
            }
            if(d==1){
                //send NOT_REGISTERED Map Referral with TTL = DEFAULT_NEGATIVE_REFERRAL_TTL
                //and Incomplete determined by the existance or not of peers
                int i = (glist_size(site->ddt_ms_peers)<1);
                mref = lisp_msg_create(LISP_MAP_REFERRAL);

                mref_map = mref_mapping_new_init_full(aux_deid,DEFAULT_NEGATIVE_REFERRAL_TTL,LISP_ACTION_NOT_REGISTERED,
                        A_AUTHORITATIVE, i, site->ddt_ms_peers, NULL, &ext_uc->la);

                rec = lisp_msg_put_mref_mapping(mref, mref_map);
                mref_hdr = lisp_msg_hdr(mref);
                MREF_NONCE(mref_hdr) = MREQ_NONCE(mreq_hdr);

                /* SEND MAP-REFERRAL */
                if (send_msg(&ms->super, mref, ext_uc) != GOOD) {
                    OOR_LOG(LDBG_1, "Couldn't send Map-Referral!");
                }else{
                    OOR_LOG(LDBG_1, "Map-Referral sent!");
                }
                mref_mapping_del(mref_map);
                lisp_msg_destroy(mref);
            }else{
                /* send negative map-reply with TTL 1 min */
                mrep = lisp_msg_neg_mrep_create(aux_deid, 1, ACT_NATIVE_FWD,A_AUTHORITATIVE,
                        MREQ_NONCE(mreq_hdr));
                OOR_LOG(LDBG_1,"The requested EID %s is not registered",
                                    lisp_addr_to_char(deid));
                OOR_LOG(LDBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mrep),
                        lisp_addr_to_char(aux_deid));
                if (map_reply_fill_uconn(&ms->super, itr_rlocs, int_uc, ext_uc, &send_uc) != GOOD){
                    OOR_LOG(LDBG_1, "Couldn't send Map Reply, no itr_rlocs reachable");
                    goto err;
                }
                if (send_msg(&ms->super, mrep, &send_uc) != GOOD) {
                    OOR_LOG(LDBG_1, "Couldn't send Map-Reply!");
                }
                lisp_msg_destroy(mrep);
            }
            lisp_addr_del(deid);
            continue;
        }
        /* If site is null, the request is for a static entry */
        if(d==1){
        	//send MS_ACK Map Referral with TTL = DEFAULT_REGISTERED_TTL
        	//and Incomplete determined by the existance or not of peers
        	int i = (glist_size(site->ddt_ms_peers)<1);
        	mref = lisp_msg_create(LISP_MAP_REFERRAL);

        	mref_map = mref_mapping_new_init_full(deid,DEFAULT_REGISTERED_TTL,LISP_ACTION_MS_ACK,
        			A_AUTHORITATIVE, i, site->ddt_ms_peers, NULL, &ext_uc->la);

        	rec = lisp_msg_put_mref_mapping(mref, mref_map);
        	mref_hdr = lisp_msg_hdr(mref);
        	MREF_NONCE(mref_hdr) = MREQ_NONCE(mreq_hdr);

        	/* SEND MAP-REFERRAL */
			if (send_msg(&ms->super, mref, ext_uc) != GOOD) {
				OOR_LOG(LDBG_1, "Couldn't send Map-Referral!");
			}else{
				OOR_LOG(LDBG_1, "Map-Referral sent!");
			}
			mref_mapping_del(mref_map);
			lisp_msg_destroy(mref);
        }

        map = rsite->site_map;

        /* IF *NOT* PROXY REPLY: forward the message to an xTR */
        if (site != NULL && site->proxy_reply == FALSE && rsite->proxy_reply == FALSE) {
            /* FIXME: once locs become one object, send that instead of mapping */
            forward_mreq(ms, buf, map);
            lisp_msg_destroy(mrep);
            lisp_addr_del(deid);
            continue;
        }

        OOR_LOG(LDBG_1,"The requested EID %s belongs to the registered prefix %s. Send Map Reply",
                lisp_addr_to_char(deid), lisp_addr_to_char(mapping_eid(map)));

        /* IF PROXY REPLY: build Map-Reply */
        mrep = lisp_msg_create(LISP_MAP_REPLY);
        rec = lisp_msg_put_mapping(mrep, map, NULL);
        /* Set the authoritative bit of the record to false*/
        MAP_REC_AUTH(rec) = A_NO_AUTHORITATIVE;

        mrep_hdr = lisp_msg_hdr(mrep);
        MREP_RLOC_PROBE(mrep_hdr) = 0;
        MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);

        /* SEND MAP-REPLY */

        if (map_reply_fill_uconn(&ms->super, itr_rlocs, int_uc, ext_uc, &send_uc) != GOOD){
            OOR_LOG(LDBG_1, "Couldn't send Map Reply, no itr_rlocs reachable");
            goto err;
        }
        if (send_msg(&ms->super, mrep, &send_uc) != GOOD) {
            OOR_LOG(LDBG_1, "Couldn't send Map-Reply!");
        }
        lisp_msg_destroy(mrep);
        lisp_addr_del(deid);
    }

    glist_destroy(itr_rlocs);
    lisp_addr_del(seid);

    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_del(deid);
    lisp_addr_del(seid);
    return(BAD);

}

static int
ms_recv_map_register(lisp_ms_t *ms, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    lisp_reg_site_t *rsite = NULL, *new_rsite = NULL;
    lisp_site_prefix_t *reg_pref = NULL;
    lisp_site_id site_id;
    lisp_xtr_id xtr_id;
    char *key = NULL;
    lisp_addr_t *eid;
    lbuf_t b,*mntf = NULL;
    void *hdr = NULL, *mntf_hdr = NULL, *enc_mntf_hdr, *mreg_auth_hdr, *mnot_auth_hdr, *rtr_auth_hdr;
    int i = 0;
    mapping_t *m = NULL;
    locator_t *probed = NULL;
    lisp_key_type_e keyid = HMAC_SHA_1_96; /* TODO configurable */
    int valid_records = FALSE;
    ms_rtr_node_t *rtr = NULL;
    uconn_t *uc;


    b = *buf;
    hdr = lisp_msg_pull_hdr(&b);

    if(ecm_hdr){ /*New NAT draft version*/
        uc = ext_uc;
    }else{
        uc = int_uc;
    }

    if (MREG_WANT_MAP_NOTIFY(hdr)) {
        mntf = lisp_msg_create(LISP_MAP_NOTIFY);
        lisp_msg_put_empty_auth_record(mntf, keyid);
    }


    mreg_auth_hdr = lisp_msg_pull_auth_field(&b);


    for (i = 0; i < MREG_REC_COUNT(hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(&b, m, &probed) != GOOD) {
            goto err;
        }

        if (mapping_auth(m) == 0){
            OOR_LOG(LWRN,"ms_recv_map_register: Received a none authoritative record in a Map Register: %s",
                    lisp_addr_to_char(mapping_eid(m)));
        }

        /* To be sure that we store the network address and not a IP-> 10.0.0.0/24 instead of 10.0.0.1/24 */
        eid = mapping_eid(m);
        pref_conv_to_netw_pref(eid);

        /* find configured prefix */
        reg_pref = mdb_lookup_entry(ms->lisp_sites_db, eid);

        if (!reg_pref) {
            OOR_LOG(LDBG_1, "EID %s not in configured lisp-sites DB "
                    "Discarding mapping", lisp_addr_to_char(eid));
            mapping_del(m);
            m = NULL;
            continue;
        }

        /* CHECK AUTH */

        /* if first record, lookup the key */
        if (!key) {
            if (lisp_msg_check_auth_field(buf, mreg_auth_hdr, reg_pref->key) != GOOD) {
                OOR_LOG(LDBG_1, "Message validation failed for EID %s with key "
                        "%s. Stopping processing!", lisp_addr_to_char(eid),
                        reg_pref->key);
                goto err;
            }
            OOR_LOG(LDBG_2, "Message validated with key associated to EID %s",
                    lisp_addr_to_char(eid));
            key = reg_pref->key;
        } else if (strncmp(key, reg_pref->key, strlen(key)) !=0 ) {
            OOR_LOG(LDBG_1, "EID %s part of multi EID Map-Register with different "
                    "key! Discarding!", lisp_addr_to_char(eid));
            goto err;
        }


        /* check more specific */
        if (reg_pref->accept_more_specifics == TRUE){
            if (!pref_is_prefix_b_part_of_a(
                    lisp_addr_get_ip_pref_addr(reg_pref->eid_prefix),
                    lisp_addr_get_ip_pref_addr(mapping_eid(m)))){
                OOR_LOG(LDBG_1, "EID %s not in configured lisp-sites DB! "
                        "Discarding mapping!", lisp_addr_to_char(eid));
                mapping_del(m);
                m = NULL;
                continue;
            }
        }else if(lisp_addr_cmp(reg_pref->eid_prefix, eid) !=0) {
            OOR_LOG(LDBG_1, "EID %s is a more specific of %s. However more "
                    "specifics not configured! Discarding",
                    lisp_addr_to_char(eid),
                    lisp_addr_to_char(reg_pref->eid_prefix));
            mapping_del(m);
            m = NULL;
            continue;
        }


        rsite = mdb_lookup_entry_exact(ms->reg_sites_db, eid);
        if (rsite) {
            if (mapping_cmp(rsite->site_map, m) != 0) {
                if (!reg_pref->merge) {
                    OOR_LOG(LDBG_3, "Prefix %s already registered, updating "
                            "locators", lisp_addr_to_char(eid));
                    mapping_update_locators(rsite->site_map,mapping_locators_lists(m));
                } else {
                    /* TREAT MERGE SEMANTICS */
                    OOR_LOG(LWRN, "Prefix %s has merge semantics",
                            lisp_addr_to_char(eid));
                }
                ms_dump_registered_sites(ms, LDBG_3);
            }
            rsite->proxy_reply = MREG_PROXY_REPLY(hdr);
            /* update registration timer */
            lsite_entry_update_expiration_timer(ms, rsite);
        } else {
            /* save prefix to the registered sites db */
            new_rsite = xzalloc(sizeof(lisp_reg_site_t));
            new_rsite->site_map = m;
            mdb_add_entry(ms->reg_sites_db, mapping_eid(m), new_rsite);
            lsite_entry_start_expiration_timer(ms, new_rsite);

            new_rsite->proxy_reply = MREG_PROXY_REPLY(hdr);
            ms_dump_registered_sites(ms, LDBG_3);
        }

        if (mntf) {
            lisp_msg_put_mapping(mntf, m, NULL);
            valid_records = TRUE;
        }

        /* if site previously registered, just remove the parsed mapping */
        if (rsite) {
            mapping_del(m);
            m = NULL;
        }
    }
    if (MREG_IBIT(hdr)){
        lisp_msg_parse_xtr_id_site_id(&b, &xtr_id, &site_id);
        OOR_LOG(LDBG_1,"  xTR_ID: %s",get_char_from_xTR_ID(&xtr_id));
        if (mntf) {
            lisp_msg_put_xtr_id_site_id(mntf, &xtr_id, &site_id);
        }
    }

    /* We don't want Map Notify */
    if (!mntf){
        return (GOOD);
    }

    /* check if key is initialized, otherwise registration failed */
    if (!key || valid_records == FALSE) {
        goto err;
    }

    mntf_hdr = lisp_msg_hdr(mntf);
    MNTF_NONCE(mntf_hdr) = MREG_NONCE(hdr);
    MNTF_I_BIT(mntf_hdr) = MREG_IBIT(hdr);
    if (!ecm_hdr){
        MNTF_R_BIT(mntf_hdr) = MREG_RBIT(hdr);
    }
    /* Add Map Notify authentication */
    mnot_auth_hdr = (uint8_t *)mntf_hdr + sizeof(map_notify_hdr_t);
    lisp_msg_fill_auth_data(mntf, mnot_auth_hdr, keyid, key);

    /* Check if Map Register is from RTR */
    if (MREG_IBIT(hdr) && ms->def_rtr_set){
        rtr = shash_lookup (ms->rtrs_table_by_ip, lisp_addr_to_char(&uc->ra));
        if (!rtr){
            OOR_LOG(LDBG_1, "Map-Server: Received Map Register from unknown RTR (%S). Discarding message!",
                    lisp_addr_to_char(&uc->ra));
            goto err;
        }
        /* Different behaviour depending on the NAT implementation of the RTR*/

        if (rtr->passwd){
            if(ecm_hdr && ECM_RTR_RELAYED_BIT(ecm_hdr)){
                /** New version of the draft **/
                /* Add internal IP/UDP header */
                pkt_push_inner_udp_and_ip(mntf, LISP_CONTROL_PORT, LISP_CONTROL_PORT,
                        lisp_addr_ip(&int_uc->la),lisp_addr_ip(&int_uc->ra));
                /* Add authentication data */
                rtr_auth_hdr = lisp_msg_push_empty_rtr_auth_data(mntf,rtr->key_type);
                lisp_msg_fill_rtr_auth_data(mntf,rtr_auth_hdr,rtr->key_type, rtr->passwd);
                /* And encap contl msg header */
                enc_mntf_hdr = lisp_msg_push_encap_lisp_header(mntf);
                ECM_RTR_PROCESS_BIT(enc_mntf_hdr) = 1;
                ECM_SECURITY_BIT(enc_mntf_hdr) = 1;
            }else{
                if (MNTF_R_BIT(mntf_hdr)){
                    rtr_auth_hdr = lisp_msg_put_empty_auth_record(mntf, keyid);
                    lisp_msg_fill_auth_data(mntf,rtr_auth_hdr,rtr->key_type, rtr->passwd);
                }
            }
        }
    }
    OOR_LOG(LDBG_1, "%s, IP: %s -> %s, UDP: %d -> %d",
            lisp_msg_hdr_to_char(mntf), lisp_addr_to_char(&uc->la),
            lisp_addr_to_char(&uc->ra), uc->lp, uc->rp);
    send_msg(&ms->super, mntf, uc);

    lisp_msg_destroy(mntf);

    return(GOOD);
err:
    mapping_del(m);
    if (mntf){
        lisp_msg_destroy(mntf);
    }
    return(BAD);
}

static int
ms_recv_inf_request(lisp_ms_t *ms, lbuf_t *buf, uconn_t *uc)
{
    lbuf_t b, *irep_buf;
    void *hdr, *irep_hdr, *req_auth_hdr, *rep_auth_hdr;
    lisp_addr_t *eid, priv_addr, *nat_addr = NULL;
    int ttl;
    lisp_site_prefix_t *reg_pref;
    glist_t *rtr_list = NULL;
    glist_entry_t *rtr_it;
    ms_rtr_node_t *rtr;
    uconn_t r_uc;

    b = *buf;
    hdr = lisp_msg_pull_hdr(&b);

    if (INF_REQ_R_bit(hdr)) {
        OOR_LOG(LDBG_1, "Map-Server: Received Info Reply message. Discarding!");
        return (BAD);
    }

    req_auth_hdr = lisp_msg_pull_auth_field(&b);

    eid = lisp_addr_new();
    if (lisp_msg_parse_inf_req_eid_ttl(&b, eid, &ttl) != GOOD) {
        goto err;
    }

    /* Verify the EID belongs to the MS */

    reg_pref = mdb_lookup_entry(ms->lisp_sites_db, eid);
    if (!reg_pref) {
        OOR_LOG(LDBG_1, "EID %s not in configured lisp-sites DB "
                "Discarding Info Request...", lisp_addr_to_char(eid));
        goto err;
    }

    /* Verify authentication of the msg */

    if (lisp_msg_check_auth_field(buf, req_auth_hdr, reg_pref->key) != GOOD) {
        OOR_LOG(LDBG_1, "Info Request validation failed for EID %s with key "
                "%s. Stopping processing!", lisp_addr_to_char(eid),
                reg_pref->key);
        goto err;
    }

    /** Generate Info Reply message **/

    /* Generate rtr list */
    rtr_list = glist_new();
    glist_for_each_entry(rtr_it,ms->def_rtr_set->rtr_list){
        rtr = (ms_rtr_node_t *)glist_entry_data(rtr_it);
        glist_add(rtr->addr,rtr_list);
    }

    lisp_addr_set_lafi(&priv_addr, LM_AFI_NO_ADDR);
    nat_addr = lisp_addr_new_init_nat(LISP_CONTROL_PORT, &uc->la,
            uc->rp,&uc->ra, &priv_addr, rtr_list);


    irep_buf = lisp_msg_inf_reply_create(eid, nat_addr,
            reg_pref->key_type, ms->def_rtr_set->ttl);
    if (!irep_buf){
        OOR_LOG(LDBG_1,"ms_recv_inf_request: Can not generate Info Reply message");
        goto err;
    }

    glist_destroy(rtr_list);
    lisp_addr_del(nat_addr);
    lisp_addr_del(eid);

    irep_hdr = lisp_msg_hdr(irep_buf);
    INF_REQ_NONCE(irep_hdr) = INF_REQ_NONCE(hdr);

    rep_auth_hdr = irep_hdr + sizeof(info_nat_hdr_t);
    lisp_msg_fill_auth_data(irep_buf, rep_auth_hdr, reg_pref->key_type, reg_pref->key);

    uconn_init(&r_uc, LISP_CONTROL_PORT, uc->rp, &uc->la, &uc->ra);
    send_msg(&ms->super, irep_buf, &r_uc);

    lisp_msg_destroy(irep_buf);

    return(GOOD);
err:
    glist_destroy(rtr_list);
    lisp_addr_del(eid);
    lisp_addr_del(nat_addr);
    return(BAD);
}


int
ms_add_lisp_site_prefix(lisp_ms_t *ms, lisp_site_prefix_t *sp)
{
    if (!sp)
        return(BAD);

    if(!mdb_add_entry(ms->lisp_sites_db, lsite_prefix(sp), sp))
        return(BAD);
    return(GOOD);
}

int
ms_add_registered_site_prefix(lisp_ms_t *ms, mapping_t *sp)
{
    if (!sp) {
        return(BAD);
    }

    lisp_reg_site_t *rs = xzalloc(sizeof(lisp_reg_site_t));
    rs->site_map = sp;
    if (!mdb_add_entry(ms->reg_sites_db, mapping_eid(sp), rs))
        return(BAD);
    return(GOOD);
}

void
ms_dump_configured_sites(lisp_ms_t *ms, int log_level)
{
    if (is_loggable(log_level) == FALSE){
        return;
    }

    void *it = NULL;
    lisp_site_prefix_t *site = NULL;

    OOR_LOG(log_level,"****************** MS configured prefixes **************\n");
    mdb_foreach_entry(ms->lisp_sites_db, it) {
        site = it;
        OOR_LOG(log_level, "Prefix: %s, accept specifics: %s merge: %s, proxy: %s",
                lisp_addr_to_char(site->eid_prefix),
                (site->accept_more_specifics) ? "on" : "off",
                (site->merge) ? "on" : "off",
                (site->proxy_reply) ? "on" : "off");
        if(glist_size(site->ddt_ms_peers)>0){
            OOR_LOG(log_level, "MS Peers for prefix: %s:",
                    lisp_addr_to_char(site->eid_prefix));
            glist_dump(site->ddt_ms_peers, (glist_to_char_fct)lisp_addr_to_char, log_level);
        }else{
            OOR_LOG(log_level, "Prefix %s has no MS Peers",
                    lisp_addr_to_char(site->eid_prefix));
        }
    } mdb_foreach_entry_end;
    OOR_LOG(log_level,"*******************************************************\n");
}

void
ms_dump_registered_sites(lisp_ms_t *ms, int log_level)
{
    if (is_loggable(log_level) == FALSE){
        return;
    }

    void *it = NULL;
    lisp_reg_site_t *rsite = NULL;

    OOR_LOG(log_level,"**************** MS registered sites ******************\n");
    mdb_foreach_entry(ms->reg_sites_db, it) {
        rsite = it;
        OOR_LOG(log_level, "%s", mapping_to_char(rsite->site_map));
    } mdb_foreach_entry_end;
    OOR_LOG(log_level,"*******************************************************\n");

}

inline lisp_ms_t *
lisp_ms_cast(oor_ctrl_dev_t *dev)
{
    /* make sure */
    lm_assert(dev->ctrl_class == &ms_ctrl_class);
    return(CONTAINER_OF(dev, lisp_ms_t, super));
}

static int
ms_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc)
{
    int ret = BAD;
    lisp_msg_type_e type;
    lisp_ms_t *ms;
    void *ecm_hdr = NULL;
    uconn_t *int_uc, *ext_uc = NULL, aux_uc;

    ms = lisp_ms_cast(dev);
    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (ms_recv_enc_ctrl_msg(ms, msg, &ecm_hdr, &aux_uc)!=GOOD){
            return (BAD);
        }
        type = lisp_msg_type(msg);
        ext_uc = uc;
        int_uc = &aux_uc;
        OOR_LOG(LDBG_1, "Map-Server: Received Encapsulated %s", lisp_msg_hdr_to_char(msg));
    }else{
        int_uc = uc;
    }

     switch(type) {
     case LISP_MAP_REQUEST:
         ret = ms_recv_map_request(ms, msg, ecm_hdr, int_uc, ext_uc);
         break;
     case LISP_MAP_REGISTER:
         ret = ms_recv_map_register(ms, msg, ecm_hdr, int_uc, ext_uc);
         break;
     case LISP_MAP_REPLY:
     case LISP_MAP_NOTIFY:
         OOR_LOG(LDBG_3, "Map-Server: Received control message with type %d."
                 " Discarding!", type);
         break;
     case LISP_INFO_NAT:
         ret = ms_recv_inf_request(ms, msg, uc);
         break;
     default:
         OOR_LOG(LDBG_3, "Map-Server: Received unidentified type (%d) control "
                 "message", type);
         ret = BAD;
         break;
     }

     if (ret != GOOD) {
         OOR_LOG(LDBG_1, "Map-Server: Failed to process  control message");
         return(BAD);
     } else {
         OOR_LOG(LDBG_3, "Map-Server: Completed processing of control message");
         return(ret);
     }
}


int
ms_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t state)
{
    return (GOOD);
}
int
ms_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status)
{
    return (GOOD);
}
int
ms_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    return (GOOD);
}

fwd_info_t *
ms_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    return (NULL);
}

static oor_ctrl_dev_t *
ms_ctrl_alloc()
{
    lisp_ms_t *ms;
    ms = xzalloc(sizeof(lisp_ms_t));
    return(&ms->super);
}

static int
ms_ctrl_construct(oor_ctrl_dev_t *dev)
{
    lisp_ms_t *ms = lisp_ms_cast(dev);

    ms->reg_sites_db = mdb_new();
    ms->lisp_sites_db = mdb_new();

    ms->rtrs_set_table = shash_new_managed((free_value_fn_t)ms_rtr_set_del);
    // rtrs_table_by_name and rtrs_table_by_ip points to the same pointers value. Only one
    // should be managed
    ms->rtrs_table_by_name = shash_new_managed((free_value_fn_t)ms_rtr_node_del);
    ms->rtrs_table_by_ip = shash_new();
    ms->def_rtr_set = NULL;

    if (!ms->reg_sites_db || !ms->lisp_sites_db) {
        return(BAD);
    }

    OOR_LOG(LDBG_1, "Finished Constructing Map-Server");

    return(GOOD);
}

static void
ms_ctrl_destruct(oor_ctrl_dev_t *dev)
{
    lisp_ms_t *ms = lisp_ms_cast(dev);
    mdb_del(ms->lisp_sites_db, (mdb_del_fct)lisp_site_prefix_del);
    mdb_del(ms->reg_sites_db, (mdb_del_fct)lisp_reg_site_del);
    shash_destroy(ms->rtrs_set_table);
    shash_destroy(ms->rtrs_table_by_name);
    shash_destroy(ms->rtrs_table_by_ip);
    // ms->def_rtr_set is destroyed when destroying ms->rtrs_set_table
}

void
ms_ctrl_dealloc(oor_ctrl_dev_t *dev)
{
    lisp_ms_t *ms = lisp_ms_cast(dev);
    OOR_LOG(LDBG_1, "Freeing Map-Server ...");
    free(ms);
}

void
ms_ctrl_run(oor_ctrl_dev_t *dev)
{
    lisp_ms_t *ms = lisp_ms_cast(dev);

    OOR_LOG (LDBG_1, "****** Summary of the configuration ******");
    ms_dump_configured_sites(ms, LDBG_1);
    ms_dump_registered_sites(ms, LDBG_1);
    if (ms->def_rtr_set){
        OOR_LOG (LDBG_1, "*** Announced RTR list ***");
        ms_rtr_set_dump(ms->def_rtr_set, LDBG_1);
    }

    OOR_LOG(LDBG_1, "Starting Map-Server ...");
}


ctrl_dev_class_t ms_ctrl_class = {
        .alloc = ms_ctrl_alloc,
        .construct = ms_ctrl_construct,
        .dealloc = ms_ctrl_dealloc,
        .destruct = ms_ctrl_destruct,
        .run = ms_ctrl_run,
        .recv_msg = ms_recv_msg,
        .if_link_update = ms_if_link_update,
        .if_addr_update = ms_if_addr_update,
        .route_update = ms_route_update,
        .get_fwd_entry = ms_get_fwd_entry
};



/*****  Basic rtr_node_t and rtr_set_t functions *****/

ms_rtr_node_t *
ms_rtr_node_new_init(char *id, lisp_addr_t *addr, char *passwd)
{
    ms_rtr_node_t *rtr = xzalloc(sizeof(ms_rtr_node_t));
    if (!rtr){
        OOR_LOG(LDBG_1, "Can't allocate a new rtr_node_t");
        return (NULL);
    }
    rtr->id = strdup(id);
    rtr->addr = lisp_addr_clone(addr);
    rtr->passwd = strdup(passwd);
    // Message Authentication Code hardcoded
    rtr->key_type = HMAC_SHA_1_96;

    return(rtr);
}

void
ms_rtr_node_del(ms_rtr_node_t * rtr)
{
    lisp_addr_del(rtr->addr);
    free(rtr->id);
    free(rtr->passwd);
    free(rtr);
}

ms_rtr_set_t *
ms_rtr_set_new_init(char *id, int ttl)
{
    ms_rtr_set_t *rtr_set = xzalloc(sizeof(ms_rtr_set_t));
    if (!rtr_set){
        OOR_LOG(LDBG_1, "Can't allocate a new rtr_set_t");
        return (NULL);
    }
    rtr_set->id = strdup(id);
    rtr_set->ttl = ttl;
    rtr_set->rtr_list = glist_new();

    return (rtr_set);
}

void
ms_rtr_set_del(ms_rtr_set_t *rtr_set)
{
    free(rtr_set->id);
    glist_destroy(rtr_set->rtr_list);
    free(rtr_set);
}

void
ms_rtr_set_dump(ms_rtr_set_t *rtr_set, int log_level)
{
    glist_entry_t *it;
    int ctr = 0;
    ms_rtr_node_t * rtr;

    if (!is_loggable(log_level)){
        return;
    }
    OOR_LOG (log_level, " RTR set name \"%s\" , ttl= %d", rtr_set->id, rtr_set->ttl);
    glist_for_each_entry(it,rtr_set->rtr_list){
        ctr++;
        rtr = (ms_rtr_node_t *)glist_entry_data (it);
        OOR_LOG(log_level,"    [%d] =>  %s",ctr,lisp_addr_to_char(rtr->addr));
    }
}
