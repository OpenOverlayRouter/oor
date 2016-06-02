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
#include "../lib/pointers_table.h"
#include "../lib/prefixes.h"


static int ms_recv_map_request(lisp_ms_t *, lbuf_t *, uconn_t *);
static int ms_recv_map_register(lisp_ms_t *, lbuf_t *, uconn_t *);
static int ms_recv_msg(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);
static inline lisp_ms_t *lisp_ms_cast(oor_ctrl_dev_t *dev);


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

    ctrl = ctrl_dev_ctrl(&(ms->super));

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


    timer = oor_timer_create(REG_SITE_EXPRY_TIMER);
    oor_timer_init(timer, ms, lsite_entry_expiration_timer_cb, rsite,
            NULL, NULL);
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
ms_recv_map_request(lisp_ms_t *ms, lbuf_t *buf, uconn_t *uc)
{

    lisp_addr_t *   seid        = NULL;
    lisp_addr_t *   deid        = NULL;
    mapping_t *     map         = NULL;
    glist_t *       itr_rlocs   = NULL;
    void *          mreq_hdr    = NULL;
    void *          mrep_hdr    = NULL;
    mapping_record_hdr_t *  rec            = NULL;
    int             i           = 0;
    lbuf_t *        mrep        = NULL;
    lbuf_t  b;
    lisp_site_prefix_t *    site            = NULL;
    lisp_reg_site_t *       rsite           = NULL;
    uint8_t act_flag;

    /* local copy of the buf that can be modified */
    b = *buf;

    seid = lisp_addr_new();


    mreq_hdr = lisp_msg_pull_hdr(&b);

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }

    OOR_LOG(LDBG_1, " src-eid: %s", lisp_addr_to_char(seid));
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
            /* send negative map-reply with TTL 15 min */

            if (lisp_addr_is_iid(deid)){
                act_flag = ACT_NO_ACTION;
            }else{
                act_flag = ACT_NATIVE_FWD;
            }
            mrep = lisp_msg_neg_mrep_create(deid, 15, act_flag,A_AUTHORITATIVE,
                    MREQ_NONCE(mreq_hdr));
            OOR_LOG(LDBG_1,"The requested EID %s doesn't belong to this Map Server",
                    lisp_addr_to_char(deid));
            OOR_LOG(LDBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mrep),
                    lisp_addr_to_char(deid));
            send_msg(&ms->super, mrep, uc);
            lisp_msg_destroy(mrep);
            lisp_addr_del(deid);

            continue;
        }

        /* Find if the site actually registered */
        if (!rsite) {
            /* send negative map-reply with TTL 1 min */
            mrep = lisp_msg_neg_mrep_create(deid, 1, ACT_NATIVE_FWD,A_AUTHORITATIVE,
                    MREQ_NONCE(mreq_hdr));
            OOR_LOG(LDBG_1,"The requested EID %s is not registered",
                                lisp_addr_to_char(deid));
            OOR_LOG(LDBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mrep),
                    lisp_addr_to_char(deid));
            send_msg(&ms->super, mrep, uc);
            lisp_msg_destroy(mrep);
            lisp_addr_del(deid);
            continue;
        }

        map = rsite->site_map;
        /* If site is null, the request is for a static entry */

        /* IF *NOT* PROXY REPLY: forward the message to an xTR */
        if (site != NULL && site->proxy_reply == FALSE) {
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
        laddr_list_get_addr(itr_rlocs, lisp_addr_ip_afi(&uc->la), &uc->ra);
        if (send_msg(&ms->super, mrep, uc) != GOOD) {
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
ms_recv_map_register(lisp_ms_t *ms, lbuf_t *buf, uconn_t *uc)
{
    lisp_reg_site_t *rsite = NULL, *new_rsite = NULL;
    lisp_site_prefix_t *reg_pref = NULL;
    char *key = NULL;
    lisp_addr_t *eid;
    lbuf_t b;
    void *hdr = NULL, *mntf_hdr = NULL;
    int i = 0;
    mapping_t *m = NULL;
    locator_t *probed = NULL;
    lbuf_t *mntf = NULL;
    lisp_key_type_e keyid = HMAC_SHA_1_96; /* TODO configurable */
    int valid_records = FALSE;


    b = *buf;
    hdr = lisp_msg_pull_hdr(&b);

    if (MREG_WANT_MAP_NOTIFY(hdr)) {
        mntf = lisp_msg_create(LISP_MAP_NOTIFY);
        lisp_msg_put_empty_auth_record(mntf, keyid);
    }

    lisp_msg_pull_auth_field(&b);


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
            continue;
        }

        /* CHECK AUTH */

        /* if first record, lookup the key */
        if (!key) {
            if (lisp_msg_check_auth_field(buf, reg_pref->key) != GOOD) {
                OOR_LOG(LDBG_1, "Message validation failed for EID %s with key "
                        "%s. Stopping processing!", lisp_addr_to_char(eid),
                        reg_pref->key);
                goto bad;
            }
            OOR_LOG(LDBG_2, "Message validated with key associated to EID %s",
                    lisp_addr_to_char(eid));
            key = reg_pref->key;
        } else if (strncmp(key, reg_pref->key, strlen(key)) !=0 ) {
            OOR_LOG(LDBG_1, "EID %s part of multi EID Map-Register has different "
                    "key! Discarding!", lisp_addr_to_char(eid));
            continue;
        }


        /* check more specific */
        if (reg_pref->accept_more_specifics == TRUE){
            if (!pref_is_prefix_b_part_of_a(
                    lisp_addr_get_ip_pref_addr(reg_pref->eid_prefix),
                    lisp_addr_get_ip_pref_addr(mapping_eid(m)))){
                OOR_LOG(LDBG_1, "EID %s not in configured lisp-sites DB! "
                        "Discarding mapping!", lisp_addr_to_char(eid));
                mapping_del(m);
                continue;
            }
        }else if(lisp_addr_cmp(reg_pref->eid_prefix, eid) !=0) {
            OOR_LOG(LDBG_1, "EID %s is a more specific of %s. However more "
                    "specifics not configured! Discarding",
                    lisp_addr_to_char(eid),
                    lisp_addr_to_char(reg_pref->eid_prefix));
            lisp_addr_del(eid);
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
                reg_pref->proxy_reply = MREG_PROXY_REPLY(hdr);
                ms_dump_registered_sites(ms, LDBG_3);
            }

            /* update registration timer */
            lsite_entry_update_expiration_timer(ms, rsite);
        } else {
            /* save prefix to the registered sites db */
            new_rsite = xzalloc(sizeof(lisp_reg_site_t));
            new_rsite->site_map = m;
            mdb_add_entry(ms->reg_sites_db, mapping_eid(m), new_rsite);
            lsite_entry_start_expiration_timer(ms, new_rsite);

            reg_pref->proxy_reply = MREG_PROXY_REPLY(hdr);
            ms_dump_registered_sites(ms, LDBG_3);
        }

        if (MREG_WANT_MAP_NOTIFY(hdr)) {
            lisp_msg_put_mapping(mntf, m, NULL);
            valid_records = TRUE;
        }

        /* if site previously registered, just remove the parsed mapping */
        if (rsite) {
            mapping_del(m);
        }

    }

    /* check if key is initialized, otherwise registration failed */
    if (mntf && key && valid_records) {
        mntf_hdr = lisp_msg_hdr(mntf);
        MNTF_NONCE(mntf_hdr) = MREG_NONCE(hdr);
        lisp_msg_fill_auth_data(mntf, keyid, key);
        OOR_LOG(LDBG_1, "%s, IP: %s -> %s, UDP: %d -> %d",
                lisp_msg_hdr_to_char(mntf), lisp_addr_to_char(&uc->la),
                lisp_addr_to_char(&uc->ra), uc->lp, uc->rp);
        send_msg(&ms->super, mntf, uc);
    }
    lisp_msg_destroy(mntf);

    return(GOOD);
err:
    return(BAD);
    mapping_del(m);
    lisp_msg_destroy(mntf);
bad: /* could return different error */
    mapping_del(m);
    lisp_msg_destroy(mntf);
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

static inline lisp_ms_t *
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

    ms = lisp_ms_cast(dev);
    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (lisp_msg_ecm_decap(msg, &uc->rp) != GOOD)
            return (BAD);
        type = lisp_msg_type(msg);
    }

     switch(type) {
     case LISP_MAP_REQUEST:
         ret = ms_recv_map_request(ms, msg, uc);
         break;
     case LISP_MAP_REGISTER:
         ret = ms_recv_map_register(ms, msg, uc);
         break;
     case LISP_MAP_REPLY:
     case LISP_MAP_NOTIFY:
     case LISP_INFO_NAT:
         OOR_LOG(LDBG_3, "Map-Server: Received control message with type %d."
                 " Discarding!", type);
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
