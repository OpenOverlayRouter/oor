/*
 * lisp_ms.c
 *
 * This file is part of LISP Mobile Node Implementation.
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
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#include "lisp_ms.h"
#include "../lib/cksum.h"
#include "../defs.h"
#include "../lib/lmlog.h"


static int ms_recv_map_request(lisp_ms_t *, lbuf_t *, uconn_t *);
static int ms_recv_map_register(lisp_ms_t *, lbuf_t *, uconn_t *);
static int ms_recv_msg(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);
static inline lisp_ms_t *lisp_ms_cast(lisp_ctrl_dev_t *dev);


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
        LMLOG(DBG_1, "get_locator_from_lcaf: Type % not supported!, ",
                lcaf_addr_get_type(lcaf));
        return (BAD);
    }
    return (GOOD);
}

/* forward encapsulated Map-Request to ETR */
static int
forward_mreq(lisp_ms_t *ms, lbuf_t *b, mapping_t *m)
{
	lisp_ctrl_t *ctrl = NULL;
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
    	LMLOG(DBG_1, "Can't find valid RLOC to forward Map-Request to "
    	                "ETR. Discarding!");
    	return(BAD);
    }

    drloc = lisp_addr_get_ip_addr(locator_addr(loct));

    if (lisp_addr_lafi(drloc) == LM_AFI_LCAF) {
        get_etr_from_lcaf(drloc, &drloc);
    }

    LMLOG(DBG_3, "Found xTR with locator %s to forward Encap Map-Request",
            lisp_addr_to_char(drloc));

    /* Set buffer to forward the encapsulated message*/
    lbuf_point_to_lisp_hdr(b);

    uconn_init(&fwd_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
    return(send_msg(&ms->super, b, &fwd_uc));
}


/* Called when the timer associated with a registered lisp site expires. */
static int
lsite_entry_expiration_timer_cb(lmtimer_t *t, void *arg)
{
    lisp_reg_site_t *rsite = NULL;
    lisp_addr_t *addr = NULL;
    lisp_ms_t *ms = t->owner;

    rsite = arg;
    addr = mapping_eid(rsite->site_map);
    LMLOG(DBG_1,"Registration of site with EID %s timed out",
            lisp_addr_to_char(addr));

    mdb_remove_entry(ms->reg_sites_db, addr);
    lisp_reg_site_del(rsite);
    ms_dump_registered_sites(ms, DBG_3);
    return(GOOD);
}

static void
lsite_entry_start_expiration_timer(lisp_ms_t *ms, lisp_reg_site_t *rsite)
{
    /* Expiration cache timer */
    if (!rsite->expiry_timer) {
        rsite->expiry_timer = lmtimer_create(REG_SITE_EXPRY_TIMER);
    }

    /* Give a 2s margin before purging the registered site */
    lmtimer_start(rsite->expiry_timer, MS_SITE_EXPIRATION + 2,
            lsite_entry_expiration_timer_cb, ms, rsite);

    LMLOG(DBG_1,"The map cache entry of EID %s will expire in %ld seconds.",
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

    /* local copy of the buf that can be modified */
    b = *buf;

    seid = lisp_addr_new();


    mreq_hdr = lisp_msg_pull_hdr(&b);

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }

    LMLOG(DBG_1, " src-eid: %s", lisp_addr_to_char(seid));
    if (MREQ_RLOC_PROBE(mreq_hdr)) {
        LMLOG(DBG_2, "Probe bit set. Discarding!");
        return(BAD);
    }

    if (MREQ_SMR(mreq_hdr)) {
        LMLOG(DBG_2, "SMR bit set. Discarding!");
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
            mrep = lisp_msg_neg_mrep_create(deid, 15, ACT_NATIVE_FWD,
                    MREQ_NONCE(mreq_hdr));
            LMLOG(DBG_1,"The requested EID %s doesn't belong to this Map Server",
                    lisp_addr_to_char(deid));
            LMLOG(DBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mrep),
                    lisp_addr_to_char(deid));
            send_msg(&ms->super, mrep, uc);
            lisp_msg_destroy(mrep);
            lisp_addr_del(deid);

            continue;
        }

        /* Find if the site actually registered */
        if (!rsite) {
            /* send negative map-reply with TTL 1 min */
            mrep = lisp_msg_neg_mrep_create(deid, 1, ACT_NATIVE_FWD,
                    MREQ_NONCE(mreq_hdr));
            LMLOG(DBG_1,"The requested EID %s is not registered",
                                lisp_addr_to_char(deid));
            LMLOG(DBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mrep),
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

        LMLOG(DBG_1,"The requested EID %s belongs to the registered prefix %s. Send Map Reply",
                lisp_addr_to_char(deid), lisp_addr_to_char(mapping_eid(map)));

        /* IF PROXY REPLY: build Map-Reply */
        mrep = lisp_msg_create(LISP_MAP_REPLY);
        rec = lisp_msg_put_mapping(mrep, map, NULL);
        /* Set the authoritative bit of the record to false*/
        MAP_REC_AUTH(rec) = 0;

        mrep_hdr = lisp_msg_hdr(mrep);
        MREP_RLOC_PROBE(mrep_hdr) = 0;
        MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);

        /* SEND MAP-REPLY */
        laddr_list_get_addr(itr_rlocs, lisp_addr_ip_afi(&uc->la), &uc->ra);
        if (send_msg(&ms->super, mrep, uc) != GOOD) {
            LMLOG(DBG_1, "Couldn't send Map-Reply!");
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

//static void
//mc_add_rlocs_to_rle(mapping_t *cmap, mapping_t *rtrmap) {
//    locator_t       *cloc = NULL, *rtrloc = NULL;
//    lcaf_addr_t     *crle = NULL, *rtrrle = NULL;
//    glist_entry_t   *it = NULL;
//    rle_node_t      *rtrnode = NULL, *itnode;
//    int             found = 0;
//
//    if (!lisp_addr_is_mc(mapping_eid(rtrmap)))
//        return;
//
//    if (rtrmap->head_v4_locators_list)
//        rtrloc = rtrmap->head_v4_locators_list->locator;
//    else if (rtrmap->head_v6_locators_list)
//        rtrloc = rtrmap->head_v6_locators_list->locator;
//
//    if (!rtrloc) {
//        LMLOG(DBG_1, "mc_add_rlocs_to_rle: NO rloc for mc channel %s. Aborting!",
//                lisp_addr_to_char(mapping_eid(rtrmap)));
//        return;
//    }
//
//    if (cmap->head_v4_locators_list)
//        cloc = cmap->head_v4_locators_list->locator;
//    else if (cmap->head_v6_locators_list)
//        cloc = cmap->head_v6_locators_list->locator;
//
//    if (!cloc) {
//        LMLOG(DBG_1, "mc_add_rlocs_to_rle: RLOC for mc channel %s is not initialized. Aborting!",
//                lisp_addr_to_char(mapping_eid(rtrmap)));
//    }
//
//    rtrrle = lisp_addr_get_lcaf(locator_addr(rtrloc));
//    crle = lisp_addr_get_lcaf(locator_addr(cloc));
//    rtrnode = glist_first_data(lcaf_rle_node_list(rtrrle));
//
//    glist_for_each_entry(it, lcaf_rle_node_list(crle)) {
//        itnode = glist_entry_data(it);
//        if (lisp_addr_cmp(itnode->addr, rtrnode->addr) == 0
//                && itnode->level == rtrnode->level)
//            found = 1;
//    }
//
//    if (!found) {
//        glist_add_tail(rle_node_clone(rtrnode), lcaf_rle_node_list(crle));
//    }
//}

static int
ms_recv_map_register(lisp_ms_t *ms, lbuf_t *buf, uconn_t *uc)
{
    lisp_reg_site_t *rsite = NULL, *new_rsite = NULL;
    lisp_site_prefix_t *reg_pref = NULL;
    char *key = NULL;
    lisp_addr_t *eid = NULL;
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
            LMLOG(LWRN,"ms_recv_map_register: Received a none authoritative record in a Map Register: %s",
                    lisp_addr_to_char(mapping_eid(m)));
        }

        eid = mapping_eid(m);
        /* find configured prefix */
        reg_pref = mdb_lookup_entry(ms->lisp_sites_db, eid);
        if (!reg_pref) {
            LMLOG(DBG_1, "EID %s not in configured lisp-sites DB! "
                    "Discarding mapping!", lisp_addr_to_char(eid));
            mapping_del(m);
            continue;
        }

        /* CHECK AUTH */

        /* if first record, lookup the key */
        if (!key) {
            if (lisp_msg_check_auth_field(buf, reg_pref->key) != GOOD) {
                LMLOG(DBG_1, "Message validation failed for EID %s with key "
                        "%s. Stopping processing!", lisp_addr_to_char(eid),
                        reg_pref->key);
                goto bad;
            }
            LMLOG(DBG_2, "Message validated with key associated to EID %s",
                    lisp_addr_to_char(eid));
            key = reg_pref->key;
        } else if (strncmp(key, reg_pref->key, strlen(key)) !=0 ) {
            LMLOG(DBG_1, "EID %s part of multi EID Map-Register has different "
                    "key! Discarding!", lisp_addr_to_char(eid));
            continue;
        }


        /* check more specific */
        if (reg_pref->accept_more_specifics == TRUE){
            // XXX To check if the more specific prefix is valid
        }else if(lisp_addr_cmp(reg_pref->eid_prefix, eid) !=0) {
            LMLOG(DBG_1, "EID %s is a more specific of %s. However more "
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
                    LMLOG(DBG_3, "Prefix %s already registered, updating "
                            "locators", lisp_addr_to_char(eid));
                    mapping_update_locators(rsite->site_map,mapping_locators_lists(m));
                } else {
                    /* TREAT MERGE SEMANTICS */
                    LMLOG(LWRN, "Prefix %s has merge semantics",
                            lisp_addr_to_char(eid));
                    /* MCs EIDs have their RLOCs aggregated into an RLE */
//                    if (lisp_addr_is_mc(eid)) {
//                        mc_add_rlocs_to_rle(rsite->site_map, m);
//                    } else {
//                        LMLOG(LWRN, "MS: Registered %s requires "
//                                "merge semantics but we don't know how to "
//                                "handle! Discarding!", lisp_addr_to_char(eid));
//                        goto bad;
//                    }
                }
                reg_pref->proxy_reply = MREG_PROXY_REPLY(hdr);
                ms_dump_registered_sites(ms, DBG_3);
            }

            /* update registration timer */
            lsite_entry_start_expiration_timer(ms, rsite);
        } else {
            /* save prefix to the registered sites db */
            new_rsite = xzalloc(sizeof(lisp_reg_site_t));
            new_rsite->site_map = m;
            mdb_add_entry(ms->reg_sites_db, mapping_eid(m), new_rsite);
            lsite_entry_start_expiration_timer(ms, new_rsite);

            reg_pref->proxy_reply = MREG_PROXY_REPLY(hdr);
            ms_dump_registered_sites(ms, DBG_3);
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
        LMLOG(DBG_1, "%s, IP: %s -> %s, UDP: %d -> %d",
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

    LMLOG(log_level,"****************** MS configured prefixes **************\n");
    mdb_foreach_entry(ms->lisp_sites_db, it) {
        site = it;
        LMLOG(log_level, "Prefix: %s, accept specifics: %s merge: %s, proxy: %s",
                lisp_addr_to_char(site->eid_prefix),
                (site->accept_more_specifics) ? "on" : "off",
                (site->merge) ? "on" : "off",
                (site->proxy_reply) ? "on" : "off");
    } mdb_foreach_entry_end;
    LMLOG(log_level,"*******************************************************\n");
}

void
ms_dump_registered_sites(lisp_ms_t *ms, int log_level)
{
    if (is_loggable(log_level) == FALSE){
        return;
    }

    void *it = NULL;
    lisp_reg_site_t *rsite = NULL;

    LMLOG(log_level,"**************** MS registered sites ******************\n");
    mdb_foreach_entry(ms->reg_sites_db, it) {
        rsite = it;
        LMLOG(log_level, "%s", mapping_to_char(rsite->site_map));
    } mdb_foreach_entry_end;
    LMLOG(log_level,"*******************************************************\n");

}

static inline lisp_ms_t *
lisp_ms_cast(lisp_ctrl_dev_t *dev)
{
    /* make sure */
    lm_assert(dev->ctrl_class == &ms_ctrl_class);
    return(CONTAINER_OF(dev, lisp_ms_t, super));
}

static int
ms_recv_msg(lisp_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc)
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
         LMLOG(DBG_3, "Map-Server: Received control message with type %d."
                 " Discarding!", type);
         break;
     default:
         LMLOG(DBG_3, "Map-Server: Received unidentified type (%d) control "
                 "message", type);
         ret = BAD;
         break;
     }

     if (ret != GOOD) {
         LMLOG(DBG_1, "Map-Server: Failed to process  control message");
         return(BAD);
     } else {
         LMLOG(DBG_3, "Map-Server: Completed processing of control message");
         return(ret);
     }
}

static lisp_ctrl_dev_t *
ms_ctrl_alloc()
{
    lisp_ms_t *ms;
    ms = xzalloc(sizeof(lisp_ms_t));
    return(&ms->super);
}

static int
ms_ctrl_construct(lisp_ctrl_dev_t *dev)
{
    lisp_ms_t *ms = lisp_ms_cast(dev);

    ms->reg_sites_db = mdb_new();
    ms->lisp_sites_db = mdb_new();

    if (!ms->reg_sites_db || !ms->lisp_sites_db) {
        return(BAD);
    }

    LMLOG(DBG_1, "Finished Constructing Map-Server");

    return(GOOD);
}

static void
ms_ctrl_destruct(lisp_ctrl_dev_t *dev)
{
    lisp_ms_t *ms = lisp_ms_cast(dev);
    mdb_del(ms->lisp_sites_db, (mdb_del_fct)lisp_site_prefix_del);
    mdb_del(ms->reg_sites_db, (mdb_del_fct)lisp_reg_site_del);
}

void
ms_ctrl_dealloc(lisp_ctrl_dev_t *dev)
{
    lisp_ms_t *ms = lisp_ms_cast(dev);
    LMLOG(DBG_1, "Freeing Map-Server ...");
    free(ms);
}

void
ms_ctrl_run(lisp_ctrl_dev_t *dev)
{
    lisp_ms_t *ms = lisp_ms_cast(dev);

    LMLOG (DBG_1, "****** Summary of the configuration ******");
    ms_dump_configured_sites(ms, DBG_1);
    ms_dump_registered_sites(ms, DBG_1);

    LMLOG(DBG_1, "Starting Map-Server ...");
}


ctrl_dev_class_t ms_ctrl_class = {
        .alloc = ms_ctrl_alloc,
        .construct = ms_ctrl_construct,
        .dealloc = ms_ctrl_dealloc,
        .destruct = ms_ctrl_destruct,
        .run = ms_ctrl_run,
        .recv_msg = ms_recv_msg,
        .if_event = NULL,
        .get_fwd_entry = NULL
};
