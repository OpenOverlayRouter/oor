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

#include "lisp_xtr.h"
#include "lispd_sockets.h"

int xtr_process_map_request_msg(lbuf_t *, udpsock_t *);

int xtr_process_ctrl_msg(lisp_ctrl_device *dev, lbuf_t *msg,
        udpsock_t *udpsock) {
    int ret = 0, type;

    type = lisp_msg_parse_type(msg);
    switch (type) {
    case LISP_MAP_REPLY:
        ret = process_map_reply_msg(msg);
        break;
    case LISP_MAP_REQUEST:
        ret = xtr_process_map_request_msg(msg, udpsock);
        break;
    case LISP_MAP_REGISTER:
        break;
    case LISP_MAP_NOTIFY:
        ret = process_map_notify(msg);
        break;
    case LISP_INFO_NAT:
        /*FC: should be de-commented once process_info_nat_msg is updated to work with lisp_msg */
        //          lispd_log_msg(DBG_1, "Received a LISP Info-Request/Info-Reply message");
        //          if(!process_info_nat_msg(packet, local_rloc)){
        //              return (BAD);
        //          }
        break;
    default:
        lmlog(DBG_1, "xTR: Unidentified type (%d) control "
                "message received", type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        lmlog(DBG_1,"xTR: Failed to process LISP control "
                "message");
        return (BAD);
    } else {
        lmlog(DBG_3,
                "xTR: Completed processing of LISP control message");
        return (ret);
    }
}

void xtr_ctrl_start(lisp_ctrl_device *dev) {

    lmlog(DBG_1, "Starting xTR ...");
    /*
    *  Register to the Map-Server(s)
    */

    map_register_all_eids();

    /*
    * SMR proxy-ITRs list to be updated with new mappings
    */

    init_smr(NULL,NULL);

    /*
    * RLOC Probing proxy ETRs
    */
    programming_petr_rloc_probing();

}

void xtr_delete(lisp_ctrl_device *dev) {
//    lisp_xtr *xtr;
//    xtr = (lisp_xtr *)dev;
//    mdb_del(xtr->local_mdb, (glist_del_fct)mapping_del_local);
//    mdb_del(xtr->map_cache, (glist_del_fct)mapping_del_remote);

}

/* implementation of base functions */
ctrl_device_vtable xtr_vtable = {
        .process_msg = xtr_process_ctrl_msg,
        .start = xtr_ctrl_start,
        .delete = xtr_delete
};

lisp_ctrl_device *xtr_ctrl_init() {
    lisp_xtr *xtr;
    xtr = calloc(1, sizeof(lisp_xtr));
    xtr->super.vtable = &xtr_vtable;
    xtr->super.mode = xTR_MODE;
    lmlog(DBG_1, "Finished Initializing xTR");

    /*
     *  set up databases
     */

    local_map_db_init();
    map_cache_init();

    return((lisp_ctrl_device *)xtr);
}


int
send_map_request_to_mr(lbuf_t *b, udpsock_t *ss)
{
    lisp_addr_copy(ss->dst, get_map_resolver());
    lisp_addr_copy(ss->src, get_default_ctrl_address(lisp_addr_ip_afi(ss->dst)));
    ss->dst_port = LISP_CONTROL_PORT;
    ss->src_port = LISP_CONTROL_PORT;

    if (core_send_msg(b, ss) != GOOD) {
        lmlog(DBG_1,"Couldn't send Map-Request!");
    }

    return(GOOD);
}

static void
select_remote_rloc(glist_t *l, int afi, lisp_addr_t *remote) {
    int i;
    glist_entry_t *it;
    lisp_addr_t *rloc;

    glist_for_each_entry(it, l) {
        rloc = glist_entry_data(it);
        if (lisp_addr_ip_afi(rloc) == afi) {
            lisp_addr_copy(remote, rloc);
            break;
        }
    }
}

int
send_map_reply(lbuf_t *b, udpsock_t *rsk, glist_t *itr_rlocs)
{
    udpsock_t ssk;
    lisp_addr_copy(&ssk.src, &rsk->dst);
    select_remote_rloc(itr_rlocs, lisp_addr_ip_afi(&rsk->src), &ssk.dst);
    ssk->src_port = LISP_CONTROL_PORT;
    if (core_send_msg(b, ssk) != GOOD) {
        lmlog(DBG_1, "Couldn't send Map-Reply!");
    }
    return(GOOD);
}


static int
reply_smr(lisp_addr_t *src_addr)
{
    map_cache_entry_t *mce;
    nonces_list *nonces;

    /* Lookup the map cache entry that match with the source EID prefix
     * of the message */
    mce = map_cache_lookup(src_addr);
    if (!mce)
        return (BAD);

    /* Only accept one solicit map request for an EID prefix. If node which
     * generates the message has more than one locator, it probably will
     * generate a solicit map request for each one. Only the first one is
     * considered. If map_cache_entry->nonces is different from null, we have
     * already received a solicit map request  */
    if (!(nonces = mcache_entry_nonces_list(mce))) {
        nonces = new_nonces_list();
        if (!nonces)
            return(BAD);

        mce->smr_inv_timer = create_timer(SMR_INV_RETRY_TIMER);
        if (!mce->smr_inv_timer)
            return(BAD);

        smr_reply_cb(mce->smr_inv_timer,(void *)mce);
    }

    return(GOOD);
}

int
xtr_process_map_request_msg(lbuf_t *buf, udpsock_t *rsk)
{
    lisp_addr_t *seid, *deid, *tloc;
    mapping_t *map;
    glist_t *itr_rlocs = NULL;
    void *mreq_hdr, *mrep_hdr, *paddr, *per;
    int i;
    lbuf_t *mrep = NULL;
    lbuf_t  b;

    /* local copy of the buf that can be modified */
    b = *buf;

    seid = lisp_addr_new();
    deid = lisp_addr_new();

    mreq_hdr = lisp_msg_pull_hdr(&b, sizeof(map_request_hdr_t));

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }

    lmlog(DBG_1, "%s src-eid: %s", lisp_msg_hdr_to_char(mreq_hdr),
            lisp_addr_to_char(seid));

    /* If packet is a Solicit Map Request, process it */
    if (lisp_addr_afi(seid) != LM_AFI_NO_ADDR && MREQ_SMR(mreq_hdr)) {
        if(reply_smr(seid) != GOOD) {
            goto err;
        }
        /* Return if RLOC probe bit is not set */
        if (!MREQ_RLOC_PROBE(mreq_hdr)) {
            goto done;
        }
    }

    /* Process additional ITR RLOCs */
    itr_rlocs = lisp_addr_list_new();
    lisp_msg_parse_itr_rlocs(&b, itr_rlocs);


    /* Process records and build Map-Reply */
    mrep = lisp_msg_create(LISP_MAP_REPLY);
    for (i = 0; i < MREQ_REC_COUNT(mreq_hdr); i++) {
        per = lbuf_data(b);
        if (lisp_msg_parse_eid_rec(b, deid, paddr) != GOOD) {
            goto err;
        }

        lmlog(DBG_1, " dst-eid: %s", lisp_addr_to_char(deid));

        if (is_mrsignaling(EID_REC_ADDR(per))) {
            mrsignaling_recv_msg(mrep, seid, deid, mrsignaling_flags(paddr));
            continue;
        }

        /* Check the existence of the requested EID */
        if (!(map = local_map_db_lookup_eid_exact(deid))) {
            lmlog(DBG_1,"EID %s not locally configured!",
                    lisp_addr_to_char(deid));
            continue;
        }

        lisp_msg_put_mapping(mrep, map, MREQ_RLOC_PROBE(mreq_hdr)
                ? &rsk->dst: NULL);
    }

    mrep_hdr = lisp_msg_hdr(mrep);
    MREP_RLOC_PROBE(mrep_hdr) = MREQ_RLOC_PROBE(mreq_hdr);
    MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);

    send_map_reply(mrep, rsk, itr_rlocs);

done:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_free(deid);
    return(BAD);
}
