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

int
xtr_process_map_request(lisp_ctrl_dev_t *, lbuf_t *, uconn_t *);

int
xtr_handle_msg(lisp_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *usk) {
    int ret = 0;
    lisp_msg_type_t type;

    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (lisp_msg_ecm_decap(msg, &(usk.lp)) != GOOD)
            return (BAD);
    }

    switch (type) {
    case LISP_MAP_REPLY:
        ret = process_map_reply_msg(dev, msg);
        break;
    case LISP_MAP_REQUEST:
        ret = xtr_process_map_request(dev, msg, usk);
        break;
    case LISP_MAP_REGISTER:
        break;
    case LISP_MAP_NOTIFY:
        ret = process_map_notify(dev, msg);
        break;
    case LISP_INFO_NAT:
        /*FC: temporary fix until info_nat uses liblisp */
        lmlog(LISP_LOG_DEBUG_1, "Info-Request/Info-Reply message");
        if (!process_info_nat_msg(lbuf_data(msg), usk.ra)) {
            return (BAD);
        }
        return (GOOD);
        break;
    default:
        lmlog(DBG_1, "xTR: Unidentified type (%d) control message received",
                type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        lmlog(DBG_1,"xTR: Failed to process LISP control message");
        return (BAD);
    } else {
        lmlog(DBG_3, "xTR: Completed processing of LISP control message");
        return (ret);
    }
}

void
xtr_ctrl_start(lisp_ctrl_dev_t *dev) {

    lmlog(DBG_1, "Starting xTR ...");
    /*
    *  Register to the Map-Server(s)
    */

    map_register_all_eids();

    /*
    * SMR proxy-ITRs list to be updated with new mappings
    */

    ctrl_dev_send_smr(NULL,NULL);

    /*
    * RLOC Probing proxy ETRs
    */
    programming_petr_rloc_probing();

}

void
xtr_delete(lisp_ctrl_dev_t *dev) {
//    lisp_xtr *xtr;
//    xtr = (lisp_xtr *)dev;
//    mdb_del(xtr->local_mdb, (glist_del_fct)mapping_del_local);
//    mdb_del(xtr->map_cache, (glist_del_fct)mapping_del_remote);

}

/* implementation of base functions */
ctrl_dev_class_t xtr_vtable = {
        .process_msg = xtr_handle_msg,
        .start = xtr_ctrl_start,
        .delete = xtr_delete
};

lisp_ctrl_dev_t *
xtr_ctrl_init() {
    lisp_xtr_t *xtr;
    xtr = calloc(1, sizeof(lisp_xtr_t));
    xtr->super.vtable = &xtr_vtable;
    xtr->super.mode = xTR_MODE;
    lmlog(DBG_1, "Finished Initializing xTR");

    /*
     *  set up databases
     */

    local_map_db_init();
    map_cache_init();

    return((lisp_ctrl_dev_t *)xtr);
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


static int
reply_to_smr(lisp_addr_t *src_addr)
{
    map_cache_entry_t *mce;
    nonces_list *nonces;

    /* Lookup the map cache entry that match with the source EID prefix
     * of the message */
    if (!(mce = map_cache_lookup(src_addr))) {
        return(BAD);
    }


    /* Only accept one solicit map request for an EID prefix. If node which
     * generates the message has more than one locator, it probably will
     * generate a solicit map request for each one. Only the first one is
     * considered. If map_cache_entry->nonces is different from null, we have
     * already received a solicit map request  */
    if (!(nonces = mcache_entry_nonces_list(mce))) {
        nonces = new_nonces_list();
        if (!nonces) {
            return(BAD);
        }

        mce->smr_inv_timer = create_timer(SMR_INV_RETRY_TIMER);
        if (!mce->smr_inv_timer) {
            return(BAD);
        }

        send_smr_invoked_map_request(mce);
    }

    return(GOOD);
}

int
xtr_process_map_request(lisp_ctrl_dev_t *dev, lbuf_t *buf, uconn_t *usk)
{
    lisp_addr_t *seid, *deid, *tloc;
    mapping_t *map;
    glist_t *itr_rlocs = NULL;
    void *mreq_hdr, *mrep_hdr, *paddr, *per;
    int i;
    lbuf_t *mrep = NULL;
    lbuf_t  b;

    lisp_xtr_t *xtr = CONTAINER_OF(dev, lisp_xtr_t, super);

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
        if(reply_to_smr(seid) != GOOD) {
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
                ? &usk->ra: NULL);
    }

    mrep_hdr = lisp_msg_hdr(mrep);
    MREP_RLOC_PROBE(mrep_hdr) = MREQ_RLOC_PROBE(mreq_hdr);
    MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);

    /* send map-reply */
    select_remote_rloc(itr_rlocs, lisp_addr_ip_afi(&usk->la), &usk.ra);
    if (send_msg(dev, b, usk) != GOOD) {
        lmlog(DBG_1, "Couldn't send Map-Reply!");
    }

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
