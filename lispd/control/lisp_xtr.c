/*
 * lisp_xtr.h
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

#include "lisp_xtr.h"

int xtr_process_map_request_msg(map_request_msg *mreq, lisp_addr_t *local_rloc, uint16_t dst_port);

int xtr_process_ctrl_msg(lisp_ctrl_device *dev, lisp_msg *msg, udpsock_t *udpsock) {
    int ret = 0;

    switch(msg->type) {
    case LISP_MAP_REPLY:
      ret = process_map_reply_msg(msg->msg);
      break;
    case LISP_MAP_REQUEST:
      ret = xtr_process_map_request_msg(msg->msg, &udpsock->dst, udpsock->src_port);
      break;
    case LISP_MAP_REGISTER:
      break;
    case LISP_MAP_NOTIFY:
      ret = process_map_notify(msg->msg);
      break;
    case LISP_INFO_NAT:
      /*FC: should be de-commented once process_info_nat_msg is updated to work with lisp_msg */
    //          lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Info-Request/Info-Reply message");
    //          if(!process_info_nat_msg(packet, local_rloc)){
    //              return (BAD);
    //          }
      break;
    default:
      lispd_log_msg(LISP_LOG_DEBUG_1, "xTR: Unidentified type (%d) control message received", msg->type);
      ret = BAD;
      break;
    }

    if (ret != GOOD) {
      lispd_log_msg(LISP_LOG_DEBUG_1, "xTR: Failed to process LISP control message");
      return(BAD);
    } else {
      lispd_log_msg(LISP_LOG_DEBUG_3, "xTR: Completed processing of LISP control message");
      return(ret);
    }
}

void xtr_ctrl_start(lisp_ctrl_device *dev) {

    lispd_log_msg(LISP_LOG_DEBUG_1, "Starting xTR ...");
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
    lispd_log_msg(LISP_LOG_DEBUG_1, "Finished Initializing xTR");

    /*
     *  set up databases
     */

    local_map_db_init();
    map_cache_init();

    return((lisp_ctrl_device *)xtr);
}



static int process_smr(lisp_addr_t *src_addr){

    lispd_map_cache_entry      *map_cache_entry        = NULL;
    /*
    * Lookup the map cache entry that match with the source EID prefix of the message
    */
    map_cache_entry = map_cache_lookup(src_addr);
    if (map_cache_entry == NULL)
        return (BAD);

    /*
    * Only accept a solicit map request for an EID prefix ->If node which generates the message
    * has more than one locator, it probably will generate a solicit map request for each one.
    * Only the first one is considered.
    * If map_cache_entry->nonces is different of null, we have already received a solicit map request
    */
    if (!mcache_entry_get_nonces_list(map_cache_entry))
        solicit_map_request_reply(NULL,(void *)map_cache_entry);

    return(GOOD);
}

int xtr_process_map_request_msg(map_request_msg *mreq, lisp_addr_t *local_rloc, uint16_t dst_port)
{
    lisp_addr_t                 *src_eid                = NULL;
    lisp_addr_t                 *dst_eid                = NULL;
    lisp_addr_t                 *remote_rloc            = NULL;
    glist_t                     *itrs                   = NULL;
    glist_entry_t               *it                     = NULL;
    glist_t                     *eids                   = NULL;
    mapping_t                   *mapping                = NULL;
    map_reply_opts              opts;
    address_field               *dfield                 = NULL;

    lispd_log_msg(LISP_LOG_DEBUG_3, "xTR: Processing LISP Map-Request message");

    if (!(src_eid = lisp_addr_init_from_field(mreq_msg_get_src_eid(mreq))))
        return(BAD);

    /* If packet is a Solicit Map Request, process it */
    if (lisp_addr_get_afi(src_eid) != LM_AFI_NO_ADDR && mreq_msg_get_hdr(mreq)->solicit_map_request) {
        if(process_smr(src_eid) != GOOD)
            goto err;
        /* Return here only if RLOC probe bit is not set */
        else if (!mreq_msg_get_hdr(mreq)->rloc_probe)
            goto done;

    }


    /* Process additional ITR RLOCs. Obtain remote RLOC to use for Map-Replies*/
    itrs = mreq_msg_get_itr_rlocs(mreq);
    glist_for_each_entry(it, itrs) {
        /* XXX: support only for IP RLOCs */
        if (ip_iana_afi_to_sock_afi(address_field_afi(glist_entry_data(it))) == lisp_addr_ip_get_afi(local_rloc)) {
            remote_rloc = lisp_addr_init_from_field(glist_entry_data(it));
            break;
        }
    }

    if (!remote_rloc){
        lispd_log_msg(LISP_LOG_DEBUG_3,"xTR: No supported AFI in the list of ITR-RLOCS");
        goto err;
    }

    /* Set flags for Map-Reply */
    opts.send_rec   = 1;
    opts.echo_nonce = 0;
    opts.rloc_probe = mreq_msg_get_hdr(mreq)->rloc_probe;
    opts.mrsig = (mrsignaling_flags_t){0, 0, 0};

    /* Process record and send Map Reply for each one */
    eids = mreq_msg_get_eids(mreq);
    glist_for_each_entry(it, eids) {
        dfield = eid_prefix_record_get_eid(glist_entry_data(it));
        if (!(dst_eid = lisp_addr_init_from_field(dfield)))
            goto err;

        /* Save prefix length only if the entry is an IP */
        if (lisp_addr_get_afi(dst_eid) == LM_AFI_IP)
            ip_prefix_set_plen(lisp_addr_get_ippref(dst_eid),
                    eid_prefix_record_get_hdr(glist_entry_data(it))->eid_prefix_length);

        lispd_log_msg(LISP_LOG_DEBUG_1, "xTR: Received Map-Request from EID %s for EID %s",
                lisp_addr_to_char(src_eid), lisp_addr_to_char(dst_eid));


        if (is_mrsignaling(dfield)) {
            mrsignaling_recv_join(src_eid, dst_eid, local_rloc, remote_rloc, dst_port,
                    mreq_msg_get_hdr(mreq)->nonce, mrsignaling_get_flags_from_field(dfield));
            goto done;
        }

        /* Check the existence of the requested EID */
        /* We don't use prefix mask and use by default 32 or 128*/
        /* XXX: Maybe here we should do a strict search in case of RLOC probing */
        if (!(mapping = local_map_db_lookup_eid(dst_eid))){
            lispd_log_msg(LISP_LOG_DEBUG_1,"xTR: The requested EID doesn't belong to this node: %s",
                    lisp_addr_to_char(dst_eid));
            lisp_addr_del(dst_eid);
            continue;
        }


        err = build_and_send_map_reply_msg(mapping, local_rloc, remote_rloc, dst_port, mreq_msg_get_hdr(mreq)->nonce, opts);

        lisp_addr_del(dst_eid);
    }

done:
    lisp_addr_del(src_eid);
    lisp_addr_del(remote_rloc);
//    lisp_addr_del(dst_eid);
    return(GOOD);
err:
    lisp_addr_del(src_eid);
    if (remote_rloc)
        lisp_addr_del(remote_rloc);
    if (dst_eid)
        lisp_addr_del(dst_eid);
    return(BAD);
}
