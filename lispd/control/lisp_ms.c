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
#include <cksum.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

void ms_ctrl_start(lisp_ctrl_device *dev) {
    lisp_ms *ms = NULL;
    ms = (lisp_ms *)dev;
    lispd_log_msg(LISP_LOG_DEBUG_1, "Starting Map-Server ...");
    ms->registered_sites_db = mdb_new();
    ms->lisp_sites_db = mdb_new();
}

void ms_ctrl_stop(lisp_ctrl_device *dev) {
    lisp_ms *ms = NULL;
    ms = (lisp_ms *)dev;

    lispd_log_msg(LISP_LOG_DEBUG_1, "Starting Map-Server ...");
    mdb_del(ms->registered_sites_db);
    mdb_del(ms->lisp_sites_db);
}

int ms_process_map_request_msg(map_request_msg *mreq, lisp_addr_t *local_rloc, uint16_t dst_port)
{
    lisp_addr_t                 *src_eid                = NULL;
    lisp_addr_t                 *dst_eid                = NULL;
    lisp_addr_t                 *remote_rloc            = NULL;
    glist_t                     *itrs                   = NULL;
    glist_t                     *eids                   = NULL;
    glist_entry_t               *it                     = NULL;
    mapping_t           *mapping                = NULL;
    map_reply_opts              opts;

    lispd_log_msg(LISP_LOG_DEBUG_3, "Map-Server: Processing LISP Map-Request message");

    if (mreq_msg_get_hdr(mreq)->rloc_probe) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "Map-Server: Received LISP Map-Request message with Probe bit set. Discarding!");
        return(BAD);
    }

    if (mreq_msg_get_hdr(mreq)->solicit_map_request) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "Map-Server: Received LISP Map-Request message with SMR bit set. Discarding!");
        return(BAD);
    }

    if (!(src_eid = lisp_addr_init_from_field(mreq_msg_get_src_eid(mreq))))
        return(BAD);

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
        lispd_log_msg(LISP_LOG_DEBUG_3,"Map-Server: No supported AFI in the list of ITR-RLOCS");
        goto err;
    }

    /* Set flags for Map-Reply */
    opts.send_rec   = 0;
    opts.echo_nonce = 0;
    opts.rloc_probe = 0;

    /* Process record and send Map Reply for each one */
    eids = mreq_msg_get_eids(mreq);
    glist_for_each_entry(it, eids) {
        if (!(dst_eid = lisp_addr_init_from_field(eid_prefix_record_get_eid(glist_entry_data(it)))))
            goto err;

        /* Save prefix length only if the entry is an IP */
        if (lisp_addr_get_afi(dst_eid) == LM_AFI_IP)
            ip_prefix_set_plen(lisp_addr_get_ippref(dst_eid),
                    eid_prefix_record_get_hdr(glist_entry_data(it))->eid_prefix_length);

        lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Server: received Map-Request from EID %s for EID %s",
                lisp_addr_to_char(src_eid), lisp_addr_to_char(dst_eid));

        /* Check the existence of the requested EID */
        if (!(mapping = local_map_db_lookup_eid(dst_eid))){
            lispd_log_msg(LISP_LOG_DEBUG_1,"Map-Server: the requested EID %s is not registered",
                    lisp_addr_to_char(dst_eid));
            lisp_addr_del(dst_eid);
            continue;
        }

//        if (is_mrsignaling(eid_prefix_record_get_eid(eid)))
//            return(mrsignaling_recv_mrequest(mreq, dst_eid, local_rloc, remote_rloc, dst_port));
        err = build_and_send_map_reply_msg(mapping, local_rloc, remote_rloc, dst_port, mreq_msg_get_hdr(mreq)->nonce, opts);

        lisp_addr_del(dst_eid);
    }

    lisp_addr_del(src_eid);
    lisp_addr_del(remote_rloc);
    return(GOOD);
err:
    lisp_addr_del(src_eid);
    if (remote_rloc)
        lisp_addr_del(remote_rloc);
    if (dst_eid)
        lisp_addr_del(dst_eid);
    return(BAD);
}

map_notify_msg *ms_build_map_notify_msg(lisp_key_type keyid, char *key, glist_t *records) {
    map_notify_msg  *msg        = NULL;
    uint8_t         *ptr        = NULL;
    glist_entry_t   *it         = NULL;
    mapping_t       *mapping    = NULL;

    msg = mnotify_msg_alloc();
    ptr = mnotify_msg_push(msg, auth_field_get_size_for_type(keyid));
    auth_field_init(ptr, keyid);

    glist_for_each_entry(it, records) {
        mapping = glist_entry_data(it);
        ptr = mnotify_msg_push(msg, mapping_get_size_in_record(mapping));
        mapping_write_to_record(ptr, mapping);
    }

}

int ms_process_map_register_msg(lisp_ctrl_device *dev, map_register_msg *mreg) {
    glist_t             *records    = NULL;
    glist_entry_t       *it         = NULL;
    mapping_t           *mapping    = NULL;
    lisp_ms             *ms         = NULL;
    lisp_site_prefix    *reg_pref   = NULL;
    map_notify_msg      *mnot_msg   = NULL;
    char                *key        = NULL;
    glist_t             *write_recs = NULL;
    auth_field          *afield     = NULL;
    lisp_addr_t         *eid        = NULL;


    ms = (lisp_ms *)dev;
    afield = mreg_msg_get_auth_data(mreg);

    if (mreg_msg_get_hdr(mreg)->map_notify == REQ_MAP_NOTIFY) {
        mnot_msg = map_notify_msg_new();
        if (!mnot_msg)
            goto err;
        mnotify_msg_alloc(mnot_msg);
        mnotify_msg_hdr(mnot_msg)->nonce = mreg_msg_get_hdr(mreg)->nonce;
//        mnotify_msg_write_auth_field(mnot_msg, auth_field_get_hdr(afield)->key_id);
        write_recs = glist_new(NO_CMP, (glist_del_fct)mapping_record_del);
    }

    records = mreg_msg_get_records(mreg);
    if (!records)
        goto err;

    glist_for_each_entry(it, records) {
        mapping = mapping_init_from_record(glist_entry_data(it));
        eid = mapping_eid(mapping);

        /* find configured prefix */
        reg_pref = mdb_lookup_entry(ms->lisp_sites_db, eid, NOT_EXACT);
        if (!reg_pref) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "MS: No prefix configured to accept registration for EID %s! Discarding mapping!",
                    lisp_addr_to_char(eid));
            free_mapping_elt(mapping, 0);
            continue;
        }

        /* check auth */
        if (!key) {
            if (!mreg_msg_check_auth(mreg, reg_pref->key)) {
                lispd_log_msg(LISP_LOG_DEBUG_1, "MS: Message validation failed with key associated to EID %s. Stopping processing!",
                        lisp_addr_to_char(eid));
                goto bad;
            }
            lispd_log_msg(LISP_LOG_DEBUG_3, "MS: Message validated with key associated to EID %s",
                    lisp_addr_to_char(eid));
            key = reg_pref->key;
        } else if (strncmp(key, reg_pref->key, strlen(key)) !=0 ) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "MS: EID %s part of multi EID Map-Register has different key! Discarding!",
                    lisp_addr_to_char(eid));
        }


        /* check if more specific */
        if (lisp_addr_cmp(reg_pref->eid_prefix, eid) !=0 && reg_pref->accept_more_specifics != MORE_SPECIFICS) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "MS: EID %s is a more specific of %s. However more specifics not configured! Discarding",
                    lisp_addr_to_char(eid), lisp_addr_to_char(reg_pref->eid_prefix));
            lisp_addr_del(eid);
            continue;
        }

        /* save prefix to the registered sites db */
        mdb_add_entry(ms->registered_sites_db, mapping_eid(mapping), mapping);

        /* start timers */

        /* add record to map-notify */
        if (mreg_msg_get_hdr(mreg)->map_notify == REQ_MAP_NOTIFY){
            glist_add_tail(write_recs, mapping);
        }

        lisp_addr_del(eid);

    }

    if (mnot_msg) {
        if (glist_size(write_recs) > 0) {
            mnotify_msg_write_records(mnot_msg, write_recs);
            mnotify_msg_fill_auth_field(mnot_msg, key);
//            send_ctrl_msg(mnot_msg);
        }
        glist_destroy(write_recs);
        // dealloc??
        map_notify_msg_del(mnot_msg);
    }


    return(GOOD);
err:
    map_notify_msg_del(mnot_msg);
    if (write_recs)
        glist_destroy(write_recs);
    return(BAD);
bad: /* could return different error */
    map_notify_msg_del(mnot_msg);
    if (write_recs)
        glist_destroy(write_recs);
    return(BAD);
}

int ms_process_lisp_ctrl_msg(lisp_ctrl_device *dev, lisp_msg *msg, lisp_addr_t *local_rloc, uint16_t remote_port) {
    int ret = BAD;

     switch(msg->type) {
     case LISP_MAP_REQUEST:
         ret = ms_process_map_request_msg(msg->msg, local_rloc, remote_port);
         break;
     case LISP_MAP_REGISTER:
         ret = ms_process_map_register_msg(dev, msg->msg);
         break;
     case LISP_MAP_REPLY:
     case LISP_MAP_NOTIFY:
     case LISP_INFO_NAT:
         lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Server: Received control message with type %d. Discarding!",
                 msg->type);
         break;
     default:
         lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Server: Received unidentified type (%d) control message", msg->type);
         ret = BAD;
         break;
     }

     if (ret != GOOD) {
         lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Server: Failed to process LISP control message");
         return(BAD);
     } else {
         lispd_log_msg(LISP_LOG_DEBUG_3, "Map-Server: Completed processing of LISP control message");
         return(ret);
     }
}

ctrl_device_vtable ms_vtable = {
        ms_process_lisp_ctrl_msg,
        ms_ctrl_start
};

lisp_ctrl_device *ms_ctrl_init() {
    lisp_ms *ms;
    ms = calloc(1, sizeof(lisp_ctrl_device));
    ms->super.mode = 2;
    ms->super.vtable = &ms_vtable;
    lispd_log_msg(LISP_LOG_DEBUG_1, "Finished Initializing Map-Server");
    local_map_db_init();

    return((lisp_ctrl_device *)ms);
}




