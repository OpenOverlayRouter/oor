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


/* for testing, should move them out */
#include <lispd_lib.h>
#include <packets.h>
#include <lispd_sockets.h>

void ms_ctrl_start(lisp_ctrl_device *dev) {
//    lisp_ms *ms = NULL;
//    ms = (lisp_ms *)dev;
    lmlog(LISP_LOG_DEBUG_1, "Starting Map-Server ...");
}

void ms_ctrl_delete(lisp_ctrl_device *dev) {
    lisp_ms *ms;
    ms = (lisp_ms *)dev;
    lmlog(LISP_LOG_DEBUG_1, "Freeing Map-Server ...");
    mdb_del(ms->lisp_sites_db, (mdb_del_fct)mapping_del);
    mdb_del(ms->registered_sites_db, (mdb_del_fct)lisp_site_prefix_del);
}

int ms_process_map_request_msg(lisp_ctrl_device *dev, map_request_msg *mreq, lisp_addr_t *local_rloc, uint16_t dst_port)
{
    lisp_addr_t                 *src_eid                = NULL;
    lisp_addr_t                 *dst_eid                = NULL;
    lisp_addr_t                 *remote_rloc            = NULL;
    glist_t                     *itrs                   = NULL;
    glist_t                     *eids                   = NULL;
    glist_entry_t               *it                     = NULL;
    mapping_t                   *mapping                = NULL;
    map_reply_opts              opts;
    lisp_ms                     *ms                     = NULL;

    ms = (lisp_ms *)dev;

    if (mreq_msg_get_hdr(mreq)->rloc_probe) {
        lmlog(LISP_LOG_DEBUG_3, "Map-Server: Received LISP Map-Request message with Probe bit set. Discarding!");
        return(BAD);
    }

    if (mreq_msg_get_hdr(mreq)->solicit_map_request) {
        lmlog(LISP_LOG_DEBUG_3, "Map-Server: Received LISP Map-Request message with SMR bit set. Discarding!");
        return(BAD);
    }

    if (!(src_eid = lisp_addr_init_from_field(mreq_msg_get_src_eid(mreq)))) {
        lmlog(LISP_LOG_DEBUG_3, "Map-Server: Couldn't read SRC EID. Discarding!");
        return(BAD);
    }

    /* Process additional ITR RLOCs. Obtain remote RLOC to use for Map-Replies*/
    itrs = mreq_msg_get_itr_rlocs(mreq);
    glist_for_each_entry(it, itrs) {
        /* XXX: support only for IP RLOCs */
        if (ip_iana_afi_to_sock_afi(address_field_afi(glist_entry_data(it))) == lisp_addr_ip_afi(local_rloc)) {
            remote_rloc = lisp_addr_init_from_field(glist_entry_data(it));
            break;
        }
    }

    if (!remote_rloc){
        lmlog(LISP_LOG_DEBUG_3,"Map-Server: No supported AFI in the list of ITR-RLOCS");
        goto err;
    }

    /* Set flags for Map-Reply */
    opts.send_rec   = 1;
    opts.echo_nonce = 0;
    opts.rloc_probe = 0;
    opts.mrsig = (mrsignaling_flags_t){0, 0, 0};

    /* Process record and send Map Reply for each one */
    eids = mreq_msg_get_eids(mreq);
    glist_for_each_entry(it, eids) {
        if (!(dst_eid = lisp_addr_init_from_field(eid_prefix_record_get_eid(glist_entry_data(it))))) {
            lmlog(LISP_LOG_DEBUG_3, "Map-Server: Couldn't read DST EID. Discarding!");
            goto err;
        }

        /* Save prefix length only if the entry is an IP */
        if (lisp_addr_afi(dst_eid) == LM_AFI_IP)
            lisp_addr_set_plen(dst_eid, eid_prefix_record_get_hdr(glist_entry_data(it))->eid_prefix_length);

        lmlog(LISP_LOG_DEBUG_1, "Map-Server: received Map-Request from EID %s for EID %s",
                lisp_addr_to_char(src_eid), lisp_addr_to_char(dst_eid));

        /* Check the existence of the requested EID */
        if (!(mapping = mdb_lookup_entry(ms->registered_sites_db, dst_eid))){
            lmlog(LISP_LOG_DEBUG_1,"Map-Server: the requested EID %s is not registered",
                    lisp_addr_to_char(dst_eid));
            lisp_addr_del(dst_eid);
            continue;
        }

        lmlog(LISP_LOG_DEBUG_3, "Map-Server: found mapping with EID %s", lisp_addr_to_char(mapping_eid(mapping)));
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

int push_ip_udp_hdr(
        map_notify_msg  *msg,
        lisp_addr_t     *addr_from,
        lisp_addr_t     *addr_dest,
        int             port_from,
        int             port_dest)
{
    void            *iph_ptr                    = NULL;
    struct udphdr   *udph_ptr                   = NULL;
//    int             ip_hdr_len                  = 0;
//    int             udp_hdr_len                 = 0;
    int             udp_hdr_and_payload_len     = 0;
    uint16_t        udpsum                      = 0;

    if (lisp_addr_ip_afi(addr_from) != lisp_addr_ip_afi(addr_dest)) {
        lmlog(LISP_LOG_DEBUG_2, "add_ip_udp_header: Different AFI addresses %d and %d",
                lisp_addr_ip_afi(addr_from), lisp_addr_ip_afi(addr_dest));
        return(BAD);
    }

    if ((lisp_addr_ip_afi(addr_from) != AF_INET) && (lisp_addr_ip_afi(addr_from) != AF_INET6)) {
        lmlog(LISP_LOG_DEBUG_2, "add_ip_udp_header: Unknown AFI %d",
               lisp_addr_ip_afi(addr_from) );
        return(BAD);
    }

    /* UDP header */
    udp_hdr_and_payload_len = sizeof(struct udphdr) + mnotify_msg_len(msg);
    udph_ptr = (struct udphdr *)mnotify_msg_push(msg, sizeof(struct udphdr));
#ifdef BSD
    udph_ptr->uh_sport = htons(port_from);
    udph_ptr->uh_dport = htons(port_dest);
    udph_ptr->uh_ulen = htons(mnotify_msg_len(msg));
    udph_ptr->uh_sum = 0;
#else
    udph_ptr->source = htons(port_from);
    udph_ptr->dest = htons(port_dest);
    udph_ptr->len = htons(udp_hdr_and_payload_len);
    udph_ptr->check = 0;
#endif

    /* IP header */
    iph_ptr = mnotify_msg_push(msg, get_ip_header_len(addr_from->afi));

    if (build_ip_header(iph_ptr, addr_from, addr_dest, udp_hdr_and_payload_len) == NULL){
        lmlog(LISP_LOG_DEBUG_2, "add_ip_udp_header: Couldn't build the inner ip header");
        return(BAD);
    }

    /*
     * Now compute the headers checksums
     */

    if ((udpsum = udp_checksum(udph_ptr, udp_hdr_and_payload_len, iph_ptr, addr_from->afi)) == -1)
        return(BAD);

    udpsum(udph_ptr) = udpsum;
    return(GOOD);
}

map_notify_msg *build_map_notify_msg(lisp_key_type keyid, char *key, glist_t *records) {
    map_notify_msg  *msg        = NULL;
    uint8_t         *ptr        = NULL;
    glist_entry_t   *it         = NULL;
    mapping_t       *mapping    = NULL;
    uint8_t         *afptr      = NULL;

    msg = map_notify_msg_new();
    if (!msg)
        goto err;
    mnotify_msg_alloc(msg);
    ptr = mnotify_msg_put(msg, auth_field_get_size_for_type(keyid));
    auth_field_init(ptr, keyid);
    afptr = ptr;
    mnotify_msg_hdr(msg)->record_count = glist_size(records);

    glist_for_each_entry(it, records) {
        mapping = glist_entry_data(it);
        ptr = mnotify_msg_put(msg, mapping_get_size_in_record(mapping));
        if (!mapping_fill_record_in_pkt((mapping_record_hdr_t *)ptr, mapping, NULL))
            goto err;
    }

    auth_field_fill((auth_field_hdr_t*)afptr, mnotify_msg_data(msg) , mnotify_msg_len(msg), keyid, key);
    return(msg);
err:
    map_notify_msg_del(msg);
    return(NULL);
}

static void mc_add_rlocs_to_rle(mapping_t *cmap, mapping_t *rtrmap) {
    locator_t       *cloc = NULL, *rtrloc = NULL;
    lcaf_addr_t     *crle = NULL, *rtrrle = NULL;
    glist_entry_t   *it = NULL;
    rle_node_t      *rtrnode = NULL, *itnode;
    int             found = 0;

    if (!lisp_addr_is_mc(mapping_eid(rtrmap)))
        return;

    if (rtrmap->head_v4_locators_list)
        rtrloc = rtrmap->head_v4_locators_list->locator;
    else if (rtrmap->head_v6_locators_list)
        rtrloc = rtrmap->head_v6_locators_list->locator;

    if (!rtrloc) {
        lmlog(LISP_LOG_DEBUG_1, "mc_add_rlocs_to_rle: NO rloc for mc channel %s. Aborting!",
                lisp_addr_to_char(mapping_eid(rtrmap)));
        return;
    }

    if (cmap->head_v4_locators_list)
        cloc = cmap->head_v4_locators_list->locator;
    else if (cmap->head_v6_locators_list)
        cloc = cmap->head_v6_locators_list->locator;

    if (!cloc) {
        lmlog(LISP_LOG_DEBUG_1, "mc_add_rlocs_to_rle: RLOC for mc channel %s is not initialized. Aborting!",
                lisp_addr_to_char(mapping_eid(rtrmap)));
    }

    rtrrle = lisp_addr_get_lcaf(locator_addr(rtrloc));
    crle = lisp_addr_get_lcaf(locator_addr(cloc));
    rtrnode = glist_first_data(lcaf_rle_node_list(rtrrle));

    glist_for_each_entry(it, lcaf_rle_node_list(crle)) {
        itnode = glist_entry_data(it);
        if (lisp_addr_cmp(itnode->addr, rtrnode->addr) == 0
                && itnode->level == rtrnode->level)
            found = 1;
    }

    if (!found)
        glist_add_tail(rle_node_clone(rtrnode), lcaf_rle_node_list(crle));


}

int ms_process_map_register_msg(lisp_ctrl_device *dev, map_register_msg *mreg, udpsock_t *udpsock) {
    glist_t             *records    = NULL;
    glist_entry_t       *it         = NULL;
    mapping_t           *mapping    = NULL;
    mapping_t           *mentry     = NULL;
    lisp_ms             *ms         = NULL;
    lisp_site_prefix    *reg_pref   = NULL;
    map_notify_msg      *mnot_msg   = NULL;
    char                *key        = NULL;
    lisp_key_type       keyid       = HMAC_SHA_1_96;
    glist_t             *write_recs = NULL;
    lisp_addr_t         *eid        = NULL;
//    auth_field          *afield     = NULL;


    ms = (lisp_ms *)dev;
//    afield = mreg_msg_get_auth_data(mreg);

    if (mreg_msg_get_hdr(mreg)->map_notify) {
        /* mappings are not freed when list is destroyed */
        write_recs = glist_new_full(NO_CMP, NO_DEL);
        mnot_msg = map_notify_msg_new();
    }

    records = mreg_msg_get_records(mreg);
    if (!records)
        goto err;

    glist_for_each_entry(it, records) {
        mapping = mapping_init_from_record(glist_entry_data(it));
        eid = mapping_eid(mapping);

        /* find configured prefix */
        reg_pref = mdb_lookup_entry(ms->lisp_sites_db, eid);
        if (!reg_pref) {
            lmlog(LISP_LOG_DEBUG_1, "MS: No prefix configured to accept registration for EID %s! Discarding mapping!",
                    lisp_addr_to_char(eid));
            mapping_del(mapping);
            continue;
        }

        /* check auth */
        if (!key) {
            if (!mreg_msg_check_auth(mreg, reg_pref->key)) {
                lmlog(LISP_LOG_DEBUG_1, "MS: Message validation failed with key %s associated to EID %s. Stopping processing!",
                        reg_pref->key, lisp_addr_to_char(eid));
                goto bad;
            }
            lmlog(LISP_LOG_DEBUG_3, "MS: Message validated with key associated to EID %s",
                    lisp_addr_to_char(eid));
            key = reg_pref->key;
        } else if (strncmp(key, reg_pref->key, strlen(key)) !=0 ) {
            lmlog(LISP_LOG_DEBUG_1, "MS: EID %s part of multi EID Map-Register has different key! Discarding!",
                    lisp_addr_to_char(eid));
            continue;
        }

        /* check if more specific */
        if (!reg_pref->accept_more_specifics && lisp_addr_cmp(reg_pref->eid_prefix, eid) !=0) {
            lmlog(LISP_LOG_DEBUG_1, "MS: EID %s is a more specific of %s. However more specifics not configured! Discarding",
                    lisp_addr_to_char(eid), lisp_addr_to_char(reg_pref->eid_prefix));
            lisp_addr_del(eid);
            continue;
        }

        mentry = mdb_lookup_entry_exact(ms->registered_sites_db, eid);
        if (mentry) {
            if (mapping_cmp(mentry, mapping) != 0) {
                if (!reg_pref->merge) {
                    lmlog(LISP_LOG_DEBUG_3, "MS: Prefix %s already registered, updating locators",
                            lisp_addr_to_char(eid));
                    mapping_update_locators(mentry, mapping->head_v4_locators_list, mapping->head_v6_locators_list, mapping->locator_count);
                    /* cheap hack to avoid cloning */
                    mapping->head_v4_locators_list = NULL;
                    mapping->head_v6_locators_list = NULL;
                } else {
                    /* TREAT MERGE SEMANTICS */
                    lmlog(LISP_LOG_WARNING, "MS: Prefix %s has merge semantics", lisp_addr_to_char(eid));
                    /* MCs EIDs have their RLOCs aggregated into an RLE */
                    if (lisp_addr_is_mc(eid)) {
                        mc_add_rlocs_to_rle(mentry, mapping);
                    } else {
                        lmlog(LISP_LOG_WARNING, "MS: Registered %s requires merge semantics but we don't know "
                                "how to handle! Discarding!", lisp_addr_to_char(eid));
                        goto bad;
                    }
                }

                ms_dump_registered_sites(dev, LISP_LOG_DEBUG_3);
            }

            mapping_del(mapping);

        } else if (!mentry){
            /* save prefix to the registered sites db */
            mdb_add_entry(ms->registered_sites_db, mapping_eid(mapping), mapping);
            ms_dump_registered_sites(dev, LISP_LOG_DEBUG_3);
            mentry = mapping;
//            /* add record to map-notify */
//            if (mreg_msg_get_hdr(mreg)->map_notify)
//                glist_add_tail(mapping, write_recs);
//            else
//                mapping_del(mapping);
        }

        /* add record to map-notify */
        if (mreg_msg_get_hdr(mreg)->map_notify)
            glist_add_tail(mentry, write_recs);

        /* TODO: start timers */
    }

    if (mnot_msg) {
        if (glist_size(write_recs) > 0) {
            mnot_msg = build_map_notify_msg(keyid, key, write_recs);
            mnotify_msg_hdr(mnot_msg)->nonce = mreg_msg_get_hdr(mreg)->nonce;
            push_ip_udp_hdr(mnot_msg, get_default_ctrl_address(lisp_addr_ip_afi(&udpsock->src)),
                    &udpsock->src, LISP_CONTROL_PORT, LISP_CONTROL_PORT);

            if (send_packet(get_default_ctrl_socket(lisp_addr_ip_afi(&udpsock->dst)),
                    mnotify_msg_data(mnot_msg), mnotify_msg_len(mnot_msg)) != GOOD) {
                lmlog(LISP_LOG_DEBUG_1, "Map-Server: Failed to send Map-Notify");
            }
        }
        glist_destroy(write_recs);
        // dealloc??
        map_notify_msg_del(mnot_msg);
    }

    return(GOOD);
err:
    if(mnot_msg)
        map_notify_msg_del(mnot_msg);
    if (write_recs)
        glist_destroy(write_recs);
    return(BAD);
bad: /* could return different error */
    if(mnot_msg)
        map_notify_msg_del(mnot_msg);
    if (write_recs)
        glist_destroy(write_recs);
    return(BAD);

}

int ms_process_lisp_ctrl_msg(lisp_ctrl_device *dev, lisp_msg *msg, udpsock_t *udpsock) {
    int ret = BAD;

     switch(msg->type) {
     case LISP_MAP_REQUEST:
         lmlog(LISP_LOG_DEBUG_1, "Map-Server: Received Map-Request");
         ret = ms_process_map_request_msg(dev, msg->msg, &udpsock->dst, udpsock->src_port);
         break;
     case LISP_MAP_REGISTER:
         lmlog(LISP_LOG_DEBUG_1, "Map-Server: Received Map-Register");
         ret = ms_process_map_register_msg(dev, msg->msg, udpsock);
         break;
     case LISP_MAP_REPLY:
     case LISP_MAP_NOTIFY:
     case LISP_INFO_NAT:
         lmlog(LISP_LOG_DEBUG_1, "Map-Server: Received control message with type %d. Discarding!",
                 msg->type);
         break;
     default:
         lmlog(LISP_LOG_DEBUG_1, "Map-Server: Received unidentified type (%d) control message", msg->type);
         ret = BAD;
         break;
     }

     if (ret != GOOD) {
         lmlog(LISP_LOG_DEBUG_1, "Map-Server: Failed to process LISP control message");
         return(BAD);
     } else {
         lmlog(LISP_LOG_DEBUG_3, "Map-Server: Completed processing of LISP control message");
         return(ret);
     }
}

ctrl_device_vtable ms_vtable = {
        .process_msg = ms_process_lisp_ctrl_msg,
        .start = ms_ctrl_start,
        .delete = ms_ctrl_delete
};

lisp_ctrl_device *ms_ctrl_init() {
    lisp_ms *ms;
    ms = calloc(1, sizeof(lisp_ms));
    ms->super.mode = MS_MODE;
    ms->super.vtable = &ms_vtable;
    lmlog(LISP_LOG_DEBUG_1, "Finished Initializing Map-Server");

    ms->registered_sites_db = mdb_new();
    ms->lisp_sites_db = mdb_new();

    return((lisp_ctrl_device *)ms);
}

int ms_add_lisp_site_prefix(lisp_ctrl_device *dev, lisp_site_prefix *sp) {
    lisp_ms *ms = NULL;
    ms = (lisp_ms *)dev;

    if (!sp)
        return(BAD);

    if(!mdb_add_entry(ms->lisp_sites_db, lsite_prefix(sp), sp))
        return(BAD);
    return(GOOD);
}

int ms_add_registered_site_prefix(lisp_ctrl_device *dev, mapping_t *sp) {
    lisp_ms *ms = (lisp_ms *)dev;

    if (!sp)
        return(BAD);
    if (!mdb_add_entry(ms->registered_sites_db, mapping_eid(sp), sp))
        return(BAD);
    return(GOOD);
}

void ms_dump_configured_sites(lisp_ctrl_device *dev, int log_level)
{
    lisp_ms             *ms = (lisp_ms *)dev;
    void                *it     = NULL;
    lisp_site_prefix    *site   = NULL;

    lmlog(log_level,"****************** MS configured prefixes **************\n");

    mdb_foreach_entry(ms->lisp_sites_db, it) {
        site = it;
        lmlog(log_level, "Prefix: %s, accept specifics: %s merge: %s, proxy: %s", lisp_addr_to_char(site->eid_prefix),
                (site->accept_more_specifics) ? "on" : "off",
                (site->merge) ? "on" : "off",
                (site->proxy_reply) ? "on" : "off");
    } mdb_foreach_entry_end;
    lmlog(log_level,"*******************************************************\n");
}

void ms_dump_registered_sites(lisp_ctrl_device *dev, int log_level) {
    lisp_ms     *ms = (lisp_ms *)dev;
    void        *it     = NULL;
    mapping_t   *mapping = NULL;

    lmlog(log_level,"**************** MS registered sites ******************\n");
    mdb_foreach_entry(ms->registered_sites_db, it) {
        mapping = it;
        dump_mapping_entry(mapping, log_level);
    } mdb_foreach_entry_end;
    lmlog(log_level,"*******************************************************\n");

}



