/*
 * lispd_map_reply.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 *    Kari Okamoto	    <okamotok@stanford.edu>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

/*
 * Map-Reply Message Format from lisp draft-ietf-lisp-08
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=2 |P|E|           Reserved                | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   |                          Record  TTL                          |
 *  |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *  e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *  o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r   |                          EID-prefix                           |
 *  d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *  | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  \|                            Locator                            |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#include <time.h>
#include "cksum.h"
#include "lispd_afi.h"
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_reply.h"
#include "lispd_pkt_lib.h"
#include "lispd_sockets.h"

int process_map_reply_record(uint8_t **cur_ptr, uint64_t nonce);
int process_map_reply_locator(uint8_t  **offset, lispd_mapping_elt *mapping);
uint8_t *build_map_reply_pkt(
        lispd_mapping_elt *mapping,
        lisp_addr_t *probed_rloc,
        map_reply_opts opts,
        uint64_t nonce,
        int *map_reply_msg_len);


int process_map_reply(uint8_t *packet)
{
    lispd_pkt_map_reply_t       *mrp;
    uint64_t                    nonce;
    //uint8_t                     rloc_probe;
    int                         record_count;
    int                         ctr;

    mrp = (lispd_pkt_map_reply_t *)packet;
    nonce = mrp->nonce;
    record_count = mrp->record_count;
    //rloc_probe = mrp->rloc_probe;

    // XXX alopez RLOC- PROBE

    packet = CO(packet, sizeof(lispd_pkt_map_reply_t));
    for (ctr=0;ctr<record_count;ctr++){
        if ((process_map_reply_record(&packet,nonce))==BAD){
            return (BAD);
        }
    }
    if (is_loggable(LISP_LOG_DEBUG_3)){
        dump_map_cache_db(LISP_LOG_DEBUG_3);
    }
    return (TRUE);
}


int process_map_reply_record(uint8_t **cur_ptr, uint64_t nonce)
{
    lispd_pkt_mapping_record_t              *record                 = NULL;
    lispd_mapping_elt                       *mapping                = NULL;
    lispd_map_cache_entry                   *cache_entry            = NULL;
    lisp_addr_t                             aux_eid_prefix;
    int                                     aux_eid_prefix_length   = 0;
    int                                     aux_iid                 = -1;
    int                                     ctr                     = 0;

    record = (lispd_pkt_mapping_record_t *)(*cur_ptr);
    mapping = new_map_cache_mapping(aux_eid_prefix,aux_eid_prefix_length,aux_iid);
    if (mapping == NULL){
        return (BAD);
    }
    *cur_ptr = (uint8_t *)&(record->eid_prefix_afi);
    if (!pkt_process_eid_afi(cur_ptr,mapping)){
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  Error processing the EID of the map reply record");
        free_mapping_elt(mapping, FALSE);
        return (BAD);
    }
    mapping->eid_prefix_length = record->eid_prefix_length;


    /*
     * Check if the map replay corresponds to a not active map cache
     */

    cache_entry = lookup_nonce_in_no_active_map_caches(mapping->eid_prefix.afi, nonce);


    if (cache_entry != NULL){
        if (cache_entry->mapping->iid != mapping->iid){
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  Instance ID of the map reply doesn't match with the inactive map cache entry");
            free_mapping_elt(mapping, FALSE);
            return (BAD);
        }
        /*
         * If the eid prefix of the received map reply doesn't match the inactive map cache entry (x.x.x.x/32 or x:x:x:x:x:x:x:x/128),then
         * we remove the inactie entry from the database and store it again with the correct eix prefix (for instance /24).
         */
        if (cache_entry->mapping->eid_prefix_length != mapping->eid_prefix_length){
            if (change_map_cache_prefix_in_db(mapping->eid_prefix, mapping->eid_prefix_length, cache_entry) == BAD){
                free_mapping_elt(mapping, FALSE);
                return (BAD);
            }
        }
        cache_entry->active = 1;
        stop_timer(cache_entry->request_retry_timer);
        cache_entry->request_retry_timer = NULL;
        lispd_log_msg(LISP_LOG_DEBUG_2,"  Activating map cache entry %s/%d",
                            get_char_from_lisp_addr_t(mapping->eid_prefix),mapping->eid_prefix_length);
        free_mapping_elt(mapping, FALSE);
    }
    /* If the nonce is not found in the no active cache enties, then it should be an active cache entry */
    else {
        /* Serch map cache entry exist*/
        cache_entry = lookup_map_cache_exact(mapping->eid_prefix,mapping->eid_prefix_length);
        if (cache_entry == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  No map cache entry found for %s/%d",
                    get_char_from_lisp_addr_t(mapping->eid_prefix),mapping->eid_prefix_length);
            free_mapping_elt(mapping, FALSE);
            return (BAD);
        }
        /* Check the found map cache entry contain the nonce of the map reply*/
        if (check_nonce(cache_entry->nonces,nonce)==BAD){
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  The nonce of the Map-Reply doesn't match the nonce of the generated Map-Request. Discarding message ...");
            free_mapping_elt(mapping, FALSE);
            return (BAD);
        }
        cache_entry->nonces = NULL;
        /* Stop timer of Map Requests retransmits */
        if (cache_entry->smr_inv_timer != NULL){
            stop_timer(cache_entry->smr_inv_timer);
            cache_entry->smr_inv_timer = NULL;
        }
        /* Check instane id.*/
        if (cache_entry->mapping->iid != mapping->iid){
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_record:  Instance ID of the map reply doesn't match with the map cache entry");
            free_mapping_elt(mapping, FALSE);
            return (BAD);
        }
        lispd_log_msg(LISP_LOG_DEBUG_2,"  A map cache entry already exists for %s/%d, replacing locators list of this entry",
                get_char_from_lisp_addr_t(cache_entry->mapping->eid_prefix),
                cache_entry->mapping->eid_prefix_length);
        free_locator_list(cache_entry->mapping->head_v4_locators_list);
        free_locator_list(cache_entry->mapping->head_v6_locators_list);
        cache_entry->mapping->head_v4_locators_list = NULL;
        cache_entry->mapping->head_v6_locators_list = NULL;
        free_mapping_elt(mapping, FALSE);
    }
    cache_entry->mapping->locator_count = record->locator_count;
    cache_entry->actions = record->action;
    cache_entry->ttl = ntohl(record->ttl);
    cache_entry->active_witin_period = 1;
    cache_entry->timestamp = time(NULL);


    /* Generate the locators */
    for (ctr=0 ; ctr < record->locator_count ; ctr++){
        if ((process_map_reply_locator (cur_ptr, cache_entry->mapping)) == BAD)
            return(BAD);
    }

    /* [re]Calculate balancing locator vectors  if it is not a negative map reply*/
    // XXX NO calculate for RLOC Probing
    if (cache_entry->mapping->locator_count != 0){
        calculate_balancing_vectors (
                cache_entry->mapping,
                &(((rmt_mapping_extended_info *)cache_entry->mapping->extended_info)->rmt_balancing_locators_vecs));
    }

    /* Reprogramming timers */
    if (!cache_entry->expiry_cache_timer){
        cache_entry->expiry_cache_timer = create_timer (EXPIRE_MAP_CACHE_TIMER);
    }
    start_timer(cache_entry->expiry_cache_timer, cache_entry->ttl*60, (timer_callback)map_cache_entry_expiration,
                     (void *)cache_entry);

    return (TRUE);
}

int process_map_reply_locator(
        uint8_t                 **offset,
        lispd_mapping_elt       *mapping)
{
    lispd_pkt_mapping_record_locator_t  *pkt_locator;
    lispd_locator_elt                   *locator;
    uint8_t                             *cur_ptr;

    cur_ptr = *offset;
    pkt_locator = (lispd_pkt_mapping_record_locator_t *)(cur_ptr);

    cur_ptr = (uint8_t *)&(pkt_locator->locator_afi);

    locator = new_rmt_locator (&cur_ptr,pkt_locator->reachable,
            pkt_locator->priority, pkt_locator->weight,
            pkt_locator->mpriority, pkt_locator->mweight);

    if (locator != NULL){
        if ((err=add_locator_to_mapping (mapping, locator)) != GOOD){
            return (BAD);
        }
    }else{
        return (BAD);
    }

    *offset = cur_ptr;
    return (GOOD);
}



/*
 * build_and_send_map_reply_msg()
 *
 */

int build_and_send_map_reply_msg(
        lispd_mapping_elt *requested_mapping,
        lisp_addr_t *local_rloc,
        lisp_addr_t *remote_rloc,
        uint16_t dport,
        uint64_t nonce,
        map_reply_opts opts)
{

    uint8_t         *packet         = NULL;
    int             packet_len      = 0;
    int             result          = 0;

    /* Build the packet */
    if (opts.rloc_probe == TRUE)
        packet = build_map_reply_pkt(requested_mapping, local_rloc, opts, nonce, &packet_len);
    else
        packet = build_map_reply_pkt(requested_mapping, NULL, opts, nonce, &packet_len);

    /* Send the packet */
    result = send_udp_ctrl_packet(remote_rloc,LISP_CONTROL_PORT, dport,(void *)packet,packet_len);

    if (result == GOOD){
        if (opts.rloc_probe == TRUE){
            lispd_log_msg(LISP_LOG_DEBUG_1, "Sent Map-Reply packet for %s/%d probing local locator %s",
                    get_char_from_lisp_addr_t(requested_mapping->eid_prefix),
                    requested_mapping->eid_prefix_length,
                    get_char_from_lisp_addr_t(*local_rloc));
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1, "Sent Map-Reply packet for %s/%d",
                    get_char_from_lisp_addr_t(requested_mapping->eid_prefix),
                    requested_mapping->eid_prefix_length);
        }
    }

    free(packet);

    if (result != GOOD){
        if (opts.rloc_probe == TRUE){
            lispd_log_msg(LISP_LOG_DEBUG_1, "Couldn't build/send Probe Reply!");
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1, "Couldn't build/send Map-Reply!");
        }
        return (BAD);
    }
    return (GOOD);
}


uint8_t *build_map_reply_pkt(lispd_mapping_elt *mapping,
         lisp_addr_t *probed_rloc, map_reply_opts opts, uint64_t nonce,
         int *map_reply_msg_len) {
    uint8_t *packet;
    lispd_pkt_map_reply_t *map_reply_msg;
    lispd_pkt_mapping_record_t *mapping_record;


    *map_reply_msg_len = sizeof(lispd_pkt_map_reply_t) +
            pkt_get_mapping_record_length(mapping);

    if ((packet = malloc(*map_reply_msg_len)) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "build_map_reply_pkt: Unable to allocate memory for  Map Reply message(%d) %s",
                *map_reply_msg_len, strerror(errno));
        return(ERR_MALLOC);
    }
    memset(packet, 0, *map_reply_msg_len);

    map_reply_msg = (lispd_pkt_map_reply_t *)packet;

    map_reply_msg->type = 2;
    if (opts.rloc_probe)
        map_reply_msg->rloc_probe = 1;
    if (opts.echo_nonce)
        map_reply_msg->echo_nonce = 1;
    map_reply_msg->record_count = 1;
    map_reply_msg->nonce = nonce;


    if (opts.send_rec) {
        mapping_record = (lispd_pkt_mapping_record_t *)
                     CO(map_reply_msg, sizeof(lispd_pkt_map_reply_t));

        if (pkt_fill_mapping_record(mapping_record, mapping, probed_rloc) == NULL) {
            free(packet);
            return(NULL);
        }
    }
    return(packet);
}



/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
