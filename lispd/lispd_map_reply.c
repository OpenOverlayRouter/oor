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
#include "lispd_rloc_probing.h"
#include "lispd_sockets.h"

/********************************** Function declaration ********************************/

int process_map_reply_record(uint8_t **cur_ptr, uint64_t nonce);

/*
 * Process a record from map-reply probe message
 */

int process_map_reply_probe_record(uint8_t **cur_ptr, uint64_t nonce);

int process_map_reply_locator(uint8_t  **offset, lispd_mapping_elt *mapping);

/*
 * Return the locator from tha mapping that match with the locator of the packet.
 * Retun null if no match found. Offset is updated to point the next locator of the packet.
 */

int process_map_reply_probe_locator(
        uint8_t                 **offset,
        lispd_mapping_elt       *mapping,
        uint64_t                nonce,
        lispd_locator_elt       **locator);

uint8_t *build_map_reply_pkt(
        lispd_mapping_elt *mapping,
        lisp_addr_t *probed_rloc,
        map_reply_opts opts,
        uint64_t nonce,
        int *map_reply_msg_len);

/****************************************************************************************/

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

    packet = CO(packet, sizeof(lispd_pkt_map_reply_t));
    for (ctr=0;ctr<record_count;ctr++){
        if (mrp->rloc_probe == FALSE){
            if ((process_map_reply_record(&packet,nonce))==BAD){
                return (BAD);
            }
            if (is_loggable(LISP_LOG_DEBUG_3)){
                dump_map_cache_db(LISP_LOG_DEBUG_3);
            }
        }else{
            if ((process_map_reply_probe_record(&packet,nonce))==BAD){
                return (BAD);
            }
        }
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
    uint8_t                                 new_mapping             = FALSE;

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
        new_mapping = TRUE;
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
    cache_entry->actions = record->action;
    cache_entry->ttl = ntohl(record->ttl);
    cache_entry->active_witin_period = 1;
    cache_entry->timestamp = time(NULL);
    //locator_count updated when adding the processed locators

    /* Generate the locators */
    for (ctr=0 ; ctr < record->locator_count ; ctr++){
        if ((process_map_reply_locator (cur_ptr, cache_entry->mapping)) == BAD){
            return(BAD);
        }
    }

    /* [re]Calculate balancing locator vectors  if it is not a negative map reply*/
    if (cache_entry->mapping->locator_count != 0){
        calculate_balancing_vectors (
                cache_entry->mapping,
                &(((rmt_mapping_extended_info *)cache_entry->mapping->extended_info)->rmt_balancing_locators_vecs));
    }
    /*
     * Reprogramming timers
     */
    /* Expiration cache timer */
    if (!cache_entry->expiry_cache_timer){
        cache_entry->expiry_cache_timer = create_timer (EXPIRE_MAP_CACHE_TIMER);
    }
    start_timer(cache_entry->expiry_cache_timer, cache_entry->ttl*60, (timer_callback)map_cache_entry_expiration,
                     (void *)cache_entry);
    lispd_log_msg(LISP_LOG_DEBUG_1,"The map cache entry %s/%d will expire in %d minutes.",
            get_char_from_lisp_addr_t(cache_entry->mapping->eid_prefix),
            cache_entry->mapping->eid_prefix_length, cache_entry->ttl);

    /* RLOC probing timer */
    if (new_mapping == TRUE && rloc_probe_interval != 0){
        programming_rloc_probing(cache_entry);
    }
    return (TRUE);
}

/*
 * Process a record from map-reply probe message
 */

int process_map_reply_probe_record(
        uint8_t     **cur_ptr,
        uint64_t    nonce)
{
    lispd_pkt_mapping_record_t              *record                 = NULL;
    lispd_mapping_elt                       *mapping                = NULL;
    lispd_map_cache_entry                   *cache_entry            = NULL;
    lispd_locator_elt                       *aux_locator            = NULL;
    lispd_locator_elt                       *locator                = NULL;
    rmt_locator_extended_info               *rmt_locator_ext_inf    = NULL;
    lispd_locators_list                     *locators_list[2]       = {NULL,NULL};
    lisp_addr_t                             aux_eid_prefix;
    int                                     aux_eid_prefix_length   = 0;
    int                                     aux_iid                 = -1;
    int                                     ctr                     = 0;
    int                                     locators_probed         = 0;

    record = (lispd_pkt_mapping_record_t *)(*cur_ptr);
    mapping = new_map_cache_mapping(aux_eid_prefix,aux_eid_prefix_length,aux_iid);
    if (mapping == NULL){
        return (BAD);
    }
    *cur_ptr = (uint8_t *)&(record->eid_prefix_afi);
    if (!pkt_process_eid_afi(cur_ptr,mapping)){
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_probe_record:  Error processing the EID of the map reply record");
        free_mapping_elt(mapping, FALSE);
        return (BAD);
    }
    mapping->eid_prefix_length = record->eid_prefix_length;

    if (record->locator_count != 0 ){
        /* Serch map cache entry exist*/
        cache_entry = lookup_map_cache_exact(mapping->eid_prefix,mapping->eid_prefix_length);
        if (cache_entry == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_probe_record:  No map cache entry found for %s/%d",
                    get_char_from_lisp_addr_t(mapping->eid_prefix),mapping->eid_prefix_length);
            free_mapping_elt(mapping, FALSE);
            return (BAD);
        }

        /* Check instane id.*/
        if (cache_entry->mapping->iid != mapping->iid){
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_reply_probe_record:  Instance ID of the map reply doesn't match with the map cache entry");
            free_mapping_elt(mapping, FALSE);
            return (BAD);
        }


        /* Free auxiliar mapping used to search the map cache entry*/
        free_mapping_elt(mapping, FALSE);

        /*
         * Check probed locators of the list. Only one locator can be probed per message
         */
        for (ctr=0 ; ctr < record->locator_count ; ctr++){
            err = process_map_reply_probe_locator (cur_ptr, cache_entry->mapping, nonce, &aux_locator);
            if (err == ERR_MALLOC){
                return (BAD);
            }
            if (aux_locator == NULL){ // The current locator is not probed
                continue;
            }
            rmt_locator_ext_inf = (rmt_locator_extended_info *)(aux_locator->extended_info);
            /* Check the nonce of the message match with the one stored in the structure of the locator */
            if ((check_nonce(rmt_locator_ext_inf->rloc_probing_nonces,nonce)) == GOOD){
                rmt_locator_ext_inf->rloc_probing_nonces = NULL;
                if (locators_probed == 0){
                    locator = aux_locator;
                    locators_probed ++;
                }else{
                    lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_reply_probe_record: Invalid Map-Reply Probe. Only one locator can be probed per message");
                    return (BAD);
                }
            }else{
                lispd_log_msg(LISP_LOG_DEBUG_1,"The nonce of the Map-Reply Probe doesn't match the nonce of the generated Map-Request Probe. Discarding message ...");
                return (BAD);
            }
        }

        lispd_log_msg(LISP_LOG_DEBUG_1,"Map-Reply probe reachability to RLOC %s of the EID cache entry %s/%d",
                    get_char_from_lisp_addr_t(*(locator->locator_addr)),
                    get_char_from_lisp_addr_t(cache_entry->mapping->eid_prefix),
                    cache_entry->mapping->eid_prefix_length);

    }else{ // Probe of a negative map cache -> proxy-etr
        if(proxy_etrs != NULL && compare_lisp_addr_t(&(mapping->eid_prefix),&(proxy_etrs->mapping->eid_prefix)) == 0){
            cache_entry = proxy_etrs;
            locators_list[0] = proxy_etrs->mapping->head_v4_locators_list;
            locators_list[1] = proxy_etrs->mapping->head_v6_locators_list;

            for (ctr=0 ; ctr < 2 ; ctr++){
                while (locators_list[ctr]!=NULL){
                    aux_locator = locators_list[ctr]->locator;
                    rmt_locator_ext_inf = (rmt_locator_extended_info *)(aux_locator->extended_info);
                    if ((check_nonce(rmt_locator_ext_inf->rloc_probing_nonces,nonce)) == GOOD){
                        rmt_locator_ext_inf->rloc_probing_nonces = NULL;
                        locator = aux_locator;
                        break;
                    }
                    locators_list[ctr] = locators_list[ctr]->next;
                }
                if (locator != NULL){
                    break;
                }
            }
            if (locator == NULL){
                lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_reply_probe_record: The nonce of the Negative Map-Reply Probe don't match any nonce of Proxy-ETR locators");
                free_mapping_elt(mapping, FALSE);
                return (BAD);
            }
            free_mapping_elt(mapping, FALSE);
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_reply_probe_record: The received negative Map-Reply Probe has not been requested: %s/%d",
                    get_char_from_lisp_addr_t(mapping->eid_prefix),mapping->eid_prefix_length);
            free_mapping_elt(mapping, FALSE);
            return (BAD);
        }

        lispd_log_msg(LISP_LOG_DEBUG_1,"Map-Reply probe reachability to the PETR with RLOC %s",
                    get_char_from_lisp_addr_t(*(locator->locator_addr)));
    }



    if (*(locator->state) == DOWN){
        *(locator->state) = UP;

        lispd_log_msg(LISP_LOG_DEBUG_1,"Map-Reply Probe received for locator %s -> Locator state changes to UP",
                           get_char_from_lisp_addr_t(*(locator->locator_addr)));

        /* [re]Calculate balancing locator vectors  if it has been a change of status*/
        calculate_balancing_vectors (
                cache_entry->mapping,
                &(((rmt_mapping_extended_info *)cache_entry->mapping->extended_info)->rmt_balancing_locators_vecs));
    }

    /*
     * Reprogramming timers of rloc probing
     */
    rmt_locator_ext_inf = (rmt_locator_extended_info *)(locator->extended_info);
    if (!rmt_locator_ext_inf->probe_timer){
        // It should never enter in this block except RLOC Probing not active and receive a Map Reply Probe.
        rmt_locator_ext_inf->probe_timer = create_timer (RLOC_PROBING_TIMER);
        rmt_locator_ext_inf->probe_timer->cb_argument = (void *)new_timer_rloc_probe_argument(cache_entry,locator);;
    }

    start_timer(rmt_locator_ext_inf->probe_timer, rloc_probe_interval, (timer_callback)rloc_probing,rmt_locator_ext_inf->probe_timer->cb_argument);
    if (record->locator_count != 0 ){
        lispd_log_msg(LISP_LOG_DEBUG_2,"Reprogramed RLOC probing of the locator %s of the EID %s/%d in %d seconds",
                get_char_from_lisp_addr_t(*(locator->locator_addr)),
                get_char_from_lisp_addr_t(cache_entry->mapping->eid_prefix),
                cache_entry->mapping->eid_prefix_length, rloc_probe_interval);
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_2,"Reprogramed RLOC probing of the locator %s (PETR) in %d seconds",
                get_char_from_lisp_addr_t(*(locator->locator_addr)), rloc_probe_interval);
    }

    return (GOOD);
}


int process_map_reply_locator(
        uint8_t                 **offset,
        lispd_mapping_elt       *mapping)
{
    lispd_pkt_mapping_record_locator_t  *pkt_locator    = NULL;
    lispd_locator_elt                   *locator        = NULL;
    uint8_t                             *cur_ptr        = NULL;
    uint8_t                             status          = UP;

    cur_ptr = *offset;
    pkt_locator = (lispd_pkt_mapping_record_locator_t *)(cur_ptr);

    cur_ptr = (uint8_t *)&(pkt_locator->locator_afi);

    /*
     * We only consider the reachable bit if the information comes from the owner of the locator (local)
     */
    if (pkt_locator->reachable == DOWN && pkt_locator->local == UP){
        status = DOWN;
    }

    locator = new_rmt_locator (&cur_ptr,status,
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
 * Return the locator from tha mapping that match with the locator of the packet.
 * Retun null if no match found. Offset is updated to point the next locator of the packet.
 */

int process_map_reply_probe_locator(
        uint8_t                 **offset,
        lispd_mapping_elt       *mapping,
        uint64_t                nonce,
        lispd_locator_elt       **locator)
{
    lispd_pkt_mapping_record_locator_t  *pkt_locator    = NULL;
    lispd_locator_elt                   *aux_locator    = NULL;
    uint8_t                             *cur_ptr        = NULL;


    *locator = NULL;
    cur_ptr = *offset;
    pkt_locator = (lispd_pkt_mapping_record_locator_t *)(cur_ptr);

    cur_ptr = (uint8_t *)&(pkt_locator->locator_afi);

    /* Extract locator from packet */
    aux_locator = new_rmt_locator (&cur_ptr,UP,
            pkt_locator->priority, pkt_locator->weight,
            pkt_locator->mpriority, pkt_locator->mweight);

    if (aux_locator == NULL){
        return (ERR_MALLOC);
    }
    /* If the locator of the packed is probed, search the structure of the locator that represents the locator of tha packet */
    if (pkt_locator->probed == TRUE){
        *locator = get_locator_from_mapping(mapping, *(aux_locator->locator_addr));
        if (*locator == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_2,"get_map_reply_locator_from_mapping: The locator %s is not found in the mapping %s/%d",
                    get_char_from_lisp_addr_t(*(aux_locator->locator_addr)),
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length);
            return (ERR_NO_EXIST);
        }
    }
    *offset = cur_ptr;
    return (GOOD);
}


/*
 * build_and_send_map_reply_msg()
 */

int build_and_send_map_reply_msg(
        lispd_mapping_elt *requested_mapping,
        lisp_addr_t *src_rloc_addr,
        lisp_addr_t *dst_rloc_addr,
        uint16_t dport,
        uint64_t nonce,
        map_reply_opts opts)
{

    uint8_t         *packet             = NULL;
    int             packet_len          = 0;
    int             result              = 0;

    /* Build the packet */
    if (opts.rloc_probe == TRUE){
        packet = build_map_reply_pkt(requested_mapping, src_rloc_addr, opts, nonce, &packet_len);
    }
    else{
        packet = build_map_reply_pkt(requested_mapping, NULL, opts, nonce, &packet_len);
    }
    if (packet == NULL){
        return (BAD);
    }

    /* Send the packet */

    if (src_rloc_addr == NULL){
        src_rloc_addr = get_default_ctrl_address(dst_rloc_addr->afi);
    }
    if (src_rloc_addr != NULL){
        result = send_udp_packet(src_rloc_addr, dst_rloc_addr,LISP_CONTROL_PORT, dport,(void *)packet,packet_len);
    }else {
        lispd_log_msg(LISP_LOG_DEBUG_1,"build_and_send_map_reply_msg: Couldn't send Map-Reply. No local RLOC compatible with the afi of the destinaion locator %s",
                get_char_from_lisp_addr_t(*dst_rloc_addr));
        result = BAD;
    }

    if (result == GOOD){
        if (opts.rloc_probe == TRUE){
            lispd_log_msg(LISP_LOG_DEBUG_1, "Sent Map-Reply packet for %s/%d probing local locator %s",
                    get_char_from_lisp_addr_t(requested_mapping->eid_prefix),
                    requested_mapping->eid_prefix_length,
                    get_char_from_lisp_addr_t(*src_rloc_addr));
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1, "Sent Map-Reply packet for %s/%d",
                    get_char_from_lisp_addr_t(requested_mapping->eid_prefix),
                    requested_mapping->eid_prefix_length);
        }
    }else {
        if (opts.rloc_probe == TRUE){
            lispd_log_msg(LISP_LOG_DEBUG_1, "Couldn't build/send Probe Reply!");
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1, "Couldn't build/send Map-Reply!");
        }
        result = BAD;
    }

    free(packet);

    return (result);
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
        return(NULL);
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
