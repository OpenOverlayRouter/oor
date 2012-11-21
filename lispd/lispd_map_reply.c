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
#include "lispd_ipc.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_reply.h"
#include "lispd_pkt_lib.h"

int process_map_reply_record(char **cur_ptr, uint64_t nonce);
int process_map_reply_locator(char  **offset, lispd_identifier_elt *identifier);
uint8_t *build_map_reply_pkt(
        lispd_identifier_elt *identifier,
        lisp_addr_t *probed_rloc,
        map_reply_opts opts,
        uint64_t nonce,
        int *map_reply_msg_len);

/*
 *
 * XXX alopez
 * Inicialitzar TIMERS
 * MEemoria quan paquet no es processa bé
 *
 *
 *
 *
 *
 *
 *
 *
 */



int process_map_reply(char *packet)
{
    lispd_pkt_map_reply_t       *mrp;
    uint64_t                    nonce;
    uint8_t                     rloc_probe;
    int                         record_count;
    int                         ctr;


    mrp = (lispd_pkt_map_reply_t *)packet;
    nonce = mrp->nonce;
    record_count = mrp->record_count;
    rloc_probe = mrp->rloc_probe;

    // XXX alopez RLOC- PROBE

    /*
     *
     *
     *
     * RLOC PROBING
     *
     *
     *
     */
    packet = CO(packet, sizeof(lispd_pkt_map_reply_t));
    for (ctr=0;ctr<record_count;ctr++){
        if ((process_map_reply_record(&packet,nonce))==BAD)
            return (BAD);
    }

    return TRUE;
}


int process_map_reply_record(char **cur_ptr, uint64_t nonce)
{
    lispd_pkt_mapping_record_t              *record;
    lispd_identifier_elt                    identifier;
    lispd_map_cache_entry                   *cache_entry;
    int                                     ctr;

    record = (lispd_pkt_mapping_record_t *)(*cur_ptr);
    init_identifier(&identifier);
    *cur_ptr = (char *)&(record->eid_prefix_afi);
    if (!pkt_process_eid_afi(cur_ptr,&identifier))
        return BAD;
    identifier.eid_prefix_length = record->eid_prefix_length;

    /*
     * Check if the map replay corresponds to a not active map cache
     */

    cache_entry = lookup_nonce_in_no_active_map_caches(identifier.eid_prefix.afi, nonce);


    if (cache_entry){
        if (cache_entry->identifier->iid != identifier.iid){
            syslog(LOG_DEBUG,"  Instance ID of the map reply don't match");
            return (BAD);
        }
        /*
         * If the eid prefix of the received map reply doesn't match the map cache entry to be activated,
         * we remove the entry from the database and store it again with the correct value.
         */
        if (cache_entry->identifier->eid_prefix_length != identifier.eid_prefix_length){
            if (change_eid_prefix_in_db(identifier.eid_prefix, identifier.eid_prefix_length, cache_entry) == BAD)
                return (BAD);
        }
        cache_entry->active = 1;
        stop_timer(cache_entry->request_retry_timer);
        syslog(LOG_DEBUG,"  Activating map cache entry %s/%d",
                            get_char_from_lisp_addr_t(identifier.eid_prefix),identifier.eid_prefix_length);
    }
    /* If the nonce is not found in the no active cache enties, then it should be an active cache entry */
    else {
        /* Serch map cache entry exist*/
        if (!lookup_eid_cache_exact(identifier.eid_prefix,identifier.eid_prefix_length,&cache_entry)){
            syslog(LOG_DEBUG,"  No map cache entry found for %s/%d",
                    get_char_from_lisp_addr_t(identifier.eid_prefix),identifier.eid_prefix_length);
            return BAD;
        }
        /* Check the found map cache entry contain the nonce of the map reply*/
        if (check_nonce(cache_entry->nonces,nonce)==BAD){
            syslog(LOG_ERR,"  Map-Reply: Map Cache entry not found for nonce:");
            lispd_print_nonce(nonce);
            return BAD;
        }
        cache_entry->nonces = NULL;
        /* Check instane id. If the entry doesn't use instane id, its value is 0 */
        if (cache_entry->identifier->iid != identifier.iid){
            syslog(LOG_DEBUG,"  Instance ID of the map reply don't match");
            return (BAD);
        }
        syslog(LOG_DEBUG,"  Existing map cache entry found, replacing locator list");
        free_locator_list(cache_entry->identifier->head_v4_locators_list);
        free_locator_list(cache_entry->identifier->head_v6_locators_list);
        cache_entry->identifier->head_v4_locators_list = NULL;
        cache_entry->identifier->head_v6_locators_list = NULL;
    }
    cache_entry->identifier->locator_count = record->locator_count;
    cache_entry->actions = record->action;
    cache_entry->ttl = record->ttl;
    cache_entry->active_witin_period = 1;
    gettimeofday(&(cache_entry->timestamp), NULL);

    /* Generate the locators */
    for (ctr=0 ; ctr < identifier.locator_count ; ctr++){
        if ((process_map_reply_locator (cur_ptr, cache_entry->identifier)) == BAD)
            return(BAD);
    }
    /* Reprogramming timers */
    if (!cache_entry->expiry_cache_timer)
        cache_entry->expiry_cache_timer = create_timer (EXPIRE_MAP_CACHE);
    start_timer(cache_entry->expiry_cache_timer, cache_entry->ttl, eid_entry_expiration,
                     (void *)cache_entry);

    /*
     *
     *
     *
     * XXX alopez
     *
     * Programar els timers
     * Recalcular locator_hash_table
     *
     *
     *
     *
     */


    return TRUE;
}

int process_map_reply_locator(char  **offset, lispd_identifier_elt *identifier)
{
    lispd_pkt_mapping_record_locator_t  *pkt_locator;
    lispd_locator_elt                   aux_locator;
    lisp_addr_t                         *locator_addr;
    uint8_t								*state;
    char                                *cur_ptr;

    cur_ptr = *offset;
    pkt_locator = (lispd_pkt_mapping_record_locator_t *)(cur_ptr);

    cur_ptr = (char *)&(pkt_locator->locator_afi);


    if (pkt_process_rloc_afi(&cur_ptr, &aux_locator) == BAD)
        return (BAD);
    if((locator_addr = malloc(sizeof(lisp_addr_t))) == NULL){
    	syslog(LOG_ERR,"pkt_process_rloc_afi: Couldn't allocate lisp_addr_t");
    	return (ERR_MALLOC);
    }
    if((state = malloc(sizeof(uint8_t))) == NULL){
    	syslog(LOG_ERR,"pkt_process_rloc_afi: Couldn't allocate uint8_t");
    	return (ERR_MALLOC);
    }

    copy_lisp_addr_t(locator_addr, aux_locator.locator_addr, FALSE);
    *state = pkt_locator->reachable;
    new_locator (identifier, locator_addr,state, DYNAMIC_LOCATOR,
            pkt_locator->priority, pkt_locator->weight,
            pkt_locator->mpriority, pkt_locator->mweight);

    *offset = cur_ptr;
    return (GOOD);
}



/*
 * build_and_send_map_reply_msg()
 *
 */

int build_and_send_map_reply_msg(lispd_identifier_elt *requested_identifier,
        lisp_addr_t *dst_rloc, uint16_t dport, uint64_t nonce, map_reply_opts opts,
        lisp_addr_t *probed_rloc) {

    uint8_t *packet;
    int packet_len = 0;
    int result;

    /* Build the packet */
    packet = build_map_reply_pkt(requested_identifier, probed_rloc, opts, nonce, &packet_len);

    /* Send the packet */
    if (dst_rloc->afi == AF_INET)
        result = send_ctrl_ipv4_packet(dst_rloc,LISP_CONTROL_PORT,dport,(void *)packet,packet_len);
    else
        result = send_ctrl_ipv6_packet(dst_rloc,LISP_CONTROL_PORT,dport,(void *)packet,packet_len);

    free(packet);

    if (result != GOOD){
        syslog(LOG_DAEMON, "Could not send Map-Reply!");
        return (BAD);
    }
    return (GOOD);
}


uint8_t *build_map_reply_pkt(lispd_identifier_elt *identifier,
         lisp_addr_t *probed_rloc, map_reply_opts opts, uint64_t nonce,
         int *map_reply_msg_len) {
    uint8_t *packet;
    lispd_pkt_map_reply_t *map_reply_msg;
    lispd_pkt_mapping_record_t *mapping_record;


    *map_reply_msg_len = sizeof(lispd_pkt_map_reply_t) +
            pkt_get_mapping_record_length(identifier);

    if ((packet = malloc(*map_reply_msg_len)) == NULL) {
        syslog(LOG_DAEMON, "build_map_reply_pkt: malloc(%d) %s",
                *map_reply_msg_len, strerror(errno));
        return(0);
    }
    memset(packet, 0, *map_reply_msg_len);

    map_reply_msg = (lispd_pkt_map_reply_t *)packet;

    map_reply_msg->type = 2;
    if (opts.rloc_probe)
        map_reply_msg->rloc_probe = 1;
    if (opts.echo_nonce)
        map_reply_msg->echo_nonce = 1;
    map_reply_msg->record_count = 0;
    map_reply_msg->nonce = nonce;


    if (opts.send_rec) {
        mapping_record = (lispd_pkt_mapping_record_t *)
                     CO(map_reply_msg, sizeof(lispd_pkt_map_reply_t));

        if (pkt_fill_mapping_record(mapping_record, identifier, probed_rloc) == NULL) {
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
