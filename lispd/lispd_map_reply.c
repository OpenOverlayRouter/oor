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

/*
 *
 *
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

    record = (lispd_pkt_mapping_record_t *)cur_ptr;
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
    pkt_locator = (lispd_pkt_mapping_record_locator_t *)cur_ptr;

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
    new_locator (identifier, locator_addr, DYNAMIC_LOCATOR,
            pkt_locator->priority, pkt_locator->weight,
            pkt_locator->mpriority, pkt_locator->mweight,
            state);
    *offset = cur_ptr;
    return (GOOD);
}


uint8_t *build_map_reply_pkt(lisp_addr_t *src, lisp_addr_t *dst, uint16_t dport,
        prefix_t eid_prefix, uint64_t nonce, map_reply_opts opts, int *len) {
    uint8_t *packet;
    int packet_len = 0;
    int iph_len = 0;
    struct udphdr *udph;
    int udpsum = 0;
    lispd_pkt_map_reply_t *map_reply_msg;
    int map_reply_msg_len = 0;
    lispd_pkt_mapping_record_t *mr_msg_eid, *next_rec;
    patricia_node_t *node = NULL;
    lispd_locator_chain_t *locator_chain_eid4 = NULL;
    lispd_locator_chain_t *locator_chain_eid6 = NULL;

    map_reply_msg_len = sizeof(lispd_pkt_map_reply_t);
    if ((iph_len = get_ip_header_len(src->afi)) == 0)
        return(0);

    /* If the options ask for a mapping record, calculate addtional length */
    if (opts.send_rec) {
        switch (eid_prefix.family) {
        case AF_INET:
            node = patricia_search_best(AF4_database, &eid_prefix);
            if (node != NULL)
                locator_chain_eid4 = ((lispd_locator_chain_t *)(node->data));
            if (locator_chain_eid4 != NULL)
                map_reply_msg_len += pkt_get_mapping_record_length(locator_chain_eid4);
            break;
        case AF_INET6:
            node = patricia_search_best(AF6_database, &eid_prefix);
            if (node != NULL)
                locator_chain_eid6 = ((lispd_locator_chain_t *)(node->data));
            if (locator_chain_eid6 != NULL)
                map_reply_msg_len += pkt_get_mapping_record_length(locator_chain_eid6);
            break;
        default:
            syslog(LOG_DAEMON, "build_map_reply_pkt: Unsupported EID prefix AFI: %d",
                    eid_prefix.family);
            return(0);
        }
    }

    packet_len = iph_len + sizeof(struct udphdr) + map_reply_msg_len;

    if ((packet = malloc(packet_len)) == NULL) {
        syslog(LOG_DAEMON, "build_map_reply_pkt: malloc(%d) %s",
                map_reply_msg_len, strerror(errno));
        return(0);
    }
    memset(packet, 0, packet_len);

    udph = build_ip_header((void *)packet, src, dst, iph_len);

#ifdef BSD
    udph->uh_sport = htons(LISP_CONTROL_PORT);
    udph->uh_dport = htons(dport);
    udph->uh_ulen  = htons(sizeof(struct udphdr) + map_reply_msg_len);
    udph->uh_sum   = 0;
#else
    udph->source = htons(LISP_CONTROL_PORT);
    udph->dest   = htons(dport);
    udph->len    = htons(sizeof(struct udphdr) + map_reply_msg_len);
    udph->check  = 0;
#endif

    map_reply_msg = (lispd_pkt_map_reply_t *) CO(udph, sizeof(struct udphdr));

    map_reply_msg->type = 2;
    if (opts.rloc_probe)
        map_reply_msg->rloc_probe = 1;
    if (opts.echo_nonce)
        map_reply_msg->echo_nonce = 1;
    map_reply_msg->record_count = 0;
    map_reply_msg->nonce = nonce;

    if (opts.send_rec) {
        /*
         * Optionally, we send Map Reply records. For RLOC Probing,
         * the language in the spec is SHOULD
         */
        mr_msg_eid = (lispd_pkt_mapping_record_t *)
                     CO(map_reply_msg, sizeof(lispd_pkt_map_reply_t));

        if (locator_chain_eid4) {
            next_rec = pkt_fill_mapping_record(mr_msg_eid, locator_chain_eid4, &opts);
            if (next_rec) {
                map_reply_msg->record_count++;
                mr_msg_eid = next_rec;
            }
        }

        if (locator_chain_eid6) {
            if (pkt_fill_mapping_record(mr_msg_eid, locator_chain_eid6, &opts))
                map_reply_msg->record_count++;
        }
    }

    /* Compute checksums */
    if (src->afi == AF_INET)
        ((struct ip *) packet)->ip_sum = ip_checksum(packet, iph_len);
    if ((udpsum = udp_checksum(udph, packet_len - iph_len, packet, src->afi)) == -1) {
        return (0);
    }
    udpsum(udph) = udpsum;
    *len = packet_len;
    return(packet);
}

/*
 * build_and_send_map_reply_msg()
 *
 */

int build_and_send_map_reply_msg(lisp_addr_t *src, lisp_addr_t *dst, uint16_t dport,
        struct sockaddr *dst_sa, int s, prefix_t eid_prefix,
        uint64_t nonce, map_reply_opts opts) {
    lisp_addr_t destination;
    struct sockaddr_storage destination_sa;
    uint8_t *packet;
    int len = 0;

    if (src == NULL) {
        syslog(LOG_DAEMON, "build_and_send_map_reply_msg: no source address");
        return(0);
    }

    if (dst == NULL && dst_sa == NULL) {
        syslog(LOG_DAEMON, "build_and_send_map_reply_msg: no destination address");
        return(0);
    }

    if (dst == NULL) {
        if (sockaddr2lisp(dst_sa, &destination) < 0) {
            syslog(LOG_DAEMON, "build_and_send_map_reply_msg: sockaddr2lisp failed");
            return(0);
        }
    } else {
        memcpy(&destination, dst, sizeof(lisp_addr_t));
    }

    if (dst_sa == NULL) {
        if (!inaddr2sockaddr(dst, (struct sockaddr *)&destination_sa, dport)) {
            syslog(LOG_DAEMON, "build_and_send_map_reply_msg: inaddr2sockaddr failed");
            return(0);
        }
    } else {
        memcpy((void *)&destination_sa, dst_sa, get_sockaddr_len(dst_sa->sa_family));
        switch (dst_sa->sa_family) {
        case AF_INET:
            dport = ntohs(((struct sockaddr_in *)dst_sa)->sin_port);
            break;
        case AF_INET6:
            dport = ntohs(((struct sockaddr_in6 *)dst_sa)->sin6_port);
            break;
        default:
            dport = LISP_CONTROL_PORT;
            break;
        }
    }

    packet = build_map_reply_pkt(src, &destination, dport, eid_prefix, nonce, opts, &len);

    /* Send the packet over a raw socket */
    if (!send_raw_udp((struct sockaddr *)&destination_sa, packet, len)) {
        syslog(LOG_DAEMON, "Could not send Map-Reply!");
        free(packet);
        return (0);
    }

    /* LJ: The code below is for the case when we reuse the receiving socket.
     *     However, since it is bound to INADDR_ANY, it selects source
     *     address based on exit interface, and because of that it will
     *     use our EID on lmn0. Because we want source port 4342, and it is
     *     already bound, we need to use raw sockets in send_map_reply()
     */
/*
    if ((nbytes = sendto(s, (const void *) packet, map_reply_msg_len, 0,
                    dst, sizeof(struct sockaddr))) < 0) {
        syslog(LOG_DAEMON, "send_map_reply: sendto: %s", strerror(errno));
        free(packet);
        return (0);
    }

    if (nbytes != map_reply_msg_len) {
        syslog(LOG_DAEMON, "build_and_send_map_reply_msg: nbytes (%d) != map_reply_msg_len (%d)\n",
                nbytes, map_reply_msg_len);
        return (0);
    }
    free(packet);
*/

    return(1);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
