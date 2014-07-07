/*
 * lispd_output.c
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
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 */



#include <assert.h>
#include "bob/lookup3.c"
#include "lispd_info_nat.h"
#include "lispd_locator.h"
#include "lispd_map_request.h"
#include "lispd_mapping.h"
#include "lispd_output.h"
#include "lispd_pkt_lib.h"
#include "lispd_referral_cache_db.h"
#include "lispd_sockets.h"
#include "api/ipc.h"


/*
 * Select the source RLOC according to the priority and weight.
 */

int select_src_locators_from_balancing_locators_vec (
        lispd_mapping_elt   *src_mapping,
        packet_tuple        tuple,
        lispd_locator_elt   **src_locator);


/*
 * Select the source and destination RLOC according to the priority and weight.
 * The destination RLOC is selected according to the AFI of the selected source RLOC
 */

int select_src_rmt_locators_from_balancing_locators_vec (
        lispd_mapping_elt   *src_mapping,
        lispd_mapping_elt   *dst_mapping,
        packet_tuple        tuple,
        lispd_locator_elt   **src_locator,
        lispd_locator_elt   **dst_locator);

int forward_native(
        uint8_t        *packet_buf,
        int             pckt_length )
{
#ifndef VPNAPI
    int             ret                        = 0;
    int             output_socket              = 0;
    int             packet_afi                 = 0;

    packet_afi = get_afi_from_packet(packet_buf);
    output_socket = get_default_output_socket(packet_afi);


    if (output_socket == -1){
        lispd_log_msg(LISP_LOG_DEBUG_2, "fordward_native: No output interface for afi %d",packet_afi);
        return (BAD);
    }


    lispd_log_msg(LISP_LOG_DEBUG_3, "Fordwarding native for destination %s",
            get_char_from_lisp_addr_t(extract_dst_addr_from_packet(packet_buf)));


    ret = send_packet(output_socket,packet_buf,pckt_length);

    return (ret);
#else
    return (BAD);
#endif
}

/*
 * Send a packet to a proxy etr
 */

int fordward_to_petr(
        uint8_t                 *buffer,
        int                     original_packet_length,
        lispd_mapping_elt       *src_mapping,
        packet_tuple            tuple)
{
    lispd_locator_elt           *outer_src_locator  = NULL;
    lispd_locator_elt           *outer_dst_locator  = NULL;
    int                         output_socket       = 0;
    lisp_addr_t                 *src_addr           = NULL;
    lisp_addr_t                 *dst_addr           = NULL;
    nat_info_str                *nat_info           = NULL;
    uint8_t 					*encap_packet 		= NULL;
    int 						encap_packet_size 	= 0;

    if (proxy_etrs == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3, "fordward_to_petr: Proxy-etr not found");
        return (BAD);
    }

    if ((select_src_rmt_locators_from_balancing_locators_vec (
                src_mapping,
                proxy_etrs->mapping,
                tuple,
                &outer_src_locator,
                &outer_dst_locator)) != GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_3, "fordward_to_petr: No Proxy-etr compatible with local locators afi");
        return (BAD);
    }

    dst_addr = outer_dst_locator->locator_addr;
    src_addr = outer_src_locator->locator_addr;

    /* If the selected src locator is behind NAT, fordware to the RTR */
    nat_info = ((lcl_locator_extended_info *)outer_src_locator->extended_info)->nat_info;
    if (nat_info != NULL && nat_info->rtr_locators_list != NULL){
        dst_addr = &(nat_info->rtr_locators_list->locator->address);
    }

    /*
     * Push lisp header to the buffer
     */
    encap_packet = CO(buffer,(IN_PACK_BUFF_OFFSET - sizeof(struct lisphdr)));
    encap_packet_size = original_packet_length + sizeof(struct lisphdr);
    add_lisp_header(encap_packet, 0);

    output_socket = *(((lcl_locator_extended_info *)(outer_src_locator->extended_info))->out_socket);
    if (send_data_packet(buffer, encap_packet_size, src_addr, dst_addr, output_socket) != GOOD){
        return (BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_3, "Fordwarded packet to petr: %s",get_char_from_lisp_addr_t(*dst_addr));

    return (GOOD);
}

int forward_to_natt_rtr(
        uint8_t             *buffer,
        int                 original_packet_length,
        lispd_locator_elt   *src_locator)
{
    uint8_t                     *encap_packet       = NULL;
    int                         encap_packet_size   = 0;
    lcl_locator_extended_info   *extended_info      = NULL;
    lispd_rtr_locators_list     *rtr_locators_list  = NULL;
    int                         output_socket       = 0;
    lisp_addr_t                 *src_addr			= NULL;
    lisp_addr_t                 *dst_addr			= NULL;

    extended_info = (lcl_locator_extended_info *)src_locator->extended_info;
    rtr_locators_list = extended_info->nat_info->rtr_locators_list;
    if (rtr_locators_list == NULL){
        //Could be due to RTR discarded by source afi type
        lispd_log_msg(LISP_LOG_DEBUG_2,"forward_to_natt_rtr: No RTR for the selected src locator (%s).",
                get_char_from_lisp_addr_t(*(src_locator->locator_addr)));
        return (BAD);
    }
    src_addr = src_locator->locator_addr;
    dst_addr = &(rtr_locators_list->locator->address);


    /*
     * Push lisp header to the buffer
     */
    encap_packet = CO(buffer,(IN_PACK_BUFF_OFFSET - sizeof(struct lisphdr)));
    encap_packet_size = original_packet_length + sizeof(struct lisphdr);
    add_lisp_header(encap_packet, 0);

    output_socket = *(extended_info->out_socket);
    if (send_data_packet(buffer, encap_packet_size, src_addr, dst_addr, output_socket) != GOOD){
        return (BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_3, "Forwarding packet to NAT RTR %s",get_char_from_lisp_addr_t(*dst_addr));

    return (GOOD);
}

/*
 * Add a not active map cache entry and init the process to request to the mapping system the information
 * for this mapping
 */
int handle_map_cache_miss(
        lisp_addr_t *requested_eid,
        lisp_addr_t *src_eid)
{

    lispd_map_cache_entry           *entry          = NULL;
    timer_map_request_argument      *arguments      = NULL;
    int                             prefix_length   = 0;


    switch (requested_eid->afi){
    case AF_INET:
        prefix_length = 32;
        break;
    case AF_INET6:
        prefix_length = 128;
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_1,"handle_map_cache_miss: Unknown AFI");
        return (BAD);
    }

    if ((arguments = malloc(sizeof(timer_map_request_argument)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"handle_map_cache_miss: Unable to allocate memory for timer_map_request_argument: %s",
                strerror(errno));
        return (ERR_MALLOC);
    }

    entry = new_map_cache_entry(
            *requested_eid,
            prefix_length,
            DYNAMIC_MAP_CACHE_ENTRY,
            DEFAULT_DATA_CACHE_TTL);

    if (entry == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_1,"handle_map_cache_miss: Couldn't create map cache entry");
        free (arguments);
        return (BAD);
    }

    arguments->map_cache_entry = entry;
    arguments->src_eid = *src_eid;

    if ((err=send_map_request_miss(NULL, (void *)arguments))!=GOOD){
        return (BAD);
    }
    return (GOOD);
}

/*
 * Add a not active map cache entry and init the process to request to the ddt mapping system the information
 * for this mapping
 */
int handle_map_cache_miss_with_ddt(
        lisp_addr_t *requested_eid,
        lisp_addr_t *src_eid)
{

    lispd_map_cache_entry               *map_cache_entry    = NULL;
    lispd_referral_cache_entry          *referral_cache     = NULL;
    lispd_pending_referral_cache_entry  *pending_referral   = NULL;
    int                                 prefix_length       = 0;

    switch (requested_eid->afi){
    case AF_INET:
        prefix_length = 32;
        break;
    case AF_INET6:
        prefix_length = 128;
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_1,"handle_map_cache_miss: Unknown AFI");
        return (BAD);
    }

    /* Serach if the entry is already in process to be resolved by ddt process */
    pending_referral = lookup_pending_referral_cache_entry_by_eid(*requested_eid, prefix_length);

    if (pending_referral != NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"handle_map_cache_miss: %s/%d is in process to be resolved by DDT client",
                get_char_from_lisp_addr_t(*requested_eid), prefix_length);
        return (GOOD);
    }

    map_cache_entry = new_map_cache_entry(
            *requested_eid,
            prefix_length,
            DYNAMIC_MAP_CACHE_ENTRY,
            DEFAULT_DATA_CACHE_TTL);

    if (map_cache_entry == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_1,"handle_map_cache_miss_with_ddt: Couldn't create map cache entry");
        return (BAD);
    }

    referral_cache = lookup_referral_cache(*requested_eid, DDT_ALL_DATABASES);
    if (referral_cache == NULL){
        lispd_log_msg(LISP_LOG_ERR,"handle_map_cache_miss_with_ddt: No DDT root found");
        return (BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_1,"handle_map_cache_miss_with_ddt: Start DDT process to resolve %s. Process started from prefix %s/%d",
            get_char_from_lisp_addr_t(*requested_eid),get_char_from_lisp_addr_t(referral_cache->mapping->eid_prefix),
            referral_cache->mapping->eid_prefix_length);

    pending_referral = new_pending_referral_cache_entry(map_cache_entry,*src_eid,referral_cache);
    if (pending_referral == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_1,"handle_map_cache_miss_with_ddt: Couldn't create pending referral");
        del_map_cache_entry_from_db(map_cache_entry->mapping->eid_prefix, map_cache_entry->mapping->eid_prefix_length);
        return (BAD);
    }
    if ((add_pending_referral_cache_entry_to_list(pending_referral))!=GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_1,"handle_map_cache_miss_with_ddt: Couldn't add the pending referral cache entry to the list");
        del_map_cache_entry_from_db(map_cache_entry->mapping->eid_prefix, map_cache_entry->mapping->eid_prefix_length);
        free_pending_referral_cache_entry(pending_referral);
        return (BAD);
    }

    if ((err=send_ddt_map_request_miss(pending_referral->ddt_request_retry_timer, (void *)pending_referral))!=GOOD){
        return (BAD);
    }
    return (GOOD);
}


/*
 * Calculate the hash of the 5 tuples of a packet
 */

uint32_t get_hash_from_tuple (packet_tuple tuple)
{
    int         hash    = 0;
    int         len     = 0;
    int         port    = tuple.src_port;
    uint32_t    *tuples = NULL;

    port = port + ((int)tuple.dst_port << 16);
    switch (tuple.src_addr.afi){
    case AF_INET:
        len = 4; // 1 integer src_addr + 1 integer dst_adr + 1 integer (ports) + 1 integer protocol
        if ((tuples = (uint32_t *)malloc(sizeof(uint32_t)*(4))) == NULL ){
            lispd_log_msg(LISP_LOG_WARNING,"get_hash_from_tuple: Couldn't allocate memory for tuples array: %s", strerror(errno));
            return (0);
        }
        tuples[0] = tuple.src_addr.address.ip.s_addr;
        tuples[1] = tuple.dst_addr.address.ip.s_addr;
        tuples[2] = port;
        tuples[3] = tuple.protocol;
        break;
    case AF_INET6:
        len = 10; // 4 integer src_addr + 4 integer dst_adr + 1 integer (ports) + 1 integer protocol
        if ((tuples = (uint32_t *)malloc(sizeof(uint32_t)*(10))) == NULL ){
            lispd_log_msg(LISP_LOG_WARNING,"get_hash_from_tuple: Couldn't allocate memory for tuples array: %s", strerror(errno));
            return (0);
        }
        memcpy(&tuples[0],&(tuple.src_addr.address.ipv6),sizeof(struct in6_addr));
        memcpy(&tuples[4],&(tuple.dst_addr.address.ipv6),sizeof(struct in6_addr));
        tuples[8] = port;
        tuples[9] = tuple.protocol;
        break;
    }

    hash = hashword (tuples,len, 2013); //2013 used as initial value
    free (tuples);

    return (hash);
}


/*
 * Select the source RLOC according to the priority and weight.
 */

int select_src_locators_from_balancing_locators_vec (
        lispd_mapping_elt   *src_mapping,
        packet_tuple        tuple,
        lispd_locator_elt   **src_locator)
{
    int                     src_vec_len     = 0;
    uint32_t                pos             = 0;
    uint32_t                hash            = 0;
    balancing_locators_vecs *src_blv        = NULL;
    lispd_locator_elt       **src_loc_vec   = NULL;

    src_blv = &((lcl_mapping_extended_info *)(src_mapping->extended_info))->outgoing_balancing_locators_vecs;

    if (src_blv->balancing_locators_vec != NULL){
        src_loc_vec = src_blv->balancing_locators_vec;
        src_vec_len = src_blv->locators_vec_length;
    }else if (src_blv->v6_balancing_locators_vec != NULL){
        src_loc_vec = src_blv->v6_balancing_locators_vec;
        src_vec_len = src_blv->v6_locators_vec_length;
    }else {
        src_loc_vec = src_blv->v4_balancing_locators_vec;
        src_vec_len = src_blv->v4_locators_vec_length;
    }
    if (src_vec_len == 0){
        lispd_log_msg(LISP_LOG_DEBUG_3,"select_src_locators_from_balancing_locators_vec: No source locators availables to send packet");
        return(BAD);
    }
    hash = get_hash_from_tuple (tuple);
    if (hash == 0){
        lispd_log_msg(LISP_LOG_DEBUG_1,"select_src_locators_from_balancing_locators_vec: Couldn't get the hash of the tuple to select the rloc. Using the default rloc");
    }
    pos = hash%src_vec_len; // if hash = 0 then pos = 0
    *src_locator =  src_loc_vec[pos];

    lispd_log_msg(LISP_LOG_DEBUG_3,"select_src_locators_from_balancing_locators_vec: src RLOC: %s",
            get_char_from_lisp_addr_t(*((*src_locator)->locator_addr)));

    return (GOOD);
}


/*
 * Select the source and destination RLOC according to the priority and weight.
 * The destination RLOC is selected according to the AFI of the selected source RLOC
 */

int select_src_rmt_locators_from_balancing_locators_vec (
        lispd_mapping_elt   *src_mapping,
        lispd_mapping_elt   *dst_mapping,
        packet_tuple        tuple,
        lispd_locator_elt   **src_locator,
        lispd_locator_elt   **dst_locator)
{
    int                     src_vec_len     = 0;
    int                     dst_vec_len     = 0;
    uint32_t                pos             = 0;
    uint32_t                hash            = 0;
    balancing_locators_vecs *src_blv        = NULL;
    balancing_locators_vecs *dst_blv        = NULL;
    lispd_locator_elt       **src_loc_vec   = NULL;
    lispd_locator_elt       **dst_loc_vec   = NULL;

    src_blv = &((lcl_mapping_extended_info *)(src_mapping->extended_info))->outgoing_balancing_locators_vecs;
    dst_blv = &((rmt_mapping_extended_info *)(dst_mapping->extended_info))->rmt_balancing_locators_vecs;

    if (src_blv->balancing_locators_vec != NULL && dst_blv->balancing_locators_vec != NULL){
        src_loc_vec = src_blv->balancing_locators_vec;
        src_vec_len = src_blv->locators_vec_length;
    }else if (src_blv->v6_balancing_locators_vec != NULL && dst_blv->v6_balancing_locators_vec != NULL){
        src_loc_vec = src_blv->v6_balancing_locators_vec;
        src_vec_len = src_blv->v6_locators_vec_length;
    }else if (src_blv->v4_balancing_locators_vec != NULL && dst_blv->v4_balancing_locators_vec != NULL){
        src_loc_vec = src_blv->v4_balancing_locators_vec;
        src_vec_len = src_blv->v4_locators_vec_length;
    }else{
        if (src_blv->v4_balancing_locators_vec == NULL && src_blv->v6_balancing_locators_vec == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_2,"get_rloc_from_balancing_locator_vec: No src locators available");
        }else {
            lispd_log_msg(LISP_LOG_DEBUG_2,"get_rloc_from_balancing_locator_vec: Source and destination RLOCs have different AFI");
        }
        return (BAD);
    }

    hash = get_hash_from_tuple (tuple);
    if (hash == 0){
        lispd_log_msg(LISP_LOG_DEBUG_1,"get_rloc_from_tuple: Couldn't get the hash of the tuple to select the RLOC. Using the default RLOC");
        //pos = hash%x_vec_len -> 0%x_vec_len = 0;
    }
    pos = hash%src_vec_len;
    *src_locator =  src_loc_vec[pos];

    switch ((*src_locator)->locator_addr->afi){
    case (AF_INET):
        dst_loc_vec = dst_blv->v4_balancing_locators_vec;
        dst_vec_len = dst_blv->v4_locators_vec_length;
        break;
    case (AF_INET6):
        dst_loc_vec = dst_blv->v6_balancing_locators_vec;
        dst_vec_len = dst_blv->v6_locators_vec_length;
        break;
    default:
        assert(0);
    }

    pos = hash%dst_vec_len;
    *dst_locator =  dst_loc_vec[pos];

    lispd_log_msg(LISP_LOG_DEBUG_3,"select_src_rmt_locators_from_balancing_locators_vec: "
            "src EID: %s, rmt EID: %s, protocol: %d, src port: %d , dst port: %d --> src RLOC: %s, dst RLOC: %s",
            get_char_from_lisp_addr_t(src_mapping->eid_prefix),
            get_char_from_lisp_addr_t(dst_mapping->eid_prefix),
            tuple.protocol, tuple.src_port, tuple.dst_port,
            get_char_from_lisp_addr_t(*((*src_locator)->locator_addr)),
            get_char_from_lisp_addr_t(*((*dst_locator)->locator_addr)));

    return (GOOD);
}


lisp_addr_t *get_default_locator_addr(
        lispd_map_cache_entry   *entry,
        int                     afi)
{

    lisp_addr_t *addr   = NULL;

    switch(afi){ 
    case AF_INET:
        addr = entry->mapping->head_v4_locators_list->locator->locator_addr;
        break;
    case AF_INET6:
        addr = entry->mapping->head_v6_locators_list->locator->locator_addr;
        break;
    }

    return (addr);
}


int is_lisp_packet(
        uint8_t *packet,
        int     packet_length)
{

    struct iphdr        *iph        = NULL;
    struct ip6_hdr      *ip6h       = NULL;
    int                 ipXh_len    = 0;
    int                 lvl4proto   = 0;
    struct udphdr       *udh        = NULL;

    iph = (struct iphdr *) packet;

    if (iph->version == 4 ) {
        lvl4proto = iph->protocol;
        ipXh_len = sizeof(struct iphdr);

    } else {
        ip6h = (struct ip6_hdr *) packet;
        lvl4proto = ip6h->ip6_nxt; //arnatal XXX: Supposing no extra headers
        ipXh_len = sizeof(struct ip6_hdr);

    }
    /*
     * Don't encapsulate LISP messages
     */

    if (lvl4proto != IPPROTO_UDP) {
        return (FALSE);
    }

    udh = (struct udphdr *)(packet + ipXh_len);

    /*
     * If either of the udp ports are the control port or data, allow
     * to go out natively. This is a quick way around the
     * route filter which rewrites the EID as the source address.
     */
    if ((ntohs(udh->dest) != LISP_CONTROL_PORT) &&
            (ntohs(udh->source) != LISP_CONTROL_PORT) &&
            (ntohs(udh->source) != LISP_DATA_PORT) &&
            (ntohs(udh->dest) != LISP_DATA_PORT) ) {

        return (FALSE);
    }

    return (TRUE);
}


int lisp_output (
        uint8_t *buffer,
        int     original_packet_length )
{
    uint8_t                     *original_packet    = CO(buffer , IN_PACK_BUFF_OFFSET);
    uint8_t                     *encap_packet       = NULL;
    int                         encap_packet_size   = 0;
    lispd_mapping_elt           *src_mapping        = NULL;
    lispd_mapping_elt           *dst_mapping        = NULL;
    lispd_map_cache_entry       *entry              = NULL;
    lispd_locator_elt           *outer_src_locator  = NULL;
    lispd_locator_elt           *outer_dst_locator  = NULL;
    lisp_addr_t                 *src_addr           = NULL;
    lisp_addr_t                 *dst_addr           = NULL;
    int                         output_socket       = 0;
    lcl_locator_extended_info   *loc_extended_info  = NULL;
    packet_tuple                tuple;
    int                         result              = 0;


    //arnatal TODO TODO: Check if local -> Do not encapsulate (can be solved with proper route configuration)
    //arnatal: Do not need to check here if route metrics setted correctly -> local more preferable than default (tun)


    if (extract_5_tuples_from_packet (original_packet,&tuple) != GOOD){
        return (BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_3,"\nOUTPUT: Orig src: %s   %d | Orig dst: %s   %d",
                get_char_from_lisp_addr_t(tuple.src_addr), tuple.src_port,get_char_from_lisp_addr_t(tuple.dst_addr), tuple.dst_port);


    /* If already LISP packet, do not encapsulate again */

    if (is_lisp_packet(original_packet,original_packet_length) == TRUE){
        return (forward_native(original_packet,original_packet_length));
    }

    /* If received packet doesn't have a source EID, forward it natively */
    src_mapping = lookup_eid_in_db (tuple.src_addr);
    if (src_mapping == NULL){
        return (forward_native(original_packet,original_packet_length));
    }

    /* If we are behind a full nat system, send the packet directly to the RTR */
    if (nat_aware == TRUE){
        if (select_src_locators_from_balancing_locators_vec (src_mapping,tuple,&outer_src_locator) != GOOD){
            return (BAD);
        }
        return (forward_to_natt_rtr(buffer, original_packet_length, outer_src_locator));
    }


    entry = lookup_map_cache(tuple.dst_addr);

    if (entry == NULL){ /* There is no entry in the map cache */
        lispd_log_msg(LISP_LOG_DEBUG_1, "No map cache retrieved for eid %s",get_char_from_lisp_addr_t(tuple.dst_addr));
        if (ddt_client == TRUE){
            handle_map_cache_miss_with_ddt(&(tuple.dst_addr), &(tuple.src_addr));
        }else{
            handle_map_cache_miss(&(tuple.dst_addr), &(tuple.src_addr));
        }
    }
    /* Packets with negative map cache entry, no active map cache entry or no map cache entry are forwarded to PETR */
    if ((entry == NULL) || (entry->active == NO_ACTIVE) || (entry->mapping->locator_count == 0) ){ /* There is no entry or is not active*/

        /* Try to fordward to petr*/
        if (fordward_to_petr(
                buffer,
                original_packet_length,
                src_mapping,
                tuple) != GOOD){
            /* If error, fordward native*/
            return (forward_native(original_packet,original_packet_length));
        }
        return (GOOD);
    }

    dst_mapping = entry->mapping;

    /* There is an entry in the map cache */

    /* Find locators to be used */
    if (select_src_rmt_locators_from_balancing_locators_vec (
            src_mapping,
            dst_mapping,
            tuple,
            &outer_src_locator,
            &outer_dst_locator)!=GOOD){
        /* If no match between afi of source and destinatiion RLOC, try to fordward to petr*/
        if (fordward_to_petr(
                buffer,
                original_packet_length,
                src_mapping,
                tuple) != GOOD){
            /* If error, fordward native*/
            return (forward_native(original_packet,original_packet_length));
        }else{
            return (GOOD);
        }
    }

    if (outer_src_locator == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"lisp_output: No output src locator");
        return (BAD);
    }
    if (outer_dst_locator == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"lisp_output: No destination locator selectable");
        return (BAD);
    }

    src_addr = outer_src_locator->locator_addr;
    dst_addr = outer_dst_locator->locator_addr;

    /* If the selected src locator is behind NAT, fordware to the RTR */
    loc_extended_info = (lcl_locator_extended_info *)outer_src_locator->extended_info;
    if (loc_extended_info->nat_info != NULL && loc_extended_info->nat_info->rtr_locators_list != NULL){
        dst_addr = &(loc_extended_info->nat_info->rtr_locators_list->locator->address);
    }

    /*
     * Push lisp header to the buffer
     */
    encap_packet = CO(buffer,IN_PACK_BUFF_OFFSET - sizeof(struct lisphdr));
    encap_packet_size = original_packet_length + sizeof(struct lisphdr);
    add_lisp_header(encap_packet, 0);

    output_socket = *(loc_extended_info->out_socket);
    result = send_data_packet(buffer, encap_packet_size, src_addr, dst_addr, output_socket);

    return (result);
}

void process_output_packet ()
{
	int 			nread   = 0;
    uint8_t         buffer[MAX_IP_PACKET];
    uint8_t         *packet = CO(buffer,IN_PACK_BUFF_OFFSET);

	nread = read ( tun_fd, packet, MAX_IP_PACKET - IN_PACK_BUFF_OFFSET );
	lisp_output ( buffer, nread );
}
