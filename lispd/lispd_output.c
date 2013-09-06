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



#include "bob/lookup3.c"
#include "lispd_locator.h"
#include "lispd_map_request.h"
#include "lispd_mapping.h"
#include "lispd_output.h"
#include "lispd_pkt_lib.h"
#include "lispd_sockets.h"
#include "lispd_info_nat.h" 


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



void add_ip_header (
        uint8_t         *position,
        uint8_t         *original_packet_position,
        int             ip_payload_length,
        lisp_addr_t     *src_addr,
        lisp_addr_t     *dst_addr)
{

    struct ip       *iph        = NULL;
    struct ip       *inner_iph  = NULL;
    struct ip6_hdr  *ip6h       = NULL;
    struct ip6_hdr  *inner_ip6h = NULL;

    int     ip_len  = 0;
    uint8_t tos     = 0;
    uint8_t ttl     = 0;


    inner_iph = (struct ip *) original_packet_position;

    /* We SHOULD copy ttl and tos fields from the inner packet to the encapsulated one */

    if (inner_iph->ip_v == 4 ) {
        tos = inner_iph->ip_tos;
        ttl = inner_iph->ip_ttl;

    } else {
        inner_ip6h = (struct ip6_hdr *) original_packet_position;
        ttl = inner_ip6h->ip6_hops; /* ttl = Hops limit in IPv6 */

        //tos = (inner_ip6h->ip6_flow & 0x0ff00000) >> 20;  /* 4 bits version, 8 bits Traffic Class, 20 bits flow-ID */
        tos = IPV6_GET_TC(*inner_ip6h); /* tos = Traffic class field in IPv6 */
    }

    /*
     * Construct and add the outer ip header
     */

    switch (dst_addr->afi){
    case AF_INET:
        ip_len = ip_payload_length + sizeof(struct ip);
        iph = (struct ip *) position;

        iph->ip_v               = IPVERSION;
        iph->ip_hl              = 5; /* Minimal IPv4 header */ /*XXX Beware, hardcoded. Supposing no IP options */
        iph->ip_tos             = tos;
        iph->ip_len             = htons(ip_len);
        iph->ip_id              = htons(get_IP_ID());
        iph->ip_off             = htons(IP_DF);   /* Do not fragment flag. See 5.4.1 in LISP RFC (6830) */
        iph->ip_ttl             = ttl;
        iph->ip_p               = IPPROTO_UDP;
        iph->ip_sum             = 0; //Computed by the NIC (checksum offloading)
        iph->ip_dst.s_addr      = dst_addr->address.ip.s_addr;
        iph->ip_src.s_addr      = src_addr->address.ip.s_addr;
        break;
    case AF_INET6:
        ip6h = ( struct ip6_hdr *) position;

        IPV6_SET_VERSION(ip6h, 6);
        IPV6_SET_TC(ip6h,tos);
        IPV6_SET_FLOW_LABEL(ip6h,0);
        ip6h->ip6_plen = htons(ip_payload_length);
        ip6h->ip6_nxt = IPPROTO_UDP;
        ip6h->ip6_hops = ttl;
        memcopy_lisp_addr(&(ip6h->ip6_dst),dst_addr);
        memcopy_lisp_addr(&(ip6h->ip6_src),src_addr);

        break;
    default:
        break;
    }
}

void add_udp_header(
        uint8_t *position,
        int     length,
        int     src_port,
        int     dst_port)
{

    struct udphdr *udh  = NULL;


    /*
     * Construct and add the udp header
     */
    udh = ( struct udphdr * ) position;

    /*
     * Hash of inner header source/dest addr. This needs thought.
     */
    udh->source = htons ( src_port ); //arnatal TODO: Selec source port based on tuple?
    udh->dest =  htons ( dst_port );
    udh->len = htons ( sizeof ( struct udphdr ) + length );
    //udh->len = htons(sizeof(struct udphdr)); /* Wireshark detects this as error*/
    udh->check = 0; // SHOULD be 0 as in LISP ID
    /* With IPv6 this MUST be calculated (or disabled at all). Calculated later */

}

void add_lisp_header(
        uint8_t *position,
        int     iid)
{

    struct lisphdr  *lisphdr = NULL;

    lisphdr = (struct lisphdr *) position;

    lisphdr->instance_id = 0;
    //lisphdr->instance_id = iid; //XXX iid not supported yet

    /* arnatal TODO: support for the rest of values*/
    lisphdr->echo_nonce = 0;
    lisphdr->lsb = 0;
    lisphdr->lsb_bits = 0;
    lisphdr->map_version = 0;
    lisphdr->nonce[0] = 0;
    lisphdr->nonce[1] = 0;
    lisphdr->nonce[2] = 0;
    lisphdr->nonce_present = 0;
    lisphdr->rflags = 0;

}

int encapsulate_packet(
        uint8_t     *original_packet,
        int         original_packet_length,
        lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr,
        int         src_port,
        int         dst_port,
        int         iid,
        uint8_t     **encap_packet,
        int         *encap_packet_size)
{
    int         extra_headers_size  = 0;
    uint8_t     *new_packet         = NULL;
    struct      udphdr *udh         = NULL;
    int         encap_afi           = 0;

    int         iphdr_len           = 0;
    int         udphdr_len          = 0;
    int         lisphdr_len         = 0;

    encap_afi = src_addr->afi;

    switch (encap_afi){
    case AF_INET:
        iphdr_len = sizeof(struct iphdr);
        break;
    case AF_INET6:
        iphdr_len = sizeof(struct ip6_hdr);
        break;
    }


    udphdr_len = sizeof(struct udphdr);
    lisphdr_len = sizeof(struct lisphdr);

    extra_headers_size = iphdr_len + udphdr_len + lisphdr_len;

    new_packet = (uint8_t *) malloc (original_packet_length + extra_headers_size);
    if (new_packet == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "encapsulate_packet: Unable to allocate memory for encapsulated packet: %s", strerror(errno));
        return (BAD);
    }

    memset(new_packet,0,original_packet_length+extra_headers_size);

    memcpy (new_packet + extra_headers_size, original_packet, original_packet_length);



    add_lisp_header(CO(new_packet,iphdr_len + udphdr_len), iid);

    add_udp_header(CO(new_packet,iphdr_len),original_packet_length+lisphdr_len,src_port,dst_port);


    add_ip_header(new_packet,
            original_packet,
            original_packet_length+lisphdr_len+udphdr_len,
            src_addr,
            dst_addr);

    /* UDP checksum mandatory for IPv6. Could be skipped if check disabled on receiver */
    udh = (struct udphdr *)(new_packet + iphdr_len);
    udh->check = udp_checksum(udh,ntohs(udh->len),new_packet,encap_afi);

    *encap_packet = new_packet;
    *encap_packet_size = extra_headers_size + original_packet_length;

    lispd_log_msg(LISP_LOG_DEBUG_3,"OUTPUT: Encap src: %s | Encap dst: %s\n",
            get_char_from_lisp_addr_t(*src_addr),get_char_from_lisp_addr_t(*dst_addr));

    return (GOOD);
}


int get_afi_from_packet(uint8_t *packet){
    int             afi     = 0;
    struct iphdr    *iph    = NULL;

    iph = (struct iphdr *) packet;

    switch (iph->version){
    case 4:
        afi = AF_INET;
        break;
    case 6:
        afi = AF_INET6;
        break;
    default:
        afi = AF_UNSPEC;
    }

    return (afi);
}


int forward_native(
        uint8_t        *packet_buf,
        int             pckt_length )
{

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

}

/*
 * Send a packet to a proxy etr
 */


int fordward_to_petr(
        uint8_t                 *original_packet,
        int                     original_packet_length,
        lispd_mapping_elt       *src_mapping,
        packet_tuple            tuple)
{
    lispd_locator_elt           *outer_src_locator  = NULL;
    lispd_locator_elt           *outer_dst_locator  = NULL;
    lisp_addr_t                 *src_addr           = NULL;
    lisp_addr_t                 *dst_addr           = NULL;
    lcl_locator_extended_info   *loc_extended_info  = NULL;
    uint8_t                     *encap_packet       = NULL;
    int                         encap_packet_size   = 0;
    int                         output_socket       = 0;

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
    src_addr = outer_src_locator->locator_addr;
    dst_addr = outer_dst_locator->locator_addr;

    /* If the selected src locator is behind NAT, fordware to the RTR */
    loc_extended_info = (lcl_locator_extended_info *)outer_src_locator->extended_info;
    if (loc_extended_info->rtr_locators_list != NULL){
        dst_addr = &(loc_extended_info->rtr_locators_list->locator->address);
    }

    if (encapsulate_packet(original_packet,
            original_packet_length,
            src_addr,
            dst_addr,
            LISP_DATA_PORT,
            LISP_DATA_PORT,
            0,
            &encap_packet,
            &encap_packet_size) != GOOD){
        return (BAD);
    }

    output_socket = *(((lcl_locator_extended_info *)(outer_src_locator->extended_info))->out_socket);

    if (send_packet (output_socket,encap_packet,encap_packet_size ) != GOOD){
        free (encap_packet );
        return (BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_3, "Fordwarded eid %s to petr",get_char_from_lisp_addr_t(extract_dst_addr_from_packet(original_packet)));
    free (encap_packet );

    return (GOOD);
}

int forward_to_natt_rtr(
        uint8_t             *original_packet,
        int                 original_packet_length,
        lispd_locator_elt   *src_locator)
{

    uint8_t                     *encap_packet       = NULL;
    int                         encap_packet_size   = 0;
    lcl_locator_extended_info   *extended_info      = NULL;
    lispd_rtr_locators_list     *rtr_locators_list  = NULL;
    int                         output_socket       = 0;
    
    lisp_addr_t                 *src_addr;
    lisp_addr_t                 *dst_addr;

    extended_info = (lcl_locator_extended_info *)src_locator->extended_info;
    rtr_locators_list = extended_info->rtr_locators_list;
    if (rtr_locators_list == NULL){
        //Could be due to RTR discarded by source afi type
        lispd_log_msg(LISP_LOG_DEBUG_2,"forward_to_natt_rtr: No RTR for the selected src locator (%s).",
                get_char_from_lisp_addr_t(*(src_locator->locator_addr)));
        return (BAD);
    }
    src_addr = src_locator->locator_addr;
    dst_addr = &(rtr_locators_list->locator->address);

    lispd_log_msg(LISP_LOG_DEBUG_3, "Forwarding eid %s to NAT RTR",get_char_from_lisp_addr_t(extract_dst_addr_from_packet(original_packet)));

    if (encapsulate_packet(original_packet,
        original_packet_length,
        src_addr,
        dst_addr,
        LISP_DATA_PORT,
        LISP_DATA_PORT,
        0,
        &encap_packet,
        &encap_packet_size) != GOOD){
        return (BAD);
    }

    output_socket = *(extended_info->out_socket);
    if (send_packet (output_socket,encap_packet,encap_packet_size ) != GOOD){
        free (encap_packet );
        return (BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_3, "Fordwarded eid %s to NAT RTR",get_char_from_lisp_addr_t(extract_dst_addr_from_packet(original_packet)));
    free (encap_packet );

    return (GOOD);
} 

lisp_addr_t extract_dst_addr_from_packet ( uint8_t *packet )
{
    lisp_addr_t     addr    = {.afi=AF_UNSPEC};
    struct iphdr    *iph    = NULL;
    struct ip6_hdr  *ip6h   = NULL;

    iph = (struct iphdr *) packet;

    switch (iph->version) {
    case 4:
        addr.afi = AF_INET;
        addr.address.ip.s_addr = iph->daddr;
        break;
    case 6:
        ip6h = (struct ip6_hdr *) packet;
        addr.afi = AF_INET6;
        memcpy(&(addr.address.ipv6),&(ip6h->ip6_dst),sizeof(struct in6_addr));
        break;

    default:
        break;
    }

    //arnatal TODO: check errors (afi unsupported)

    return (addr);
}


lisp_addr_t extract_src_addr_from_packet ( uint8_t *packet )
{
    lisp_addr_t         addr    = {.afi=AF_UNSPEC};
    struct iphdr        *iph    = NULL;
    struct ip6_hdr      *ip6h   = NULL;

    iph = (struct iphdr *) packet;

    switch (iph->version) {
    case 4:
        addr.afi = AF_INET;
        addr.address.ip.s_addr = iph->saddr;
        break;
    case 6:
        ip6h = (struct ip6_hdr *) packet;
        addr.afi = AF_INET6;
        memcpy(&(addr.address.ipv6),&(ip6h->ip6_src),sizeof(struct in6_addr));
    default:
        break;
    }

    //arnatal TODO: check errors (afi unsupported)

    return (addr);
}

int handle_map_cache_miss(
        lisp_addr_t *requested_eid,
        lisp_addr_t *src_eid)
{

    lispd_map_cache_entry       *entry          = NULL;
    timer_map_request_argument  *arguments      = NULL;

    if ((arguments = malloc(sizeof(timer_map_request_argument)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"handle_map_cache_miss: Unable to allocate memory for timer_map_request_argument: %s",
                strerror(errno));
        return (ERR_MALLOC);
    }


    //arnatal TODO: check if this works
    entry = new_map_cache_entry(
            *requested_eid,
            get_prefix_len(requested_eid->afi),
            DYNAMIC_MAP_CACHE_ENTRY,
            DEFAULT_DATA_CACHE_TTL);

    arguments->map_cache_entry = entry;
    arguments->src_eid = *src_eid;

    if ((err=send_map_request_miss(NULL, (void *)arguments))!=GOOD)
        return (BAD);

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
            lispd_log_msg(LISP_LOG_DEBUG_2,"get_rloc_from_balancing_locator_vec: Source and destination RLOCs have differnet afi");
        }
        return (BAD);
    }

    hash = get_hash_from_tuple (tuple);
    if (hash == 0){
        lispd_log_msg(LISP_LOG_DEBUG_1,"get_rloc_from_tuple: Couldn't get the hash of the tuple to select the rloc. Using the default rloc");
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
        uint8_t *original_packet,
        int     original_packet_length )
{
    lispd_mapping_elt           *src_mapping        = NULL;
    lispd_mapping_elt           *dst_mapping        = NULL;
    lispd_map_cache_entry       *entry              = NULL;
    uint8_t                     *encap_packet       = NULL;
    int                         encap_packet_size   = 0;
    lispd_locator_elt           *outer_src_locator  = NULL;
    lispd_locator_elt           *outer_dst_locator  = NULL;
    lisp_addr_t                 *src_addr           = NULL;
    lisp_addr_t                 *dst_addr           = NULL;
    lcl_locator_extended_info   *loc_extended_info  = NULL;
    int                         output_socket       = 0;
    packet_tuple                tuple;

    //arnatal TODO TODO: Check if local -> Do not encapsulate (can be solved with proper route configuration)
    //arnatal: Do not need to check here if route metrics setted correctly -> local more preferable than default (tun)


    if (extract_5_tuples_from_packet (original_packet,&tuple) != GOOD){
        return (BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_3,"OUTPUT: Orig src: %s | Orig dst: %s\n",
            get_char_from_lisp_addr_t(tuple.src_addr),get_char_from_lisp_addr_t(tuple.dst_addr));


    /* If already LISP packet, do not encapsulate again */

    if (is_lisp_packet(original_packet,original_packet_length) == TRUE){
        return (forward_native(original_packet,original_packet_length));
    }

    /* If received packet doesn't have a source EID, forward it natively */
    src_mapping = lookup_eid_in_db (tuple.src_addr);
    if (src_mapping == NULL){
        return (forward_native(original_packet,original_packet_length));
    }

    /* If we are behind a full nat system, send the message directly to the RTR */
    if ((nat_aware == TRUE)&&(nat_status == FULL_NAT)){
        if (select_src_locators_from_balancing_locators_vec (src_mapping,tuple,&outer_src_locator) != GOOD){
            return (BAD);
        }
        return (forward_to_natt_rtr(original_packet, original_packet_length, outer_src_locator));
    }


    entry = lookup_map_cache(tuple.dst_addr);

    if (entry == NULL){ /* There is no entry in the map cache */
        lispd_log_msg(LISP_LOG_DEBUG_1, "No map cache retrieved for eid %s",get_char_from_lisp_addr_t(tuple.dst_addr));
        handle_map_cache_miss(&(tuple.dst_addr), &(tuple.src_addr));
    }
    /* Packets with negative map cache entry, no active map cache entry or no map cache entry are forwarded to PETR */
    if ((entry == NULL) || (entry->active == NO_ACTIVE) || (entry->mapping->locator_count == 0) ){ /* There is no entry or is not active*/

        /* Try to fordward to petr*/
        if (fordward_to_petr(
                original_packet,
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
                original_packet,
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
    if (loc_extended_info->rtr_locators_list != NULL){
        dst_addr = &(loc_extended_info->rtr_locators_list->locator->address);
    }

    encapsulate_packet(original_packet,
            original_packet_length,
            src_addr,
            dst_addr,
            LISP_DATA_PORT, //TODO: UDP src port based on hash?
            LISP_DATA_PORT,
            //entry->mapping->iid, //XXX iid not supported yet
            0,
            &encap_packet,
            &encap_packet_size);

    output_socket = *(((lcl_locator_extended_info *)(outer_src_locator->extended_info))->out_socket);
    send_packet (output_socket,encap_packet,encap_packet_size);

    free (encap_packet);

    return (GOOD);
}

void process_output_packet (
        int             fd,
        uint8_t         *tun_receive_buf,
        unsigned int    tun_receive_size )
{
    int nread   = 0;

    nread = read ( fd, tun_receive_buf, tun_receive_size );

    lisp_output ( tun_receive_buf, nread );
}
