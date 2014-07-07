/*
 * lispd_pkt_lib.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
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
 *    Lorand Jakab  <ljakab@ac.upc.edu>
 *
 */

#include "lispd_afi.h"
#include "lispd_pkt_lib.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_register.h"
#include "lispd_external.h"
#include "lispd_sockets.h"
#include "api/ipc.h"
#include <netinet/udp.h>
#include <netinet/tcp.h>

uint16_t ip_id = 0;

/*
 *  get_locators_length
 *
 *  Compute the sum of the lengths of the locators
 *  so we can allocate  memory for the packet....
 */
int get_locators_length(
        lispd_locators_list *locators_list,
        int                 *loc_count);


int pkt_get_mapping_record_length(lispd_mapping_elt *mapping)
{
    lispd_locators_list *locators_list[2] = {
            mapping->head_v4_locators_list,
            mapping->head_v6_locators_list};
    int             length          = 0;
    int             loc_length      = 0;
    int             eid_length      = 0;
    int             ctr             = 0;
    int             locator_count   = 0;
    int             aux_loc_count   = 0;

    for (ctr = 0 ; ctr < 2 ; ctr ++){
        loc_length += get_locators_length(locators_list[ctr], &aux_loc_count);
        locator_count += aux_loc_count;
    }
    eid_length = get_mapping_length(mapping);
    length = sizeof(lispd_pkt_mapping_record_t) + eid_length +
            (locator_count * sizeof(lispd_pkt_mapping_record_locator_t)) +loc_length;

    return (length);
}


/*
 *  get_locators_length
 *
 *  Compute the sum of the lengths of the locators
 *  so we can allocate  memory for the packet....
 */

int get_locators_length(
        lispd_locators_list *locators_list,
        int                 *loc_count)
{
    int                 sum             = 0;
    int                 num_loc         = 0;
    lisp_addr_t         *prev_rtr_addr  = NULL;
    lispd_locator_elt   *locator        = NULL;
    nat_info_str        *nat_info       = NULL;

    while (locators_list) {
        locator = locators_list->locator;

        /* Only consider locators with status UP */
        if(*(locator->state) != UP){
            locators_list = locators_list->next;
            continue;
        }
        /*
         * If we have enabled nat_aware, we only add locators with status known.
         * A same RTR can only be added one time
         */
        if (nat_aware == TRUE ){
            nat_info = ((lcl_locator_extended_info *)locator->extended_info)->nat_info;
            if (nat_info->status == UNKNOWN || nat_info->status == NO_INFO_REPLY){
                locators_list = locators_list->next;
                continue;
            }
            // Even a RTR is associated with more than one interface, we only add the same RTR one time
            if (compare_lisp_addr_t (prev_rtr_addr, &(nat_info->rtr_locators_list->locator->address))== 0){
                locators_list = locators_list->next;
                continue;
            }else{
                prev_rtr_addr = &(nat_info->rtr_locators_list->locator->address);
            }
        }
    	/* If the locator is behind NAT, the afi of the RTR is the same of the local locator */
        switch (locator->locator_addr->afi) {
        case AF_INET:
            sum += sizeof(struct in_addr);
            num_loc++;
            break;
        case AF_INET6:
            sum += sizeof(struct in6_addr);
            num_loc++;
            break;
        default:
            /* It should never happen*/
            lispd_log_msg(LISP_LOG_DEBUG_2, "get_locators_length: Uknown AFI (%d) - It should never happen",
               locator->locator_addr->afi);
            break;
        }
        locators_list = locators_list->next;
    }
    *loc_count = num_loc;

    return(sum);
}

/*
 *  get_up_locators_length
 *
 *  Compute the sum of the lengths of the locators that has the status up
 *  so we can allocate  memory for the packet....
 *  We remove locators behind NAT except when it is the only one UP
 */

int get_up_locators_length(
        lispd_locators_list *locators_list,
        int                 *loc_count)
{
    int 						sum 		 = 0;
    int 						counter 	 = 0;
    lisp_addr_t  				*aux_addr 	 = NULL;
    lcl_locator_extended_info	*loc_ext_inf = NULL;



    while (locators_list) {
        if (*(locators_list->locator->state)== DOWN){
            locators_list = locators_list->next;
            continue;
        }

        loc_ext_inf = (lcl_locator_extended_info *)(locators_list->locator->extended_info);
        if (loc_ext_inf->nat_info != NULL && loc_ext_inf->nat_info->rtr_locators_list != NULL){
            aux_addr =  loc_ext_inf->nat_info->public_addr;
            locators_list = locators_list->next;
            continue;
        }


        switch (locators_list->locator->locator_addr->afi) {
        case AF_INET:
            sum += sizeof(struct in_addr);
            counter++;
            break;
        case AF_INET6:
            sum += sizeof(struct in6_addr);
            counter++;
            break;
        default:
            /* It should never happen*/
            lispd_log_msg(LISP_LOG_DEBUG_2, "get_up_locators_length: Uknown AFI (%d) - It should never happen",
               locators_list->locator->locator_addr->afi);
            break;
        }
        locators_list = locators_list->next;
    }

    if (counter == 0  && aux_addr != NULL){
        sum += get_addr_len(aux_addr->afi);
        counter++;
    }
    *loc_count = counter;
    return(sum);
}



/*
 *  get_mapping_length
 *
 *  Compute the lengths of the mapping to be use in a record
 *  so we can allocate  memory for the packet....
 */


int get_mapping_length(lispd_mapping_elt *mapping)
{
    int ident_len = 0;
    switch (mapping->eid_prefix.afi) {
    case AF_INET:
        ident_len += sizeof(struct in_addr);
        break;
    case AF_INET6:
        ident_len += sizeof(struct in6_addr);
        break;
    default:
        break;
    }

    if (mapping->iid > 0){
        ident_len += sizeof(lispd_pkt_lcaf_t) + sizeof(lispd_pkt_lcaf_iid_t);
    }

    return (ident_len);
}

uint8_t *pkt_fill_eid(
        uint8_t                 *offset,
        lispd_mapping_elt       *mapping)
{
    uint16_t                *afi_ptr;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    lispd_pkt_lcaf_iid_t    *iid_ptr;
    void                    *eid_ptr;
    int                     eid_addr_len;

    afi_ptr = (uint16_t *)offset;
    eid_addr_len = get_addr_len(mapping->eid_prefix.afi);

    /* For IID = 0, we skip LCAF/IID field */
    if (mapping->iid == 0) {
        *afi_ptr = htons(get_lisp_afi(mapping->eid_prefix.afi, NULL));
        eid_ptr  = CO(offset, sizeof(uint16_t));
    } else {
        *afi_ptr = htons(LISP_AFI_LCAF);
        lcaf_ptr = (lispd_pkt_lcaf_t *) CO(offset, sizeof(uint16_t));
        iid_ptr  = (lispd_pkt_lcaf_iid_t *) CO((uint8_t *)lcaf_ptr, sizeof(lispd_pkt_lcaf_t));
        eid_ptr  = (void *) CO((uint8_t *)iid_ptr, sizeof(lispd_pkt_lcaf_iid_t));
        lcaf_ptr->rsvd1 = 0;
        lcaf_ptr->flags = 0;
        lcaf_ptr->type  = 2;
        lcaf_ptr->rsvd2 = 0;    /* This can be IID mask-len, not yet supported */
        lcaf_ptr->len   = htons(sizeof(lispd_pkt_lcaf_iid_t) + eid_addr_len);

        iid_ptr->iid = htonl(mapping->iid);
        iid_ptr->afi = htons(mapping->eid_prefix.afi);
    }

    if ((copy_addr(eid_ptr,&(mapping->eid_prefix), 0)) == 0) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "pkt_fill_eid: copy_addr failed");
        return NULL;
    }
    return (CO((uint8_t *)eid_ptr, eid_addr_len));
}


uint8_t *pkt_fill_mapping_record(
    lispd_pkt_mapping_record_t              *rec,
    lispd_mapping_elt                       *mapping,
    lisp_addr_t                             *probed_rloc)
{
    uint8_t                                 *cur_ptr            = NULL;
    int                                     cpy_len             = 0;
    lispd_pkt_mapping_record_locator_t      *loc_ptr            = NULL;
    lispd_locators_list                     *locators_list[2]   = {NULL,NULL};
    lispd_locator_elt                       *locator            = NULL;
    nat_info_str                            *nat_info           = NULL;
    lisp_addr_t                             *itr_address        = NULL;
    lisp_addr_t                             *last_rtr_addr      = NULL;
    int                                     ctr                 = 0;
    int                                     locator_count       = 0;

    if ((rec == NULL) || (mapping == NULL)){
        return NULL;
    }

    rec->ttl                    = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
    rec->eid_prefix_length      = mapping->eid_prefix_length;
    rec->action                 = 0;
    rec->authoritative          = 1;
    rec->version_hi             = 0;
    rec->version_low            = 0;

    cur_ptr = (uint8_t *)&(rec->eid_prefix_afi);
    cur_ptr = pkt_fill_eid(cur_ptr, mapping);
    loc_ptr = (lispd_pkt_mapping_record_locator_t *)cur_ptr;

    if (loc_ptr == NULL){
        return NULL;
    }

    lispd_log_msg(LISP_LOG_DEBUG_2, "Record information EID: %s/%d",
            get_char_from_lisp_addr_t(mapping->eid_prefix),
            rec->eid_prefix_length);

    locators_list[0] = mapping->head_v4_locators_list;
    locators_list[1] = mapping->head_v6_locators_list;
    for (ctr = 0 ; ctr < 2 ; ctr++){
        while (locators_list[ctr]) {
            locator              = locators_list[ctr]->locator;
            nat_info             = ((lcl_locator_extended_info *)(locator->extended_info))->nat_info;

            if (*(locator->state) != UP){
                locators_list[ctr] = locators_list[ctr]->next;
                continue;
            }

            if (nat_info != NULL){
                nat_info = ((lcl_locator_extended_info *)locator->extended_info)->nat_info;
                // XXX Locators using RTR whose interface is down are not added
                // XXX When locator don't use RTR, it is added with R bit = 0 and priority 255
                if (nat_info->status == UNKNOWN || nat_info->status == NO_INFO_REPLY){
                    locators_list[ctr] = locators_list[ctr]->next;
                    continue;
                }
                // Even a RTR is associated with more than one interface, we only add the same RTR one time
                if (compare_lisp_addr_t (last_rtr_addr, &(nat_info->rtr_locators_list->locator->address))== 0){
                    locators_list[ctr] = locators_list[ctr]->next;
                    continue;
                }else{
                    last_rtr_addr = &(nat_info->rtr_locators_list->locator->address);
                }
            }

            loc_ptr->priority    = locator->priority;
            loc_ptr->weight      = locator->weight;
            loc_ptr->mpriority   = locator->mpriority;
            loc_ptr->mweight     = locator->mweight;
            loc_ptr->local       = 1;
            if (probed_rloc != NULL && compare_lisp_addr_t(locator->locator_addr,probed_rloc)==0){
                loc_ptr->probed  = 1;
            }

            loc_ptr->reachable   = *(locator->state);


            if (nat_info != NULL && nat_info->rtr_locators_list != NULL){
                itr_address = &(nat_info->rtr_locators_list->locator->address);
            }else{
                itr_address = locator->locator_addr;
            }
            loc_ptr->locator_afi = htons(get_lisp_afi(itr_address->afi,NULL));

            if ((cpy_len = copy_addr((void *) CO(loc_ptr,
                    sizeof(lispd_pkt_mapping_record_locator_t)), itr_address, 0)) == 0) {
                lispd_log_msg(LISP_LOG_DEBUG_3, "pkt_fill_mapping_record: copy_addr failed for locator %s",
                        get_char_from_lisp_addr_t(*(locator->locator_addr)));
                return(NULL);
            }

            lispd_log_msg(LISP_LOG_DEBUG_2, "Record information Locator: %s  P:%d-W:%d-MP:%d-MW:%d  Reachable: %d Probed: %d",
                                    get_char_from_lisp_addr_t(*(locators_list[ctr]->locator->locator_addr)),
                                    loc_ptr->priority, loc_ptr->weight, loc_ptr->mpriority, loc_ptr->mweight, loc_ptr->reachable, loc_ptr->probed);

            locator_count++;
            loc_ptr = (lispd_pkt_mapping_record_locator_t *)
                            CO(loc_ptr, (sizeof(lispd_pkt_mapping_record_locator_t) + cpy_len));


            locators_list[ctr] = locators_list[ctr]->next;

        }
    }
    rec->locator_count          = locator_count;
    return ((void *)loc_ptr);
}
/*
 * Fill the tuple with the 5 tuples of a packet: (SRC IP, DST IP, PROTOCOL, SRC PORT, DST PORT)
 */
int extract_5_tuples_from_packet (
        uint8_t         *packet ,
        packet_tuple    *tuple)
{
    struct iphdr        *iph    = NULL;
    struct ip6_hdr      *ip6h   = NULL;
    struct udphdr       *udp    = NULL;
    struct tcphdr       *tcp    = NULL;
    int                 len     = 0;

    iph = (struct iphdr *) packet;

    switch (iph->version) {
    case 4:
        tuple->src_addr.afi = AF_INET;
        tuple->dst_addr.afi = AF_INET;
        tuple->src_addr.address.ip.s_addr = iph->saddr;
        tuple->dst_addr.address.ip.s_addr = iph->daddr;
        tuple->protocol = iph->protocol;
        len = iph->ihl*4;
        break;
    case 6:
        ip6h = (struct ip6_hdr *) packet;
        tuple->src_addr.afi = AF_INET6;
        tuple->dst_addr.afi = AF_INET6;
        memcpy(&(tuple->src_addr.address.ipv6),&(ip6h->ip6_src),sizeof(struct in6_addr));
        memcpy(&(tuple->dst_addr.address.ipv6),&(ip6h->ip6_dst),sizeof(struct in6_addr));
        tuple->protocol = ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        len = sizeof(struct ip6_hdr);
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2,"extract_5_tuples_from_packet: No ip packet identified");
        return (BAD);
    }

    if (tuple->protocol == IPPROTO_UDP){
        udp = (struct udphdr *)CO(packet,len);
        tuple->src_port = ntohs(udp->source);
        tuple->dst_port = ntohs(udp->dest);
    }else if (tuple->protocol == IPPROTO_TCP){
        tcp = (struct tcphdr *)CO(packet,len);
        tuple->src_port = ntohs(tcp->source);
        tuple->dst_port = ntohs(tcp->dest);
    }else{//If protocol is not TCP or UDP, ports of the tuple set to 0
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }
    return (GOOD);
}



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
        uint8_t     *buffer, // Original packet + lisp header
        int         packet_length, // Size of original packet + size of lisp header
        lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr,
        int         src_port,
        int         dst_port,
        int         iid,
        uint8_t     **encap_packet,
        int         *encap_packet_size)
{
    uint8_t     *original_packet    = NULL;
    uint8_t     *udp_hdr            = NULL;
    uint8_t     *ip_hdr             = NULL;
    struct      udphdr *udh         = NULL;
    int         encap_afi           = 0;

    int         iphdr_len           = 0;

    encap_afi = src_addr->afi;

    switch (encap_afi){
    case AF_INET:
        iphdr_len = sizeof(struct iphdr);
        break;
    case AF_INET6:
        iphdr_len = sizeof(struct ip6_hdr);
        break;
    }

    original_packet    = CO(buffer,IN_PACK_BUFF_OFFSET);
    udp_hdr            = CO(buffer,(IN_PACK_BUFF_OFFSET - sizeof(struct lisphdr) - sizeof(struct udphdr)));
    ip_hdr             = CO(buffer,(IN_PACK_BUFF_OFFSET - sizeof(struct lisphdr) - sizeof(struct udphdr) - iphdr_len));

    *encap_packet = ip_hdr;
    *encap_packet_size = packet_length +  sizeof(struct udphdr) + iphdr_len;

    add_udp_header(udp_hdr,packet_length,src_port,dst_port);

    add_ip_header(ip_hdr,
            original_packet, //dest packet
            packet_length+sizeof(struct udphdr),
            src_addr,
            dst_addr);

    /* UDP checksum mandatory for IPv6. Could be skipped if check disabled on receiver */
    udh = (struct udphdr *)udp_hdr;
    udh->check = udp_checksum(udh,ntohs(udh->len),ip_hdr,encap_afi);



    lispd_log_msg(LISP_LOG_DEBUG_3,"OUTPUT: Encap src: %s | Encap dst: %s\n",
            get_char_from_lisp_addr_t(*src_addr),get_char_from_lisp_addr_t(*dst_addr));

    return (GOOD);
}

int get_afi_from_packet(uint8_t *packet)
{
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


/*
 * Generate IP header. Returns the poninter to the transport header
 */

struct udphdr *build_ip_header(
        uint8_t               *cur_ptr,
        lisp_addr_t           *src_addr,
        lisp_addr_t           *dst_addr,
        int                   ip_len)
{
    struct ip      *iph;
    struct ip6_hdr *ip6h;
    struct udphdr  *udph;

    switch (src_addr->afi) {
    case AF_INET:
        ip_len = ip_len + sizeof(struct ip);
        iph                = (struct ip *) cur_ptr;
        iph->ip_hl         = 5;
        iph->ip_v          = IPVERSION;
        iph->ip_tos        = 0;
        iph->ip_len        = htons(ip_len);
        iph->ip_id         = htons(get_IP_ID());
        iph->ip_off        = 0;   /* XXX Control packets can be fragmented  */
        iph->ip_ttl        = 255;
        iph->ip_p          = IPPROTO_UDP;
        iph->ip_src.s_addr = src_addr->address.ip.s_addr;
        iph->ip_dst.s_addr = dst_addr->address.ip.s_addr;
        iph->ip_sum        = 0;
        iph->ip_sum        = ip_checksum((uint16_t *)cur_ptr, sizeof(struct ip));

        udph              = (struct udphdr *) CO(iph,sizeof(struct ip));
        break;
    case AF_INET6:
        ip6h           = (struct ip6_hdr *) cur_ptr;
        ip6h->ip6_hops = 255;
        ip6h->ip6_vfc  = (IP6VERSION << 4);
        ip6h->ip6_nxt  = IPPROTO_UDP;
        ip6h->ip6_plen = htons(ip_len);
        memcpy(ip6h->ip6_src.s6_addr,
               src_addr->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        memcpy(ip6h->ip6_dst.s6_addr,
                dst_addr->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        udph = (struct udphdr *) CO(ip6h,sizeof(struct ip6_hdr));
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2,"build_ip_header: Uknown AFI of the source address: %d",src_addr->afi);
        return(NULL);
    }
    return(udph);
}

/*
 * Generates an IP header and an UDP header
 * and copies the original packet at the end
 */

uint8_t *build_ip_udp_pcket(
        uint8_t         *orig_pkt,
        int             orig_pkt_len,
        lisp_addr_t     *addr_from,
        lisp_addr_t     *addr_dest,
        int             port_from,
        int             port_dest,
        int             *encap_pkt_len)
{
    uint8_t         *encap_pkt                  = NULL;
    void            *iph_ptr                    = NULL;
    struct udphdr   *udph_ptr                   = NULL;
    int             ip_hdr_len                  = 0;
    int             udp_hdr_len                 = 0;
    int             udp_hdr_and_payload_len     = 0;
    uint16_t        udpsum                      = 0;


    if (addr_from->afi != addr_dest->afi) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_ip_udp_header: Different AFI addresses");
        return (NULL);
    }

    if ((addr_from->afi != AF_INET) && (addr_from->afi != AF_INET6)) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_ip_udp_header: Unknown AFI %d",
               addr_from->afi);
        return (NULL);
    }

    /* Headers lengths */

    ip_hdr_len = get_ip_header_len(addr_from->afi);

    udp_hdr_len = sizeof(struct udphdr);

    udp_hdr_and_payload_len = udp_hdr_len + orig_pkt_len;


    /* Assign memory for the original packet plus the new headers */

    *encap_pkt_len = ip_hdr_len + udp_hdr_len + orig_pkt_len;

    if ((encap_pkt = (uint8_t *) malloc(*encap_pkt_len)) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_ip_udp_header: Couldn't allocate memory for the packet to be generated %s", strerror(errno));
        return (NULL);
    }

    /* Make sure it's clean */

    memset(encap_pkt, 0, *encap_pkt_len);


    /* IP header */

    iph_ptr = encap_pkt;

    if ((udph_ptr = build_ip_header(iph_ptr, addr_from, addr_dest, udp_hdr_and_payload_len)) == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "add_ip_udp_header: Couldn't build the inner ip header");
        free (encap_pkt);
        return (NULL);
    }

    /* UDP header */


#ifdef BSD
    udph_ptr->uh_sport = htons(port_from);
    udph_ptr->uh_dport = htons(port_dest);
    udph_ptr->uh_ulen = htons(udp_payload_len);
    udph_ptr->uh_sum = 0;
#else
    udph_ptr->source = htons(port_from);
    udph_ptr->dest = htons(port_dest);
    udph_ptr->len = htons(udp_hdr_and_payload_len);
    udph_ptr->check = 0;
#endif

    /* Copy original packet after the headers */
    memcpy(CO(udph_ptr, udp_hdr_len), orig_pkt, orig_pkt_len);


    /*
     * Now compute the headers checksums
     */

    if ((udpsum = udp_checksum(udph_ptr, udp_hdr_and_payload_len, iph_ptr, addr_from->afi)) == -1) {
        free (encap_pkt);
        return (NULL);
    }
    udpsum(udph_ptr) = udpsum;


    return (encap_pkt);

}

uint8_t *build_control_encap_pkt(
        uint8_t             * orig_pkt,
        int                 orig_pkt_len,
        lisp_addr_t         *addr_from,
        lisp_addr_t         *addr_dest,
        int                 port_from,
        int                 port_dest,
        encap_control_opts  opts,
        int                 *control_encap_pkt_len)
{
    uint8_t                     *lisp_encap_pkt_ptr      = NULL;
    uint8_t                     *inner_pkt_ptr      = NULL;
    lisp_encap_control_hdr_t    *lisp_hdr_ptr       = NULL;
    int                         encap_pkt_len       = 0;
    int                         lisp_hdr_len        = 0;


    /* Add the interal IP and UDP headers */

    inner_pkt_ptr = build_ip_udp_pcket(orig_pkt,
                                           orig_pkt_len,
                                           addr_from,
                                           addr_dest,
                                           port_from,
                                           port_dest,
                                           &encap_pkt_len);
    /* Header length */

    lisp_hdr_len = sizeof(lisp_encap_control_hdr_t);

    /* Assign memory for the original packet plus the new header */

    *control_encap_pkt_len = lisp_hdr_len + encap_pkt_len;

    if ((lisp_encap_pkt_ptr = (void *) malloc(*control_encap_pkt_len)) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "malloc(packet_len): %s", strerror(errno));
        free(inner_pkt_ptr);
        return (NULL);
    }

    memset(lisp_encap_pkt_ptr, 0, *control_encap_pkt_len);

    /* LISP encap control header */

    lisp_hdr_ptr = (lisp_encap_control_hdr_t *) lisp_encap_pkt_ptr;

    lisp_hdr_ptr->type = LISP_ENCAP_CONTROL_TYPE;
    lisp_hdr_ptr->s_bit = 0; /* XXX Security field not supported */
    lisp_hdr_ptr->ddt_bit = opts.ddt_bit;

    /* Copy original packet after the LISP control header */

    memcpy((uint8_t *)CO(lisp_hdr_ptr, lisp_hdr_len), inner_pkt_ptr, encap_pkt_len);
    free (inner_pkt_ptr);

    return (lisp_encap_pkt_ptr);
}


/*
 * Process encapsulated map request header:  lisp header and the interal IP and UDP header
 */

int process_encapsulated_map_request_headers(
        uint8_t        *packet,
        int            *len,
        uint16_t       *dst_port){

    struct ip                  *iph                    = NULL;
    struct ip6_hdr             *ip6h                   = NULL;
    struct udphdr              *udph                   = NULL;
    int                        ip_header_len           = 0;
    int                        encap_afi               = 0;
    uint16_t                   udpsum                  = 0;
    uint16_t                   ipsum                   = 0;
    int                        udp_len                 = 0;

    /*
     * Read IP header.source_mapping
     */

    iph = (struct ip *) CO(packet, sizeof(lisp_encap_control_hdr_t));

    switch (iph->ip_v) {
    case IPVERSION:
        ip_header_len = sizeof(struct ip);
        udph = (struct udphdr *) CO(iph, ip_header_len);
        encap_afi = AF_INET;
        break;
    case IP6VERSION:
        ip6h = (struct ip6_hdr *) CO(packet, sizeof(lisp_encap_control_hdr_t));
        ip_header_len = sizeof(struct ip6_hdr);
        udph = (struct udphdr *) CO(ip6h, ip_header_len);
        encap_afi = AF_INET6;
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_request_msg: couldn't read incoming Encapsulated Map-Request: IP header corrupted.");
        return(BAD);
    }

    /* This should overwrite the external port (dst_port in map-reply = inner src_port in encap map-request) */
    *dst_port = ntohs(udph->source);

#ifdef BSD
    udp_len = ntohs(udph->uh_ulen);
    // sport   = ntohs(udph->uh_sport);
#else
    udp_len = ntohs(udph->len);
    // sport   = ntohs(udph->source);
#endif


    /*
     * Verify the checksums.
     */
    if (iph->ip_v == IPVERSION) {
        ipsum = ip_checksum((uint16_t *)iph, ip_header_len);
        if (ipsum != 0) {
            lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_request_msg: Map-Request: IP checksum failed.");
        }
        /* We accept checksum 0 in the inner header*/
        if (udph->check != 0){
            if ((udpsum = udp_checksum(udph, udp_len, iph, encap_afi)) == -1) {
                return(BAD);
            }
            if (udpsum != 0) {
                lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_request_msg: Map-Request: UDP checksum failed.");
                return(BAD);
            }
        }
    }

    //Pranathi: Added this
    if (iph->ip_v == IP6VERSION) {
        /* We accept checksum 0 in the inner header*/
        if (udph->check != 0){
            if ((udpsum = udp_checksum(udph, udp_len, iph, encap_afi)) == -1) {
                return(BAD);
            }
            if (udpsum != 0) {
                lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_request_msg: Map-Request:v6 UDP checksum failed.");
                return(BAD);
            }
        }
    }

    *len = sizeof(lisp_encap_control_hdr_t)+ip_header_len + sizeof(struct udphdr);

    return (GOOD);
}

uint16_t get_IP_ID()
{
    ip_id ++;
    return (ip_id);
}


uint8_t is_ctrl_packet (uint8_t *packet)
{
	struct iphdr        *iph 	= NULL;
	struct udphdr       *udph 	= NULL;

	iph = (struct iphdr *)packet;
	switch (iph->version){
	case 4:
		udph = (struct udphdr *) CO(packet,sizeof(struct iphdr));
		break;
	case 6:
		udph = (struct udphdr *) CO(packet,sizeof(struct ip6_hdr));
		break;
	default:
		return (FALSE);
	}
	if (ntohs(udph->dest) == LISP_CONTROL_PORT || ntohs(udph->source) == LISP_CONTROL_PORT){
		return (TRUE);
	}else{
		return (FALSE);
	}
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
