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
#include <netinet/udp.h>
#include <netinet/tcp.h>

/*
 *  get_locators_length
 *
 *  Compute the sum of the lengths of the locators
 *  so we can allocate  memory for the packet....
 */
int get_locators_length(lispd_locators_list *locators_list);


int pkt_get_mapping_record_length(lispd_mapping_elt *mapping)
{
    lispd_locators_list *locators_list[2] = {
            mapping->head_v4_locators_list,
            mapping->head_v6_locators_list};
    int length          = 0;
    int loc_length      = 0;
    int eid_length      = 0;
    int ctr;

    for (ctr = 0 ; ctr < 2 ; ctr ++){
        if (locators_list[ctr] == NULL)
            continue;
        loc_length += get_locators_length(locators_list[ctr]);
    }
    eid_length = get_mapping_length(mapping);
    length = sizeof(lispd_pkt_mapping_record_t) + eid_length +
            (mapping->locator_count * sizeof(lispd_pkt_mapping_record_locator_t)) +
            loc_length;

    return (length);
}


/*
 *  get_locators_length
 *
 *  Compute the sum of the lengths of the locators
 *  so we can allocate  memory for the packet....
 */

int get_locators_length(lispd_locators_list *locators_list)
{
    int sum = 0;
    while (locators_list) {
        switch (locators_list->locator->locator_addr->afi) {
        case AF_INET:
            sum += sizeof(struct in_addr);
            break;
        case AF_INET6:
            sum += sizeof(struct in6_addr);
            break;
        default:
            /* It should never happen*/
            lispd_log_msg(LISP_LOG_DEBUG_2, "get_locators_length: Uknown AFI (%d) - It should never happen",
               locators_list->locator->locator_addr->afi);
            break;
        }
        locators_list = locators_list->next;
    }
    return(sum);
}

/*
 *  get_up_locators_length
 *
 *  Compute the sum of the lengths of the locators that has the status up
 *  so we can allocate  memory for the packet....
 */

int get_up_locators_length(
        lispd_locators_list *locators_list,
        int                 *loc_count)
{
    int sum = 0;
    int counter = 0;
    while (locators_list) {
        if (*(locators_list->locator->state)== DOWN){
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

    if (mapping->iid >= 0)
        ident_len += sizeof(lispd_pkt_lcaf_t) + sizeof(lispd_pkt_lcaf_iid_t);

    return ident_len;
}

void *pkt_fill_eid(
        void                    *offset,
        lispd_mapping_elt       *mapping)
{
    uint16_t                *afi_ptr;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    lispd_pkt_lcaf_iid_t    *iid_ptr;
    void                    *eid_ptr;
    int                     eid_addr_len;

    afi_ptr = (uint16_t *)offset;
    eid_addr_len = get_addr_len(mapping->eid_prefix.afi);

    /* For negative IID values, we skip LCAF/IID field */
    if (mapping->iid < 0) {
        *afi_ptr = htons(get_lisp_afi(mapping->eid_prefix.afi, NULL));
        eid_ptr  = CO(offset, sizeof(uint16_t));
    } else {
        *afi_ptr = htons(LISP_AFI_LCAF);
        lcaf_ptr = (lispd_pkt_lcaf_t *) CO(offset, sizeof(uint16_t));
        iid_ptr  = (lispd_pkt_lcaf_iid_t *) CO(lcaf_ptr, sizeof(lispd_pkt_lcaf_t));
        eid_ptr  = (void *) CO(iid_ptr, sizeof(lispd_pkt_lcaf_iid_t));

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

    return CO(eid_ptr, eid_addr_len);
}


void *pkt_fill_mapping_record(
    lispd_pkt_mapping_record_t              *rec,
    lispd_mapping_elt                       *mapping,
    lisp_addr_t                             *probed_rloc)
{
    int                                     cpy_len             = 0;
    lispd_pkt_mapping_record_locator_t      *loc_ptr            = NULL;
    lispd_locators_list                     *locators_list[2]   = {NULL,NULL};
    lispd_locator_elt                       *locator            = NULL;
    int                                     ctr                 = 0;

    if ((rec == NULL) || (mapping == NULL))
        return NULL;

    rec->ttl                    = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
    rec->locator_count          = mapping->locator_count;
    rec->eid_prefix_length      = mapping->eid_prefix_length;
    rec->action                 = 0;
    rec->authoritative          = 1;
    rec->version_hi             = 0;
    rec->version_low            = 0;

    loc_ptr = (lispd_pkt_mapping_record_locator_t *)pkt_fill_eid(&(rec->eid_prefix_afi), mapping);

    if (loc_ptr == NULL){
        return NULL;
    }

    locators_list[0] = mapping->head_v4_locators_list;
    locators_list[1] = mapping->head_v6_locators_list;
    for (ctr = 0 ; ctr < 2 ; ctr++){
        while (locators_list[ctr]) {
            locator              = locators_list[ctr]->locator;
            loc_ptr->priority    = locator->priority;
            loc_ptr->weight      = locator->weight;
            loc_ptr->mpriority   = locator->mpriority;
            loc_ptr->mweight     = locator->mweight;
            loc_ptr->local       = 1;
            if (probed_rloc != NULL && compare_lisp_addr_t(locator->locator_addr,probed_rloc)==0){
                loc_ptr->probed  = 1;
            }
            loc_ptr->reachable   = *(locator->state);
            loc_ptr->locator_afi = htons(get_lisp_afi(locator->locator_addr->afi,NULL));

            if ((cpy_len = copy_addr((void *) CO(loc_ptr,
                    sizeof(lispd_pkt_mapping_record_locator_t)), locator->locator_addr, 0)) == 0) {
                lispd_log_msg(LISP_LOG_DEBUG_3, "pkt_fill_mapping_record: copy_addr failed for locator %s",
                        get_char_from_lisp_addr_t(*(locator->locator_addr)));
                return(NULL);
            }

            loc_ptr = (lispd_pkt_mapping_record_locator_t *)
                            CO(loc_ptr, (sizeof(lispd_pkt_mapping_record_locator_t) + cpy_len));
            locators_list[ctr] = locators_list[ctr]->next;
        }
    }
    return (void *)loc_ptr;
}
/*
 * Fill the tuple with the 5 tuples of a packet: (SRC IP, DST IP, PROTOCOL, SRC PORT, DST PORT)
 */
int extract_5_tuples_from_packet (
        char *packet ,
        packet_tuple *tuple)
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
        tuple->src_port = udp->source;
        tuple->dst_port = udp->dest;
    }else if (tuple->protocol == IPPROTO_TCP){
        tcp = (struct tcphdr *)CO(packet,len);
        tuple->src_port = tcp->source;
        tuple->dst_port = tcp->dest;
    }else{//If protocol is not TCP or UDP, ports of the tuple set to 0
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }
    return (GOOD);
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
