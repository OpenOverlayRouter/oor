/*
 * lispd_input.c
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


#include "lispd_input.h"

void process_input_packet(int fd,
                          int afi,
                          int tun_receive_fd)
{
    uint8_t             *packet = NULL;
    int                 length = 0;
    uint8_t             ttl = 0;
    uint8_t             tos = 0;

    struct lisphdr      *lisp_hdr = NULL;
    struct iphdr        *iph = NULL;
    struct ip6_hdr      *ip6h = NULL;
    struct udphdr       *udph = NULL;


    if ((packet = (uint8_t *) malloc(MAX_IP_PACKET))==NULL){
        lispd_log_msg(LISP_LOG_ERR,"process_input_packet: Couldn't allocate space for packet: %s", strerror(errno));
        return;
    }

    memset(packet,0,MAX_IP_PACKET);
    
    if (get_data_packet (fd,
                         afi,
                         packet,
                         &length,
                         &ttl,
                         &tos) == BAD){
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_input_packet: get_data_packet error: %s", strerror(errno));
        free(packet);
        return;
    }

    if(afi == AF_INET){
        /* With input RAW UDP sockets in IPv4, we get the whole external IPv4 packet */
        udph = (struct udphdr *) CO(packet,sizeof(struct iphdr));
    }else{
        /* With input RAW UDP sockets in IPv6, we get the whole external UDP packet */
        udph = (struct udphdr *) packet;
    }
    
    /* With input RAW UDP sockets, we receive all UDP packets, we only want lisp data ones */
    if(ntohs(udph->dest) != LISP_DATA_PORT){
        free(packet);
        //lispd_log_msg(LISP_LOG_DEBUG_3,"INPUT (No LISP data): UDP dest: %d ",ntohs(udph->dest));
        return;
    }

    lisp_hdr = (struct lisphdr *) CO(udph,sizeof(struct udphdr));

    length = length - sizeof(struct udphdr) - sizeof(struct lisphdr);
    
    iph = (struct iphdr *) CO(lisp_hdr,sizeof(struct lisphdr));

    lispd_log_msg(LISP_LOG_DEBUG_3,"INPUT (4341): Inner src: %s | Inner dst: %s ",
                  get_char_from_lisp_addr_t(extract_src_addr_from_packet((char *)iph)),
                  get_char_from_lisp_addr_t(extract_dst_addr_from_packet((char *)iph)));
    
    if (iph->version == 4) {
        
        if(ttl!=0){ /*XXX It seems that there is a bug in uClibc that causes ttl=0 in OpenWRT. This is a quick workaround */
            iph->ttl = ttl;
        }
        iph->tos = tos;

        /* We need to recompute the checksum since we have changed the TTL and TOS header fields */
        iph->check = 0; /* New checksum must be computed with the checksum header field with 0s */
        iph->check = ip_checksum((uint16_t*) iph, sizeof(struct iphdr));
        
    }else{
        ip6h = ( struct ip6_hdr *) iph;

        if(ttl!=0){ /*XXX It seems that there is a bug in uClibc that causes ttl=0 in OpenWRT. This is a quick workaround */
            ip6h->ip6_hops = ttl; /* ttl = Hops limit in IPv6 */
        }
        
        IPV6_SET_TC(ip6h,tos); /* tos = Traffic class field in IPv6 */
    }

    if ((write(tun_receive_fd, iph, length)) < 0){
        lispd_log_msg(LISP_LOG_DEBUG_2,"lisp_input: write error: %s\n ", strerror(errno));
    }
    
    free(packet);
}

