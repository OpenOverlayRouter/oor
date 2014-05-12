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
#include "lispd_tun.h"
#include "lispd_output.h"
#include "packets.h"

static uint8_t pkt_recv_buf[MAX_IP_PKT_LEN+1];

lisp_addr_t extract_src_addr_from_packet( uint8_t *packet )
{
    lisp_addr_t         addr    = {.afi=AF_UNSPEC, .lafi=LM_AFI_IP};
    struct iphdr        *iph    = NULL;
    struct ip6_hdr      *ip6h   = NULL;

    iph = (struct iphdr *) packet;

    switch (iph->version) {
    case 4:
        ip_addr_set_v4(lisp_addr_ip(&addr), &iph->saddr);
        break;
    case 6:
        ip_addr_set_v6(lisp_addr_ip(&addr), &ip6h->ip6_src);
        break;
    default:
        lmlog(DBG_3,"extract_src_addr_from_packet: uknown ip version %d", iph->version);
        break;
    }

    return (addr);
}

int read_and_decap_lisp_data_packet(int sock, struct iphdr **iph, int *length) {

    uint8_t             ttl = 0;
    uint8_t             tos = 0;
    int                 afi = 0;

    struct lisphdr      *lisp_hdr = NULL;
    struct ip6_hdr      *ip6h = NULL;
    struct udphdr       *udph = NULL;

    /* clear recv buffer */
    memset(pkt_recv_buf, 0, MAX_IP_PKT_LEN);

    if (get_data_packet(sock, &afi, pkt_recv_buf, length, &ttl, &tos) != GOOD) {
        lmlog(DBG_2,"process_input_packet: get_data_packet error: %s", strerror(errno));
        return(BAD);
    }

    if(afi == AF_INET){
        /* With input RAW UDP sockets in IPv4, we get the whole external IPv4 packet */
        udph = (struct udphdr *) CO(pkt_recv_buf,sizeof(struct iphdr));
    }else{
        /* With input RAW UDP sockets in IPv6, we get the whole external UDP packet */
        udph = (struct udphdr *) pkt_recv_buf;
    }

    /* With input RAW UDP sockets, we receive all UDP packets, we only want lisp data ones */
    if(ntohs(udph->dest) != LISP_DATA_PORT){
        //lispd_log_msg(DBG_3,"INPUT (No LISP data): UDP dest: %d ",ntohs(udph->dest));
        return(ERR_NOT_LISP);
    }

    lisp_hdr = (struct lisphdr *) CO(udph,sizeof(struct udphdr));
    *length = *length - sizeof(struct udphdr) - sizeof(struct lisphdr);
    *iph = (struct iphdr *) CO(lisp_hdr,sizeof(struct lisphdr));

    if ((*iph)->version == 4) {
        if(ttl!=0) /*XXX It seems that there is a bug in uClibc that causes ttl=0 in OpenWRT. This is a quick workaround */
            (*iph)->ttl = ttl;

        (*iph)->tos = tos;

        /* We need to recompute the checksum since we have changed the TTL and TOS header fields */
        (*iph)->check = 0; /* New checksum must be computed with the checksum header field with 0s */
        (*iph)->check = ip_checksum((uint16_t*) *iph, sizeof(struct iphdr));

    }else{
        ip6h = ( struct ip6_hdr *) *iph;

        if(ttl!=0) /*XXX It seems that there is a bug in uClibc that causes ttl=0 in OpenWRT. This is a quick workaround */
            ip6h->ip6_hops = ttl; /* ttl = Hops limit in IPv6 */

        IPV6_SET_TC(ip6h,tos); /* tos = Traffic class field in IPv6 */
    }

    if (lisp_hdr->instance_id == 1){ //Poor discriminator for data map notify...
        lmlog(DBG_2,"Data-Map-Notify received\n ");
        //Is there something to do here?
    }

    return(GOOD);
}

int
process_input_packet(struct sock *sl)
{
    struct iphdr *iph = NULL;
    int length = 0;

    if (read_and_decap_lisp_data_packet(sl->fd, &iph, &length) != GOOD)
        return (BAD);

    lmlog(DBG_3,"INPUT (4341): Inner src: %s | Inner dst: %s ",
                  lisp_addr_to_char((lisp_addr_t[]){extract_src_addr_from_packet((uint8_t *)iph)}),
                  lisp_addr_to_char((lisp_addr_t[]){extract_dst_addr_from_packet((uint8_t *)iph)}));

    if ((write(tun_receive_fd, iph, length)) < 0) {
        lmlog(DBG_2, "lisp_input: write error: %s\n ",
                strerror(errno));
    }

    return (GOOD);
}

int rtr_process_input_packet(struct sock *sl)
{
    struct iphdr        *iph    = NULL;
    int                 length  = 0;

    if (read_and_decap_lisp_data_packet(sl->fd, &iph, &length) != GOOD)
        return(BAD);

    lmlog(DBG_3,"INPUT (4341): Inner src: %s | Inner dst: %s ",
                  lisp_addr_to_char((lisp_addr_t[]){extract_src_addr_from_packet((uint8_t *)iph)}),
                  lisp_addr_to_char((lisp_addr_t[]){extract_dst_addr_from_packet((uint8_t *)iph)}));

    lmlog(DBG_3, "INPUT (4341): Forwarding to OUPUT for re-encapsulation");
    lisp_output((uint8_t *)iph, length);

    return(GOOD);
}

