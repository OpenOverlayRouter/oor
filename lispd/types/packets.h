/*
 * lispd_pkt_lib.h
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

#ifndef LISPD_PKT_LIB_H_
#define LISPD_PKT_LIB_H_

#include "defs.h"
//#include "lispd_local_db.h"


/*
 * Fill the tuple with the 5 tuples of a packet: (SRC IP, DST IP, PROTOCOL, SRC PORT, DST PORT)
 */

int extract_5_tuples_from_packet(uint8_t *packet, packet_tuple *tuple);

/*
 * Generate IP header. Returns the poninter to the transport header
 */

struct udphdr *build_ip_header(uint8_t *cur_ptr, lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr, int ip_len);

/*
 * Generates an IP header and an UDP header
 * and copies the original packet at the end
 */

uint8_t *build_ip_udp_pcket(uint8_t *orig_pkt, int orig_pkt_len,
        lisp_addr_t *addr_from, lisp_addr_t *addr_dest, int port_from,
        int port_dest, int *pkt_len);

/*
 * Encapsulates a control lisp message
 */

uint8_t *build_control_encap_pkt(uint8_t *orig_pkt, int orig_pkt_len,
        lisp_addr_t *addr_from, lisp_addr_t *addr_dest, int port_from,
        int port_dest, int *control_encap_pkt_len);

/* Returns IP ID for the packet */
uint16_t get_IP_ID();


uint16_t ip_checksum(uint16_t *buffer, int size);

/* Calculate the IPv4 or IPv6 UDP checksum */
uint16_t udp_checksum(struct udphdr *udph, int udp_len, void *iphdr, int afi);

int ip_hdr_ver_to_len(int ih_ver);
void *pkt_pull_ipv4(struct lbuf *b);
void *pkt_pull_ipv6(struct lbuf *b);
void *pkt_pull_ip(struct lbuf *);

void *pkt_push_ipv4(lbuf_t *, struct in_addr *, struct in_addr *);
void *pkt_push_ipv6(lbuf_t *, struct in6_addr *, struct in6_addr *);
void *pkt_push_udp(lbuf_t *, uint16_t , uint16_t );
void *pkt_push_ip(lbuf_t *, ip_addr_t *, ip_addr_t *);
int pkt_compute_udp_cksum(lbuf_t *, int afi);

#endif /*LISPD_PKT_LIB_H_*/
