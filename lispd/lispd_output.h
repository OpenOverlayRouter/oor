/*
 * lispd_output.h
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


#ifndef LISPD_OUTPUT_H_
#define LISPD_OUTPUT_H_

#include <stdio.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "lispd.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "cksum.h"
#include "lispd_map_cache_db.h"
#include "lispd_external.h"


void process_output_packet(int fd, char *tun_receive_buf, unsigned int tun_receive_size);

lisp_addr_t extract_dst_addr_from_packet ( char *packet );

lisp_addr_t extract_src_addr_from_packet ( char *packet );

int handle_map_cache_miss(lisp_addr_t *requested_eid, lisp_addr_t *src_eid);

lisp_addr_t *get_proxy_etr(int afi);




/* Macros extracted from ROHC library code: http://rohc-lib.org/ */


/*
 * Generic IP macros:
 */

/// Get a subpart of a 16-bit IP field
#define IP_GET_16_SUBFIELD(field, bitmask, offset) \
((ntohs(field) & (bitmask)) >> (offset))

/// Get a subpart of a 32-bit IP field
#define IP_GET_32_SUBFIELD(field, bitmask, offset) \
((ntohl(field) & (bitmask)) >> (offset))

/// Set a subpart of a 16-bit IP field
#define IP_SET_16_SUBFIELD(field, bitmask, offset, value) \
(field) = (((field) & htons(~(bitmask))) | htons(((value) << (offset)) & (bitmask)))

/// Set a subpart of a 32-bit IP field
#define IP_SET_32_SUBFIELD(field, bitmask, offset, value) \
(field) = (((field) & htonl(~(bitmask))) | htonl(((value) << (offset)) & (bitmask)))


/*
 * IPv4 definitions & macros:
 */

/// The offset for the DF flag in an ipv4_hdr->frag_off variable
#define IPV4_DF_OFFSET  14

/// Get the IPv4 Don't Fragment (DF) bit from an ipv4_hdr object
#define IPV4_GET_DF(ip4) \
IP_GET_16_SUBFIELD((ip4).frag_off, IP_DF, IPV4_DF_OFFSET)

/// Set the IPv4 Don't Fragment (DF) bit in an ipv4_hdr object
#define IPV4_SET_DF(ip4, value) \
IP_SET_16_SUBFIELD((ip4)->frag_off, IP_DF, IPV4_DF_OFFSET, (value))

/// The format to print an IPv4 address
#define IPV4_ADDR_FORMAT \
"%02x%02x%02x%02x (%u.%u.%u.%u)"

/// The data to print an IPv4 address in raw format
#define IPV4_ADDR_RAW(x) \
(x)[0], (x)[1], (x)[2], (x)[3], \
(x)[0], (x)[1], (x)[2], (x)[3]


/*
 * IPv6 definitions & macros:
 */

/// The bitmask for the Version field in an ipv6_hdr->ip6_flow variable
#define IPV6_VERSION_MASK  0xf0000000
/// The offset for the Version field in an ipv6_hdr->ip6_flow variable
#define IPV6_VERSION_OFFSET  28

/// The bitmask for the Traffic Class (TC) field in an ipv6_hdr->ip6_flow variable
#define IPV6_TC_MASK  0x0ff00000
/// The offset for the Traffic Class (TC) field in an ipv6_hdr->ip6_flow variable
#define IPV6_TC_OFFSET  20

/// The bitmask for the FLow Label field in an ipv6_hdr->ip6_flow variable
#define IPV6_FLOW_LABEL_MASK  0x000fffff

/// Get the IPv6 Version 4-bit field from ipv6_hdr object
#define IPV6_GET_VERSION(ip6) \
IP_GET_32_SUBFIELD((ip6).ip6_flow, IPV6_VERSION_MASK, IPV6_VERSION_OFFSET)

/// Set the IPv6 Version 4-bit field in an ipv6_hdr object
#define IPV6_SET_VERSION(ip6, value) \
IP_SET_32_SUBFIELD((ip6)->ip6_flow, IPV6_VERSION_MASK, IPV6_VERSION_OFFSET, (value))

/// Get the IPv6 Traffic Class (TC) byte from an ipv6_hdr object
#define IPV6_GET_TC(ip6) \
IP_GET_32_SUBFIELD((ip6).ip6_flow, IPV6_TC_MASK, IPV6_TC_OFFSET)

/// Set the IPv6 Traffic Class (TC) byte in an ipv6_hdr object
#define IPV6_SET_TC(ip6, value) \
IP_SET_32_SUBFIELD((ip6)->ip6_flow, IPV6_TC_MASK, IPV6_TC_OFFSET, (value))

/// Get the IPv6 Flow Label 20-bit field from an ipv6_hdr object
#define IPV6_GET_FLOW_LABEL(ip6) \
IP_GET_32_SUBFIELD((ip6).ip6_flow, IPV6_FLOW_LABEL_MASK, 0)

/// Set the IPv6 Flow Label 20-bit field in an ipv6_hdr variable
#define IPV6_SET_FLOW_LABEL(ip6, value) \
IP_SET_32_SUBFIELD((ip6)->ip6_flow, IPV6_FLOW_LABEL_MASK, 0, (value))

/// The format to print an IPv6 address
#define IPV6_ADDR_FORMAT \
"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"

/// The data to print an IPv6 address in (struct ipv6_addr *) format
#define IPV6_ADDR_IN6(x) \
IPV6_ADDR_RAW((x)->s6_addr)

/// The data to print an IPv6 address in raw format
#define IPV6_ADDR_RAW(x) \
(x)[0], (x)[1], (x)[2], (x)[3], (x)[4], (x)[5], (x)[6], (x)[7], \
(x)[8], (x)[9], (x)[10], (x)[11], (x)[12], (x)[13], (x)[14], (x)[15]

/// Compare two IPv6 addresses in (struct ipv6_addr *) format
#define IPV6_ADDR_CMP(x, y) \
((x)->s6_addr32[0] == (y)->s6_addr32[0] && \
(x)->s6_addr32[1] == (y)->s6_addr32[1] && \
(x)->s6_addr32[2] == (y)->s6_addr32[2] && \
(x)->s6_addr32[3] == (y)->s6_addr32[3])

#endif /*LISPD_OUTPUT_H_*/
