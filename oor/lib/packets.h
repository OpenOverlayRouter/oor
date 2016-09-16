/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef PACKETS_H_
#define PACKETS_H_

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "lbuf.h"
#include "mem_util.h"
#include "../defs.h"
#include "../liblisp/lisp_address.h"



#define MAX_IP_PKT_LEN          4096
#define MAX_IP_HDR_LEN          40  /* without options or IPv6 hdr extensions */
#define UDP_HDR_LEN             8

#ifdef BSD
#define udpsport(x) x->uh_sport
#define udpdport(x) x->uh_dport
#define udplen(x) x->uh_ulen
#define udpsum(x) x->uh_sum
#else
#define udpsport(x) x->source
#define udpdport(x) x->dest
#define udplen(x) x->len
#define udpsum(x) x->check
#endif

#ifdef BSD
#define tcpsport(x) x->th_sport
#define tcpdport(x) x->th_dport
#else
#define tcpsport(x) x->source
#define tcpdport(x) x->dest
#endif



/* shared between data and control */
typedef struct packet_tuple {
    lisp_addr_t                     src_addr;
    lisp_addr_t                     dst_addr;
    uint16_t                        src_port;
    uint16_t                        dst_port;
    uint8_t                         protocol;
    uint32_t                        iid;
} packet_tuple_t;



/*
 * Generate IP header. Returns the poninter to the transport header
 */

struct udphdr *build_ip_header(uint8_t *cur_ptr, lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr, int ip_len);

/*
 * Generates an IP header and an UDP header
 * and copies the original packet at the end */
uint8_t *build_ip_udp_pcket(uint8_t *orig_pkt, int orig_pkt_len,
        lisp_addr_t *addr_from, lisp_addr_t *addr_dest, int port_from,
        int port_dest, int *pkt_len);



void *pkt_pull_ipv4(lbuf_t *b);
void *pkt_pull_ipv6(lbuf_t *b);
void *pkt_pull_ip(lbuf_t *);
struct udphdr *pkt_pull_udp(lbuf_t *);

struct ip *pkt_push_ipv4(lbuf_t *, struct in_addr *, struct in_addr *, int);
struct ip6_hdr *pkt_push_ipv6(lbuf_t *, struct in6_addr *, struct in6_addr *,
        int);
void *pkt_push_udp(lbuf_t *, uint16_t , uint16_t);
void *pkt_push_ip(lbuf_t *, ip_addr_t *, ip_addr_t *, int proto);
int pkt_push_udp_and_ip(lbuf_t *, uint16_t, uint16_t, ip_addr_t *,
        ip_addr_t *);
int ip_hdr_set_ttl_and_tos(struct iphdr *, int ttl, int tos);
int ip_hdr_ttl_and_tos(struct iphdr *, int *ttl, int *tos);

int pkt_parse_5_tuple(lbuf_t *b, packet_tuple_t *tuple);
uint32_t pkt_tuple_hash(packet_tuple_t *tuple);
int pkt_tuple_cmp(packet_tuple_t *t1, packet_tuple_t *t2);
packet_tuple_t *pkt_tuple_clone(packet_tuple_t *);
void pkt_tuple_del(packet_tuple_t *tpl);
char *pkt_tuple_to_char(packet_tuple_t *tpl);

char * ip_src_and_dst_to_char(struct iphdr *iph, char *fmt);

void pkt_add_uint32_in_3bytes (uint8_t *pkt, uint32_t val);
uint32_t pkt_get_uint32_from_3bytes (uint8_t *pkt);



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
#endif /*PACKETS_H_*/
