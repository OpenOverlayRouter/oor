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

#include "cksum.h"
#include "oor_log.h"
#include "../liblisp/lisp_messages.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>


uint16_t
ip_checksum(uint16_t *buffer, int size)
{
    uint32_t cksum = 0;

    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(uint16_t);
    }

    if (size) {
        cksum += *(uint8_t *) buffer;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return ((uint16_t) (~cksum));
}

/*
 *
 *  Calculate the IPv4 UDP checksum (calculated with the whole packet).
 *
 *  Parameters:
 *
 *  buff    -   pointer to the UDP header
 *  len -   the UDP packet length.
 *  src -   the IP source address (in network format).
 *  dest    -   the IP destination address (in network format).
 *
 *  Returns:        The result of the checksum
 *
 */

uint16_t
udp_ipv4_checksum(const void *b, unsigned int len,
        in_addr_t src, in_addr_t dst)
{

    const uint16_t *buf = b;
    uint16_t *ip_src = (void *) &src;
    uint16_t *ip_dst = (void *) &dst;
    uint32_t length = len;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    /* Add the padding if the packet length is odd */

    if (len & 1)
        sum += *((uint8_t *) buf);

    /* Add the pseudo-header */

    sum += *(ip_src++);
    sum += *ip_src;

    sum += *(ip_dst++);
    sum += *ip_dst;

    sum += htons(IPPROTO_UDP);
    sum += htons(length);

    /* Add the carries */

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    /* Return the one's complement of sum */

    return ((uint16_t) (~sum));
}

uint16_t
udp_ipv6_checksum(const struct ip6_hdr *ip6, const struct udphdr *up,
        unsigned int len)
{
    size_t i;
    register const u_int16_t *sp;
    uint32_t sum;
    union {
        struct {
            struct in6_addr ph_src;
            struct in6_addr ph_dst;
            u_int32_t ph_len;
            u_int8_t ph_zero[3];
            u_int8_t ph_nxt;
        } ph;
        u_int16_t pa[20];
    } phu;

    /* pseudo-header */
    memset(&phu, 0, sizeof(phu));
    phu.ph.ph_src = ip6->ip6_src;
    phu.ph.ph_dst = ip6->ip6_dst;
    phu.ph.ph_len = htonl(len);
    phu.ph.ph_nxt = IPPROTO_UDP;

    sum = 0;
    for (i = 0; i < sizeof(phu.pa) / sizeof(phu.pa[0]); i++)
        sum += phu.pa[i];

    sp = (const u_int16_t *) up;

    for (i = 0; i < (len & ~1); i += 2)
        sum += *sp++;

    if (len & 1)
        sum += htons((*(const u_int8_t *) sp) << 8);

    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum & 0xffff;

    return (sum);
}

/*
 *  upd_checksum
 *
 *  Calculate the IPv4 or IPv6 UDP checksum  */
uint16_t
udp_checksum(struct udphdr *udph, int udp_len, void *iphdr, int afi)
{
    switch (afi) {
    case AF_INET:
        return (udp_ipv4_checksum(udph, udp_len,
                ((struct ip *) iphdr)->ip_src.s_addr,
                ((struct ip *) iphdr)->ip_dst.s_addr));
    case AF_INET6:
        return (udp_ipv6_checksum(iphdr, udph, udp_len));
    default:
        OOR_LOG(LDBG_2, "udp_checksum: Unknown AFI");
        return (-1);
    }
}

