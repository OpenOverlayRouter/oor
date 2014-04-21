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
#include "packets.h"
#include "lispd_lib.h"
#include <lispd_local_db.h>
#include <lispd_map_register.h>
#include "lispd_external.h"
#include "lispd_sockets.h"
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <lisp_messages.h>
#include "cksum.h"

uint16_t ip_id = 0;


uint16_t
ip_checksum(uint16_t *buffer, int size) {
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

static uint16_t
udp_ipv4_checksum(const void *b, unsigned int len,
        in_addr_t src, in_addr_t dst) {

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
        unsigned int len) {
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
uint16_t udp_checksum(struct udphdr *udph, int udp_len, void *iphdr, int afi) {
    switch (afi) {
    case AF_INET:
        return (udp_ipv4_checksum(udph, udp_len,
                ((struct ip *) iphdr)->ip_src.s_addr,
                ((struct ip *) iphdr)->ip_dst.s_addr));
    case AF_INET6:
        return (udp_ipv6_checksum(iphdr, udph, udp_len));
    default:
        lmlog(LISP_LOG_DEBUG_2, "udp_checksum: Unknown AFI");
        return (-1);
    }
}


/*
 * Generate IP header. Returns the pointer to the transport header
 */

struct udphdr *build_ip_header(uint8_t *cur_ptr, lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr, int ip_len) {
    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct udphdr *udph;

    switch (src_addr->afi) {
    case AF_INET:
        ip_len = ip_len + sizeof(struct ip);
        iph = (struct ip *) cur_ptr;
        iph->ip_hl = 5;
        iph->ip_v = IPVERSION;
        iph->ip_tos = 0;
        iph->ip_len = htons(ip_len);
        iph->ip_id = htons(get_IP_ID());
        iph->ip_off = 0; /* XXX Control packets can be fragmented  */
        iph->ip_ttl = 255;
        iph->ip_p = IPPROTO_UDP;
        iph->ip_src.s_addr = src_addr->address.ip.s_addr;
        iph->ip_dst.s_addr = dst_addr->address.ip.s_addr;
        iph->ip_sum = 0;
        iph->ip_sum = ip_checksum((uint16_t *) cur_ptr, sizeof(struct ip));

        udph = (struct udphdr *) CO(iph, sizeof(struct ip));
        break;
    case AF_INET6:
        ip6h = (struct ip6_hdr *) cur_ptr;
        ip6h->ip6_hops = 255;
        ip6h->ip6_vfc = (IP6VERSION << 4);
        ip6h->ip6_nxt = IPPROTO_UDP;
        ip6h->ip6_plen = htons(ip_len);
        memcpy(ip6h->ip6_src.s6_addr, src_addr->address.ipv6.s6_addr,
                sizeof(struct in6_addr));
        memcpy(ip6h->ip6_dst.s6_addr, dst_addr->address.ipv6.s6_addr,
                sizeof(struct in6_addr));
        udph = (struct udphdr *) CO(ip6h, sizeof(struct ip6_hdr));
        break;
    default:
        lmlog(LISP_LOG_DEBUG_2,
                "build_ip_header: Uknown AFI of the source address: %d",
                src_addr->afi);
        return (NULL);
    }
    return (udph);
}

/*
 * Generates an IP header and an UDP header
 * and copies the original packet at the end
 */

uint8_t *build_ip_udp_pcket(uint8_t *orig_pkt, int orig_pkt_len,
        lisp_addr_t *addr_from, lisp_addr_t *addr_dest, int port_from,
        int port_dest, int *encap_pkt_len) {

    uint8_t *encap_pkt = NULL;
    void *iph_ptr = NULL;
    struct udphdr *udph_ptr = NULL;
    int ip_hdr_len = 0;
    int udp_hdr_len = 0;
    int udp_hdr_and_payload_len = 0;
    uint16_t udpsum = 0;

    if (lisp_addr_ip_afi(addr_from) != lisp_addr_ip_afi(addr_dest)) {
        lmlog(LISP_LOG_DEBUG_2,
                "add_ip_udp_header: Different AFI addresses %d (%s) and %d (%s)",
                lisp_addr_ip_afi(addr_from), lisp_addr_to_char(addr_from),
                lisp_addr_ip_afi(addr_dest), lisp_addr_to_char(addr_dest));
        return (NULL);
    }

    if ((lisp_addr_ip_afi(addr_from) != AF_INET)
            && (lisp_addr_ip_afi(addr_from) != AF_INET6)) {
        lmlog(LISP_LOG_DEBUG_2, "add_ip_udp_header: Unknown AFI %d",
                lisp_addr_ip_afi(addr_from));
        return (NULL);
    }

    /* Headers lengths */

    ip_hdr_len = get_ip_header_len(addr_from->afi);

    udp_hdr_len = sizeof(struct udphdr);

    udp_hdr_and_payload_len = udp_hdr_len + orig_pkt_len;

    /* Assign memory for the original packet plus the new headers */

    *encap_pkt_len = ip_hdr_len + udp_hdr_len + orig_pkt_len;

    if ((encap_pkt = (uint8_t *) malloc(*encap_pkt_len)) == NULL) {
        lmlog(LISP_LOG_DEBUG_2,
                "add_ip_udp_header: Couldn't allocate memory for the packet to be generated %s",
                strerror(errno));
        return (NULL);
    }

    /* Make sure it's clean */

    memset(encap_pkt, 0, *encap_pkt_len);

    /* IP header */

    iph_ptr = encap_pkt;

    if ((udph_ptr = build_ip_header(iph_ptr, addr_from, addr_dest,
            udp_hdr_and_payload_len)) == NULL) {
        lmlog(LISP_LOG_DEBUG_2,
                "add_ip_udp_header: Couldn't build the inner ip header");
        free(encap_pkt);
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

    if ((udpsum = udp_checksum(udph_ptr, udp_hdr_and_payload_len, iph_ptr,
            addr_from->afi)) == -1) {
        free(encap_pkt);
        return (NULL);
    }
    udpsum(udph_ptr) = udpsum;

    return (encap_pkt);

}

uint8_t *build_control_encap_pkt(uint8_t * orig_pkt, int orig_pkt_len,
        lisp_addr_t *addr_from, lisp_addr_t *addr_dest, int port_from,
        int port_dest, int *control_encap_pkt_len) {

    uint8_t *lisp_encap_pkt_ptr = NULL;
    uint8_t *inner_pkt_ptr = NULL;
    ecm_hdr_t *lisp_hdr_ptr = NULL;
    int encap_pkt_len = 0;
    int lisp_hdr_len = 0;

    /* Add the interal IP and UDP headers */

    inner_pkt_ptr = build_ip_udp_pcket(orig_pkt, orig_pkt_len, addr_from,
            addr_dest, port_from, port_dest, &encap_pkt_len);

    /* Header length */
    lisp_hdr_len = sizeof(ecm_hdr_t);

    /* Assign memory for the original packet plus the new header */

    *control_encap_pkt_len = lisp_hdr_len + encap_pkt_len;

    if ((lisp_encap_pkt_ptr = (void *) malloc(*control_encap_pkt_len)) == NULL) {
        lmlog(LISP_LOG_DEBUG_2, "malloc(packet_len): %s",
                strerror(errno));
        free(inner_pkt_ptr);
        return (NULL);
    }

    memset(lisp_encap_pkt_ptr, 0, *control_encap_pkt_len);

    /* LISP encap control header */

    lisp_hdr_ptr = (ecm_hdr_t *) lisp_encap_pkt_ptr;

    lisp_hdr_ptr->type = LISP_ENCAP_CONTROL_TYPE;
    lisp_hdr_ptr->s_bit = 0; /* XXX Security field not supported */

    /* Copy original packet after the LISP control header */

    memcpy((uint8_t *) CO(lisp_hdr_ptr, lisp_hdr_len), inner_pkt_ptr,
            encap_pkt_len);
    free(inner_pkt_ptr);

    return (lisp_encap_pkt_ptr);
}

uint16_t get_IP_ID() {
    ip_id++;
    return (ip_id);
}

int ip_hdr_ver_to_len(int ih_ver)
{
    switch (ih_ver) {
    case IPVERSION:
        return(sizeof(struct ip));
    case IP6VERSION:
        return(sizeof(struct ip6_hdr));
        break;
    default:
        lmlog(LISP_LOG_DEBUG_2, "lbuf_pull_ip: couldn't read incoming "
                "Encapsulated Map-Request: IP header corrupted.");
        return(BAD);
    }
}

void *
pkt_pull_ipv4(lbuf_t *b)
{
    void *data = lbuf_data(b);
    return(lbuf_pull(b, sizeof(struct ip)));
}

void *
pkt_pull_ipv6(lbuf_t *b) {
    void *data = lbuf_data(b);
    return(lbuf_pull(b, sizeof(struct ip6_hdr)));
}

void *
pkt_pull_ip(lbuf_t *b)
{
    void *data;
    int ip_hdr_len;

    data = lbuf_data(b);
    ip_hdr_len = ip_hdr_ver_to_len(((struct ip *)data)->ip_v);

    if (ip_hdr_len < 1)
        return(NULL);

    return(lbuf_pull(b, ip_hdr_len));
}

void *
pkt_push_ipv4(lbuf_t *b, struct in_addr *src, struct in_addr *dst)
{
    struct ip *iph;
    iph = lbuf_push_uninit(b, sizeof(struct ip));
    lbuf_reset_ip(b);

    iph->ip_hl = 5;
    iph->ip_v = IPVERSION;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip) + lbuf_size(b));
    iph->ip_id = htons(get_IP_ID());
    iph->ip_off = 0; /* XXX Control packets can be fragmented  */
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_src.s_addr = src->s_addr;
    iph->ip_dst.s_addr = dst->s_addr;
    iph->ip_sum = 0;
    iph->ip_sum = ip_checksum((uint16_t *) iph, sizeof(struct ip));
    return(iph);
}

void *
pkt_push_ipv6(lbuf_t *b, struct in6_addr *src, struct in6_addr *dst)
{
    struct ip6_hdr *ip6h;
    ip6h = lbuf_push_uninit(b, sizeof(struct ip6_hdr));
    lbuf_reset_ip(b);

    ip6h->ip6_hops = 255;
    ip6h->ip6_vfc = (IP6VERSION << 4);
    ip6h->ip6_nxt = IPPROTO_UDP;
    ip6h->ip6_plen = htons(lbuf_size(b));
    memcpy(ip6h->ip6_src.s6_addr, src->s6_addr, sizeof(struct in6_addr));
    memcpy(ip6h->ip6_dst.s6_addr, dst->s6_addr, sizeof(struct in6_addr));
    return(ip6h);
}

void *
pkt_push_udp(lbuf_t *b, uint16_t sp, uint16_t dp) {
    struct udphdr *uh;
    int udp_len;

    udp_len = sizeof(struct udphdr) + lbuf_size(b);
    uh = lbuf_push_uninit(b, sizeof(struct udphdr));
    lbuf_reset_udp(b);

#ifdef BSD
    uh->uh_sport = htons(port_from);
    uh->uh_dport = htons(port_dest);
    uh->uh_ulen = htons(udp_payload_len);
    uh->uh_sum = 0;
#else
    uh->source = htons(sp);
    uh->dest = htons(dp);
    uh->len = htons(udp_len);
    uh->check = 0; /* to be filled in after IP is pushed */
#endif
    return(uh);
}

void *
pkt_push_ip(lbuf_t *b, ip_addr_t *src, ip_addr_t *dst)
{

    void *iph;
    if (ip_addr_afi(src) != ip_addr_afi(dst)) {
        lmlog(DBG_1, "src %s and dst % IP have different AFI! Discarding!",
                ip_addr_to_char(src), ip_addr_to_char(dst));
        return(NULL);
    }

    switch (ip_addr_afi(src)) {
    case AF_INET:
        iph = pkt_push_ipv4(b, ip_addr_get_addr(src), ip_addr_get_addr(dst));
        break;
    case AF_INET6:
        iph = pkt_push_ipv6(b, ip_addr_get_addr(src), ip_addr_get_addr(dst));
        break;
    }

    return(iph);
}

int
pkt_compute_udp_cksum(lbuf_t *b, int afi)
{
    uint16_t udpsum;
    struct udphdr *uh;

    uh = lbuf_udp(b);
    if ((udpsum = udp_checksum(uh, ntoh(uh->len), lbuf_ip(b), afi)) == -1) {
        return (BAD);
    }
    udpsum(uh) = udpsum;
    return(GOOD);
}

int
pkt_push_udp_and_ip(lbuf_t *b, uint16_t sp, uint16_t dp, ip_addr_t *sip,
        ip_addr_t *dip)
{
    pkt_push_udp(b, sp, dp);
    pkt_push_ip(b, sip, dip);
    pkt_compute_udp_cksum(b, ip_addr_afi(sip));
    return(GOOD);
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
