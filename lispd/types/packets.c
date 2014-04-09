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

/*
 * Generate IP header. Returns the poninter to the transport header
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

int ip_hdr_ver_to_len(int ih_ver) {
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

void *lbuf_pull_ipv4(struct lbuf *b) {
    void *data = lbuf_data(b);
    return(lbuf_pull(b, sizeof(struct ip)));
}

void *lbuf_pull_ipv6(struct lbuf *b) {
    void *data = lbuf_data(b);
    return(lbuf_pull(b, sizeof(struct ip6_hdr)));
}

void *lbuf_pull_ip(struct lbuf *b) {
    void *data;
    int ip_hdr_len;

    data = lbuf_data(b);
    ip_hdr_len = ip_hdr_ver_to_len(((struct ip *)data)->ip_v);

    if (ip_hdr_len < 1)
        return(NULL);

    return(lbuf_pull(b, ip_hdr_len));
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
