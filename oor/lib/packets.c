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

#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "packets.h"
#include "../oor_external.h"
#include "sockets.h"
#include "../liblisp/lisp_address.h"
#include "cksum.h"
#include "mem_util.h"
#include "oor_log.h"

/* needed for hashword */
#include "../elibs/bob/lookup3.c"


uint16_t ip_id = 0;

/* Returns IP ID for the packet */
static inline uint16_t
get_IP_ID()
{
    ip_id++;
    return (ip_id);
}


void *
pkt_pull_ipv4(lbuf_t *b)
{
    return(lbuf_pull(b, sizeof(struct ip)));
}

void *
pkt_pull_ipv6(lbuf_t *b)
{
    return(lbuf_pull(b, sizeof(struct ip6_hdr)));
}

void *
pkt_pull_ip(lbuf_t *b)
{
    void *data;
    int ip_hdr_len;

    data = lbuf_data(b);
    ip_hdr_len = ip_hdr_ver_to_len(((struct ip *)data)->ip_v);

    if (ip_hdr_len < 1) {
        return(NULL);
    }
    return(lbuf_pull(b, ip_hdr_len));
}

struct udphdr *
pkt_pull_udp(lbuf_t *b)
{
    struct udphdr *udph;
    udph = lbuf_data(b);

    /* Jump the UDP header */
    lbuf_pull(b, sizeof(struct udphdr));
    return(udph);
}

void *
pkt_push_udp(lbuf_t *b, uint16_t sp, uint16_t dp)
{
    struct udphdr *uh;
    int udp_len;

    udp_len = sizeof(struct udphdr) + lbuf_size(b);
    uh = lbuf_push_uninit(b, sizeof(struct udphdr));

    udpsport(uh) = htons(sp);
    udpdport(uh) = htons(dp);
    udplen(uh) = htons(udp_len);
    udpsum(uh) = 0; /* to be filled in after IP is pushed */

    return(uh);
}

struct ip *
pkt_push_ipv4(lbuf_t *b, struct in_addr *src, struct in_addr *dst, int proto)
{
    struct ip *iph;
    iph = lbuf_push_uninit(b, sizeof(struct ip));

    /* XXX: assume no other headers */
    iph->ip_hl = 5;
    iph->ip_v = IPVERSION;
    iph->ip_tos = 0;
    iph->ip_len = htons(lbuf_size(b));
    iph->ip_id = htons(get_IP_ID());
    /* Do not fragment flag. See 5.4.1 in LISP RFC (6830)
     * TODO: decide if we allow fragments in case of control */
    iph->ip_off = htons(IP_DF);
    iph->ip_ttl = 255;
    iph->ip_p = proto;
    iph->ip_src.s_addr = src->s_addr;
    iph->ip_dst.s_addr = dst->s_addr;
    /* FIXME: ip checksum could be offloaded to NIC*/
    /* iph->ip_sum = 0; */
    iph->ip_sum = ip_checksum((uint16_t *) iph, sizeof(struct ip));
    return(iph);
}

struct ip6_hdr *
pkt_push_ipv6(lbuf_t *b, struct in6_addr *src, struct in6_addr *dst, int proto)
{
    struct ip6_hdr *ip6h;
    int len;

    len = lbuf_size(b);
    ip6h = lbuf_push_uninit(b, sizeof(struct ip6_hdr));

    ip6h->ip6_hops = 255;
    ip6h->ip6_vfc = (IP6VERSION << 4);
    ip6h->ip6_nxt = proto;
    ip6h->ip6_plen = htons(len);
    memcpy(ip6h->ip6_src.s6_addr, src->s6_addr, sizeof(struct in6_addr));
    memcpy(ip6h->ip6_dst.s6_addr, dst->s6_addr, sizeof(struct in6_addr));
    return(ip6h);
}

void *
pkt_push_ip(lbuf_t *b, ip_addr_t *src, ip_addr_t *dst, int proto)
{
    void *iph = NULL;
    if (ip_addr_afi(src) != ip_addr_afi(dst)) {
        OOR_LOG(LDBG_1, "src %s and dst %s IP have different AFI! Discarding!",
                ip_addr_to_char(src), ip_addr_to_char(dst));
        return(NULL);
    }

    switch (ip_addr_afi(src)) {
    case AF_INET:
        iph = pkt_push_ipv4(b, ip_addr_get_addr(src), ip_addr_get_addr(dst),
                proto);
        break;
    case AF_INET6:
        iph = pkt_push_ipv6(b, ip_addr_get_addr(src), ip_addr_get_addr(dst),
                proto);
        break;
    }

    return(iph);
}

int
pkt_push_udp_and_ip(lbuf_t *b, uint16_t sp, uint16_t dp, ip_addr_t *sip,
        ip_addr_t *dip)
{
    uint16_t udpsum;
    struct udphdr *uh;

    if (pkt_push_udp(b, sp, dp) == NULL) {
        OOR_LOG(LDBG_1, "Failed to push UDP header! Discarding");
        return(BAD);
    }

    lbuf_reset_udp(b);

    if (pkt_push_ip(b, sip, dip, IPPROTO_UDP) == NULL) {
        OOR_LOG(LDBG_1, "Failed to push IP header! Discarding");
        return(BAD);
    }

    lbuf_reset_ip(b);

    uh = lbuf_udp(b);
    udpsum = udp_checksum(uh, ntohs(udplen(uh)), lbuf_ip(b), ip_addr_afi(sip));
    if (udpsum == -1) {
        OOR_LOG(LDBG_1, "Failed UDP checksum! Discarding");
        return (BAD);
    }
    udpsum(uh) = udpsum;
    return(GOOD);
}

/* Fill the tuple with the 5 tuples of a packet:
 * (SRC IP, DST IP, PROTOCOL, SRC PORT, DST PORT) */
int
pkt_parse_5_tuple(lbuf_t *b, packet_tuple_t *tuple)
{
    struct iphdr *iph = NULL;
    struct ip6_hdr *ip6h = NULL;
    struct udphdr *udp = NULL;
    struct tcphdr *tcp = NULL;
    lbuf_t packet = *b;

    iph = lbuf_ip(&packet);

    lisp_addr_set_lafi(&tuple->src_addr, LM_AFI_IP);
    lisp_addr_set_lafi(&tuple->dst_addr, LM_AFI_IP);

    switch (iph->version) {
    case 4:
        lisp_addr_ip_init(&tuple->src_addr, &iph->saddr, AF_INET);
        lisp_addr_ip_init(&tuple->dst_addr, &iph->daddr, AF_INET);
        tuple->protocol = iph->protocol;
        lbuf_pull(&packet, iph->ihl * 4);
        break;
    case 6:
        ip6h = (struct ip6_hdr *)iph;
        lisp_addr_ip_init(&tuple->src_addr, &ip6h->ip6_src, AF_INET6);
        lisp_addr_ip_init(&tuple->dst_addr, &ip6h->ip6_dst, AF_INET6);
        /* XXX: assuming no extra headers */
        tuple->protocol = ip6h->ip6_nxt;
        lbuf_pull(&packet, sizeof(struct ip6_hdr));
        break;
    default:
        OOR_LOG(LDBG_2, "pkt_parse_5_tuple: Not an IP packet!");
        return (BAD);
    }

    if (tuple->protocol == IPPROTO_UDP) {
        udp = lbuf_data(&packet);
        tuple->src_port = ntohs(udpsport(udp));
        tuple->dst_port = ntohs(udpdport(udp));
    } else if (tuple->protocol == IPPROTO_TCP) {
        tcp = lbuf_data(&packet);
        tuple->src_port = ntohs(tcpsport(tcp));
        tuple->dst_port = ntohs(tcpdport(tcp));
    } else {
        /* If protocol is not TCP or UDP, ports of the tuple set to 0 */
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }
    return (GOOD);
}


/* Calculate the hash of the 5 tuples of a packet */
uint32_t
pkt_tuple_hash(packet_tuple_t *tuple)
{
    int hash = 0;
    int len = 0;
    int port = tuple->src_port;
    uint32_t *tuples = NULL;

    port = port + ((int)tuple->dst_port << 16);
    switch (lisp_addr_ip_afi(&tuple->src_addr)){
    case AF_INET:
        /* 1 integer src_addr
         * + 1 integer dst_adr
         * + 1 integer (ports)
         * + 1 integer protocol
         * + 1 iid*/
        len = 5;
        tuples = xmalloc(len * sizeof(uint32_t));
        lisp_addr_copy_to(&tuples[0], &tuple->src_addr);
        lisp_addr_copy_to(&tuples[1], &tuple->dst_addr);
        tuples[2] = port;
        tuples[3] = tuple->protocol;
        tuples[4] = tuple->iid;
        break;
    case AF_INET6:
        /* 4 integer src_addr
         * + 4 integer dst_adr
         * + 1 integer (ports)
         * + 1 integer protocol
         * + 1 iid */
        len = 11;
        tuples = xmalloc(len * sizeof(uint32_t));
        lisp_addr_copy_to(&tuples[0], &tuple->src_addr);
        lisp_addr_copy_to(&tuples[4], &tuple->dst_addr);
        tuples[8] = port;
        tuples[9] = tuple->protocol;
        tuples[10] = tuple->iid;
        break;
    }

    /* XXX: why 2013 used as initial value? */
    hash = hashword(tuples, len, 2013);
    free(tuples);
    return (hash);
}

int
pkt_tuple_cmp(packet_tuple_t *t1, packet_tuple_t *t2)
{
    return(t1->src_port == t2->src_port
           && t1->dst_port == t2->dst_port
           && (lisp_addr_cmp(&t1->src_addr, &t2->src_addr) == 0)
           && (lisp_addr_cmp(&t1->dst_addr, &t2->dst_addr) == 0)
           && t1->iid == t2->iid);
}

packet_tuple_t *
pkt_tuple_clone(packet_tuple_t *tpl)
{
    packet_tuple_t *cpy = xzalloc(sizeof(packet_tuple_t));
    cpy->src_port = tpl->src_port;
    cpy->dst_port = tpl->dst_port;
    cpy->protocol = tpl->protocol;
    lisp_addr_copy(&cpy->src_addr, &tpl->src_addr);
    lisp_addr_copy(&cpy->dst_addr, &tpl->dst_addr);
    cpy->iid = tpl->iid;
    return(cpy);
}

void
pkt_tuple_del(packet_tuple_t *tpl)
{
    lisp_addr_dealloc(&tpl->dst_addr);
    lisp_addr_dealloc(&tpl->src_addr);
    free(tpl);
    tpl = NULL;
}

char *
pkt_tuple_to_char(packet_tuple_t *tpl)
{
    static char buf[2][200];
    static int i=0;
    /* hack to allow more than one locator per line */
    i++; i = i % 2;
    *buf[i] = '\0';
    if (tpl == NULL){
        sprintf(buf[i], "_NULL_");
        return (buf[i]);
    }
    sprintf(buf[i], "Src_addr: %s, ", lisp_addr_to_char(&tpl->src_addr));
    sprintf(buf[i] + strlen(buf[i]), "Dst addr: %s, ", lisp_addr_to_char(&tpl->dst_addr));
    sprintf(buf[i] + strlen(buf[i]), "Proto: ");

    switch (tpl->protocol){
    case IPPROTO_UDP:
        sprintf(buf[i] + strlen(buf[i]), "UDP, ");
        break;
    case IPPROTO_TCP:
        sprintf(buf[i] + strlen(buf[i]), "TCP, ");
        break;
    case IPPROTO_ICMP:
        sprintf(buf[i] + strlen(buf[i]), "ICMP, ");
        break;
    default:
        sprintf(buf[i] + strlen(buf[i]), "%d, ",tpl->protocol);
        break;
    }
    sprintf(buf[i] + strlen(buf[i]), "Src Port: %d, ",tpl->src_port);
    sprintf(buf[i] + strlen(buf[i]), "Dst Port: %d\n",tpl->dst_port);
    sprintf(buf[i] + strlen(buf[i]), "IID|VNI: %d\n",tpl->iid);

    return (buf[i]);
}


int
ip_hdr_set_ttl_and_tos(struct iphdr *iph, int ttl, int tos)
{
    struct ip6_hdr *ip6h;

    if (iph->version == 4) {
        /*XXX It seems that there is a bug in uClibc that causes ttl=0 in
         * OpenWRT. This is a quick workaround */
        if (ttl != 0) {
            iph->ttl = ttl;
        }

        iph->tos = tos;

        /* We need to recompute the checksum since we have changed the TTL
         * and TOS header fields.
         *
         * New checksum must be computed with the checksum header field
         * with 0s */
        iph->check = 0;
        iph->check = ip_checksum((uint16_t*) iph, sizeof(struct iphdr));

    } else if (iph->version == 6) {
        ip6h = (struct ip6_hdr *) iph;

        /*XXX It seems that there is a bug in uClibc that causes ttl=0 in
         * OpenWRT. This is a quick workaround */
        if (ttl != 0) {
            /* ttl = Hops limit in IPv6 */
            ip6h->ip6_hops = ttl;
        }

        /* tos = Traffic class field in IPv6 */
        IPV6_SET_TC(ip6h, tos);
    } else {
        return(BAD);
    }

    return(GOOD);
}

int
ip_hdr_ttl_and_tos(struct iphdr *iph, int *ttl, int *tos)
{
    struct ip6_hdr *ip6h;

    switch (iph->version) {
    case 4:
        *tos = iph->tos;
        *ttl = iph->ttl;
        return(GOOD);
    case 6:
        ip6h = (struct ip6_hdr *) iph;
        *ttl = ip6h->ip6_hops;
        *tos = IPV6_GET_TC(*ip6h);
        return(GOOD);
    default:
        return(BAD);
    }
}


/*
 * Generate IP header. Returns the pointer to the transport header
 */

struct udphdr *
build_ip_header(uint8_t *cur_ptr, lisp_addr_t *src_addr, lisp_addr_t *dst_addr,
        int ip_len)
{
    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct udphdr *udph;

    switch (lisp_addr_ip_afi(src_addr)) {
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
        iph->ip_src.s_addr = ip_addr_get_v4(lisp_addr_ip(src_addr))->s_addr;
        iph->ip_dst.s_addr = ip_addr_get_v4(lisp_addr_ip(dst_addr))->s_addr;
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
        memcpy(ip6h->ip6_src.s6_addr,ip_addr_get_v6(lisp_addr_ip(src_addr)),
                sizeof(struct in6_addr));
        memcpy(ip6h->ip6_dst.s6_addr,ip_addr_get_v6(lisp_addr_ip(dst_addr)),
                sizeof(struct in6_addr));
        udph = (struct udphdr *) CO(ip6h, sizeof(struct ip6_hdr));
        break;
    default:
        OOR_LOG(LDBG_2,
                "build_ip_header: Uknown AFI of the source address: %d",
                lisp_addr_ip_afi(src_addr));
        return (NULL);
    }
    return (udph);
}

/*
 * Generates an IP header and an UDP header
 * and copies the original packet at the end
 */

uint8_t *
build_ip_udp_pcket(uint8_t *orig_pkt, int orig_pkt_len,lisp_addr_t *addr_from,
        lisp_addr_t *addr_dest, int port_from,int port_dest, int *encap_pkt_len)
{
    uint8_t *encap_pkt;
    void *iph_ptr;
    struct udphdr *udph_ptr;
    int ip_hdr_len;
    int udp_hdr_len;
    int udp_hdr_and_payload_len;
    uint16_t udpsum;

    if (lisp_addr_ip_afi(addr_from) != lisp_addr_ip_afi(addr_dest)) {
        OOR_LOG(LDBG_2,
                "add_ip_udp_header: Different AFI addresses %d (%s) and %d (%s)",
                lisp_addr_ip_afi(addr_from), lisp_addr_to_char(addr_from),
                lisp_addr_ip_afi(addr_dest), lisp_addr_to_char(addr_dest));
        return (NULL);
    }

    if ((lisp_addr_ip_afi(addr_from) != AF_INET)
            && (lisp_addr_ip_afi(addr_from) != AF_INET6)) {
        OOR_LOG(LDBG_2, "add_ip_udp_header: Unknown AFI %d",
                lisp_addr_ip_afi(addr_from));
        return (NULL);
    }

    /* Headers lengths */

    ip_hdr_len = ip_sock_afi_to_hdr_len(lisp_addr_ip_afi(addr_from));

    udp_hdr_len = sizeof(struct udphdr);

    udp_hdr_and_payload_len = udp_hdr_len + orig_pkt_len;

    /* Assign memory for the original packet plus the new headers */

    *encap_pkt_len = ip_hdr_len + udp_hdr_len + orig_pkt_len;

    if ((encap_pkt = (uint8_t *) malloc(*encap_pkt_len)) == NULL) {
        OOR_LOG(LDBG_2,
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
        OOR_LOG(LDBG_2,
                "add_ip_udp_header: Couldn't build the inner ip header");
        free(encap_pkt);
        return (NULL);
    }

    /* UDP header */
    udpsport(udph_ptr) = htons(port_from);
    udpdport(udph_ptr) = htons(port_dest);
    udplen(udph_ptr) = htons(udp_hdr_and_payload_len);
    udpsum(udph_ptr) = 0;


    /* Copy original packet after the headers */
    memcpy(CO(udph_ptr, udp_hdr_len), orig_pkt, orig_pkt_len);

    /*
     * Now compute the headers checksums
     */

    if ((udpsum = udp_checksum(udph_ptr, udp_hdr_and_payload_len, iph_ptr,
            lisp_addr_ip_afi(addr_from))) == -1) {
        free(encap_pkt);
        return (NULL);
    }
    udpsum(udph_ptr) = udpsum;

    return (encap_pkt);

}

char *
ip_src_and_dst_to_char(struct iphdr *iph, char *fmt)
{
    static char buf[150];
    struct ip6_hdr *ip6h;

    *buf = '\0';
    switch (iph->version) {
    case 4:
        sprintf(buf, fmt, ip_to_char(&iph->saddr, AF_INET),
                ip_to_char(&iph->daddr, AF_INET));
        break;
    case 6:
        ip6h = (struct ip6_hdr *)iph;
        sprintf(buf, fmt, ip_to_char(&ip6h->ip6_src, AF_INET6),
                ip_to_char(&ip6h->ip6_dst, AF_INET6));
        break;
    default:
        sprintf(buf, fmt, "NOT IP", "NOT IP");
    }

    return(buf);
}

void
pkt_add_uint32_in_3bytes (uint8_t *pkt, uint32_t val)
{
    uint8_t *val_bytes;
    uint32_t net_val = htonl(val);
    val_bytes = (uint8_t *)&net_val;
    pkt[0] = val_bytes[1];
    pkt[1] = val_bytes[2];
    pkt[2] = val_bytes[3];
}

uint32_t
pkt_get_uint32_from_3bytes (uint8_t *pkt)
{
    return (((uint32_t) pkt[0]) << 16) | (((uint32_t) pkt[1]) << 8) | ((uint32_t) pkt[2]);
}
