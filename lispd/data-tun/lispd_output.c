/*
 * lispd_output.c
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
 *    Florin Coras <fcoras@ac.upc.edu>
 */



#include "lispd_output.h"
#include <elibs/bob/lookup3.c>
#include <lispd_locator.h>
#include <lispd_mapping.h>
#include <packets.h>
#include <lispd_sockets.h>
#include <lispd_info_nat.h>
//#include <lispd_re.h>
#include <lisp_control.h>
#include <netinet/tcp.h>
#include "lispd_tun.h"


int lisp_output_multicast(uint8_t *pkt, int plen, lisp_addr_t *dst_eid);

/*
 * Fill the tuple with the 5 tuples of a packet: (SRC IP, DST IP, PROTOCOL, SRC PORT, DST PORT)
 */
int
extract_5_tuples_from_packet(uint8_t *packet, packet_tuple_t *tuple)
{
    /* TODO: would be nice for this to use ip_addr_t in the future */
    struct iphdr *iph = NULL;
    struct ip6_hdr *ip6h = NULL;
    struct udphdr *udp = NULL;
    struct tcphdr *tcp = NULL;
    int len = 0;

    iph = (struct iphdr *) packet;

    lisp_addr_set_afi(&tuple->src_addr, LM_AFI_IP);
    lisp_addr_set_afi(&tuple->dst_addr, LM_AFI_IP);

    switch (iph->version) {
    case 4:
        ip_addr_set_v4(lisp_addr_ip(&tuple->src_addr), &iph->saddr);
        ip_addr_set_v4(lisp_addr_ip(&tuple->dst_addr), &iph->daddr);
        tuple->protocol = iph->protocol;
        len = iph->ihl * 4;
        break;
    case 6:
        ip6h = (struct ip6_hdr *) packet;
        ip_addr_set_v6(lisp_addr_ip(&tuple->src_addr), &ip6h->ip6_src);
        ip_addr_set_v6(lisp_addr_ip(&tuple->dst_addr), &ip6h->ip6_dst);
        tuple->protocol = ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        len = sizeof(struct ip6_hdr);
        break;
    default:
        lmlog(DBG_2, "extract_5_tuples_from_packet: No ip packet identified");
        return (BAD);
    }

    if (tuple->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *) CO(packet, len);
        tuple->src_port = ntohs(udp->source);
        tuple->dst_port = ntohs(udp->dest);
    } else if (tuple->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *) CO(packet, len);
        tuple->src_port = ntohs(tcp->source);
        tuple->dst_port = ntohs(tcp->dest);
    } else { //If protocol is not TCP or UDP, ports of the tuple set to 0
        tuple->src_port = 0;
        tuple->dst_port = 0;
    }
    return (GOOD);
}


void add_ip_header (
        uint8_t         *position,
        uint8_t         *original_packet_position,
        int             ip_payload_length,
        lisp_addr_t     *src_addr,
        lisp_addr_t     *dst_addr)
{

    struct ip       *iph        = NULL;
    struct ip       *inner_iph  = NULL;
    struct ip6_hdr  *ip6h       = NULL;
    struct ip6_hdr  *inner_ip6h = NULL;

    int     ip_len  = 0;
    uint8_t tos     = 0;
    uint8_t ttl     = 0;


    inner_iph = (struct ip *) original_packet_position;

    /* We SHOULD copy ttl and tos fields from the inner packet to the encapsulated one */

    if (inner_iph->ip_v == 4 ) {
        tos = inner_iph->ip_tos;
        ttl = inner_iph->ip_ttl;

    } else {
        inner_ip6h = (struct ip6_hdr *) original_packet_position;
        ttl = inner_ip6h->ip6_hops; /* ttl = Hops limit in IPv6 */

        //tos = (inner_ip6h->ip6_flow & 0x0ff00000) >> 20;  /* 4 bits version, 8 bits Traffic Class, 20 bits flow-ID */
        tos = IPV6_GET_TC(*inner_ip6h); /* tos = Traffic class field in IPv6 */
    }

    /*
     * Construct and add the outer ip header
     */

    switch (ip_addr_afi(lisp_addr_ip(dst_addr))){
        case AF_INET:
            ip_len = ip_payload_length + sizeof(struct ip);
            iph = (struct ip *) position;

            iph->ip_v               = IPVERSION;
            iph->ip_hl              = 5; /* Minimal IPv4 header */ /*XXX Beware, hardcoded. Supposing no IP options */
            iph->ip_tos             = tos;
            iph->ip_len             = htons(ip_len);
            iph->ip_id              = htons(get_IP_ID());
            iph->ip_off             = htons(IP_DF);   /* Do not fragment flag. See 5.4.1 in LISP RFC (6830) */
            iph->ip_ttl             = ttl;
            iph->ip_p               = IPPROTO_UDP;
            iph->ip_sum             = 0; //Computed by the NIC (checksum offloading)
            lisp_addr_copy_to(&iph->ip_dst, dst_addr);
            lisp_addr_copy_to(&iph->ip_src, src_addr);
            break;
        case AF_INET6:
            ip6h = ( struct ip6_hdr *) position;

            IPV6_SET_VERSION(ip6h, 6);
            IPV6_SET_TC(ip6h,tos);
            IPV6_SET_FLOW_LABEL(ip6h,0);
            ip6h->ip6_plen = htons(ip_payload_length);
            ip6h->ip6_nxt = IPPROTO_UDP;
            ip6h->ip6_hops = ttl;
            lisp_addr_copy_to(&(ip6h->ip6_dst), dst_addr);
            lisp_addr_copy_to(&(ip6h->ip6_src), src_addr);

            break;
        default:
            break;
    }
}

void add_udp_header(
        uint8_t *position,
        int     length,
        int     src_port,
        int     dst_port)
{

    struct udphdr *udh  = NULL;


    /*
     * Construct and add the udp header
     */
    udh = ( struct udphdr * ) position;

    /*
     * Hash of inner header source/dest addr. This needs thought.
     */
    udh->source = htons ( src_port ); //arnatal TODO: Selec source port based on tuple?
    udh->dest =  htons ( dst_port );
    udh->len = htons ( sizeof ( struct udphdr ) + length );
    //udh->len = htons(sizeof(struct udphdr)); /* Wireshark detects this as error*/
    udh->check = 0; // SHOULD be 0 as in LISP ID
    /* With IPv6 this MUST be calculated (or disabled at all). Calculated later */

}

void add_lisp_header(
        uint8_t *position,
        int     iid)
{

    struct lisphdr  *lisphdr = NULL;

    lisphdr = (struct lisphdr *) position;

    lisphdr->instance_id = 0;
    //lisphdr->instance_id = iid; //XXX iid not supported yet

    /* arnatal TODO: support for the rest of values*/
    lisphdr->echo_nonce = 0;
    lisphdr->lsb = 0;
    lisphdr->lsb_bits = 0;
    lisphdr->map_version = 0;
    lisphdr->nonce[0] = 0;
    lisphdr->nonce[1] = 0;
    lisphdr->nonce[2] = 0;
    lisphdr->nonce_present = 0;
    lisphdr->rflags = 0;

}

int encapsulate_packet(
        uint8_t     *original_packet,
        int         original_packet_length,
        lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr,
        int         src_port,
        int         dst_port,
        int         iid,
        uint8_t     **encap_packet,
        int         *encap_packet_size)
{
    int         extra_headers_size  = 0;
    uint8_t     *new_packet         = NULL;
    struct      udphdr *udh         = NULL;
    int         encap_afi           = 0;

    int         iphdr_len           = 0;
    int         udphdr_len          = 0;
    int         lisphdr_len         = 0;

    encap_afi = ip_addr_afi(lisp_addr_ip(src_addr));

    switch (encap_afi){
    case AF_INET:
        iphdr_len = sizeof(struct iphdr);
        break;
    case AF_INET6:
        iphdr_len = sizeof(struct ip6_hdr);
        break;
    }

    udphdr_len = sizeof(struct udphdr);
    lisphdr_len = sizeof(struct lisphdr);

    extra_headers_size = iphdr_len + udphdr_len + lisphdr_len;

    new_packet = (uint8_t *) malloc (original_packet_length + extra_headers_size);
    if (new_packet == NULL){
        lmlog(LWRN, "encapsulate_packet: Unable to allocate memory for encapsulated packet: %s", strerror(errno));
        return (BAD);
    }

    memset(new_packet,0,original_packet_length+extra_headers_size);
    memcpy(new_packet + extra_headers_size, original_packet, original_packet_length);

    add_lisp_header(CO(new_packet, iphdr_len + udphdr_len), iid);
    add_udp_header(CO(new_packet, iphdr_len), original_packet_length+lisphdr_len, src_port, dst_port);

    add_ip_header(new_packet,
            original_packet,
            original_packet_length+lisphdr_len+udphdr_len,
            src_addr,
            dst_addr);

    /* UDP checksum mandatory for IPv6. Could be skipped if check disabled on receiver */
    udh = (struct udphdr *)(new_packet + iphdr_len);
    udh->check = udp_checksum(udh,ntohs(udh->len),new_packet,encap_afi);

    *encap_packet = new_packet;
    *encap_packet_size = extra_headers_size + original_packet_length;

    lmlog(DBG_3,"OUTPUT: Encap src: %s | Encap dst: %s\n",
            lisp_addr_to_char(src_addr),lisp_addr_to_char(dst_addr));

    return (GOOD);
}


int
get_afi_from_packet(uint8_t *packet)
{
    int afi = 0;
    struct iphdr *iph = NULL;

    iph = (struct iphdr *) packet;

    switch (iph->version) {
    case 4:
        afi = AF_INET;
        break;
    case 6:
        afi = AF_INET6;
        break;
    default:
        afi = AF_UNSPEC;
    }

    return (afi);
}


int
forward_native(uint8_t *pbuf, int plen)
{
    int ret = 0;
    int output_socket = 0;
    int packet_afi = 0;

    packet_afi = get_afi_from_packet(pbuf);
    output_socket = get_default_output_socket(packet_afi);

    if (output_socket == -1) {
        lmlog(DBG_2, "fordward_native: No output interface for afi %d",
                packet_afi);
        return (BAD);
    }

    lmlog(DBG_3, "Fordwarding native for destination %s",
            get_char_from_lisp_addr_t(extract_dst_addr_from_packet(pbuf)));

    ret = send_packet(output_socket, pbuf, plen);
    return (ret);
}


lisp_addr_t
extract_dst_addr_from_packet(uint8_t *packet)
{
    lisp_addr_t addr = { .afi = AF_UNSPEC, .lafi = LM_AFI_IP };
    struct iphdr *iph = NULL;
    struct ip6_hdr *ip6h = NULL;

    iph = (struct iphdr *) packet;

    switch (iph->version) {
    case 4:
        ip_addr_set_v4(lisp_addr_ip(&addr), &iph->daddr);
        break;
    case 6:
        ip_addr_set_v6(lisp_addr_ip(&addr), &ip6h->ip6_dst);
        break;
    default:
        lmlog(DBG_3, "extract_dst_addr_from_packet: uknown ip version %d",
                iph->version);
        break;
    }

    return (addr);
}



int
is_lisp_packet(uint8_t *packet, int packet_length)
{

    struct iphdr        *iph        = NULL;
    struct ip6_hdr      *ip6h       = NULL;
    int                 ipXh_len    = 0;
    int                 lvl4proto   = 0;
    struct udphdr       *udh        = NULL;

    iph = (struct iphdr *) packet;

    if (iph->version == 4 ) {
        lvl4proto = iph->protocol;
        ipXh_len = sizeof(struct iphdr);

    } else {
        ip6h = (struct ip6_hdr *) packet;
        lvl4proto = ip6h->ip6_nxt; //arnatal XXX: Supposing no extra headers
        ipXh_len = sizeof(struct ip6_hdr);

    }
    /*
     * Don't encapsulate LISP messages
     */

    if (lvl4proto != IPPROTO_UDP) {
        return (FALSE);
    }

    udh = (struct udphdr *)(packet + ipXh_len);

    /*
     * If either of the udp ports are the control port or data, allow
     * to go out natively. This is a quick way around the
     * route filter which rewrites the EID as the source address.
     */
    if ((ntohs(udh->dest) != LISP_CONTROL_PORT) &&
            (ntohs(udh->source) != LISP_CONTROL_PORT) &&
            (ntohs(udh->source) != LISP_DATA_PORT) &&
            (ntohs(udh->dest) != LISP_DATA_PORT) ) {

        return (FALSE);
    }

    return (TRUE);
}


int
lisp_output_multicast(uint8_t *pkt, int plen, lisp_addr_t *dst_eid)
{
    glist_t *or_list = NULL;
    uint8_t *encap_packet = NULL;
    lisp_addr_t *src_rloc = NULL;
    lisp_addr_t *dst_rloc = NULL;
    locator_t *locator = NULL;
    glist_entry_t *it = NULL;
    int encap_plen = 0;
    int osock = 0;

    /* get the output RLOC list */
    or_list = re_get_orlist(dst_eid);
    if (!or_list)
        return(BAD);

    glist_for_each_entry(it, or_list){
        /* TODO: take locator out, just send mcaddr and out socket */
        locator =  (locator_t *)glist_entry_data(it);
        src_rloc = lcaf_mc_get_src(lisp_addr_get_lcaf(locator_addr(locator)));
        dst_rloc = lcaf_mc_get_grp(lisp_addr_get_lcaf(locator_addr(locator)));
        encapsulate_packet(pkt,
                plen,
                src_rloc,
                dst_rloc,
                LISP_DATA_PORT, //TODO: UDP src port based on hash?
                LISP_DATA_PORT,
                //entry->mapping->iid, //XXX iid not supported yet
                0,
                &encap_packet,
                &encap_plen);

        osock = iface_socket(get_interface_with_address(src_rloc), lisp_addr_ip_afi(src_rloc));
        send_packet(osock, encap_packet, encap_plen);

        free (encap_packet);
    }

    glist_destroy(or_list);

    return (GOOD);
}




int
lisp_output_unicast(uint8_t *pkt, int plen, packet_tuple_t *tuple)
{
    fwd_entry_t *fwd_entry = NULL;
    uint8_t *encap_pkt = NULL;
    int encap_plen = 0, dafi;
    iface_t *iface;
    int osock;

    fwd_entry = ctrl_get_forwarding_entry(tuple);

    /* Packets with no/negative map cache entry AND no PETR
     * OR packets with missing src or dst RLOCs
     * forward them natively */
    if (!fwd_entry || (!fwd_entry->srloc && !fwd_entry->drloc)) {
        return(forward_native(pkt, plen));
    }

    dafi = lisp_addr_ip_afi(fwd_entry->drloc);

    /* if no srloc, choose default */
    if (!fwd_entry->srloc) {
        fwd_entry->srloc = get_default_output_address(dafi);
        if (!fwd_entry->srloc) {
            free(fwd_entry);
            lmlog(DBG_1, "Failed to set source RLOC with afi %d", dafi);
            return(BAD);
        }
    }

    iface = get_interface_with_address(fwd_entry->srloc);
    osock = iface_socket(iface, dafi);

    encapsulate_packet(pkt, plen,
            fwd_entry->srloc, fwd_entry->drloc,
            LISP_DATA_PORT,
            LISP_DATA_PORT,
            0, &encap_pkt, &encap_plen);

    send_packet(osock, encap_pkt, encap_plen);

    free(encap_pkt);
    free(fwd_entry);
    return (GOOD);
}

int
tuple_get_dst_lisp_addr(packet_tuple_t *tuple, lisp_addr_t *addr){

    /* TODO this really needs optimization */

    uint16_t    plen;
    lcaf_addr_t *lcaf;

    if (ip_addr_is_multicast(lisp_addr_ip(&tuple->dst_addr))) {
        if (lisp_addr_afi(&tuple->src_addr) != LM_AFI_IP
            || lisp_addr_afi(&tuple->src_addr) != LM_AFI_IP) {
           lmlog(DBG_1, "tuple_get_dst_lisp_addr: (S,G) (%s, %s)pair is not "
                   "of IP syntax!", lisp_addr_to_char(&tuple->src_addr),
                   lisp_addr_to_char(&tuple->dst_addr));
           return(BAD);
        }

        lisp_addr_set_afi(addr, LM_AFI_LCAF);
        plen = ip_afi_to_default_mask(lisp_addr_ip_afi(tuple->dst_addr));
        lcaf = lisp_addr_get_lcaf(addr);
        lcaf_addr_set_mc(lcaf, &tuple.src_addr, &tuple.dst_addr, plen, plen, 0);

    } else {
        lisp_addr_set_afi(addr, LM_AFI_IP);
        ip_addr_copy(lisp_addr_ip(addr), lisp_addr_ip(&tuple->dst_addr));
    }

    return(GOOD);
}

int
lisp_output(uint8_t *pkt, int plen)
{
    packet_tuple_t tuple;
    lisp_addr_t *daddr = NULL;

    /* fcoras TODO: should use get_dst_lisp_addr instead of tuple */
    if (extract_5_tuples_from_packet(pkt, &tuple) != GOOD)
        return (BAD);

    lmlog(DBG_3,"OUTPUT: Orig src: %s | Orig dst: %s",
            lisp_addr_to_char(&tuple.src_addr),
            lisp_addr_to_char(&tuple.dst_addr));


    /* If already LISP packet, do not encapsulate again */
    if (is_lisp_packet(pkt, plen)) {
        return (forward_native(pkt, plen));
    }

    /* convert tuple to lisp_addr_t, to be used for map-cache lookup
     * TODO: should be a tad more efficient  */
    daddr = lisp_addr_new();
    if (tuple_get_dst_lisp_addr(&tuple, daddr) != GOOD) {
        lmlog(LWRN, "lisp_output: Unable to determine "
                "destination address from tuple: src %s dst %s",
                lisp_addr_to_char(&tuple.src_addr),
                lisp_addr_to_char(&tuple.dst_addr));
        return(BAD);
    }

    switch (lisp_addr_afi(daddr)) {
        case LM_AFI_IP:
        case LM_AFI_IP6:
            lisp_output_unicast(pkt, plen, &tuple);
            break;
        case LM_AFI_LCAF:
            if(lisp_addr_lcaf_get_type(daddr) == LCAF_MCAST_INFO) {
                lisp_output_multicast(pkt, plen, daddr);
            }
            break;
        default:
            lmlog(LWRN, "lisp_output: Unable to forward anything but IP "
                    "and mcast packets!");
            break;
    }

    lisp_addr_del(daddr);

    return(GOOD);
}

int
recv_output_packet(struct sock *sl)
{
    int nread = 0;

    nread = read(sl->fd, tun_receive_buf, TUN_RECEIVE_SIZE);
    if (nread == 0) {
        lmlog(LWRN, "OUTPUT: Error while reading from tun:%s",
                strerror(errno));
        return (BAD);
    }

    lisp_output(tun_receive_buf, nread);
    return (GOOD);
}


