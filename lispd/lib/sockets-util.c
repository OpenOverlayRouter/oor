/*
 * sockets-util.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
 * All rights reserved.
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

#include <errno.h>
#include <unistd.h>
#include <netdb.h>

#include "sockets-util.h"
#include "lmlog.h"
//#include <defs.h>

int
open_device_bound_raw_socket(char *device, int afi)
{
    int device_len = 0;
    int s = 0;
    int on = 1;

    switch (afi) {
    case AF_INET:
        if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
            lmlog(LERR, "open_device_bound_raw_socket: socket creation failed"
                    " %s", strerror(errno));
            return (BAD);
        }
        break;
    case AF_INET6:
        if ((s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
            lmlog(LERR, "open_device_bound_raw_socket: socket creation failed"
                    " %s", strerror(errno));
            return (BAD);
        }
        break;
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) == -1) {
        lmlog(LWRN, "open_device_bound_raw_socket: socket option reuse %s",
                strerror(errno));
        close(s);
        return (BAD);
    }

    /* XXX: binding might not work on all devices */
    device_len = strlen(device);
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, device, device_len) == -1) {
        lmlog(LWRN, "open_device_binded_raw_socket: socket option device %s",
                strerror(errno));
        close(s);
        return (BAD);
    }

    lmlog(DBG_2, "open_device_binded_raw_socket: open socket %d in interface"
            " %s with afi: %d", s, device, afi);

    return s;

}

int
open_raw_socket(int afi)
{

    struct protoent *proto = NULL;
    int sock = 0;
    int tr = 1;

    if ((proto = getprotobyname("UDP")) == NULL) {
        lmlog(LERR, "open_raw_socket: getprotobyname: %s", strerror(errno));
        return (BAD);
    }

    /*
     *  build the ipv4_data_input_fd, and make the port reusable
     */

    if ((sock = socket(afi, SOCK_RAW, proto->p_proto)) < 0) {
        lmlog(LERR, "open_raw_input_socket: socket: %s", strerror(errno));
        return (BAD);
    }
    lmlog(DBG_3, "open_raw_socket: socket at creation: %d\n", sock);

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1) {
        lmlog(LWRN,"open_raw_socket: setsockopt SO_REUSEADDR: %s",
                strerror(errno));
        close(sock);
        return (BAD);
    }

    return (sock);
}

int
open_udp_socket(int afi)
{
    struct protoent *proto = NULL;
    int sock = 0;
    int tr = 1;

    if ((proto = getprotobyname("UDP")) == NULL) {
        lmlog(LERR, "open_udp_socket: getprotobyname: %s", strerror(errno));
        return (BAD);
    }

    /* build the ipv4_data_input_fd, and make the port reusable */
    if ((sock = socket(afi, SOCK_DGRAM, proto->p_proto)) < 0) {
        lmlog(LERR, "open_udp_socket: socket: %s", strerror(errno));
        return (BAD);
    }
    lmlog(DBG_3, "open_udp_socket: socket at creation: %d\n", sock);

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1) {
        lmlog(LWRN, "open_udp_socket: setsockopt SO_REUSEADDR: %s",
                strerror(errno));

        return (BAD);
    }

    return sock;
}

int
bind_socket_address(int sock, lisp_addr_t *addr)
{
    int result = TRUE;
    struct sockaddr *src_addr = NULL;
    int src_addr_len = 0;
    struct sockaddr_in src_addr4;
    struct sockaddr_in6 src_addr6;

    memset((char *) &src_addr, 0, sizeof(src_addr));

    switch (addr->afi) {
    case AF_INET:
        memset((char *) &src_addr4, 0, sizeof(src_addr4));
        src_addr4.sin_family = AF_INET;
        src_addr4.sin_addr.s_addr = addr->address.ip.s_addr;

        src_addr = (struct sockaddr *) &src_addr4;
        src_addr_len = sizeof(struct sockaddr_in);

        break;
    case AF_INET6:
        memset((char *) &src_addr6, 0, sizeof(src_addr6));
        src_addr6.sin6_family = AF_INET6;
        memcpy(&(src_addr6.sin6_addr), &(addr->address.ipv6),
                sizeof(struct in6_addr));

        src_addr = (struct sockaddr *) &src_addr6;
        src_addr_len = sizeof(struct sockaddr_in6);

        break;
    }

    if (bind(sock, src_addr, src_addr_len) != 0) {
        lmlog(LWRN, "bind_socket_src_address: %s", strerror(errno));
        result = BAD;
    }
    return (result);
}

int
bind_socket(int sock, int afi, int port)
{
    struct sockaddr_in sock_addr_v4;
    struct sockaddr_in6 sock_addr_v6;
    struct sockaddr *sock_addr = NULL;
    int sock_addr_len = 0;

    switch (afi) {
    case AF_INET:
        memset(&sock_addr_v4, 0, sizeof(sock_addr_v4)); /* be sure */
        sock_addr_v4.sin_port = htons(port);
        sock_addr_v4.sin_family = AF_INET;
        sock_addr_v4.sin_addr.s_addr = INADDR_ANY;

        sock_addr = (struct sockaddr *) &sock_addr_v4;
        sock_addr_len = sizeof(sock_addr_v4);
        break;

    case AF_INET6:
        memset(&sock_addr_v6, 0, sizeof(sock_addr_v6)); /* be sure */
        sock_addr_v6.sin6_family = AF_INET6;
        sock_addr_v6.sin6_port = htons(port);
        sock_addr_v6.sin6_addr = in6addr_any;

        sock_addr = (struct sockaddr *) &sock_addr_v6;
        sock_addr_len = sizeof(sock_addr_v6);
        break;

    default:
        return BAD;
    }

    if (bind(sock, sock_addr, sock_addr_len) == -1) {
        lmlog(LWRN, "bind input socket: %s", strerror(errno));
        return (BAD);
    }

    return (sock);
}

/*
 * Sends a raw packet through the specified interface
 * XXX: kept for backwards compatibiliy. Should be removed
 * in the future
 */
int send_packet (
        int     sock,
        uint8_t *packet,
        int     packet_length)
{
    struct sockaddr *dst_addr = NULL;
    int dst_addr_len = 0;
    struct sockaddr_in dst_addr4;
    struct sockaddr_in6 dst_addr6;
    ip_addr_t pkt_src_addr;
    ip_addr_t pkt_dst_addr;
    struct iphdr *iph = NULL;
    struct ip6_hdr *ip6h = NULL;
    int nbytes = 0;


    memset((char *) &dst_addr, 0, sizeof(dst_addr));

    iph = (struct iphdr *) packet;

    switch (iph->version) {
    case 4:
        memset((char *) &dst_addr4, 0, sizeof(dst_addr4));
        dst_addr4.sin_family = AF_INET;
        dst_addr4.sin_addr.s_addr = iph->daddr;

        dst_addr = (struct sockaddr *) &dst_addr4;
        dst_addr_len = sizeof(struct sockaddr_in);

        break;
    case 6:
        ip6h = (struct ip6_hdr *) packet;

        memset((char *) &dst_addr6, 0, sizeof(dst_addr6));
        dst_addr6.sin6_family = AF_INET6;
        dst_addr6.sin6_addr = ip6h->ip6_dst;

        dst_addr = (struct sockaddr *) &dst_addr6;
        dst_addr_len = sizeof(struct sockaddr_in6);

        break;
    }

    nbytes = sendto(sock, (const void *) packet, packet_length, 0, dst_addr,
            dst_addr_len);

    if (nbytes != packet_length) {

        switch (iph->version) {
        case 4:
            ip_addr_set_v4(&pkt_src_addr, &iph->saddr);
            ip_addr_set_v4(&pkt_dst_addr, &iph->daddr);
            break;
        case 6:
            ip6h = (struct ip6_hdr *) packet;
            ip_addr_set_v6(&pkt_src_addr, &ip6h->ip6_src);
            ip_addr_set_v6(&pkt_dst_addr, &ip6h->ip6_dst);
            break;
        }

        lmlog(DBG_2,
                "send_packet: send failed %s. Src addr: %s, Dst addr: %s, Socket: %d, packet len %d",
                strerror(errno), ip_addr_to_char(&pkt_src_addr),
                ip_addr_to_char(&pkt_dst_addr), sock, packet_length);
        return (BAD);
    }

    return (GOOD);

}

/* Sends a raw packet out the socket file descriptor 'sfd'  */
int
send_raw(int sfd, const void *pkt, int plen, ip_addr_t *dip)
{
    struct sockaddr *saddr;
    int slen = 0;
    int nbytes = 0;

    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;

    /* build sock addr */
    switch (ip_addr_afi(dip)) {
    case AF_INET:
        memset(&sa4, 0, sizeof(sa4));
        sa4.sin_family = AF_INET;
        ip_addr_copy_to(&sa4.sin_addr, dip);
        slen = sizeof(struct sockaddr_in);
        saddr = (struct sockaddr *)&sa4;
        break;
    case AF_INET6:
        memset(&sa6, 0, sizeof(sa6));
        sa6.sin6_family = AF_INET6;
        ip_addr_copy_to(&sa6.sin6_addr, dip);
        slen = sizeof(struct sockaddr_in6);
        saddr = (struct sockaddr *)&sa6;
        break;
    }

    lmlog(DBG_1, "Sending out socket %d", sfd);
    nbytes = sendto(sfd, pkt, plen, 0, saddr, slen);

    return (nbytes);
}
