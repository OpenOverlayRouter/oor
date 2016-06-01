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
#include <netdb.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "oor_log.h"
#include "sockets-util.h"

int
open_ip_raw_socket(int afi)
{
    int s;
    int on = 1;

    if ((s = socket(afi, SOCK_RAW, IPPROTO_RAW)) < 0) {
        OOR_LOG(LERR, "open_ip_raw_socket: socket creation failed"
                " %s", strerror(errno));
        return (ERR_SOCKET);
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) == -1) {
        OOR_LOG(LWRN, "open_ip_raw_socket: socket option reuse %s",
                strerror(errno));
        close(s);
        return (ERR_SOCKET);
    }

    OOR_LOG(LDBG_3, "open_ip_raw_socket: open socket %d with afi: %d", s, afi);

    return s;

}


int
open_udp_raw_socket(int afi)
{
    struct protoent *proto = NULL;
    int sock = ERR_SOCKET;
    int tr = 1;
    int protonum = 0;

#ifdef ANDROID
    protonum = IPPROTO_UDP;
#else
    if ((proto = getprotobyname("UDP")) == NULL) {
        OOR_LOG(LERR, "open_udp_raw_socket: getprotobyname: %s", strerror(errno));
        return(-1);
    }
    protonum = proto->p_proto;
#endif

    /*
     *  build the ipv4_data_input_fd, and make the port reusable
     */

    if ((sock = socket(afi, SOCK_RAW, protonum)) < 0) {
        OOR_LOG(LERR, "open_udp_raw_socket: socket: %s", strerror(errno));
        return (ERR_SOCKET);
    }
    OOR_LOG(LDBG_3, "open_udp_raw_socket: Created socket %d associated to %s addresses\n",
            sock, (afi == AF_INET) ? "IPv4":"IPv6");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1) {
        OOR_LOG(LWRN,"open_udp_raw_socket: setsockopt SO_REUSEADDR: %s",
                strerror(errno));
        close(sock);
        return (ERR_SOCKET);
    }

    return (sock);
}

int
open_udp_datagram_socket(int afi)
{
    struct protoent *proto = NULL;
    int sock = ERR_SOCKET;
    int tr = 1;
    int protonum = 0;

#ifdef ANDROID
    protonum = IPPROTO_UDP;
#else
    if ((proto = getprotobyname("UDP")) == NULL) {
        OOR_LOG(LERR, "open_udp_datagram_socket: getprotobyname: %s", strerror(errno));
        return(ERR_SOCKET);
    }
    protonum = proto->p_proto;
#endif

    if ((sock = socket(afi, SOCK_DGRAM, protonum)) < 0) {
        OOR_LOG(LERR, "open_udp_datagram_socket: socket: %s", strerror(errno));
        return (ERR_SOCKET);
    }
    OOR_LOG(LDBG_3, "open_udp_datagram_socket: Created socket %d associated to %s addresses\n",
            sock, (afi == AF_INET) ? "IPv4":"IPv6");

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1) {
        OOR_LOG(LWRN, "open_udp_datagram_socket: setsockopt SO_REUSEADDR: %s",
                strerror(errno));

        return (ERR_SOCKET);
    }

    return sock;
}

int
opent_netlink_socket()
{
    int netlink_fd;
    struct sockaddr_nl addr;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
                   | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_MROUTE
                   | RTMGRP_IPV6_MROUTE;

    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (netlink_fd < 0) {
        OOR_LOG(LERR, "opent_netlink_socket: Failed to connect to "
                "netlink socket");
        return (ERR_SOCKET);
    }

    bind(netlink_fd, (struct sockaddr *) &addr, sizeof(addr));

    return (netlink_fd);
}

/* XXX: binding might not work on all devices */
inline int
socket_bindtodevice(int sock, char *device)
{
    int device_len = 0;

    device_len = strlen(device);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device, device_len) == -1) {
        OOR_LOG(LWRN, "socket_bindtodevice: Error binding socket to device %s:",
                strerror(errno));
        return (BAD);
    }
    return (GOOD);
}

inline int
socket_conf_req_ttl_tos(int sock, int afi)
{
    const int on = 1;

    switch (afi) {
    case AF_INET:

        /* IP_RECVTOS is requiered to get later the IPv4 original TOS */
        if (setsockopt(sock, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on)) < 0) {
            OOR_LOG(LWRN, "open_data_raw_input_socket: setsockopt IP_RECVTOS: %s", strerror(errno));
            return (BAD);
        }

        /* IP_RECVTTL is requiered to get later the IPv4 original TTL */
        if (setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on)) < 0) {
            OOR_LOG(LWRN, "open_data_raw_input_socket: setsockopt IP_RECVTTL: %s", strerror(errno));
            return (BAD);
        }

        break;

    case AF_INET6:

        /* IPV6_RECVTCLASS is requiered to get later the IPv6 original TOS */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on))
                < 0) {
            OOR_LOG(LWRN, "open_data_raw_input_socket: setsockopt IPV6_RECVTCLASS: %s", strerror(errno));
            return (BAD);
        }

        /* IPV6_RECVHOPLIMIT is requiered to get later the IPv6 original TTL */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on))
                < 0) {
            OOR_LOG(LWRN, "open_data_raw_input_socket: setsockopt IPV6_RECVHOPLIMIT: %s", strerror(errno));
            return (BAD);
        }

        break;

    default:
        return (BAD);
    }

    return (GOOD);
}


/*
 * Bind a socket to a specific address and port if specified
 * Afi is used when the src address is not specified
 */
int
bind_socket(int sock, int afi, lisp_addr_t *src_addr, int src_port)
{
    int result = TRUE;
    struct sockaddr *sock_addr;
    int sock_addr_len;
    struct sockaddr_in sock_addr_v4;
    struct sockaddr_in6 sock_addr_v6;

    switch(afi){
    case AF_INET:
        memset ( ( char * ) &sock_addr_v4, 0, sizeof ( sock_addr_v4 ) );
        sock_addr_v4.sin_family = AF_INET;
        if (src_port != 0){
            sock_addr_v4.sin_port        = htons(src_port);
        }
        if (src_addr != NULL){
            sock_addr_v4.sin_addr.s_addr = ip_addr_get_v4(lisp_addr_ip(src_addr))->s_addr;
        }else{
            sock_addr_v4.sin_addr.s_addr = INADDR_ANY;
        }

        sock_addr = ( struct sockaddr * ) &sock_addr_v4;
        sock_addr_len = sizeof ( struct sockaddr_in );

        break;
    case AF_INET6:
        memset ( ( char * ) &sock_addr_v6, 0, sizeof ( sock_addr_v6 ) );
        sock_addr_v6.sin6_family = AF_INET6;
        if (src_port != 0){
            sock_addr_v6.sin6_port     = htons(src_port);
        }
        if (src_addr != NULL){
            memcpy(&(sock_addr_v6.sin6_addr),ip_addr_get_v6(lisp_addr_ip(src_addr)),sizeof(struct in6_addr));
        }else{
            sock_addr_v6.sin6_addr     = in6addr_any;
        }

        sock_addr = ( struct sockaddr * ) &sock_addr_v6;
        sock_addr_len = sizeof ( struct sockaddr_in6 );

        break;
    default:
        return (BAD);
    }

    if (bind(sock,sock_addr,sock_addr_len) != 0){
        OOR_LOG(LDBG_1, "bind_socket: %s", strerror(errno));
        result = BAD;
    }else{
        OOR_LOG(LDBG_1, "bind_socket: Binded socket %d to source address %s and port %d with afi %d",
                sock, lisp_addr_to_char(src_addr),src_port, afi);
    }

    return (result);
}


/* Sends a raw packet out the socket file descriptor 'sfd'  */
int
send_raw_packet(int socket, const void *pkt, int plen, ip_addr_t *dip)
{
    struct sockaddr *saddr = NULL;
    int slen, nbytes;

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

    nbytes = sendto(socket, pkt, plen, 0, saddr, slen);
    if (nbytes != plen) {
        OOR_LOG(LDBG_2, "send_raw_packet: send packet to %s using fail descriptor %d failed -> %s", ip_addr_to_char(dip),
                socket, strerror(errno));
        return(BAD);
    }

    return (GOOD);
}

int
send_datagram_packet (int sock, const void *packet, int packet_length,
        lisp_addr_t *addr_dest, int port_dest)
{
    struct sockaddr_in sock_addr_v4;
    struct sockaddr_in6 sock_addr_v6;
    struct sockaddr *sock_addr = NULL;
    int sock_addr_len = 0;

    switch (lisp_addr_ip_afi(addr_dest)){
    case AF_INET:
        memset(&sock_addr_v4,0,sizeof(sock_addr_v4));           /* be sure */
        sock_addr_v4.sin_port        = htons(port_dest);
        sock_addr_v4.sin_family      = AF_INET;
        sock_addr_v4.sin_addr.s_addr = ip_addr_get_v4(lisp_addr_ip(addr_dest))->s_addr;
        sock_addr = (struct sockaddr *) &sock_addr_v4;
        sock_addr_len = sizeof(sock_addr_v4);
        break;
    case AF_INET6:
        memset(&sock_addr_v6,0,sizeof(sock_addr_v6));                   /* be sure */
        sock_addr_v6.sin6_family   = AF_INET6;
        sock_addr_v6.sin6_port     = htons(port_dest);
        memcpy(&sock_addr_v6.sin6_addr, ip_addr_get_v6(lisp_addr_ip(addr_dest)),sizeof(struct in6_addr));
        sock_addr = (struct sockaddr *) &sock_addr_v6;
        sock_addr_len = sizeof(sock_addr_v6);
        break;
    default:
        OOR_LOG(LDBG_2, "send_datagram_packet: Unknown afi %d",lisp_addr_ip_afi(addr_dest));
        return (BAD);
    }

    if (sendto(sock, packet, packet_length, 0, sock_addr, sock_addr_len) < 0){
        OOR_LOG(LDBG_2, "send_datagram_packet: send failed %s.",strerror ( errno ));
        return (BAD);
    }
    return (GOOD);
}




