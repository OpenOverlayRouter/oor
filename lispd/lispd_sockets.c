/*
 * lispd_tun.c
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

#include "lispd_sockets.h"

int open_device_binded_raw_socket(char *device, int afi){
    
    //char *device = OUTPUT_IFACE;
    
    int device_len;
    
    int s;
    int tr = 1;
    
    
    if ((s = socket(afi, SOCK_RAW, IPPROTO_RAW)) < 0) {
        syslog(LOG_DAEMON, "open_raw_socket: socket creation failed %s", strerror(errno));
        return (BAD);
    }
    
    
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1) {
        syslog(LOG_DAEMON, "open_raw_socket: socket option reuse %s", strerror(errno));
        close(s);
        return (BAD);
    }
    
    
    // bind a socket to a device name (might not work on all systems):
    device_len = strlen(device);
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, device, device_len) == -1) {
        syslog(LOG_DAEMON, "open_raw_socket: socket option device %s", strerror(errno));
        close(s);
        return (BAD);
    }
    
    return s;
    
}


int open_udp_socket(int afi){

    struct protoent     *proto;
    int                 sock;
    int                 tr = 1;
    
    if ((proto = getprotobyname("UDP")) == NULL) {
        syslog(LOG_DAEMON, "getprotobyname: %s", strerror(errno));
        return(BAD);
    }
     
    /*
     *  build the v4_receive_fd, and make the port reusable
     */

    
    if ((sock = socket(afi,SOCK_DGRAM,proto->p_proto)) < 0) {
        syslog(LOG_DAEMON, "socket: %s", strerror(errno));
        return(BAD);
    }
    printf("socket at creation: %d\n",sock);
    
    if (setsockopt(sock,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &tr,
                   sizeof(int)) == -1) {
        syslog(LOG_DAEMON, "setsockopt SO_REUSEADDR: %s", strerror(errno));
    
    return(BAD);
    }

    return sock;
}
int open_input_socket(int afi, int port){

    struct sockaddr_in  sock_addr_v4;
    struct sockaddr_in6 sock_addr_v6;
    struct sockaddr     *sock_addr;
    int                 sock_addr_len;
    
    
    
    int sock;
    
    
    sock = open_udp_socket(afi);
    
    if(sock == BAD){
        return BAD;
    }
    
    switch (afi){
        case AF_INET:
            memset(&sock_addr_v4,0,sizeof(sock_addr_v4));           /* be sure */
            sock_addr_v4.sin_port        = htons(port);
            sock_addr_v4.sin_family      = AF_INET;
            sock_addr_v4.sin_addr.s_addr = INADDR_ANY;
            
            sock_addr = (struct sockaddr *) &sock_addr_v4;
            sock_addr_len = sizeof(sock_addr_v4);
            break;
            
        case AF_INET6:
            memset(&sock_addr_v6,0,sizeof(sock_addr_v6));                   /* be sure */
            sock_addr_v6.sin6_family   = AF_INET6;
            sock_addr_v6.sin6_port     = htons(port);
            sock_addr_v6.sin6_addr     = in6addr_any;
            
            sock_addr = (struct sockaddr *) &sock_addr_v6;
            sock_addr_len = sizeof(sock_addr_v6);
            break;
            
        default:
            return BAD;
    }
    
    
    if (bind(sock,sock_addr, sock_addr_len) == -1) {
        syslog(LOG_DAEMON, "bind input socket: %s", strerror(errno));
        return(BAD);
    }
    
    return sock;
    
}


int open_control_input_socket(int afi){

    const int on=1;
    
    int sock;
    

    sock = open_input_socket(afi,LISP_CONTROL_PORT);

    if(sock == BAD){
        return BAD;
    }

    switch (afi){
        case AF_INET:
            
            /* IP_PKTINFO is requiered to get later the IPv4 destination address of incoming control packets*/
            if(setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on))< 0){
                syslog(LOG_DAEMON, "setsockopt IP_PKTINFO: %s", strerror(errno));
            }
            
        break;

        case AF_INET6:

            /* IPV6_RECVPKTINFO is requiered to get later the IPv6 destination address of incoming control packets*/
            if(setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0){
                syslog(LOG_DAEMON, "setsockopt IPV6_RECVPKTINFO: %s", strerror(errno));
            }

        break;

        default:
            return BAD;
    }
    
    return sock;
}


int open_data_input_socket(int afi){
    
    int sock;
    
    sock = open_input_socket(afi,LISP_DATA_PORT);

    if(sock == BAD){
        return BAD;
    }
    
    return sock;
}

/*

lisp_addr_t receive_packet_on_udp_socket_with_dst_addr(int sock, char *packet, int packet_len){

    int bytes_received;
    struct sockaddr_in6 from;
    struct iovec iovec[1];
    struct msghdr msg;
    char msg_control[1024];
    
    iovec[0].iov_base = packet;
    iovec[0].iov_len = packet_len;
    
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = iovec;
    msg.msg_iovlen = sizeof(iovec) / sizeof(*iovec);
    msg.msg_control = msg_control;
    msg.msg_controllen = sizeof(msg_control);
    msg.msg_flags = 0;
    bytes_received = recvmsg(sock, &msg, 0);
    
}
*/