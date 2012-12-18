/*
 * lispd_sockets.c
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
#include "lispd_log.h"

int open_device_binded_raw_socket(
    char *device,
    int afi)
{
    
    //char *device = OUTPUT_IFACE;
    
    int device_len;
    
    int s;
    int tr = 1;
    
    
    if ((s = socket(afi, SOCK_RAW, IPPROTO_RAW)) < 0) {
        lispd_log_msg(LISP_LOG_ERR, "open_device_binded_raw_socket: socket creation failed %s", strerror(errno));
        return (BAD);
    }
    
    
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == -1) {
        lispd_log_msg(LISP_LOG_WARNING, "open_device_binded_raw_socket: socket option reuse %s", strerror(errno));
        close(s);
        return (BAD);
    }
    
    
    // bind a socket to a device name (might not work on all systems):
    device_len = strlen(device);
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, device, device_len) == -1) {
        lispd_log_msg(LISP_LOG_WARNING, "open_device_binded_raw_socket: socket option device %s", strerror(errno));
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
        lispd_log_msg(LISP_LOG_ERR, "open_udp_socket: getprotobyname: %s", strerror(errno));
        return(BAD);
    }
     
    /*
     *  build the ipv4_data_input_fd, and make the port reusable
     */

    
    if ((sock = socket(afi,SOCK_DGRAM,proto->p_proto)) < 0) {
        lispd_log_msg(LISP_LOG_ERR, "open_udp_socket: socket: %s", strerror(errno));
        return(BAD);
    }
    lispd_log_msg(LISP_LOG_DEBUG_3,"open_udp_socket: socket at creation: %d\n",sock);

    if (setsockopt(sock,
            SOL_SOCKET,
            SO_REUSEADDR,
            &tr,
            sizeof(int)) == -1) {
        lispd_log_msg(LISP_LOG_WARNING, "open_udp_socket: setsockopt SO_REUSEADDR: %s", strerror(errno));

        return(BAD);
    }

    return sock;
}
int open_input_socket(
    int afi,
    int port)
{

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
        lispd_log_msg(LISP_LOG_WARNING, "bind input socket: %s", strerror(errno));
        return(BAD);
    }
    
    return(sock);
    
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
                lispd_log_msg(LISP_LOG_WARNING, "setsockopt IP_PKTINFO: %s", strerror(errno));
            }

        break;

        case AF_INET6:

            /* IPV6_RECVPKTINFO is requiered to get later the IPv6 destination address of incoming control packets*/
            if(setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0){
                lispd_log_msg(LISP_LOG_WARNING, "setsockopt IPV6_RECVPKTINFO: %s", strerror(errno));
            }

        break;

        default:
            return(BAD);
    }
    return(sock);
}


int open_data_input_socket(int afi){
    
    int sock;
    
    sock = open_input_socket(afi,LISP_DATA_PORT);

    if(sock == BAD){
        return(BAD);
    }
    
    return(sock);
}

/*
 * Send a ipv4 packet over a udp datagram to the destination address
 * If the selected port is 0, then a random port is used.
 */

int send_udp_ipv4_packet(
        lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr,
        uint16_t    src_port,
        uint16_t    dst_port,
        void        *packet,
        int         packet_len)
{
    int                 s;      /*socket */
    int                 nbytes;
    struct sockaddr_in  dst;
    struct sockaddr_in  src;

    if ((s = open_udp_socket(AF_INET)) < 0) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "send_udp_ipv4_packet: socket: %s", strerror(errno));
        return(BAD);
    }

    memset((char *) &src, 0, sizeof(struct sockaddr_in));
    src.sin_family       = AF_INET;
    src.sin_port         = htons(src_port);
    src.sin_addr.s_addr  = src_addr->address.ip.s_addr;
    static char address[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &(src.sin_addr), address, INET_ADDRSTRLEN);

    if (bind(s, (struct sockaddr *)&src, sizeof(struct sockaddr_in)) < 0) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "send_udp_ipv4_packet: bind: %s", strerror(errno));
        close(s);
        return(BAD);
    }

    memset((char *) &dst, 0, sizeof(struct sockaddr_in));

    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = dst_addr->address.ip.s_addr;
    dst.sin_port        = htons(dst_port);
    if ((nbytes = sendto(s,
            (const void *) packet,
            packet_len,
            0,
            (struct sockaddr *)&dst,
            sizeof(struct sockaddr))) < 0) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "send_udp_ipv4_packet: sendto: %s", strerror(errno));
        close(s);
        return(BAD);
    }

    if (nbytes != packet_len) {
        lispd_log_msg(LISP_LOG_DEBUG_2,
                "send_udp_ipv4_packet: nbytes (%d) != packet (%d)\n",
                nbytes, packet_len);
        close(s);
        return(BAD);
    }

    close(s);
    return (GOOD);
}

/*
 * Send a ipv6 packet over a udp datagram to the destination address
 * If the selected port is 0, then a random port is used.
 */

int send_udp_ipv6_packet(
        lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr,
        uint16_t    src_port,
        uint16_t    dst_port,
        void        *packet,
        int         packet_len)
{
    int                 s;      /*socket */
    int                 nbytes;
    struct sockaddr_in6  dst;
    struct sockaddr_in6  src;


    if ((s = open_udp_socket(AF_INET6)) < 0) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "send_udp_ipv6_packet: socket: %s", strerror(errno));
        return(BAD);
    }
    memset((char *) &src, 0, sizeof(struct sockaddr_in));
    src.sin6_family       = AF_INET6;
    src.sin6_port         = htons(src_port);
    memcpy(&src.sin6_addr,&(src_addr->address.ipv6),sizeof(struct in6_addr));

    if (bind(s, (struct sockaddr *)&src, sizeof(struct sockaddr_in6)) < 0) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "send_udp_ipv6_packet: bind: %s", strerror(errno));
        close(s);
        return(BAD);
    }

    memset((char *) &dst, 0, sizeof(struct sockaddr_in));

    dst.sin6_family      = AF_INET6;
    dst.sin6_port        = htons(dst_port);
    memcpy(&dst.sin6_addr,&(dst_addr->address.ipv6),sizeof(struct in6_addr));


    if ((nbytes = sendto(s,
            (const void *) packet,
            packet_len,
            0,
            (struct sockaddr *)&dst,
            sizeof(struct sockaddr))) < 0) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "send_udp_ipv6_packet: sendto: %s", strerror(errno));
        close(s);
        return(BAD);
    }

    if (nbytes != packet_len) {
        lispd_log_msg(LISP_LOG_DEBUG_2,
                "send_udp_ipv6_packet: nbytes (%d) != packet (%d)\n",
                nbytes, packet_len);
        close(s);
        return(BAD);
    }

    close(s);
    return (GOOD);
}

/*
 * Sends a raw packet through the specified interface
 */

int send_raw_packet (
        lispd_iface_elt     *iface,
        char                *packet_buf,
        int                 pckt_length )
{

    int socket;

    struct sockaddr *dst_addr;
    int dst_addr_len;
    struct sockaddr_in dst_addr4;
    //struct sockaddr_in6 dst_addr6;
    struct iphdr *iph;
    int nbytes;

    if (!iface){
        lispd_log_msg(LISP_LOG_DEBUG_2, "send_raw_packet: No output interface found");
        return (BAD);
    }
    memset ( ( char * ) &dst_addr, 0, sizeof ( dst_addr ) );

    iph = ( struct iphdr * ) packet_buf;

    if ( iph->version == 4 ) {
        memset ( ( char * ) &dst_addr4, 0, sizeof ( dst_addr4 ) );
        dst_addr4.sin_family = AF_INET;
        dst_addr4.sin_port = htons ( LISP_DATA_PORT );
        dst_addr4.sin_addr.s_addr = iph->daddr;

        dst_addr = ( struct sockaddr * ) &dst_addr4;
        dst_addr_len = sizeof ( struct sockaddr_in );
        socket = iface->out_socket_v4;
    } else {
        return (GOOD);
        //arnatal TODO: write IPv6 support
    }

    nbytes = sendto ( socket,
                      ( const void * ) packet_buf,
                      pckt_length,
                      0,
                      dst_addr,
                      dst_addr_len );

    if ( nbytes != pckt_length ) {
        lispd_log_msg( LISP_LOG_DEBUG_2, "send_raw_packet: send failed %s", strerror ( errno ) );
        return (BAD);
    }

    return (GOOD);

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
