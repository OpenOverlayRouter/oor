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
    
    int device_len  = 0;
    
    int s           = 0;
    int on          = 1;
    

    //TODO arnatal to merge if this still the same after testing IPv6 RLOCs
    switch (afi){
        case AF_INET:
            if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
                lispd_log_msg(LISP_LOG_ERR, "open_device_binded_raw_socket: socket creation failed %s", strerror(errno));
                return (BAD);
            }
            break;
        case AF_INET6:
            if ((s = socket(AF_INET6, SOCK_RAW,IPPROTO_RAW)) < 0) {
                lispd_log_msg(LISP_LOG_ERR, "open_device_binded_raw_socket: socket creation failed %s", strerror(errno));
                return (BAD);
            }
            break;
    }
    
    
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) == -1) {
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
    
    lispd_log_msg(LISP_LOG_DEBUG_2, "open_device_binded_raw_socket: open socket %d in interface %s with afi: %d", s, device, afi);

    return s;
    
}

int open_raw_input_socket(int afi){
    
    struct protoent     *proto  = NULL;
    int                 sock    = 0;
    int                 tr      = 1;
    
    if ((proto = getprotobyname("UDP")) == NULL) {
        lispd_log_msg(LISP_LOG_ERR, "open_raw_input_socket: getprotobyname: %s", strerror(errno));
        return(BAD);
    }
    
    /*
     *  build the ipv4_data_input_fd, and make the port reusable
     */
    
    
    if ((sock = socket(afi,SOCK_RAW,proto->p_proto)) < 0) {
        lispd_log_msg(LISP_LOG_ERR, "open_raw_input_socket: socket: %s", strerror(errno));
        return(BAD);
    }
    lispd_log_msg(LISP_LOG_DEBUG_3,"open_raw_input_socket: socket at creation: %d\n",sock);
    
    if (setsockopt(sock,
        SOL_SOCKET,
        SO_REUSEADDR,
        &tr,
        sizeof(int)) == -1) {
        lispd_log_msg(LISP_LOG_WARNING, "open_raw_input_socket: setsockopt SO_REUSEADDR: %s", strerror(errno));
    
    return(BAD);
        }
        
        return sock;
}


int open_udp_socket(int afi){

    struct protoent     *proto  = NULL;
    int                 sock    = 0;
    int                 tr      = 1;
    
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

int bind_socket(int sock,
                int afi,
                int port)
{
    struct sockaddr_in  sock_addr_v4;
    struct sockaddr_in6 sock_addr_v6;
    struct sockaddr     *sock_addr      = NULL;
    int                 sock_addr_len   = 0;
    
        
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

    const int   on      = 1;
    int         sock    = 0;

    sock = open_udp_socket(afi);
    
    sock = bind_socket(sock,afi,LISP_CONTROL_PORT);
    
    if(sock == BAD){
        return (BAD);
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
    
    int         sock        = 0;
    int         dummy_sock  = 0; /* To avoid ICMP port unreacheable packets */
    const int   on          = 1;
    
    sock = open_raw_input_socket(afi);

    dummy_sock = open_udp_socket(afi);
    
    dummy_sock = bind_socket(dummy_sock,afi,LISP_DATA_PORT);

    if(sock == BAD){
        return(BAD);
    }

    switch (afi){
        case AF_INET:
            
            /* IP_RECVTOS is requiered to get later the IPv4 original TOS */
            if(setsockopt(sock, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on))< 0){
                lispd_log_msg(LISP_LOG_WARNING, "setsockopt IP_RECVTOS: %s", strerror(errno));
            }

            /* IP_RECVTTL is requiered to get later the IPv4 original TTL */
            if(setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on))< 0){
                lispd_log_msg(LISP_LOG_WARNING, "setsockopt IP_RECVTTL: %s", strerror(errno));
            }
            
            break;
            
        case AF_INET6:
            
            /* IPV6_RECVTCLASS is requiered to get later the IPv6 original TOS */
            if(setsockopt(sock, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on))< 0){
                lispd_log_msg(LISP_LOG_WARNING, "setsockopt IPV6_RECVTCLASS: %s", strerror(errno));
            }
            
            /* IPV6_RECVHOPLIMIT is requiered to get later the IPv6 original TTL */
            if(setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on))< 0){
                lispd_log_msg(LISP_LOG_WARNING, "setsockopt IPV6_RECVHOPLIMIT: %s", strerror(errno));
            }
            
            break;
            
        default:
            return(BAD);
    }
    
    return(sock);
}

/*
 * Send a control packet over a udp datagram to the destination address.
 */

int send_udp_ctrl_packet(
        lisp_addr_t *dst_addr,
        uint16_t    src_port,
        uint16_t    dst_port,
        void        *packet,
        int         packet_len)
{
    switch (dst_addr->afi){
    case AF_INET:
        if (default_ctrl_iface_v4 != NULL){
            err = send_udp_ipv4_packet(default_ctrl_iface_v4->ipv4_address,dst_addr,src_port,dst_port,(void *)packet,packet_len);
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1,"send_udp_ctrl_packet: No local RLOC compatible with the afi of the destinaion locator %s",
                    get_char_from_lisp_addr_t(*dst_addr));
            err = BAD;
        }
        break;
    case AF_INET6:
        if (default_ctrl_iface_v6 != NULL){
            err = send_udp_ipv6_packet(default_ctrl_iface_v6->ipv6_address,dst_addr,src_port,dst_port,(void *)packet,packet_len);
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1,"send_udp_ctrl_packet: No local RLOC compatible with the afi of the destination locator %s",
                    get_char_from_lisp_addr_t(*dst_addr));
            err = BAD;
        }
        break;
    }
    return err;
}

/*
 * Send a ipv4 packet over a udp datagram to the destination address
 * If the src port is 0, then a random port is used.
 */

int send_udp_ipv4_packet(
        lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr,
        uint16_t    src_port,
        uint16_t    dst_port,
        void        *packet,
        int         packet_len)
{
    int                 s       = 0;      /*socket */
    int                 nbytes  = 0;
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
            sizeof(struct sockaddr_in))) < 0) {
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
 * If the src port is 0, then a random port is used.
 */

int send_udp_ipv6_packet(
        lisp_addr_t *src_addr,
        lisp_addr_t *dst_addr,
        uint16_t    src_port,
        uint16_t    dst_port,
        void        *packet,
        int         packet_len)
{
    int                     s       = 0;      /*socket */
    int                     nbytes  = 0;
    struct sockaddr_in6     dst;
    struct sockaddr_in6     src;

    if ((s = open_udp_socket(AF_INET6)) < 0) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "send_udp_ipv6_packet: socket: %s", strerror(errno));
        return(BAD);
    }

    memset((char *) &src, 0, sizeof(struct sockaddr_in6));
    src.sin6_family       = AF_INET6;
    src.sin6_port         = htons(src_port);
    memcpy(&src.sin6_addr,&(src_addr->address.ipv6),sizeof(struct in6_addr));

    if (bind(s, (struct sockaddr *)&src, sizeof(struct sockaddr_in6)) < 0) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "send_udp_ipv6_packet: bind: %s", strerror(errno));
        close(s);
        return(BAD);
    }

    memset((char *) &dst, 0, sizeof(struct sockaddr_in6));

    dst.sin6_family      = AF_INET6;
    dst.sin6_port        = htons(dst_port);
    memcpy(&dst.sin6_addr,&(dst_addr->address.ipv6),sizeof(struct in6_addr));


    if ((nbytes = sendto(s,
            (const void *) packet,
            packet_len,
            0,
            (struct sockaddr *)&dst,
            sizeof(struct sockaddr_in6))) < 0) {
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

int send_packet (
        int     sock,
        char    *packet,
        int     packet_length )
{

    struct sockaddr     *dst_addr       = NULL;
    int                 dst_addr_len    = 0;
    struct sockaddr_in  dst_addr4;
    struct sockaddr_in6 dst_addr6;
    struct iphdr        *iph            = NULL;
    struct ip6_hdr      *ip6h           = NULL;
    int                 nbytes          = 0;

    memset ( ( char * ) &dst_addr, 0, sizeof ( dst_addr ) );


    iph = ( struct iphdr * ) packet;

    switch(iph->version){

        case 4:

            memset ( ( char * ) &dst_addr4, 0, sizeof ( dst_addr4 ) );
            dst_addr4.sin_family = AF_INET;
            //dst_addr4.sin_port = htons ( LISP_DATA_PORT );
            dst_addr4.sin_addr.s_addr = iph->daddr;

            dst_addr = ( struct sockaddr * ) &dst_addr4;
            dst_addr_len = sizeof ( struct sockaddr_in );
            break;
        case 6:

            ip6h = (struct ip6_hdr *) packet;
            
            memset ( ( char * ) &dst_addr6, 0, sizeof ( dst_addr6 ) );
            dst_addr6.sin6_family = AF_INET6;
            //dst_addr6.sin6_port = htons ( LISP_DATA_PORT );
            //memcpy(&(dst_addr6.sin6_addr),&(ip6h->ip6_dst),32);
            dst_addr6.sin6_addr = ip6h->ip6_dst;
            
            dst_addr = ( struct sockaddr * ) &dst_addr6;
            dst_addr_len = sizeof ( struct sockaddr_in6 );
            
            break;
    }

    nbytes = sendto ( sock,
                      ( const void * ) packet,
                      packet_length,
                      0,
                      dst_addr,
                      dst_addr_len );

    if ( nbytes != packet_length ) {
        lispd_log_msg( LISP_LOG_DEBUG_2, "send_packet: send failed %s", strerror ( errno ) );
        return (BAD);
    }

    return (GOOD);

}


int get_control_packet (
        int             sock,
        int             afi,
        uint8_t         *packet,
        lisp_addr_t     *local_rloc,
        uint16_t        *remote_port)
{
    union control_data {
        struct cmsghdr cmsg;
        u_char data4[CMSG_SPACE(sizeof(struct in_pktinfo))]; /* Space for IPv4 pktinfo */
        u_char data6[CMSG_SPACE(sizeof(struct in6_pktinfo))]; /* Space for IPv6 pktinfo */
    };
    
    
    struct sockaddr_in  s4;
    struct sockaddr_in6 s6;
    struct msghdr       msg;
    struct iovec        iov[1];
    union control_data  cmsg;
    struct cmsghdr      *cmsgptr    = NULL;
    int                 nbytes      = 0;

    iov[0].iov_base = packet;
    iov[0].iov_len = MAX_IP_PACKET;

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg;
    msg.msg_controllen = sizeof cmsg;
    if (afi == AF_INET){
        msg.msg_name = &s4;
        msg.msg_namelen = sizeof (struct sockaddr_in);
    }else{
        msg.msg_name = &s6;
        msg.msg_namelen = sizeof (struct sockaddr_in6);
    }

    nbytes = recvmsg(sock, &msg, 0);
    if (nbytes == -1) {
        lispd_log_msg(LISP_LOG_WARNING, "read_packet: recvmsg error: %s", strerror(errno));
        return (BAD);
    }

    if (afi == AF_INET){
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
            if (cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == IP_PKTINFO) {
                local_rloc->afi = AF_INET;
                local_rloc->address.ip = ((struct in_pktinfo *)(CMSG_DATA(cmsgptr)))->ipi_addr;
                break;
            }
        }

        *remote_port = ntohs(s4.sin_port);
    }else {
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
            if (cmsgptr->cmsg_level == IPPROTO_IPV6 && cmsgptr->cmsg_type == IPV6_PKTINFO) {
                local_rloc->afi = AF_INET6;
                memcpy(&(local_rloc->address.ipv6.s6_addr),
                        &(((struct in6_pktinfo *)(CMSG_DATA(cmsgptr)))->ipi6_addr.s6_addr),
                        sizeof(struct in6_addr));
                break;
            }
        }
        *remote_port = ntohs(s6.sin6_port);
    }

    return (GOOD);
}


int get_data_packet (
    int             sock,
    int             afi,
    uint8_t         *packet,
    int             *length,
    uint8_t         *ttl,
    uint8_t         *tos)
{

    union control_data {
        struct cmsghdr cmsg;
        u_char data[CMSG_SPACE(sizeof(int))+CMSG_SPACE(sizeof(int))]; /* Space for TTL and TOS data */
    };
    
    struct sockaddr_in  s4;
    struct sockaddr_in6 s6;
    struct msghdr       msg;
    struct iovec        iov[1];
    union  control_data  cmsg;
    struct cmsghdr      *cmsgptr    = NULL;
    int                 nbytes      = 0;
    
    iov[0].iov_base = packet;
    iov[0].iov_len = MAX_IP_PACKET;
    
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg;
    msg.msg_controllen = sizeof cmsg; 
    if (afi == AF_INET){
        msg.msg_name = &s4;
        msg.msg_namelen = sizeof (struct sockaddr_in);
    }else{
        msg.msg_name = &s6;
        msg.msg_namelen = sizeof (struct sockaddr_in6);
    }
    
    nbytes = recvmsg(sock, &msg, 0);
    if (nbytes == -1) {
        lispd_log_msg(LISP_LOG_WARNING, "read_packet: recvmsg error: %s", strerror(errno));
        return (BAD);
    }

    *length = nbytes;
    
    if (afi == AF_INET){
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
            
            if (cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == IP_TTL) {
                *ttl = *((uint8_t *)CMSG_DATA(cmsgptr));
            }

            if (cmsgptr->cmsg_level == IPPROTO_IP && cmsgptr->cmsg_type == IP_TOS) {
                *tos = *((uint8_t *)CMSG_DATA(cmsgptr));
            }
        }

    }else {
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
            
            if (cmsgptr->cmsg_level == IPPROTO_IPV6 && cmsgptr->cmsg_type == IPV6_HOPLIMIT) {
                *ttl = *((uint8_t *)CMSG_DATA(cmsgptr));
            }
            
            if (cmsgptr->cmsg_level == IPPROTO_IPV6 && cmsgptr->cmsg_type == IPV6_TCLASS) {
                *tos = *((uint8_t *)CMSG_DATA(cmsgptr));
            }
        }
    }
    
    return (GOOD);
}
