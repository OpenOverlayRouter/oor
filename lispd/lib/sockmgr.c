/*
 * sockmgr.c
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
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#include "sockmgr.h"
#include <defs.h>

sockmgr_t *sockmgr_create() {
    sockmgr_t *mgr;
    mgr = calloc(1, sizeof(sockmgr_t));
    mgr->if_socks = shash_new_managed(sock_del);
    return(mgr);
}

void sockmgr_destroy(sockmgr_t *mgr) {
    shash_del(mgr->if_socks);
    free(mgr);
}

sock_t *sockmgr_get_if_sock(sockmgr_t *mgr, lisp_addr_t *addr) {
    return(shash_lookup(mgr->if_socks, lisp_addr_to_char(addr)));
}

int sockmgr_open_ctrl_sock(sockmgr_t *mgr, int afi) {

    const int on = 1;
    int fd = 0;

    fd = open_udp_socket(afi);
    fd = bind_socket(fd, afi, LISP_CONTROL_PORT);

    if(fd == BAD)
        return (BAD);

    switch (afi){
    case AF_INET:
        /* IP_PKTINFO is requiered to get later the IPv4 destination address of incoming control packets*/
        if(setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on))< 0){
            lmlog(LISP_LOG_WARNING, "setsockopt IP_PKTINFO: %s", strerror(errno));
        }
        break;
    case AF_INET6:
        /* IPV6_RECVPKTINFO is requiered to get later the IPv6 destination address of incoming control packets*/
        if(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0){
            lmlog(LISP_LOG_WARNING, "setsockopt IPV6_RECVPKTINFO: %s", strerror(errno));
        }
    break;

    default:
        return(BAD);
    }

    mgr->ctrl_sock->fd = fd;

    return(GOOD);
}
