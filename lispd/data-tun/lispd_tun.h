/*
 * lispd_tun.h
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

#ifndef LISPD_TUN_H_
#define LISPD_TUN_H_

#include <stdio.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include "../lispd.h"

#ifdef ANDROID
#define CLONEDEV                "/dev/tun"
#else
#define CLONEDEV                "/dev/net/tun"
#endif

#define TUN_IFACE_NAME          "lispTun0"

#define TUN_RECEIVE_SIZE        2048 // Should probably tune to match largest MTU

/*
 * From section 5.4.1 of LISP RFC (6830)
 *

 1 .  Define H to be the size, in* octets, of the outer header an ITR
 prepends to a packet.  This includes the UDP and LISP header
 lengths.
 
 2.  Define L to be the size, in octets, of the maximum-sized packet
 an ITR can send to an ETR without the need for the ITR or any
 intermediate routers to fragment the packet.
 
 3.  Define an architectural constant S for the maximum size of a
 packet, in octets, an ITR must receive so the effective MTU can
 be met.  That is, S = L - H.

 [...]

 This specification RECOMMENDS that L be defined as 1500.
 
 */

/* H = 40 (IPv6 header) + 8 (UDP header) + 8 (LISP header) + 4 (extra/safety) = 60 */

#define TUN_MTU                 1440 /* 1500 - 60 = 1440 */


/* Tun MN variables */

int tun_receive_fd;
int tun_ifindex;
uint8_t *tun_receive_buf;

int tun_configure_data_plane(
        uint8_t router_mode,
        lisp_addr_t *ipv4_addr,
        lisp_addr_t *ipv6_addr);

int configure_routing_to_tun(
        uint8_t router_mode,
        lisp_addr_t *tun_v4_addr,
        lisp_addr_t *tun_v6_addr);

#endif /* LISPD_TUN_H_ */

