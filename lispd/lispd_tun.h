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

#pragma once

#include <stdio.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include "lispd.h"
#include "lispd_lib.h"

#define CLONEDEV                "/dev/net/tun"

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

/* Local OpenWRT tun IPv4 address
 *
 * Local IPv4 address for tun interface when running on OpenWRT
 */

#define TUN_LOCAL_V4_ADDR "127.0.0.127"
#define TUN_LOCAL_V6_ADDR "::127"

/* Tun MN variables */

int tun_receive_fd;
int tun_ifindex;
char *tun_receive_buf;



int create_tun(
    char                *tun_dev_name,
    unsigned int        tun_receive_size,
    int                 tun_mtu,
    int                 *tun_receive_fd,
    int                 *tun_ifindex,
    char                **tun_receive_buf);


/*
 * tun_bring_up_iface()
 *
 * Bring up interface
 */
int tun_bring_up_iface(char *tun_dev_name);

/*
 * tun_add_eid_to_iface()
 *
 * Add an EID to the TUN/TAP interface
 */
int tun_add_eid_to_iface(
    lisp_addr_t         eid_address,
    char                *tun_dev_name);

int tun_add_v6_eid_to_iface(
    lisp_addr_t         eid_address_v6,
    char                *tun_dev_name);

int add_route(
    uint32_t            ifindex,
    lisp_addr_t         *dest,
    lisp_addr_t         *src,
    lisp_addr_t         *gw,
    uint32_t            prefix_len,
    uint32_t            metric);

int del_route(
    uint32_t            ifindex,
    lisp_addr_t         *dest,
    lisp_addr_t         *src,
    lisp_addr_t         *gw,
    uint32_t            prefix_len,
    uint32_t            metric);

int set_tun_default_route_v4();
int set_tun_default_route_v6();
int del_tun_default_route_v6();
