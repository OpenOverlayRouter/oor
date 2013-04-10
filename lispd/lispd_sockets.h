/*
 * lispd_sockets.h
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
 *    Albert López <alopez@ac.upc.edu>
 */

#ifndef LISPD_SOCKETS_H_
#define LISPD_SOCKETS_H_

/* Define _GNU_SOURCE in order to use in6_pktinfo (get destinatio address of received ctrl packets*/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "lispd.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "lispd_output.h"


int open_device_binded_raw_socket(
    char *device,
    int afi);

int open_data_input_socket(int afi);

int open_control_input_socket(int afi);

int open_udp_socket(int afi);

/*
 * Send a control packet over a udp datagram to the destination address.
 */

int send_udp_ctrl_packet(
        lisp_addr_t *dst_addr,
        uint16_t    src_port,
        uint16_t    dst_port,
        void        *packet,
        int         packet_len);

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
        int         packet_len);



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
        int         packet_len);

/*
 * Sends a raw packet through the specified socket
 */

int send_packet (
        int     sock,
        char    *packet,
        int     packet_length );

/*
 * Get a packet from the socket. It also returns the destination addres and source port of the packet
 */

int get_control_packet (
        int             sock,
        int             afi,
        uint8_t         *packet,
        lisp_addr_t     *local_rloc,
        uint16_t        *remote_port);

int get_data_packet (
    int             sock,
    int             afi,
    uint8_t         *packet,
    int             *length,
    uint8_t         *ttl,
    uint8_t         *tos);

#endif /*LISPD_SOCKETS_H_*/
