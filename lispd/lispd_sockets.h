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


#define LOCAL_RX_IPC_ADDR       "127.0.1.1"
#define LOCAL_TX_IPC_ADDR       "127.0.1.1"
#define IPC_CONTROL_RX_PORT     10000
#define IPC_CONTROL_TX_PORT     10001
#define IPC_DATA_RX_PORT        10002
#define IPC_DATA_TX_PORT        10003


#include "lispd.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "lispd_output.h"


int new_device_binded_raw_socket(
    char *device,
    int afi);

int new_udp_socket(int afi);

/*
 * Bind a socket to a specific address and port if specified
 * Afi is used when the src address is not specified
 */
int bind_socket(
        int         sock,
        int         afi,
        lisp_addr_t *src_addr,
        int         src_port);

int open_data_input_socket(int afi);

int open_control_input_socket(int afi);

int open_ipc_socket(int port);


/*
 * Sends a raw packet through the specified socket
 */

int send_packet (
        int     sock,
        uint8_t *packet,
        int     packet_length );

int send_datagram_packet (
		int     		sock,
		uint8_t         *packet,
		int             packet_length,
		lisp_addr_t     *addr_dest,
		int             port_from,
		int             port_dest);

int send_packet_ipc (
        int     sock,
        int 	port,
        uint8_t *packet,
        int     packet_length);

/*
 * Get a packet from the socket. It also returns the destination addres and source port of the packet.
 * Used for control packets
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


/*
 * Send a lisp control message
 */
int send_control_msg(
        uint8_t         *msg,
        int             msg_length,
        lisp_addr_t     *src_addr,
        lisp_addr_t     *dest_addr,
        int             src_port,
        int             dst_port);

/*
 * Send a lisp data packet
 */
int send_data_packet(
        uint8_t         *buffer,
        int             packet_length,
        lisp_addr_t     *src_addr,
        lisp_addr_t     *dst_addr,
        int             output_socket);

#ifdef VPNAPI
    void reset_socket();
#endif

void close_socket(int socket);

#endif /*LISPD_SOCKETS_H_*/
