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


#ifndef SOCKETS_UTIL_H_
#define SOCKETS_UTIL_H_

#include "lisp_address.h"

int open_device_bound_raw_socket(char *device, int afi);
int open_raw_socket(int afi);

int open_udp_socket(int afi);
int bind_socket_address(int sock, lisp_addr_t *);
int bind_socket(int sock, int afi, int port);
int send_raw(int, const void *, int, ip_addr_t *);

int send_packet(int sock, uint8_t *packet, int packet_length);

#endif /* SOCKETS_UTIL_H_ */
