/*
 * cksum.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Implementation for UDP checksum.
 *
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 *    David Meyer   <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

#ifndef CKSUM_H_
#define CKSUM_H_

#include "lispd.h"

uint16_t ip_checksum(uint16_t *buffer,int size);

/*
 *  Calculate the IPv4 or IPv6 UDP checksum
 */

uint16_t udp_checksum (
     struct udphdr *udph,
     int       udp_len,
     void      *iphdr,
     int       afi);

#endif /* CKSUM_H_ */
