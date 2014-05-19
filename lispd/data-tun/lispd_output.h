/*
 * lispd_output.h
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


#ifndef LISPD_OUTPUT_H_
#define LISPD_OUTPUT_H_

#include <stdio.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <defs.h>
#include <iface_list.h>
#include <lispd_lib.h>
#include <cksum.h>
//#include <lisp_map_cache.h>
#include <lispd_external.h>
#include <lisp_control.h>


int recv_output_packet(struct sock *sl);
int lisp_output(uint8_t *original_packet, int original_packet_length);

lisp_addr_t extract_dst_addr_from_packet(uint8_t *packet);
lisp_addr_t extract_src_addr_from_packet(uint8_t *packet);


#endif /*LISPD_OUTPUT_H_*/
