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


#pragma once

#include <stdio.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "lispd.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "cksum.h"
#include "lispd_map_cache_db.h"
#include "lispd_external.h"


void process_output_packet(int fd, char *tun_receive_buf, unsigned int tun_receive_size);

lisp_addr_t extract_dst_addr_from_packet ( char *packet );

int handle_map_cache_miss(lisp_addr_t *requested_eid, lisp_addr_t *src_eid);

lisp_addr_t *get_proxy_etr(int afi);
