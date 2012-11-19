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

#define TUN_MTU                 1450 // Less than the Ethernet default (1500) for precaution


/* Tun MN variables */

int tun_receive_fd;
int tun_ifindex;
char *tun_receive_buf;

int data_out_socket;



int create_tun(char *tun_dev_name,
               unsigned int tun_receive_size,
               int tun_mtu,
               int *tun_receive_fd,
               int *tun_ifindex,
               char **tun_receive_buf);

int tun_bring_up_iface_v4_eid(lisp_addr_t eid_address_v4,
                   char *tun_dev_name);

int tun_add_v6_eid_to_iface(lisp_addr_t eid_address_v6,
                   char *tun_dev_name,
                   int tun_ifindex);

int install_default_route(int tun_ifindex, int afi);

//void process_input_packet(int fd, int tun_receive_fd);

//void process_output_packet(int fd, char *tun_receive_buf, unsigned int tun_receive_size);