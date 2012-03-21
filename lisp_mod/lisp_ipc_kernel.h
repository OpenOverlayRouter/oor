/*
 * lisp_ipc_kernel.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Declares the kernel private structures and 
 * functions for inter-process communications. 
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
 *    Chris White       <chris@logicalelegance.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 */

#pragma once

#include "net/ip.h"

/*
 * Function declarations
 */
void dump_message(char *msg, int length);
void send_cache_miss_notification(lisp_addr_t, short);
void send_cache_sample_notification(lisp_map_cache_t *, sample_reason_e);
void send_map_cache_list(int dstpid, uint16_t request_type,
                         char with_traffic_only);

void handle_no_action(lisp_cmd_t *cmd, int pid);
void handle_map_cache_lookup(lisp_cmd_t *cmd, int pid);
void handle_map_cache_add(lisp_cmd_t *cmd, int pid);
void handle_map_cache_list_request(lisp_cmd_t *cmd, int pid);
void handle_map_db_lookup(lisp_cmd_t *cmd, int pid);
void handle_map_db_add(lisp_cmd_t *cmd, int pid);
void handle_map_db_delete(lisp_cmd_t *cmd, int pid);
void handle_cache_sample(lisp_cmd_t *cmd, int pid);
void handle_set_rloc(lisp_cmd_t *cmd, int pid);
void handle_daemon_register(lisp_cmd_t *cmd, int pid);
void handle_traffic_mon_start(lisp_cmd_t *cmd, int pid);
void handle_set_udp_ports(lisp_cmd_t *cmd, int pid);
void handle_add_eid(lisp_cmd_t *cmd, int pid);

void lisp_netlink_input(struct sk_buff *skb);
int setup_netlink_socket(void);
void teardown_netlink_socket(void);
