/*
 * lispd_external.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * External definitions for lispd
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
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#ifndef LISPD_EXTERNAL_H_
#define LISPD_EXTERNAL_H_

#include <iface_list.h>

extern map_server_list_t *map_servers;
extern char *config_file;
extern int debug_level;
extern int daemonize;
extern int default_rloc_afi;
extern int netlink_fd;
extern int ipv6_data_input_fd;
extern int ipv4_data_input_fd;
extern int nat_aware;
extern int nat_status;
extern nonces_list_t *nat_ir_nonce;
extern iface_list_elt *head_interface_list;
extern iface_t *default_ctrl_iface_v4;
extern iface_t *default_ctrl_iface_v6;
extern iface_t *default_out_iface_v4;
extern iface_t *default_out_iface_v6;

extern sockmstr_t *smaster;
extern lisp_ctrl_dev_t *ctrl_dev;
extern lisp_ctrl_t *lctrl;
extern shash_t *iface_addr_ht;


extern void exit_cleanup();

#endif /*LISPD_EXTERNAL_H_*/

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
