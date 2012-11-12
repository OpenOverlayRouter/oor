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

#include "lispd.h"
#include "lispd_iface_list.h"


extern  lispd_database_t  *lispd_database;
extern  lispd_map_cache_t *lispd_map_cache;
extern  patricia_tree_t   *AF4_database;
extern  patricia_tree_t   *AF6_database;
extern  datacache_t   *datacache;

extern  lispd_addr_list_t *map_resolvers;
extern  lispd_addr_list_t *proxy_itrs;
extern  lispd_weighted_addr_list_t *proxy_etrs;
extern  lispd_map_server_list_t *map_servers;
extern  char            *config_file;
extern  char            *map_resolver;
extern  char            *map_server;
extern  char            *proxy_etr;
extern  char            *proxy_itr;
extern  char            msg[];
extern  int             map_request_retries;
extern  int             control_port;
extern  int             debug;
extern  int             daemonize;

extern  int         netlink_fd;
extern  int         v6_receive_fd;
extern  int         v4_receive_fd;
extern  int         timers_fd;
#ifdef LISPMOBMH
extern  int			smr_timer_fd;
#endif
extern  struct  sockaddr_nl dst_addr;
extern  struct  sockaddr_nl src_addr;
extern  nlsock_handle       nlh;
extern  lispd_iface_elt      *ctrl_iface;
extern  lisp_addr_t         source_rloc;

#endif /*LISPD_EXTERNAL_H_*/

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
