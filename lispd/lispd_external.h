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

#include "lispd.h"

/* from patricia.h */


extern  uint64_t build_nonce(int seed);
extern  struct udphdr *build_ip_header();
extern  int get_afi(char * str);
extern  lisp_addr_t *get_my_addr(char *if_name, int afi);
extern  lisp_addr_t *lispd_get_address(char *host,
                    lisp_addr_t *addr,
                    uint32_t *flags);
extern  lisp_addr_t *lispd_get_ifaceaddress(char *iface_name,
                                        lisp_addr_t *addr);
extern  uint8_t *build_map_request_pkt();
extern int process_map_reply(uint8_t *packet);
extern  lispd_pkt_map_register_t *build_map_register_pkt (lispd_locator_chain_t
                              *locator_chain);
extern  int install_database_mapping(lispd_db_entry_t *db_entry);
extern  patricia_node_t * make_and_lookup (patricia_tree_t *tree,
                       int afi, char *string);
extern  char *prefix_toa (prefix_t * prefix);
extern  int setup_netlink_iface();
extern  int process_netlink_iface();
extern  int update_iface_list(char *iface_name, 
                                char *eid_preifx, 
                                lispd_db_entry_t *db_entry, int ready,
                                int weight, int priority);
extern  iface_list_elt *find_active_ctrl_iface ();
extern  iface_list_elt *search_iface_list(char *iface_name);


extern  iface_list_elt *get_first_iface_elt();

extern  void add_item_to_db_entry_list(db_entry_list *dbl, 
                                        db_entry_list_elt *elt);
extern  int del_item_from_db_entry_list(db_entry_list *dbl, 
                                        lispd_db_entry_t *elt);

#ifdef LISPMOBMH
extern  void smr_pitrs(void);
#endif


extern  lispd_database_t  *lispd_database;
extern  lispd_map_cache_t *lispd_map_cache;
extern  patricia_tree_t   *AF4_database;
extern  patricia_tree_t   *AF6_database;
extern  datacache_t   *datacache;

extern  lispd_addr_list_t *map_resolvers;
extern  lispd_addr_list_t *proxy_etrs;
extern  lispd_addr_list_t *proxy_itrs;
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
extern  int         map_register_timer_fd;
#ifdef LISPMOBMH
extern  int			smr_timer_fd;
#endif
extern  struct  sockaddr_nl dst_addr;
extern  struct  sockaddr_nl src_addr;
extern  nlsock_handle       nlh;
extern  iface_list_elt      *ctrl_iface; 
extern  lisp_addr_t         source_rloc;

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
