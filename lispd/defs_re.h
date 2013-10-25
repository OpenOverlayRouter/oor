/*
 * defs_re.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
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
 *    Florin Coras  <fcoras@ac.upc.edu>
 *
 */

#ifndef DEFS_RE_H_
#define DEFS_RE_H_

#include <stdio.h>
#include "lispd.h"
#include "lispd_lib.h"
#include "lispd_re_control.h"



/*
 * lisp_addr_t functions
 */

extern inline lisp_afi_t        get_lisp_addr_afi(lisp_addr_t *addr);
extern inline ip_addr_t         *get_lisp_addr_ip(lisp_addr_t *addr);
extern inline mc_addr_t         *get_lisp_addr_mc(lisp_addr_t *addr);
extern inline struct in_addr    *get_lisp_addr_ip_v4(lisp_addr_t *addr);
extern inline struct in6_addr   *get_lisp_addr_ip_v6(lisp_addr_t *addr);
extern inline ip_afi_t          get_lisp_addr_ip_afi(lisp_addr_t *addr);
extern inline ip_addr_t         *get_lisp_addr_mc_src(lisp_addr_t *addr);
extern inline ip_addr_t         *get_lisp_addr_mc_grp(lisp_addr_t *addr);
extern char                     *get_lisp_addr_to_char(lisp_addr_t *addr);
extern inline void              set_lisp_addr_afi(lisp_addr_t *addr, afi_t afi);
extern inline void              set_lisp_addr_mc_src(lisp_addr_t *addr, ip_addr_t *ip);
extern inline void              set_lisp_addr_mc_grp(lisp_addr_t *addr, ip_addr_t *ip);
extern inline void              set_lisp_addr(lisp_addr_t *dst, lisp_addr_t *src);

/*
 * ip_addr_t functions
 */

extern inline ip_afi_t          get_ip_addr_afi(ip_addr_t *ipaddr);
extern inline struct in_addr    *get_ip_addr_v4(ip_addr_t *ipaddr);
extern inline struct in6_addr   *get_ip_addr_v6(ip_addr_t *ipaddr);
extern inline uint8_t           get_ip_addr_size(ip_addr_t *ipaddr);
extern inline void              set_ip_addr_afi(ip_addr_t *ipaddr, lisp_afi_t afi);
extern inline void              set_ip_addr_v4(ip_addr_t *ipaddr, struct in_addr *ipv4);
extern inline void              set_ip_addr_v6(ip_addr_t *ipaddr, struct in6_addr *ipv6);
extern char                     *get_ip_addr_to_char (ip_addr_t *addr);
extern inline void              set_ip_addr(ip_addr_t *dst, ip_addr_t *src);



/*
 * mc_addr_t functions
 */

extern inline void              set_mc_addr_src(mc_addr_t *mc, ip_addr_t *ip);
extern inline void              set_mc_addr_grp(mc_addr_t *mc, ip_addr_t *ip);
extern inline ip_addr_t         *get_mc_addr_src(mc_addr_t *mc);
extern inline ip_addr_t         *get_mc_addr_grp(mc_addr_t *mc);
extern char                     *get_mc_addr_to_char (mc_addr_t *mcaddr);
extern inline void              set_mc_addr(mc_addr_t *dst, mc_addr_t *src);


/*
 * lispd_mapping_elt functions
 */

extern inline void              set_mapping_iid(lispd_mapping_elt *mapping, uint16_t iid);
extern inline void              set_mapping_extended_info(lispd_mapping_elt *mapping, void *extended_info);
extern inline void              set_mapping_eid_addr(lispd_mapping_elt *mapping, lisp_addr_t *addr);
extern inline void              set_mapping_eid_plen(lispd_mapping_elt *mapping, uint8_t plen);
extern inline lisp_addr_t       *get_mapping_eid_addr(lispd_mapping_elt *mapping);
extern inline lisp_addr_t       *get_mapping_mc_eid_addr(lispd_mapping_elt *mapping);
extern inline uint8_t           get_mapping_ip_eid_plen(lispd_mapping_elt *mapping);
extern inline uint8_t           get_mapping_mc_eid_src_plen(lispd_mapping_elt *mapping);
extern inline uint8_t           get_mapping_mc_eid_grp_plen(lispd_mapping_elt *mapping);
extern inline lisp_iid_t        get_mapping_iid(lispd_mapping_elt *mapping, lisp_iid_t iid);
extern char                     *get_mapping_eid_prefix_to_char (lispd_mapping_elt *mapping);
extern inline uint8_t           get_mapping_eid_plen(lispd_mapping_elt *mapping);

/*
 * lispd_map_cache_entry  functions
 */

extern inline void                  set_mcache_entry_eid_addr(lispd_map_cache_entry *mapcache, lisp_addr_t *addr);
extern inline void                  set_mcache_entry_eid_plen(lispd_map_cache_entry *mapcache, uint_8 plen);
extern inline lispd_mapping_elt     *get_mcache_entry_mapping(lispd_map_cache_entry* mapcache);
extern inline lisp_addr_t           *get_mcache_entry_eid_addr(lispd_map_cache_entry* mapcache);
extern inline uint8_t               get_mcache_entry_eid_plen(lispd_map_cache_entry* mapcache);
extern char                         *get_mcache_entry_eid_prefix_to_char(lispd_map_cache_entry *mapcache);

#endif /* DEFS_RE_H_ */
