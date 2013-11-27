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
#include "lispd_lcaf.h"
//#include "lispd_lib.h"
#include "lispd_re.h"
#include "lispd_re_jib.h"
#include "lispd_generic_list.h"
#include "lispd_afi.h"
#include "lispd.h"

#define MCASTMIN4   0xE0000000
#define MCASTMAX4   0xEFFFFFFF

/* foreach for old lists */
#define list_for_each_old(pos, head) \
    for (pos = (head)->next; pos != (NULL); \
            pos = pos->next)

/*
 * lisp_addr_t functions
 */
extern inline lisp_addr_t       *lisp_addr_new();
extern inline lisp_addr_t       *lisp_addr_new_ip();
extern inline lisp_addr_t       *lisp_addr_new_ippref();
extern inline lisp_addr_t       *lisp_addr_new_lcaf();
extern inline lisp_addr_t       *lisp_addr_new_afi(uint8_t afi);
extern inline void              lisp_addr_del(lisp_addr_t *laddr);
extern inline lisp_afi_t        lisp_addr_get_afi(lisp_addr_t *addr);
extern inline ip_addr_t         *lisp_addr_get_ip(lisp_addr_t *addr);
extern inline ip_addr_t         *lisp_addr_get_ippref(lisp_addr_t *addr);
extern inline mc_addr_t         *lisp_addr_get_mc(lisp_addr_t *addr);
extern inline ip_afi_t          lisp_addr_get_ip_afi(lisp_addr_t *addr);
extern inline lisp_addr_t       *lisp_addr_get_mc_src(lisp_addr_t *addr);
extern inline lisp_addr_t       *lisp_addr_get_mc_grp(lisp_addr_t *addr);
extern inline lcaf_addr_t       *lisp_addr_get_lcaf(lisp_addr_t *addr);
extern inline uint16_t           lisp_addr_get_iana_afi(lisp_addr_t laddr);

extern inline uint16_t          lisp_addr_get_plen(lisp_addr_t *laddr);
extern inline uint32_t          lisp_addr_get_size_in_pkt(lisp_addr_t *laddr);
extern char                     *lisp_addr_to_char(lisp_addr_t *addr);

extern inline void              lisp_addr_set_afi(lisp_addr_t *addr, lisp_afi_t afi);
extern inline void              lisp_addr_set_ip(lisp_addr_t *addr, ip_addr_t *ip);
extern inline void              lisp_addr_copy(lisp_addr_t *dst, lisp_addr_t *src);
extern inline uint32_t          lisp_addr_copy_to(void *dst, lisp_addr_t *src);
extern inline int               lisp_addr_copy_to_pkt(void *offset, lisp_addr_t *laddr, uint8_t convert);
extern inline uint8_t           lisp_addr_is_mc(lisp_addr_t *laddr);
extern inline uint8_t           lisp_addr_is_lcaf(lisp_addr_t *laddr);



/*
 * ip_addr_t functions
 */

extern inline ip_addr_t         *ip_addr_new();
inline void                     ip_addr_del(ip_addr_t *ip);
extern inline ip_afi_t          ip_addr_get_afi(ip_addr_t *ipaddr);
extern inline uint8_t           *ip_addr_get_addr(ip_addr_t *ipaddr);
extern inline struct in_addr    *ip_addr_get_v4(ip_addr_t *ipaddr);
extern inline struct in6_addr   *ip_addr_get_v6(ip_addr_t *ipaddr);
extern inline uint8_t           ip_addr_get_size(ip_addr_t *ipaddr);
extern inline uint8_t           ip_addr_get_size_in_pkt(ip_addr_t *ipaddr);
extern inline uint8_t           ip_addr_afi_to_size(uint8_t afi);
extern inline uint16_t          ip_addr_get_iana_afi(ip_addr_t *ipaddr);
extern inline void              ip_addr_set_afi(ip_addr_t *ipaddr, lisp_afi_t afi);
extern inline void              ip_addr_set_v4(ip_addr_t *ipaddr, void *src);
extern inline void              ip_addr_set_v6(ip_addr_t *ipaddr, void *src);
extern inline void              ip_addr_copy(ip_addr_t *dst, ip_addr_t *src);
extern inline void              ip_addr_copy_to(void *dst, ip_addr_t *src);
extern inline uint8_t           *ip_addr_copy_to_pkt(void *dst, ip_addr_t *src, uint8_t convert);
extern inline int               ip_addr_read_from_pkt(void *offset, uint16_t afi, ip_addr_t *dst);
extern inline int               ip_addr_cmp(ip_addr_t *ip1, ip_addr_t *ip2);
extern inline uint16_t          ip_afi_to_iana_afi(uint16_t afi);
extern char                     *ip_addr_to_char (ip_addr_t *addr);



/*
 * ip_prefix_t functions
 */
extern inline void              ip_prefix_get_plen(ip_prefix_t *pref);
extern inline ip_addr_t         *ip_prefix_get_addr(ip_prefix_t *pref);
extern inline uint8_t           ip_prefix_get_afi(ip_prefix_t *pref);
extern inline void              ip_prefix_set(ip_prefix_t *pref, ip_addr_t *ipaddr, uint8_t plen);
extern inline void              ip_prefix_set_plen(ip_prefix_t *pref, uint8_t plen);

extern char                     *ip_prefix_to_char(ip_prefix_t *pref);



/*
 * mc_addr_t functions
 */

extern inline mc_addr_t         *mc_addr_new();
extern inline void              mc_addr_del(void *mcaddr);
extern inline mc_addr_t         *mc_addr_init(ip_addr_t *src, ip_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);
extern inline void              mc_addr_set_src(mc_addr_t *mc, ip_addr_t *ip);
extern inline void              mc_addr_set_grp(mc_addr_t *mc, ip_addr_t *ip);
extern inline lisp_addr_t       *mc_addr_get_src(mc_addr_t *mc);
extern inline lisp_addr_t       *mc_addr_get_grp(mc_addr_t *mc);
extern inline uint32_t          *mc_addr_get_iid(mc_addr_t *mc);
extern inline uint8_t           mc_addr_get_src_plen(mc_addr_t *mc);
extern inline uint8_t           mc_addr_get_grp_plen(mc_addr_t *mc);
extern inline uint16_t          mc_addr_get_src_afi(mc_addr_t *mc);
extern inline uint16_t          mc_addr_get_src_afi(mc_addr_t *mc);
extern char                     *mc_addr_to_char (mc_addr_t *mcaddr);
extern inline uint32_t          mc_addr_get_size_in_pkt(mc_addr_t *mc);
extern inline uint8_t           *mc_addr_copy_to_pkt(void *offset, mc_addr_t *mc);
extern inline void              mc_addr_copy(mc_addr_t *dst, mc_addr_t *src);
extern inline void              mc_addr_set(mc_addr_t *dst, ip_addr_t *src, ip_addr_t *grp);



/*
 * iid_addr_t functions
 */

extern inline iid_addr_t        *iid_addr_new();
extern inline uint8_t           iid_addr_get_mlen(iid_addr_t *addr);
inline inline uint32_t          iid_addr_get_iidaddr(iid_addr_t *addr);

extern inline void              iid_addr_set_iid(iid_addr_t *addr, uint32_t iid);
extern inline void              iid_addr_set_mlen(iid_addr_t *addr, uint8_t mlen);
extern inline int               iid_addr_cmp(iid_addr_t *iid1, iid_addr_t *iid2);
extern inline uint32_t          iid_addr_get_size_in_pkt(iid_addr_t *iid);
extern inline uint8_t           *iid_addr_copy_to_pkt(void *offset, iid_addr_t *iid);
extern inline uint32_t          iid_addr_read_from_pkt(void *offset, iid_addr_t *iid);





/*
 * geo_addr_t functions
 */
extern inline void              geo_addr_set_lat(geo_addr_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
extern inline void              geo_addr_set_long(geo_addr_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
extern inline void              geo_addr_set_altitude(geo_addr_t *geo, uint32_t altitude);
extern inline uint32_t          geo_addr_read_from_pkt(void *offset, geo_addr_t *geo);





/*
 * lispd_mapping_elt functions
 */

extern inline void              mapping_set_iid(lispd_mapping_elt *mapping, uint16_t iid);
extern inline void              mapping_set_extended_info(lispd_mapping_elt *mapping, void *extended_info);
extern inline void              set_mapping_eid_addr(lispd_mapping_elt *mapping, lisp_addr_t *addr);
extern inline void              mapping_set_eid_plen(lispd_mapping_elt *mapping, uint8_t plen);
extern inline lisp_addr_t       *mapping_get_eid_addr(lispd_mapping_elt *mapping);
extern inline uint8_t           get_mapping_ip_eid_plen(lispd_mapping_elt *mapping);
extern inline uint8_t           get_mapping_mc_eid_src_plen(lispd_mapping_elt *mapping);
extern inline uint8_t           get_mapping_mc_eid_grp_plen(lispd_mapping_elt *mapping);
extern inline lisp_iid_t        get_mapping_iid(lispd_mapping_elt *mapping, lisp_iid_t iid);
extern char                     *get_mapping_eid_prefix_to_char (lispd_mapping_elt *mapping);
extern lispd_jib_t              *mapping_get_jib(lispd_mapping_elt *mapping);
extern inline uint8_t           get_mapping_eid_plen(lispd_mapping_elt *mapping);


/*
 * lispd_map_cache_entry  functions
 */

extern inline void                  mcache_entry_set_eid_addr(lispd_map_cache_entry *mapcache, lisp_addr_t *addr);
extern inline void                  mcache_entry_set_eid_plen(lispd_map_cache_entry *mapcache, uint8_t plen);
extern inline lispd_mapping_elt     *mcache_entry_get_mapping(lispd_map_cache_entry* mapcache);
extern inline lisp_addr_t           *mcache_entry_get_eid_addr(lispd_map_cache_entry* mapcache);
extern inline nonces_list           *mcache_entry_get_nonces_list(lispd_map_cache_entry *mce);




/*
 * other
 */
extern inline uint8_t               ip_addr_is_multicast(ip_addr_t addr);
extern inline uint8_t               ipv4_addr_is_multicast(struct in_addr *addr);
extern inline uint8_t               ipv6_addr_is_multicast(struct in6_addr *addr);
extern inline uint8_t               tuple_get_dst_lisp_addr(packet_tuple tuple, lisp_addr_t *addr);


#endif /* DEFS_RE_H_ */
