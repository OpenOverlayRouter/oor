/*
 * lispd_re_lib.c
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

#ifndef LISPD_RE_LIB_H_
#define LISPD_RE_LIB_H_

#include "defs_re.h"








/*
 * lispd_map_cache_entry  functions
 */

inline void mcache_entry_set_eid_addr(lispd_map_cache_entry *mce, lisp_addr_t *addr) {
    mapping_set_eid_addr(mcache_entry_get_mapping(mce), addr);
}


inline lispd_mapping_elt *mcache_entry_get_mapping(lispd_map_cache_entry* mce) {
    assert(mce);
    return(&(mce->mapping));
}

inline lisp_addr_t *mcache_entry_get_eid_addr(lispd_map_cache_entry *mce) {
    return(mapping_get_eid_addr(mcache_entry_get_mapping(mce)));
}

inline nonces_list *mcache_entry_get_nonces_list(lispd_map_cache_entry *mce) {
    assert(mce);
    return(mce->nonces);
}





/*
 * other
 */

int ip_addr_is_link_local (lisp_addr_t addr) {
    /*
     * Return TRUE if the address belongs to:
     *          IPv4: 169.254.0.0/16
     *          IPv6: fe80::/10
     */
    int         is_link_local = FALSE;
    uint32_t    ipv4_network  = 0;
    uint32_t    mask          = 0;

    switch (lisp_addr_get_afi(addr)){
        case AF_INET:
            inet_pton(AF_INET,"169.254.0.0",&(ipv4_network));
            inet_pton(AF_INET,"255.255.0.0",&(mask));
            if ((addr.address.ip.s_addr & mask) == ipv4_network){
                is_link_local = TRUE;
            }
            break;
        case AF_INET6:
            if (((addr.address.ipv6.__in6_u.__u6_addr8[0] & 0xff) == 0xfe) &&
                    ((addr.address.ipv6.__in6_u.__u6_addr8[1] & 0xc0) == 0x80)){
                is_link_local = TRUE;
            }
            break;
    }

    return (is_link_local);
}

inline uint8_t ip_addr_is_multicast(ip_addr_t *addr) {
    switch(ip_addr_get_afi(addr)) {
    case AF_INET:
        return ipv4_addr_is_multicast(ip_addr_get_v4(addr));
        break;
    case AF_INET6:
        return ipv6_addr_is_multicast(ip_addr_get_v6(addr));
        break;
    default:
        lisp_log_msg(LISP_LOG_WARNING, "is_multicast_addr: Unknown afi %s",
                ip_addr_get_afi(addr));
        break;
    }
    return(0);
}

inline uint8_t ipv4_addr_is_multicast(struct in_addr *addr) {
    if (ntohl(addr->s_addr)>=MCASTMIN4 && ntohl(addr->s_addr)<=MCASTMAX4)
        return(1);
    else
        return(0);
}

inline uint8_t ipv6_addr_is_multicast(struct in_addr *addr) {
    /* TODO fcoras: implement this */
    lisp_log_msg(LISP_LOG_WARNING, "is_multicast_addr6 : THIS IS A STUB for "
            "IPv6 multicast address test!");
    return(0);
}

inline int tuple_get_dst_lisp_addr(packet_tuple tuple, lisp_addr_t *addr){

    uint16_t plen;
    plen = (tuple->dst_addr->afi == AF_INET) ? 32 : 128;

    /* TODO tuple fields dst and src address are lisp_addr_t should be ip_addr_t*/
    if (ip_addr_is_multicast(lisp_addr_get_ippref(&(tuple->dst_addr)))) {
        lisp_addr_set_afi(LM_AFI_LCAF);
        lcaf_addr_set_type(lisp_addr_get_lcaf(tuple->dst_addr), LCAF_MCAST_INFO);
        mc_addr_set(
                lcaf_addr_get_mc(lisp_addr_get_lcaf(addr)),
                ip_prefix_get_addr(lisp_addr_get_ippref(&(tuple->src_addr))),
                ip_prefix_get_addr(lisp_addr_get_ippref(&(tuple->dst_addr))),
                plen, plen, 0);
    } else {
        /* XXX this converts from old lisp_addr_t to new struct, potential source for errors*/
//        addr->lafi = tuple->src_addr.lafi;
        lisp_addr_set_afi(addr, LM_AFI_IPPREF);
        ip_prefix_set(lisp_addr_get_ippref(addr), ip_prefix_get_addr(lisp_addr_get_ippref(&(tuple->dst_addr))), plen);
    }

    return(GOOD);
}

#endif /* LISPD_RE_LIB_H_ */
