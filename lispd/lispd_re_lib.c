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
 * lisp_addr_t functions
 */

inline lisp_afi_t get_lisp_addr_afi(lisp_addr_t *addr) {
    assert(addr);
    return(addr->lafi);
}

inline ip_addr_t *get_lisp_addr_ip(lisp_addr_t *addr){
    /* this should work with both old and new lisp_addr_t ip format */
    assert(addr);
    return(&(addr->ip));
}

inline mc_addr_t *get_lisp_addr_mc(lisp_addr_t *addr){
    assert(addr);
    return (&(addr->mc));
}

inline struct in_addr *get_lisp_addr_ip_v4(lisp_addr_t *addr){
    return get_ip_addr_v4(get_lisp_addr_ip(addr));
}

inline struct in6_addr *get_lisp_addr_ip_v6(lisp_addr_t *addr){
    assert(addr);
    return get_ip_addr_v6(get_lisp_addr_ip(addr));
}

inline ip_afi_t get_lisp_addr_ip_afi(lisp_addr_t *addr){
    return get_ip_addr_afi(get_lisp_addr_ip(addr));
}

inline ip_addr_t *get_lisp_addr_mc_src(lisp_addr_t *addr) {
    assert(addr);
    return get_mc_addr_src(get_lisp_addr_mc(addr));
}

inline ip_addr_t *get_lisp_addr_mc_grp(lisp_addr_t *addr) {
    assert(addr);
    return get_mc_addr_grp(get_lisp_addr_mc(addr));
}

char *get_lisp_addr_to_char(lisp_addr_t *addr) {
    assert(addr);

    switch(get_lisp_addr_afi(addr)) {
    case LM_AFI_IP:
        return(get_ip_addr_to_char(get_lisp_addr_ip(addr)));
        break;
    case LM_AF_MC:
        return(get_mc_addr_to_char(get_lisp_addr_mc(addr)));
        break;
    case LM_AFI_IP6:
        return(get_ip_addr_to_char(get_lisp_addr_ip(addr)));
        break;
    default:
        lisp_log_msg(LISP_LOG_WARNING, "get_lisp_addr_to_char: Trying to convert"
                " to string unknown lisp afi %d", get_lisp_addr_afi(addr) );
        break;

    }
}


inline void set_lisp_addr_afi(lisp_addr_t *addr, afi_t afi) {
    assert(addr);
    addr->afi = afi;
}

inline void set_lisp_addr_mc_src(lisp_addr_t *addr, ip_addr_t *ip) {
    assert(addr);
    assert(ip);
    set_mc_addr_src(get_lisp_addr_mc(addr), ip);
}

inline void set_lisp_addr_mc_grp(lisp_addr_t *addr, ip_addr_t *ip) {
    assert(mc);
    assert(addr);
    set_mc_addr_grp(get_lisp_addr_mc(addr), ip);
}

inline void set_lisp_addr(lisp_addr_t *dst, lisp_addr_t *src) {
    assert(dst);
    assert(src);
    memcpy(dst, src, sizeof(lisp_addr_t));
}




/*
 * ip_addr_t functions
 */

inline ip_afi_t get_ip_addr_afi(ip_addr_t *ipaddr) {
    assert(ipaddr);
    return(ipaddr->afi);
}

inline struct in_addr *get_ip_addr_v4(ip_addr_t *ipaddr) {
    assert(ipaddr);
    return(ipaddr->v4);
}

inline struct in6_addr *get_ip_addr_v6(ip_addr_t *ipaddr) {
    assert(ipaddr);
    return(ipaddr->v6);
}

inline uint8_t get_ip_addr_size(ip_addr_t *ipaddr) {

    switch (get_ip_addr_afi(ipaddr)) {
    case AF_UNSPEC:
        return (0);
    case AF_INET:
        return(sizeof(struct in_addr));
    case AF_INET6:
        return(sizeof(struct in6_addr));
    default:
        lispd_log_msg(LISP_LOG_WARNING, "get_ip_addr_size: unknown IP AFI (%d)", get_ip_addr_afi(ipaddr));
        return(0);
    }
}

inline void set_ip_addr_afi(ip_addr_t *ipaddr, lisp_afi_t afi) {
    assert(ipaddr);
    ipaddr->afi = afi;
}

void set_ip_addr_v4(ip_addr_t *ipaddr, struct in_addr *ipv4) {
    assert(ipaddr);
    set_ip_addr_afi(ipaddr, AF_INET);
    memcpy(get_ip_addr_v4(ipaddr), ipv4, sizeof(struct in_addr));
}

inline void set_ip_addr_v6(ip_addr_t *ipaddr, struct in6_addr *ipv6) {
    assert(ipaddr);
    set_ip_addr_afi(ipaddr, AF_INET6);
    memcpy(get_ip_addr_v6(ipaddr), ipv6, sizeof(struct in6_addr));
}

char *get_ip_addr_to_char (ip_addr_t *addr){
    static char address[10][INET6_ADDRSTRLEN];
    static unsigned int i; //XXX Too much memory allocation for this, but standard syntax

    /* Hack to allow more than one addresses per printf line. Now maximum = 5 */
    i++;
    i = i % 10;

    switch (get_ip_addr_afi(addr)){
    case AF_INET:
        inet_ntop(AF_INET, get_ip_addr_v4(addr), address[i], INET_ADDRSTRLEN);
        return (address[i]);
    case AF_INET6:
        inet_ntop(AF_INET6, get_ip_addr_v6(addr), address[i], INET6_ADDRSTRLEN);
        return (address[i]);
    default:
        return (NULL);
    }
}

inline void set_ip_addr(ip_addr_t *dst, ip_addr_t *src) {
    assert(src);
    assert(dst);
    memcpy(dst, src, sizeof(ip_addr_t));
}




/*
 * mc_addr_t functions
 */

inline void set_mc_addr_src(mc_addr_t *mc, ip_addr_t *ip) {
    assert(mc);
    assert(ip);
    memcpy(&get_mc_addr_src(mc), ip, sizeof(ip_addr_t) );
}

inline void set_mc_addr_grp(mc_addr_t *mc, ip_addr_t *ip) {
    assert(mc);
    assert(ip);
    memcpy(&get_mc_addr_grp(mc), ip, sizeof(ip_addr_t) );
}

inline void set_mc_addr(mc_addr_t *dst, mc_addr_t *src) {
    assert(src);
    assert(dst);
    memcpy(dst, src, sizeof(mc_addr_t));
}


inline ip_addr_t *get_mc_addr_src(mc_addr_t *mc) {
    assert(mc);
    return(&(mc->src));
}

inline ip_addr_t *get_mc_addr_grp(mc_addr_t *mc) {
    assert(mc);
    return(&(mc->grp));
}

char *get_mc_addr_to_char (mc_addr_t *mcaddr){
    static char address[INET6_ADDRSTRLEN*2+4];
    sprintf(address, "(%s,%s)",
            get_ip_addr_to_char(get_mc_addr_src(mcaddr)),
            get_ip_addr_to_char(get_mc_addr_grp(mcaddr)));
    return(address);
}




/*
 * lispd_mapping_elt functions
 */

inline void set_mapping_extended_info(lispd_mapping_elt *mapping, void *extended_info) {
    assert(mapping);
    assert(extended_info);
    mapping->extended_info = extended_info;
}

inline void set_mapping_iid(lispd_mapping_elt *mapping, lisp_iid_t iid) {
    assert(mapping);
    mapping->iid = iid;
}

inline void set_mapping_eid_addr(lispd_mapping_elt *mapping, lisp_addr_t *addr) {
    assert(mapping);
    assert(addr);
    set_lisp_addr(get_mapping_eid_addr(mapping), addr);
}

inline void set_mapping_eid_plen(lispd_mapping_elt *mapping, uint8_t plen) {
    assert(mapping);
    mapping->eid_prefix_length = plen;
}

inline uint8_t get_mapping_ip_eid_plen(lispd_mapping_elt *mapping) {
    assert(mapping);
    if (    get_lisp_addr_afi(get_mapping_eid_addr(mapping)) != LM_AFI_IP &&
            get_lisp_addr_afi(get_mapping_eid_addr(mapping)) != LM_AFI_IP6)
        return(0);

    return(mapping->eid_prefix_length);
}

inline lisp_iid_t get_mapping_iid(lispd_mapping_elt *mapping, lisp_iid_t iid) {
    assert(mapping);
    return(mapping->iid);
}

inline lisp_addr_t *get_mapping_eid_addr(lispd_mapping_elt *mapping) {
    assert(mapping);
    return(&(mapping->eid_prefix));
}

inline lisp_addr_t *get_mapping_mc_eid_addr(lispd_mapping_elt *mapping) {
    assert(mapping);
    if (get_lisp_addr_afi(get_mapping_eid_addr(mapping)) != LM_AFI_MC)
        return(NULL);
    return(&(mapping->eid_prefix));
}

inline uint8_t get_mapping_mc_eid_src_plen(lispd_mapping_elt *mapping){
    assert(mapping);

    /* check if mcast address */
    if (get_lisp_addr_afi(get_mapping_eid_addr(mapping)) != LM_AFI_MC)
        return(0);

    return(mapping->eid_prefix_length);
}

inline uint8_t get_mapping_mc_eid_grp_plen(lispd_mapping_elt *mapping){
    assert(mapping);

    /* check if mcast address */
    if (get_lisp_addr_afi(get_mapping_eid_addr(mapping)) != LM_AFI_MC)
        return(0);

    return(((mcinfo_mapping_extended_info *)mapping->extended_info)->grp_plen);
}

char *get_mapping_eid_prefix_to_char (lispd_mapping_elt *mapping) {
    assert(mapping);

    static char address[INET6_ADDRSTRLEN*2+20];
    lisp_addr_t     *addr   = NULL;
    uint8_t         plen    = NULL;
    uint8_t         gplen   = NULL;

    addr = get_mapping_eid_addr(mapping);

    switch(get_lisp_addr_afi(addr)) {
    case LM_AFI_IP:
        sprintf(address, "%s/%d", get_ip_addr_to_char(addr), get_mapping_ip_eid_plen(mapping));
        break;
    case LM_AFI_IP6:
        sprintf(address, "%s/%d", get_ip_addr_to_char(addr), get_mapping_ip_eid_plen(mapping));
        break;
    case LM_AFI_MC:
        sprintf(address, "(%s/%d,%s/%d)",
                get_ip_addr_to_char(get_mc_addr_src(addr)), get_mapping_mc_eid_src_plen(mapping),
                get_ip_addr_to_char(get_mc_addr_grp(addr)), get_mapping_mc_eid_grp_plen(mapping));
        break;
    default:
        break;
    }
    return(address);
}

inline uint8_t get_mapping_eid_plen(lispd_mapping_elt *mapping) {
    switch (get_lisp_addr_afi(get_mapping_eid_addr(mapping))) {
    case LM_AFI_IP:
        return(get_mapping_ip_eid_plen(mapping));
        break;
    case LM_AFI_IP6:
        return(get_mapping_ip_eid_plen(mapping));
        break;
    case LM_AFI_MC:
        /* Hack to simplify processing of mc_addr_t.
         * Return prefix length of S because
         * it is used in the first step of storing
         * (S,G) in the map-cache
         */
        return(get_mapping_mc_eid_src_plen(mapping));
        break;
    default:
        lisp_log_msg(LISP_LOG_WARNING, "get_lisp_addr_to_char: Trying to convert"
                " to string unknown afi %d", get_lisp_addr_afi(addr) );
        return(0);
        break;
    }
}




/*
 * lispd_map_cache_entry  functions
 */

inline void set_mcache_entry_eid_addr(lispd_map_cache_entry *mapcache, lisp_addr_t *addr) {
    set_mapping_eid_addr(get_mcache_entry_mapping(mapcache), addr);
}

inline void set_mcache_entry_eid_plen(lispd_map_cache_entry *mapcache, uint_8 plen) {
    set_mapping_eid_plen(get_mcache_mapping(mapcache), addr);
}


inline lispd_mapping_elt *get_mcache_entry_mapping(lispd_map_cache_entry* mapcache) {
    assert(mapcache);
    return(&(mapcache->mapping));
}

inline lisp_addr_t *get_mcache_entry_eid_addr(lispd_map_cache_entry* mapcache) {
    return(get_mapping_eid_addr(get_mcache_entry_mapping(mapcache)));
}

inline uint8_t get_mcache_entry_eid_plen(lispd_map_cache_entry *mapcache) {
    return(get_mapping_eid_plen(get_mcache_entry_mapping(mapcache)));
}

char *get_mcache_entry_eid_prefix_to_char(lispd_map_cache_entry *mapcache) {
    return(get_mapping_eid_prefix_to_char(get_mcache_entry_mapping(mapcache)));
}

#endif /* LISPD_RE_LIB_H_ */
