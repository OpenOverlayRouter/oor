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

inline lisp_addr_t *lisp_addr_new_ip() {
    lisp_addr_t *laddr = lisp_addr_new();
    lisp_addr_set_afi(laddr, LM_AFI_IP);
    ip_addr_set_afi(lisp_addr_get_ip(laddr), AF_UNSPEC);
    return(laddr);
}

inline lisp_addr_t *lisp_addr_new_ippref() {
    lisp_addr_t *laddr = lisp_addr_new();
    lisp_addr_set_afi(laddr, LM_AFI_IPPREF);
    return(laddr);
}

inline lisp_addr_t *lisp_addr_new_lcaf() {
    lisp_addr_t *laddr;
    lcaf_addr_t *lcaf;

    laddr = lisp_addr_new();
    lcaf = lisp_addr_get_lcaf(laddr);
    lcaf = lcaf_addr_new();

    lisp_addr_set_afi(laddr, LM_AFI_LCAF);
    return(laddr);
}

inline lisp_addr_t *lisp_addr_new_afi(uint8_t afi) {
    switch(afi) {
        case LM_AFI_IP:
            return(lisp_addr_new_ip());
        case LM_AFI_IPPREF:
            return(lisp_addr_new_ippref());
        case LM_AFI_LCAF:
            return(lisp_addr_new_lcaf());
        default:
            lisp_log_msg(LISP_LOG_WARNING, "lisp_addr_new_afi: unknown lisp addr afi %d", afi);
            break;
    }
    return(NULL);
}

inline lisp_addr_t *lisp_addr_new() {
    return(calloc(1, sizeof(lisp_addr_t)));
}

inline void lisp_addr_del(lisp_addr_t *laddr) {
    switch (lisp_addr_get_afi(laddr)) {
        case LM_AFI_IPPREF:
            free(laddr);
            break;
        case LM_AFI_LCAF:
            lcaf_addr_del(lips_addr_get_lcaf(laddr));
            free(laddr);
            break;
        default:
            lisp_log_msg(LISP_LOG_WARNING, "lisp_addr_delete: unknown lisp addr afi %d", lisp_addr_get_afi(laddr));
            return;
    }
}

inline lisp_afi_t lisp_addr_get_afi(lisp_addr_t *addr) {
    assert(addr);
    return(addr->afi);
}

inline ip_addr_t *lisp_addr_get_ip(lisp_addr_t *addr) {
    /* this should work with both old and new lisp_addr_t ip format */
    assert(addr);
    return(&(addr->ip));
}

inline ip_addr_t *lisp_addr_get_ippref(lisp_addr_t *addr) {
    assert(addr);
    return(&(addr->ippref));
}

inline mc_addr_t *lisp_addr_get_mc(lisp_addr_t *addr){
    assert(addr);
    return (&(addr->mc));
}

inline ip_afi_t lisp_addr_get_ip_afi(lisp_addr_t *addr){
    return ip_addr_get_afi(lisp_addr_get_ippref(addr));
}

inline ip_addr_t *lisp_addr_get_mc_src(lisp_addr_t *addr) {
    assert(addr);
    return mc_addr_get_src(lisp_addr_get_mc(addr));
}

inline ip_addr_t *lisp_addr_get_mc_grp(lisp_addr_t *addr) {
    assert(addr);
    return mc_addr_get_grp(lisp_addr_get_mc(addr));
}

inline lcaf_addr_t *lisp_addr_get_lcaf(lisp_addr_t *addr) {
    assert(addr);
    return(&(addr->lcaf));
}

inline uint16_t lisp_addr_get_iana_afi(lisp_addr_t laddr) {

    switch (lisp_addr_get_afi(laddr)) {
        case LM_AFI_IPPREF:
            return(ip_addr_get_iana_afi(ip_prefix_get_addr(lisp_addr_get_ippref(laddr))));
            break;
        case LM_AFI_LCAF:
            return(LISP_AFI_LCAF);
        case LM_AFI_NO_ADDR:
            return(LISP_AFI_NO_ADDR);
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2, "lisp_addr_get_iana_afi: unknown AFI (%d)", lisp_addr_get_afi(laddr));
            return (BAD);
    }
}

inline uint32_t lisp_addr_get_size_in_pkt(lisp_addr_t *laddr) {
    /* Returns the size needed in a packet for laddr */
    switch(lisp_addr_get_afi(laddr)) {
        case LM_AFI_NO_ADDR:
            return(sizeof(uint16_t));
        case LM_AFI_IPPREF:
            return(ip_addr_get_size_in_pkt(ip_prefix_get_addr(lisp_addr_get_ippref(laddr))));
            break;
        case LM_AFI_LCAF:
            return(lcaf_addr_get_size_in_pkt(lisp_addr_get_lcaf(laddr)));
        default:
            break;
    }
    return(0);
}

inline uint16_t lisp_addr_get_plen(lisp_addr_t *laddr) {
    /* XXX: hack to obtain a prefixlen to be used in the mapcache.
     * Should be removed in the future! */
    switch (lisp_addr_get_afi(laddr)) {
        case LM_AFI_IPPREF:
            return(ip_prefix_get_plen(lisp_addr_get_ippref(laddr)));
            break;
        case LM_AFI_LCAF:
            switch(lcaf_addr_get_type(lisp_addr_get_lcaf(laddr))) {
                case LCAF_MCAST_INFO:
                    return(mc_addr_get_src_plen(lcaf_addr_get_mc(laddr)));
                    break;
                default:
                    lispd_log_msg(LISP_LOG_DEBUG_2, "replace_map_cache_entry: uknown lcaf type (%d)",
                            lcaf_addr_get_type(lisp_addr_get_lcaf(laddr)));
                    break;
            }
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2, "replace_map_cache_entry: uknown afi type (%d)", lisp_addr_get_afi(laddr));
            break;
    }
    return(0);
}

char *lisp_addr_to_char(lisp_addr_t *addr) {
    assert(addr);

    switch(lisp_addr_get_afi(addr)) {
        case LM_AFI_IPPREF:
        case LM_AFI_IP6:
            return(ip_prefix_to_char(lisp_addr_get_ippref(addr)));
            break;
        case LM_AFI_LCAF:
            return(lcaf_addr_to_char(lisp_addr_get_lcaf(addr)));
            break;
        default:
            lisp_log_msg(LISP_LOG_WARNING, "get_lisp_addr_to_char: Trying to convert"
                    " to string unknown lisp afi %d", lisp_addr_get_afi(addr) );
            break;
    }
    return(NULL);
}


inline void lisp_addr_set_afi(lisp_addr_t *addr, lisp_afi_t afi) {
    assert(addr);
    addr->lafi = afi;
}


inline void lisp_addr_copy(lisp_addr_t *dst, lisp_addr_t *src) {
    assert(src);
    if (!dst)
        dst = lisp_addr_new();

    lisp_addr_set_afi(dst, lisp_addr_get_afi(src));
    switch (lisp_addr_get_afi(dst)) {
        case LM_AFI_IP:
            ip_addr_copy(lisp_addr_get_ip(dst), lisp_addr_get_ip(src));
            break;
        case LM_AFI_IPPREF:
            ip_prefix_copy(lisp_addr_get_ippref(dst), lisp_addr_get_ippref(src));
            break;
        case LM_AFI_LCAF:
            lcaf_addr_copy(lisp_addr_get_lcaf(dst), lisp_addr_get_lcaf(src));
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2,"lisp_addr_copy:  Unknown AFI type %d in EID", lisp_addr_get_afi(dst));
            break;
    }
}

inline uint32_t lisp_addr_copy_to(void *dst, lisp_addr_t *src) {
    assert(dst);
    assert(src);

    switch (lisp_addr_get_afi(src)) {
        case LM_AFI_IP:
            ip_addr_copy_to(dst, lisp_addr_get_ip(src));
            return(ip_addr_get_size(lisp_addr_get_ip(src)));
        case LM_AFI_IPPREF:
            ip_addr_copy_to(dst, ip_prefix_get_addr(lisp_addr_get_ippref(src)));
            return(ip_addr_get_size(ip_prefix_get_addr(lisp_addr_get_ippref(src))));
        case LM_AFI_LCAF:
            break;
        default:
            break;
    }
    return(0);
}

inline uint8_t *lisp_addr_copy_to_pkt(void *offset, lisp_addr_t *laddr) {
    assert(offset);
    assert(laddr);

//    (uint16_t *)offset = htons(lisp_addr_get_iana_afi(laddr));
    memset(offset, htons(lisp_addr_get_iana_afi(laddr)), sizeof(uint16_t));
    offset = CO(offset, sizeof(uint16_t));

    switch (lisp_addr_get_afi(laddr)) {
        case LM_AFI_IPPREF:
            /* XXX: I'm using 0 as in previous code!! Not sure this is right */
            return(ip_addr_copy_to_pkt(offset, lisp_addr_get_ippref(laddr), 0));
        case LM_AFI_LCAF:
            return(lcaf_addr_copy_to_pkt(laddr, offset));
        case LM_AFI_NO_ADDR:
            memset(offset, 0, lisp_addr_get_size_in_pkt(laddr));
            return(CO(offset, lisp_addr_get_size_in_pkt(laddr)));
        default:
            break;
    }
    return(NULL);
}


int lisp_addr_read_from_pkt(void **offset, lisp_addr_t *laddr) {
    uint8_t                 *cur_ptr;
    uint16_t                afi, len;

    cur_ptr  = *offset;
    afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr = CO(cur_ptr, sizeof(uint16_t));
    len = 0;

    switch(afi) {
        case LISP_AFI_IP:
        case LISP_AFI_IPV6:
            len = ip_addr_read_from_pkt(cur_ptr, afi,ip_prefix_get_addr(lisp_addr_get_ippref(laddr)));
            lisp_addr_set_afi(laddr, LM_AFI_IPPREF);
            break;
        case LISP_AFI_LCAF:
            len = lcaf_addr_read_from_pkt(cur_ptr, lisp_addr_get_lcaf(laddr));
            break;
        case LISP_AFI_NO_ADDR:
            len = sizeof(uint16_t);
            lisp_addr_set_afi(laddr, LM_AFI_NO_ADDR);
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_eid_afi:  Unknown AFI type %d in EID", lisp_addr_get_afi(laddr));
            return(BAD);
            break;
    }
    cur_ptr = CO(cur_ptr, len);
    *offset = cur_ptr;

    return (GOOD);
}

inline int lisp_addr_cmp(lisp_addr_t *addr1, lisp_addr_t *addr2) {
    /*
     * Compare two lisp_addr_t.
     * Returns:
     *          -1: If they are from different afi
     *           0: Both address are the same
     *           1: Addr1 is bigger than addr2
     *           2: Addr2 is bigger than addr1
     */

      int cmp;
      if ( !addr1 || !addr2){
          return (-1);
      }
      if (lisp_addr_get_afi(addr1) != lisp_addr_get_afi(addr2)){
          return (-1);
      }

      switch (lisp_addr_get_afi(addr1)) {
          case LM_AFI_IPPREF:
              cmp = ip_addr_cmp(ip_prefix_get_addr(lisp_addr_get_ippref(addr1)), ip_prefix_get_addr(lisp_addr_get_ippref(addr2)));
              break;
          case LM_AFI_LCAF:
              cmp = lcaf_addr_com(lisp_addr_get_lcaf(addr1), lisp_addr_get_lcaf(addr2));
              break;
          default:
              break;
      }

      if (cmp == 0)
          return (0);
      else if (cmp > 0)
          return (1);
      else
          return (2);
}

inline uint8_t lisp_addr_cmp_iids(lisp_addr_t *addr1, lisp_addr_t *addr2) {
    if (lisp_addr_get_afi(addr1) != lisp_addr_get_afi(addr2))
        return(0);

    switch(lisp_addr_get_afi(addr1)) {
        case LM_AFI_LCAF:
            return(lcaf_addr_cmp_iids(lisp_addr_get_lcaf(addr1), lisp_addr_get_lcaf(addr2)));
        default:
            return(0);
    }
}


inline uint8_t lisp_addr_is_mc(lisp_addr_t *laddr) {
    assert(laddr);
    if (!lisp_addr_is_lcaf(laddr))
        return(0);

    return(lcaf_addr_get_type(lisp_addr_get_lcaf(laddr)) == LCAF_MCAST_INFO);
}

inline uint8_t lisp_addr_is_lcaf(lisp_addr_t *laddr) {
    assert(laddr);
    return(lisp_addr_get_afi(laddr) == LM_AFI_LCAF);
}

/*
 * ip_addr_t functions
 */

inline ip_addr_t *ip_addr_new() {
    return(calloc(1, sizeof(ip_addr_t)));
}

inline void ip_addr_del(ip_addr_t *ip) {
    free(ip);
}

inline ip_afi_t ip_addr_get_afi(ip_addr_t *ipaddr) {
    assert(ipaddr);
    return(ipaddr->afi);
}

inline uint8_t *ip_addr_get_addr(ip_addr_t *ipaddr) {
    return (&(ipaddr->addr));
}

inline struct in_addr *ip_addr_get_v4(ip_addr_t *ipaddr) {
    assert(ipaddr);
    return(&(ipaddr->addr.v4));
}

inline struct in6_addr *ip_addr_get_v6(ip_addr_t *ipaddr) {
    assert(ipaddr);
    return(&(ipaddr->addr.v6));
}

inline uint8_t ip_addr_get_size(ip_addr_t *ipaddr) {
    assert(ipaddr);
    return(ip_addr_afi_to_size(ip_addr_get_afi(ipaddr)));
}

inline uint8_t ip_addr_get_size_in_pkt(ip_addr_t *ipaddr) {
    return(ip_addr_get_size(ipaddr));
}

inline uint8_t ip_addr_afi_to_size(uint16_t afi){
    switch (afi) {
        case AF_UNSPEC:
            return (0);
        case AF_INET:
            return(sizeof(struct in_addr));
        case AF_INET6:
            return(sizeof(struct in6_addr));
        default:
            lispd_log_msg(LISP_LOG_WARNING, "ip_addr_get_size: unknown IP AFI (%d)", afi);
            return(0);
    }
}

inline uint16_t ip_addr_get_iana_afi(ip_addr_t *ipaddr) {
    assert(ipaddr);
    return(ip_afi_to_iana_afi(ip_addr_get_afi(ipaddr)));
}

inline int ip_addr_set_afi(ip_addr_t *ipaddr, lisp_afi_t afi) {
    assert(ipaddr);
    if (afi != AF_INET && afi != AF_INET6 && afi != AF_UNSPEC) {
        lispd_log_msg(LISP_LOG_WARNING, "ip_addr_set_afi: unknown IP AFI (%d)", afi);
        return(BAD);
    }
    ipaddr->afi = afi;
    return(GOOD);
}

void ip_addr_set_v4(ip_addr_t *ipaddr, void *src) {
    assert(ipaddr);
    ip_addr_set_afi(ipaddr, AF_INET);
    memcpy(ip_addr_get_v4(ipaddr), src, sizeof(struct in_addr));
}

inline void ip_addr_set_v6(ip_addr_t *ipaddr, void *src) {
    assert(ipaddr);
    ip_addr_set_afi(ipaddr, AF_INET6);
    memcpy(ip_addr_get_v6(ipaddr), src, sizeof(struct in6_addr));
}

char *ip_addr_to_char (ip_addr_t *addr){
    static char address[10][INET6_ADDRSTRLEN];
    static unsigned int i; //XXX Too much memory allocation for this, but standard syntax

    /* Hack to allow more than one addresses per printf line. Now maximum = 5 */
    i++;
    i = i % 10;

    switch (ip_addr_get_afi(addr)){
    case AF_INET:
        inet_ntop(AF_INET, ip_addr_get_v4(addr), address[i], INET_ADDRSTRLEN);
        return (address[i]);
    case AF_INET6:
        inet_ntop(AF_INET6, ip_addr_get_v6(addr), address[i], INET6_ADDRSTRLEN);
        return (address[i]);
    default:
        return (NULL);
    }
}

inline void ip_addr_copy(ip_addr_t *dst, ip_addr_t *src) {
    assert(src);
    assert(dst);
    memcpy(dst, src, sizeof(ip_addr_t));
}

inline void ip_addr_copy_to(void *dst, ip_addr_t *src) {
    assert(dst);
    assert(src);
    memcpy(dst, ip_addr_get_addr(src), ip_addr_get_size(src));
}

inline uint8_t *ip_addr_copy_to_pkt(void *dst, ip_addr_t *src, uint8_t convert) {
    assert(dst);
    assert(src);
    if (convert && ip_addr_get_afi(src) == AF_INET)
        memcpy(dst, htonl(*(ip_addr_get_v4(src))), ip_addr_get_size(src));
    else
        memcpy(dst, ip_addr_get_addr(src), ip_addr_get_size(src));
    return(CO(dst, ip_addr_get_size(src)));
}

inline int ip_addr_cmp(ip_addr_t *ip1, ip_addr_t *ip2) {
    assert(ip1);
    assert(ip2);
    if (ip_addr_get_afi(ip1) != ip_addr_get_afi(ip2))
        return(-1);
    return(memcmp(ip_addr_get_addr(ip1),
                  ip_addr_get_addr(ip2),
                  ip_addr_get_size(ip1)) );
}


inline int ip_addr_read_from_pkt(void *offset, uint16_t afi, ip_addr_t *dst) {

    if(afi == AF_UNSPEC || ip_addr_set_afi(dst, afi) == BAD)
        return(0);
    memcpy(offset, ip_addr_get_addr(dst), ip_addr_afi_to_size(afi));
    return(ip_addr_afi_to_size(afi));
}

inline uint16_t ip_afi_to_iana_afi(uint16_t afi) {
    switch (afi){
        case AF_INET:
            return(LISP_AFI_IP);
        case AF_INET6:
            return(LISP_AFI_IPV6);
        default:
            lispd_log_msg(LISP_LOG_WARNING, "ip_addr_afi_to_iana_afi: unknown IP AFI (%d)", afi);
            return(0);
    }
}



/*
 * ip_prefix_t functions
 */

inline uint8_t ip_prefix_get_plen(ip_prefix_t *pref) {
    assert(pref);
    return(pref->plen);
}

inline ip_addr_t *ip_prefix_get_addr(ip_prefix_t *pref) {
    assert(pref);
    return(&(pref->prefix));
}

inline uint8_t ip_prefix_get_afi(ip_prefix_t *pref) {
    assert(pref);
    return(ip_addr_get_afi(ip_prefix_get_addr(pref)));
}

inline void ip_prefix_set(ip_prefix_t *pref, ip_addr_t *ipaddr, uint8_t plen) {
    assert(pref);
    assert(ipaddr);
    ip_addr_copy(ip_prefix_get_addr(pref), ipaddr);
    ip_prefix_set_plen(pref, plen);
}

inline void ip_prefix_set_plen(ip_prefix_t *pref, uint8_t plen) {
    assert(pref);
    pref->plen = plen;
}

inline void ip_prefix_copy(ip_prefix_t *dst, ip_prefix_t *src) {
    assert(src);
    assert(dst);
    ip_prefix_set_plen(dst, ip_prefix_get_plen(src));
    ip_addr_copy(ip_prefix_get_addr(dst), ip_prefix_get_addr(src));
}

char *ip_prefix_to_char(ip_prefix_t *pref) {
    static char address[INET6_ADDRSTRLEN+5];
    sprintf(address, "%s/%s", ip_addr_to_char(ip_prefix_get_addr(pref)), ip_prefix_get_plen(pref));
    return(address);
}






/*
 * mc_addr_t functions
 */

inline mc_addr_t *mc_addr_new() {
    mc_addr_t *mc = calloc(1, sizeof(mc_addr_t));
    mc->src = ip_addr_new();
    mc->grp = ip_addr_new();
    return(mc);
}

inline void mc_addr_del(mc_addr_t *mcaddr) {
    lisp_addr_del(mc_addr_get_src(mcaddr));
    lisp_addr_del(mc_addr_get_grp(mcaddr));

    free(mcaddr);
}

inline mc_addr_t *mc_addr_init(ip_addr_t *src, ip_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid) {
    mc_addr_t *mc;
    mc = mc_addr_new();
    mc_addr_set(mc, src, grp, splen, gplen, iid);
    return(mc);
}

inline void mc_addr_set_src_plen(mc_addr_t *mc, uint8_t plen) {
    assert(mc);
    mc->src_plen = plen;
}

inline void mc_addr_set_grp_plen(mc_addr_t *mc, uint8_t plen) {
    assert(mc);
    mc->grp_plen = plen;
}

inline void mc_addr_set_iid(mc_addr_t *mc, uint32_t iid) {
    assert(mc);
    mc->iid = iid;
}

inline void mc_addr_set_src(mc_addr_t *mc, lisp_addr_t *src) {
    assert(mc);
    assert(src);
    lisp_addr_copy(lisp_addr_get_src(mc), src);
}

inline void mc_addr_set_grp(mc_addr_t *mc, lisp_addr_t *grp) {
    assert(mc);
    assert(grp);
    lisp_addr_copy(lisp_addr_get_grp(mc), grp);
}

inline void mc_addr_copy(mc_addr_t *dst, mc_addr_t *src) {
    assert(src);
    assert(dst);
    mc_addr_set_iid(dst, mc_addr_get_iid(src));
    mc_addr_set_src_plen(dst, mc_addr_get_src_plen(src));
    mc_addr_set_grp_plen(dst, mc_addr_get_grp_plen(src));
    mc_addr_set_src(dst, mc_addr_get_src(src));
    mc_addr_set_grp(dst, mc_addr_get_grp(src));
}

inline int mc_addr_cmp(mc_addr_t *mc1, mc_addr_t *mc2) {
    if (    (mc_addr_get_iid(mc1) != mc_addr_get_iid(mc2)) ||
            (mc_addr_get_src_plen(mc1) != mc_addr_get_src_plen(mc2)) ||
            (mc_addr_get_grp_plen(mc1) != mc_addr_get_grp_plen(mc2)))
        return(-1);
    return((lisp_addr_cmp(mc_addr_get_src(mc1), mc_addr_get_src(mc2)) +
            lisp_addr_cmp(mc_addr_get_grp(mc1), mc_addr_get_grp(mc2)))/2);
}

inline void mc_addr_set(mc_addr_t *dst, ip_addr_t *src, ip_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid) {
    assert(src);
    assert(dst);
    assert(grp);
    mc_addr_set_src(dst, src);
    mc_addr_set_grp(dst, grp);
    mc_addr_set_src_plen(splen);
    mc_addr_set_grp_plen(gplen);
    mc_addr_set_iid(iid);
}


inline lisp_addr_t *mc_addr_get_src(mc_addr_t *mc) {
    assert(mc);
    return(mc->src);
}

inline lisp_addr_t *mc_addr_get_grp(mc_addr_t *mc) {
    assert(mc);
    return(mc->grp);
}

inline uint32_t *mc_addr_get_iid(mc_addr_t *mc) {
    assert(mc);
    return(mc->iid);
}

inline uint8_t mc_addr_get_src_plen(mc_addr_t *mc) {
    assert(mc);
    return(mc->src_plen);
}

inline uint8_t mc_addr_get_grp_plen(mc_addr_t *mc) {
    assert(mc);
    return(mc->grp_plen);
}

inline uint16_t mc_addr_get_src_afi(mc_addr_t *mc) {
    assert(mc);
    return(ip_addr_get_afi(mc_addr_get_src(mc)));
}

inline uint16_t mc_addr_get_grp_afi(mc_addr_t *mc) {
    assert(mc);
    return(ip_addr_get_afi(mc_addr_get_grp(mc)));
}

char *mc_addr_to_char(mc_addr_t *mcaddr){
    static char address[INET6_ADDRSTRLEN*2+4];
    sprintf(address, "(%s,%s)",
            ip_addr_to_char(mc_addr_get_src(mcaddr)),
            ip_addr_to_char(mc_addr_get_grp(mcaddr)));
    return(address);
}

inline uint32_t mc_addr_get_size_in_pkt(mc_addr_t *mc) {
    return( sizeof(lispd_lcaf_mcinfo_hdr_t)+
            lisp_addr_get_size_in_pkt(mc_addr_get_src(mc)) +
            sizeof(uint16_t)+ /* grp afi */
            lisp_addr_get_size_in_pkt(mc_addr_get_grp(mc)) );
}

inline uint8_t *mc_addr_copy_to_pkt(void *offset, mc_addr_t *mc) {
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->rsvd1 = 0;
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->flags = 0;
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->type = LCAF_MCAST_INFO;
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->rsvd2 = 0;
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->rbit = 0;
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->lbit = 0;
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->jbit = 0;
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->len = htons(mc_addr_get_size_in_pkt(mc));
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->iid = htonl(mc_addr_get_iid(mc));
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->reserved = 0;
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->src_mlen = mc_addr_get_src_plen(mc);
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->grp_mlen = mc_addr_get_grp_plen(mc);
    ((lispd_lcaf_mcinfo_hdr_t *)offset)->src_afi = htons(lcaf_addr_get_afi(mc_addr_get_src(mc)));
    return(CO(offset, ((lispd_lcaf_mcinfo_hdr_t *)offset)->len));
}

inline uint32_t mc_addr_read_from_pkt(void *offset, mc_addr_t *mc) {
    mc = calloc(1, sizeof(mc_addr_t));
    mc_addr_set_iid((mc_addr_t *)mc, ((lispd_lcaf_mcinfo_hdr_t *)offset)->iid);
    mc_addr_set_src_plen((mc_addr_t *)mc, ((lispd_lcaf_mcinfo_hdr_t *)offset)->src_mlen);
    mc_addr_set_grp_plen((mc_addr_t *)mc, ((lispd_lcaf_mcinfo_hdr_t *)offset)->grp_mlen);

    offset = CO(offset, sizeof(lispd_lcaf_mcinfo_hdr_t));

    return(sizeof(lispd_lcaf_mcinfo_hdr_t) +
            lisp_addr_read_from_pkt(offset, mc_addr_get_src(mc)) +
            lisp_addr_read_from_pkt(offset, mc_addr_get_grp(mc)));
}






/*
 * iid_addr_t functions
 */
inline iid_addr_t *iid_addr_new() {
    iid_addr_t *iid;
    iid = (iid_addr_t *)calloc(1, sizeof(iid_addr_t));
    iid->iidaddr = lisp_addr_new();
    return(iid);
}

inline void iid_addr_del(iid_addr_t *iidaddr) {
    lisp_addr_del(iid_addr_get_addr(iidaddr));
    free(iidaddr);
}

inline uint8_t iid_addr_get_mlen(iid_addr_t *addr) {
    assert(addr);
    return(addr->mlen);
}

inline uint32_t iid_addr_get_iidaddr(iid_addr_t *addr) {
    assert(addr);
    return(addr->iidaddr);
}



inline void iid_addr_set_iid(iid_addr_t *addr, uint32_t iid) {
    assert(addr);
    addr->iid = iid;
}

inline void iid_addr_set_mlen(iid_addr_t *addr, uint8_t mlen) {
    assert(addr);
    addr->mlen = mlen;
}

inline lisp_addr_t *iid_addr_get_addr(iid_addr_t *addr) {
    assert(addr);
    return(addr->iidaddr);
}

inline int iid_addr_cmp(iid_addr_t *iid1, iid_addr_t *iid2) {
    if ((iid_addr_get_iid(iid1) != iid_addr_get_iid(iid2)) || (iid_addr_get_mlen(iid1) != iid_addr_get_mlen(iid2)))
        return(-1);
    return(lisp_addr_cmp(iid_addr_get_iidaddr(iid1), iid_addr_get_iidaddr(iid2)));
}

inline uint32_t iid_addr_get_size_in_pkt(iid_addr_t *iid) {
    return( sizeof(lispd_pkt_lcaf_t)+
            sizeof(lispd_pkt_lcaf_iid_t)+
            lisp_addr_get_size_in_pkt(iid_addr_get_addr(iid)));
}

inline uint8_t *iid_addr_copy_to_pkt(void *offset, iid_addr_t *iid) {
    ((lispd_pkt_iid_hdr_t *)offset)->rsvd1 = 0;
    ((lispd_pkt_iid_hdr_t *)offset)->flags = 0;
    ((lispd_pkt_iid_hdr_t *)offset)->type = LCAF_IID;
    ((lispd_pkt_iid_hdr_t *)offset)->mlen = iid_addr_get_mlen(iid);
    ((lispd_pkt_iid_hdr_t *)offset)->len = htons(iid_addr_get_size_in_pkt(iid));
    ((lispd_pkt_iid_hdr_t *)offset)->iid = htonl(iid_addr_get_iidaddr(iid));
    ((lispd_pkt_iid_hdr_t *)offset)->afi = htons(lisp_addr_get_afi(iid_addr_get_iidaddr(iid)));
    return(CO(offset, ((lispd_pkt_iid_hdr_t *)offset)->len));
}

inline uint32_t iid_addr_read_from_pkt(void *offset, iid_addr_t *iid) {
    iid = calloc(1, sizeof(iid_addr_t));
    iid_addr_set_mlen(iid, ((lispd_pkt_iid_hdr_t *)offset)->mlen);
    iid_addr_set_iid(iid, ((lispd_pkt_iid_hdr_t *)offset)->iid);

    offset = CO(offset, sizeof(lispd_pkt_iid_hdr_t));
    return(lisp_addr_read_from_pkt(&offset, iid_addr_get(iid)) + sizeof(lispd_pkt_iid_hdr_t));
}


/*
 * geo_addr_t functions
 */
inline void geo_addr_set_lat(geo_addr_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec) {
    assert(geo);
    geo->latitude.dir = dir;
    geo->latitude.deg = deg;
    geo->latitude.min = min;
    geo->latitude.sec = sec;
}

inline void geo_addr_set_long(geo_addr_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec) {
    assert(geo);
    geo->longitude.dir = dir;
    geo->longitude.deg = deg;
    geo->longitude.min = min;
    geo->longitude.sec = sec;
}

inline void geo_addr_set_altitude(geo_addr_t *geo, uint32_t altitude) {
    assert(geo);
    geo->altitude = altitude;
}

inline uint32_t geo_addr_read_from_pkt(void *offset, geo_addr_t *geo) {
    geo = calloc(1, sizeof(geo_addr_t));
    geo_addr_set_lat((geo_addr_t *)geo,
            ((lispd_lcaf_geo_hdr_t *)offset)->latitude_dir,
            ((lispd_lcaf_geo_hdr_t *)offset)->latitude_deg,
            ((lispd_lcaf_geo_hdr_t *)offset)->latitude_min,
            ((lispd_lcaf_geo_hdr_t *)offset)->latitude_sec);
    geo_addr_set_long((geo_addr_t *)geo,
            ((lispd_lcaf_geo_hdr_t *)offset)->longitude_dir,
            ((lispd_lcaf_geo_hdr_t *)offset)->longitude_deg,
            ((lispd_lcaf_geo_hdr_t *)offset)->longitude_min,
            ((lispd_lcaf_geo_hdr_t *)offset)->longitude_sec);
    geo_addr_set_altitude((geo_addr_t *)geo, ((lispd_lcaf_geo_hdr_t *)offset)->altitude);

    offset = CO(offset, sizeof(lispd_lcaf_geo_hdr_t));
    return(sizeof(lispd_lcaf_geo_hdr_t) +
            lisp_addr_read_from_pkt(&offset, geo_addr_get_addr((geo_addr_t *)geo)));
}





/*
 * rle_addr_t functions
 */
inline rle_addr_t *rle_addr_new() {
    return((rle_addr_t *)calloc(1, sizeof(iid_addr_t)));
}

inline void rle_addr_del(rle_addr_t *rleaddr) {
    uint32_t lvls;
    lvls = rle_addr_get_nb_levels(rleaddr);

    free(rleaddr);
}










/*
 * lispd_mapping_elt functions
 */

inline void mapping_set_extended_info(lispd_mapping_elt *mapping, void *extended_info) {
    assert(mapping);
    assert(extended_info);
    mapping->extended_info = extended_info;
}

inline void mapping_set_iid(lispd_mapping_elt *mapping, lisp_iid_t iid) {
    assert(mapping);
    mapping->iid = iid;
}

inline void set_mapping_eid_addr(lispd_mapping_elt *mapping, lisp_addr_t *addr) {
    assert(mapping);
    assert(addr);
    lisp_addr_copy(mapping_get_eid_addr(mapping), addr);
}

inline void mapping_set_eid_plen(lispd_mapping_elt *mapping, uint8_t plen) {
    assert(mapping);
    mapping->eid_prefix_length = plen;
}

inline uint8_t get_mapping_ip_eid_plen(lispd_mapping_elt *mapping) {
    assert(mapping);
    if (    lisp_addr_get_afi(mapping_get_eid_addr(mapping)) != LM_AFI_IPPREF &&
            lisp_addr_get_afi(mapping_get_eid_addr(mapping)) != LM_AFI_IP6)
        return(0);

    return(mapping->eid_prefix_length);
}

inline lisp_iid_t get_mapping_iid(lispd_mapping_elt *mapping, lisp_iid_t iid) {
    assert(mapping);
    return(mapping->iid);
}

inline lisp_addr_t *mapping_get_eid_addr(lispd_mapping_elt *mapping) {
    assert(mapping);
    return(&(mapping->eid_prefix));
}

lispd_jib_t *mapping_get_jib(lispd_mapping_elt *mapping) {
    assert(mapping);
    if (!(mapping->eid_prefix))
        return(NULL);
    return(((mcinfo_mapping_extended_info*)mapping->extended_info)->jib);
}





/*
 * lispd_map_cache_entry  functions
 */

inline void mcache_entry_set_eid_addr(lispd_map_cache_entry *mce, lisp_addr_t *addr) {
    set_mapping_eid_addr(mcache_entry_get_mapping(mce), addr);
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
