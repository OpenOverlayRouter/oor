/*
 * lispd_addr.c
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
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#include "lispd_address.h"
#include "defs.h"

/*
 * lisp_addr_t functions
 */

static inline lisp_addr_t *_new_afi(uint8_t afi) {
    switch(afi) {
        case LM_AFI_IP:
            return(lisp_addr_new_ip());
        case LM_AFI_IPPREF:
            return(lisp_addr_new_ippref());
        case LM_AFI_LCAF:
            return(lisp_addr_new_lcaf());
        default:
            lispd_log_msg(LISP_LOG_WARNING, "lisp_addr_new_afi: unknown lisp addr afi %d", afi);
            break;
    }
    return(NULL);
}

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
    lcaf = lcaf_addr_new();

    lisp_addr_set_afi(laddr, LM_AFI_LCAF);
    lisp_addr_set_lcaf(laddr, lcaf);
    return(laddr);
}

inline lisp_addr_t *lisp_addr_new_afi(uint8_t afi) {
    return(_new_afi(afi));
}

inline lisp_addr_t *lisp_addr_new() {
    return(calloc(1, sizeof(lisp_addr_t)));
}

inline void lisp_addr_del(lisp_addr_t *laddr) {
    assert(laddr);
    switch (lisp_addr_get_afi(laddr)) {
        case LM_AFI_IPPREF:
            free(laddr);
            break;
        case LM_AFI_LCAF:
            lcaf_addr_del(lisp_addr_get_lcaf(laddr));
            free(laddr);
            break;
        default:
            lispd_log_msg(LISP_LOG_WARNING, "lisp_addr_delete: unknown lisp addr afi %d", lisp_addr_get_afi(laddr));
            return;
    }
}

inline lm_afi_t lisp_addr_get_afi(lisp_addr_t *addr) {
    assert(addr);
    return(addr->lafi);
}

inline ip_addr_t *lisp_addr_get_ip(lisp_addr_t *addr) {
    /* this should work with both old and new lisp_addr_t ip format */
    assert(addr);
    return(&(addr->ip));
}

inline ip_prefix_t *lisp_addr_get_ippref(lisp_addr_t *addr) {
    assert(addr);
    return(&(addr->ippref));
}

inline lcaf_addr_t *lisp_addr_get_lcaf(lisp_addr_t *addr) {
    assert(addr);
    return(addr->lcaf);
}

inline uint16_t lisp_addr_get_iana_afi(lisp_addr_t *laddr) {

    switch (lisp_addr_get_afi(laddr)) {
        case LM_AFI_IP:
            return(ip_addr_get_iana_afi(lisp_addr_get_ip(laddr)));
            break;
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
        case LM_AFI_IP:
            return(ip_addr_get_size_in_pkt(lisp_addr_get_ip(laddr)));
            break;
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

//inline uint16_t lisp_addr_get_plen(lisp_addr_t *laddr) {
//    /* XXX: hack to obtain a prefixlen to be used in the mapcache.
//     * Should be removed in the future! */
//    switch (lisp_addr_get_afi(laddr)) {
//        case LM_AFI_IPPREF:
//            return(ip_prefix_get_plen(lisp_addr_get_ippref(laddr)));
//            break;
//        case LM_AFI_LCAF:
//            switch(lcaf_addr_get_type(lisp_addr_get_lcaf(laddr))) {
//                case LCAF_MCAST_INFO:
//                    return(mc_addr_get_src_plen(lcaf_addr_get_mc(lisp_addr_get_lcaf(laddr))));
//                    break;
//                default:
//                    lispd_log_msg(LISP_LOG_DEBUG_2, "lisp_addr_get_plen: lcaf type (%d) has no prefix",
//                            lcaf_addr_get_type(lisp_addr_get_lcaf(laddr)));
//                    break;
//            }
//            break;
//        default:
//            lispd_log_msg(LISP_LOG_DEBUG_2, "lisp_addr_get_plen: afi type (%d) has no prefix len", lisp_addr_get_afi(laddr));
//            break;
//    }
//    return(0);
//}

char *lisp_addr_to_char(lisp_addr_t *addr) {
    assert(addr);

    switch(lisp_addr_get_afi(addr)) {
        case LM_AFI_IP:
        case LM_AFI_IP6:
            return(ip_addr_to_char(lisp_addr_get_ip(addr)));
        case LM_AFI_IPPREF:
            return(ip_prefix_to_char(lisp_addr_get_ippref(addr)));
            break;
        case LM_AFI_LCAF:
            return(lcaf_addr_to_char(lisp_addr_get_lcaf(addr)));
            break;
        default:
            lispd_log_msg(LISP_LOG_WARNING, "lisp_addr_to_char: Trying to convert"
                    " to string unknown LISP AFI %d", lisp_addr_get_afi(addr) );
            break;
    }
    return(NULL);
}

inline void lisp_addr_set_afi(lisp_addr_t *addr, lm_afi_t afi) {
    assert(addr);
    addr->lafi = afi;
}

inline void lisp_addr_set_lcaf(lisp_addr_t *laddr, lcaf_addr_t *lcaf) {
    assert(laddr);
    assert(lcaf);
    laddr->lcaf = lcaf;
}

/**
 * lisp_addr_copy - copies src to dst. Still works if they have different internal
 * structures. Note that dst MUST be allocated prior to calling the function
 */
void lisp_addr_copy(lisp_addr_t *dst, lisp_addr_t *src) {
    assert(src);
    lcaf_addr_t *lcaf;

    lisp_addr_set_afi(dst, lisp_addr_get_afi(src));
    switch (lisp_addr_get_afi(dst)) {
        case LM_AFI_IP:
            ip_addr_copy(lisp_addr_get_ip(dst), lisp_addr_get_ip(src));
            break;
        case LM_AFI_IPPREF:
            ip_prefix_copy(lisp_addr_get_ippref(dst), lisp_addr_get_ippref(src));
            break;
        case LM_AFI_LCAF:
            lcaf = lisp_addr_get_lcaf(dst);
            lcaf_addr_copy(&lcaf, lisp_addr_get_lcaf(src));
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2,"lisp_addr_copy:  Unknown AFI type %d in EID", lisp_addr_get_afi(dst));
            break;
    }
}

lisp_addr_t *lisp_addr_clone(lisp_addr_t *src) {
    assert(src);
    lisp_addr_t *dst;

    dst = lisp_addr_new();
    lisp_addr_copy(dst, src);
    return(dst);
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

inline uint8_t *lisp_addr_write_to_pkt(void *offset, lisp_addr_t *laddr) {
    assert(offset);
    assert(laddr);

//    (uint16_t *)offset = htons(lisp_addr_get_iana_afi(laddr));
    memset(offset, htons(lisp_addr_get_iana_afi(laddr)), sizeof(uint16_t));
    offset = CO(offset, sizeof(uint16_t));

    switch (lisp_addr_get_afi(laddr)) {
        case LM_AFI_IPPREF:
            /* XXX: I'm using 0 as in previous code!! Not sure this is right */
            return(ip_addr_copy_to_pkt(offset, ip_prefix_get_addr(lisp_addr_get_ippref(laddr)), 0));
        case LM_AFI_LCAF:
            return(lcaf_addr_write_to_pkt(laddr, offset));
        case LM_AFI_NO_ADDR:
            memset(offset, 0, lisp_addr_get_size_in_pkt(laddr));
            return(CO(offset, lisp_addr_get_size_in_pkt(laddr)));
        default:
            break;
    }
    return(NULL);
}


int lisp_addr_read_from_pkt(uint8_t **offset, lisp_addr_t *laddr) {
    uint16_t    len;
    lisp_afi_t  afi;

    afi = ntohs(*(uint16_t *)*offset);
    *offset = CO(*offset, sizeof(uint16_t));
    len = 0;

    if (!laddr)
        laddr = lisp_addr_new();

    switch(afi) {
        case LISP_AFI_IP:
        case LISP_AFI_IPV6:
            len = ip_addr_read_from_pkt((void *)*offset, afi,ip_prefix_get_addr(lisp_addr_get_ippref(laddr)));
            lisp_addr_set_afi(laddr, LM_AFI_IPPREF);
            break;
        case LISP_AFI_LCAF:
            len = lcaf_addr_read_from_pkt((void *)*offset, lisp_addr_get_lcaf(laddr));
            lisp_addr_set_afi(laddr, LM_AFI_LCAF);
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

    if (len <= 0)
        return (BAD);
    else {
        len = len+sizeof(uint16_t);
        *offset = CO(*offset, len);
        return(len);
    }
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
              cmp = lcaf_addr_cmp(lisp_addr_get_lcaf(addr1), lisp_addr_get_lcaf(addr2));
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


inline int lisp_addr_is_lcaf(lisp_addr_t *laddr) {
    assert(laddr);
    return(lisp_addr_get_afi(laddr) == LM_AFI_LCAF);
}

inline lisp_addr_t *lisp_addr_init_ip(ip_addr_t *ip) {
    assert(ip);
    lisp_addr_t *laddr;
    laddr = _new_afi(LM_AFI_IP);
    ip_addr_copy(lisp_addr_get_ip(laddr), ip);
    return(laddr);
}

inline lisp_addr_t *lisp_addr_init_lcaf(lcaf_addr_t *lcaf) {
    assert(lcaf);
    lisp_addr_t *laddr;
    lcaf_addr_t *llcaf;

    laddr = _new_afi(LM_AFI_LCAF);
    llcaf = lisp_addr_get_lcaf(laddr);
    lcaf_addr_copy(&llcaf, lcaf);
    return(laddr);
}
