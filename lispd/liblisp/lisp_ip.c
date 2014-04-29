/*
 * lispd_ip.h
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

#include "lisp_address.h"
#include "defs.h"

/*
 * ip_addr_t functions
 */

inline ip_addr_t *ip_addr_new() {
    return(calloc(1, sizeof(ip_addr_t)));
}

inline void ip_addr_del(ip_addr_t *ip) {
    free(ip);
}

inline int ip_addr_afi(ip_addr_t *ipaddr) {
//    assert(ipaddr);
    return(ipaddr->afi);
}

inline uint8_t *ip_addr_get_addr(ip_addr_t *ipaddr) {
    return ((uint8_t *)&(ipaddr->addr));
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
    return(ip_sock_afi_to_size(ip_addr_afi(ipaddr)));
}

inline uint8_t ip_addr_get_size_to_write(ip_addr_t *ipaddr) {
    /* includes afi size */
    return(ip_sock_afi_to_size(ip_addr_afi(ipaddr))+sizeof(uint16_t));
}

inline uint16_t ip_addr_get_iana_afi(ip_addr_t *ipaddr) {
    assert(ipaddr);
    return(ip_sock_to_iana_afi(ip_addr_afi(ipaddr)));
}

inline int ip_addr_set_afi(ip_addr_t *ipaddr, int afi) {
    assert(ipaddr);
    if (afi != AF_INET && afi != AF_INET6 && afi != AF_UNSPEC) {
        lmlog(LISP_LOG_WARNING, "ip_addr_set_afi: unknown IP AFI (%d)", afi);
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

inline void ip_addr_init(ip_addr_t *ipaddr, void *src, uint8_t afi) {
    assert(ipaddr);
    switch(afi) {
        case AF_INET:
            ip_addr_set_v4(ipaddr, src);
            break;
        case AF_INET6:
            ip_addr_set_v6(ipaddr, src);
            break;
        default:
            lmlog(LISP_LOG_WARNING, "ip_addr_init: unknown IP AFI (%d)", afi);
            break;
    }
}

char *
ip_to_char(void *ip, int afi) {
    static char address[10][INET6_ADDRSTRLEN];
    static unsigned int i;

    switch(afi){
    case AF_INET:
        inet_ntop(AF_INET, ip, address[i], INET_ADDRSTRLEN);
        return(address[i]);
    case AF_INET6:
        inet_ntop(AF_INET6, ip, address[i], INET6_ADDRSTRLEN);
        return (address[i]);
    }
}

char *
ip_addr_to_char(ip_addr_t *addr){
    return(ip_to_char(ip_addr_get_addr(addr), ip_addr_afi(addr)));
}

/* ip_addr_copy
 *
 * @dst : the destination where the ip should be copied
 * @src : the ip address to be copied
 * Description: The function copies src structure to dst
 * structure. It does a full memory copy
 */
inline void ip_addr_copy(ip_addr_t *dst, ip_addr_t *src) {
    assert(src);
    assert(dst);
    memcpy(dst, src, sizeof(ip_addr_t));
}

/* ip_addr_copy_to
 *
 * @dst : memory location
 * @src : the ip address to be copied
 * Description: The function copies what is *CONTAINED* in an ip address
 * to a given memory location, NOT the whole structure! See ip_addr_copy
 * for copying ip addresses
 */
inline void ip_addr_copy_to(void *dst, ip_addr_t *src) {
    assert(dst);
    assert(src);
    memcpy(dst, ip_addr_get_addr(src), ip_addr_get_size(src));
}

inline int ip_addr_write_to_pkt(void *dst, ip_addr_t *src, uint8_t convert) {
    *(uint16_t *)dst = htons(ip_addr_get_iana_afi(src));
    dst = CO(dst, sizeof(uint16_t));

    if (convert && ip_addr_afi(src) == AF_INET)
        /* XXX: haven't encountered a case when this is used */
        *((uint32_t *)dst) = htonl(ip_addr_get_v4(src)->s_addr);
    else
        memcpy(dst, ip_addr_get_addr(src), ip_addr_get_size(src));
    return(sizeof(uint16_t)+ip_addr_get_size(src));
}

inline int ip_addr_cmp(ip_addr_t *ip1, ip_addr_t *ip2) {
    if (ip_addr_afi(ip1) != ip_addr_afi(ip2))
        return(-1);
    return(memcmp(ip_addr_get_addr(ip1),
                  ip_addr_get_addr(ip2),
                  ip_addr_get_size(ip1)) );
}


inline int ip_addr_parse(void *offset, uint16_t iana_afi, ip_addr_t *dst) {
    if(ip_addr_set_afi(dst, ip_iana_to_sock_afi(iana_afi)) == BAD)
        return(0);
    memcpy(ip_addr_get_addr(dst), CO(offset, sizeof(uint16_t)), ip_iana_afi_to_size(iana_afi));
    return(sizeof(uint16_t) + ip_iana_afi_to_size(iana_afi));
}

inline uint8_t ip_addr_afi_to_default_mask(ip_addr_t *ip) {
    assert(ip);
    return(ip_addr_get_size(ip)*8);
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

inline uint8_t ip_prefix_afi(ip_prefix_t *pref) {
    assert(pref);
    return(ip_addr_afi(ip_prefix_get_addr(pref)));
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

inline void ip_prefix_set_afi(ip_prefix_t *pref, int afi) {
    ip_addr_set_afi(&pref->prefix, afi);
}

inline void ip_prefix_copy(ip_prefix_t *dst, ip_prefix_t *src) {
    assert(src);
    assert(dst);
    ip_prefix_set_plen(dst, ip_prefix_get_plen(src));
    ip_addr_copy(ip_prefix_get_addr(dst), ip_prefix_get_addr(src));
}

char *ip_prefix_to_char(ip_prefix_t *pref) {
    static char address[10][INET6_ADDRSTRLEN+5];
    static unsigned int i;

    /* Hack to allow more than one addresses per printf line. Now maximum = 5 */
    i++;
    i = i % 10;

    sprintf(address[i], "%s/%d", ip_addr_to_char(ip_prefix_get_addr(pref)), ip_prefix_get_plen(pref));
    return(address[i]);
}







/*
 * other ip functions
 */

inline uint16_t ip_sock_to_iana_afi(uint16_t afi) {
    switch (afi){
        case AF_INET:
            return(LISP_AFI_IP);
        case AF_INET6:
            return(LISP_AFI_IPV6);
        default:
            lmlog(LISP_LOG_WARNING, "ip_addr_sock_afi_to_iana_afi: unknown IP AFI (%d)", afi);
            return(0);
    }
}

inline uint16_t ip_iana_to_sock_afi(uint16_t afi) {
    switch (afi) {
        case LISP_AFI_IP:
            return(AF_INET);
        case LISP_AFI_IPV6:
            return(AF_INET6);
        default:
            lmlog(LISP_LOG_WARNING, "ip_addr_iana_afi_to_sock_afi: unknown IP AFI (%d)", afi);
            return(0);
    }
}

inline uint8_t ip_sock_afi_to_size(uint16_t afi){
    switch (afi) {
    case AF_INET:
        return(sizeof(struct in_addr));
    case AF_INET6:
        return(sizeof(struct in6_addr));
    default:
        lmlog(LISP_LOG_WARNING, "ip_addr_get_size: unknown IP AFI (%d)", afi);
        return(0);
    }
}

inline uint8_t ip_iana_afi_to_size(uint16_t afi) {
    switch(afi) {
    case LISP_AFI_IP:
        return(sizeof(struct in_addr));
    case LISP_AFI_IPV6:
        return(sizeof(struct in6_addr));
    default:
        lmlog(LISP_LOG_DEBUG_3, "ip_iana_afi_to_size: unknown AFI (%d)", afi);
        return(0);
    }
    return(0);
}

int ip_addr_is_link_local(ip_addr_t *ipaddr) {
    /*
     * Return TRUE if the address belongs to:
     *          IPv4: 169.254.0.0/16
     *          IPv6: fe80::/10
     */
    int         is_link_local = FALSE;
    uint32_t    ipv4_network  = 0;
    uint32_t    mask          = 0;

    switch (ip_addr_afi(ipaddr)){
        case AF_INET:
            inet_pton(AF_INET,"169.254.0.0",&(ipv4_network));
            inet_pton(AF_INET,"255.255.0.0",&(mask));
            if ((ipaddr->addr.v4.s_addr & mask) == ipv4_network){
                is_link_local = TRUE;
            }
            break;
        case AF_INET6:
//            if (((addr.address.ipv6.__in6_u.__u6_addr8[0] & 0xff) == 0xfe) &&
//                    ((addr.address.ipv6.__in6_u.__u6_addr8[1] & 0xc0) == 0x80)){
//            }
            if (IN6_IS_ADDR_LINKLOCAL(ip_addr_get_v6(ipaddr)))
                is_link_local = TRUE;
            break;
    }

    return (is_link_local);
}

inline uint8_t ip_addr_is_multicast(ip_addr_t *addr) {
    switch(ip_addr_afi(addr)) {
    case AF_INET:
        return ipv4_addr_is_multicast(ip_addr_get_v4(addr));
        break;
    case AF_INET6:
        return ipv6_addr_is_multicast(ip_addr_get_v6(addr));
        break;
    default:
        lmlog(LISP_LOG_WARNING, "is_multicast_addr: Unknown afi %s",
                ip_addr_afi(addr));
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

inline uint8_t ipv6_addr_is_multicast(struct in6_addr *addr) {
    /* TODO fcoras: implement this */
    lmlog(LISP_LOG_WARNING, "is_multicast_addr6 : THIS IS A STUB for "
            "IPv6 multicast address test!");
    return(0);
}

uint8_t
ip_version_to_sock_afi(uint8_t ver) {
    switch(ver) {
    case IPVERSION:
        return(AF_INET);
    case IP6VERSION:
        return(AF_INET6);
    default:
        return(0);
    }
}
