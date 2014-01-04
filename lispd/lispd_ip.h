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

#ifndef LISPD_IP_H_
#define LISPD_IP_H_

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <stdint.h>

/*
 * Maximum length (in bytes) of an IP address
 */
#define MAX_INET_ADDRSTRLEN INET6_ADDRSTRLEN

#define MCASTMIN4   0xE0000000
#define MCASTMAX4   0xEFFFFFFF


typedef int         ip_afi_t;

/*
 * IP address type
 */
typedef struct {
    ip_afi_t      afi;
    union {
        struct in_addr      v4;
        struct in6_addr     v6;
    } addr;
} ip_addr_t;

typedef struct {
    ip_addr_t   prefix;
    uint8_t     plen;
} ip_prefix_t;


/*
 * ip_addr_t functions
 */

inline ip_addr_t         *ip_addr_new();
inline void              ip_addr_del(ip_addr_t *ip);
inline ip_afi_t          ip_addr_get_afi(ip_addr_t *ipaddr);
inline uint8_t           *ip_addr_get_addr(ip_addr_t *ipaddr);
inline struct in_addr    *ip_addr_get_v4(ip_addr_t *ipaddr);
inline struct in6_addr   *ip_addr_get_v6(ip_addr_t *ipaddr);
inline uint8_t           ip_addr_get_size(ip_addr_t *ipaddr);
inline uint8_t           ip_addr_get_size_in_pkt(ip_addr_t *ipaddr);
inline uint8_t           ip_addr_afi_to_size(uint16_t afi);
inline uint16_t          ip_addr_get_iana_afi(ip_addr_t *ipaddr);
inline int               ip_addr_set_afi(ip_addr_t *ipaddr, ip_afi_t afi);
inline void              ip_addr_set_v4(ip_addr_t *ipaddr, void *src);
inline void              ip_addr_set_v6(ip_addr_t *ipaddr, void *src);
inline void              ip_addr_init(ip_addr_t *ipaddr, void *src, uint8_t afi);
inline void              ip_addr_copy(ip_addr_t *dst, ip_addr_t *src);
inline void              ip_addr_copy_to(void *dst, ip_addr_t *src);
inline int               ip_addr_copy_to_pkt(void *dst, ip_addr_t *src, uint8_t convert);
inline int               ip_addr_read_from_pkt(void *offset, uint16_t afi, ip_addr_t *dst);
inline int               ip_addr_cmp(ip_addr_t *ip1, ip_addr_t *ip2);
inline uint16_t          ip_addr_sock_afi_to_iana_afi(uint16_t afi);
inline uint16_t          ip_addr_iana_afi_to_sock_afi(uint16_t afi);
inline uint8_t           ip_addr_afi_to_mask(ip_addr_t *ip);
char                     *ip_addr_to_char (ip_addr_t *addr);



/*
 * ip_prefix_t functions
 */
inline uint8_t           ip_prefix_get_plen(ip_prefix_t *pref);
inline ip_addr_t         *ip_prefix_get_addr(ip_prefix_t *pref);
inline uint8_t           ip_prefix_get_afi(ip_prefix_t *pref);
inline void              ip_prefix_set(ip_prefix_t *pref, ip_addr_t *ipaddr, uint8_t plen);
inline void              ip_prefix_set_plen(ip_prefix_t *pref, uint8_t plen);
inline void             ip_prefix_copy(ip_prefix_t *dst, ip_prefix_t *src);

char                     *ip_prefix_to_char(ip_prefix_t *pref);

/*
 * other
 */
inline int          ip_addr_is_link_local (ip_addr_t *addr);
inline uint8_t      ip_addr_is_multicast(ip_addr_t *addr);
inline uint8_t      ipv4_addr_is_multicast(struct in_addr *addr);
inline uint8_t      ipv6_addr_is_multicast(struct in6_addr *addr);


#endif /* LISPD_IP_H_ */
