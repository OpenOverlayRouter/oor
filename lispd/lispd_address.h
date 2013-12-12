/*
 * lispd_addr.h
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

#ifndef LISPD_ADDRESS_H_
#define LISPD_ADDRESS_H_

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <stdint.h>

/*
 * LISP AFI codes
 */

#define LISP_AFI_NO_ADDR                0
#define LISP_AFI_IP                     1
#define LISP_AFI_IPV6                   2
#define LISP_AFI_LCAF                   16387

/*
 * Maximum length (in bytes) of an IP address
 */
#define MAX_INET_ADDRSTRLEN INET6_ADDRSTRLEN

/*
 * Lisp address structure
 */

typedef int         ip_afi_t;
typedef uint32_t    lisp_iid_t;

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

typedef enum {
    LM_AFI_NO_ADDR = 0,
    LM_AFI_IP,
    LM_AFI_IPPREF,
    LM_AFI_LCAF,
    /* compatibility */
//    l4, l5, l6, l7, l8, l9,
    LM_AFI_IP6 = AF_INET6
}lm_afi_t;
//#define LM_AFI_NO_ADDR      0
//#define LM_AFI_IP           1
//#define LM_AFI_IPPREF       2
//#define LM_AFI_LCAF         3
//
///* for compatibility*/
//#define LM_AFI_IP6          AF_INET6

/* TODO fcoras: The cool thing about the new lisp_addr_t
 * is that we can access in 2 ways the same data
 * either as old struct or as ip_addr_t. Still, would be nice
 * to change lisp_addr_t to ip_addr_t where needed in the future
 */

typedef struct _lisp_addr_t lisp_addr_t;
typedef struct _lcaf_addr_t lcaf_addr_t;

struct _lisp_addr_t {
    union {
        struct {
            int  afi;
            union {
                struct in_addr   ip;
                struct in6_addr  ipv6;
            } address;
        };
        struct {
            union {
                ip_addr_t       ip;
                ip_prefix_t     ippref;
                lcaf_addr_t     *lcaf;
            };
            lm_afi_t        lafi;
        };
    };
};


/*
 *  generic list of addresses
 */

typedef struct _lispd_addr_list_t {
    lisp_addr_t                 *address;
    struct _lispd_addr_list_t   *next;
} lispd_addr_list_t;


/*
 *  generic list of addresses with priority and weight
 */

typedef struct _lispd_weighted_addr_list_t {
    lisp_addr_t                         *address;
    uint8_t                             priority;
    uint8_t                             weight;
    struct _lispd_weighted_addr_list_t  *next;
} lispd_weighted_addr_list_t;


typedef struct _lispd_map_server_list_t {
    lisp_addr_t                     *address;
    uint8_t                         key_type;
    char                            *key;
    uint8_t                         proxy_reply;
    struct _lispd_map_server_list_t *next;
} lispd_map_server_list_t;

typedef struct packet_tuple_ {
    lisp_addr_t                     src_addr;
    lisp_addr_t                     dst_addr;
    uint16_t                        src_port;
    uint16_t                        dst_port;
    uint8_t                         protocol;
} packet_tuple;

/*
 * lisp_addr_t functions
 */
inline lisp_addr_t       *lisp_addr_new();
inline lisp_addr_t       *lisp_addr_new_ip();
inline lisp_addr_t       *lisp_addr_new_ippref();
inline lisp_addr_t       *lisp_addr_new_lcaf();
inline lisp_addr_t       *lisp_addr_new_afi(uint8_t afi);
inline void              lisp_addr_del(lisp_addr_t *laddr);
inline lm_afi_t          lisp_addr_get_afi(lisp_addr_t *addr);
inline ip_addr_t         *lisp_addr_get_ip(lisp_addr_t *addr);
inline ip_prefix_t       *lisp_addr_get_ippref(lisp_addr_t *addr);
inline ip_afi_t          lisp_addr_get_ip_afi(lisp_addr_t *addr);
inline lisp_addr_t       *lisp_addr_get_mc_src(lisp_addr_t *addr);
inline lisp_addr_t       *lisp_addr_get_mc_grp(lisp_addr_t *addr);
inline lcaf_addr_t       *lisp_addr_get_lcaf(lisp_addr_t *addr);
inline uint16_t           lisp_addr_get_iana_afi(lisp_addr_t *laddr);

//inline uint16_t          lisp_addr_get_plen(lisp_addr_t *laddr);
inline uint32_t          lisp_addr_get_size_in_pkt(lisp_addr_t *laddr);
char                     *lisp_addr_to_char(lisp_addr_t *addr);

inline void              lisp_addr_set_afi(lisp_addr_t *addr, lm_afi_t afi);
inline void              lisp_addr_set_lcaf(lisp_addr_t *laddr, lcaf_addr_t *lcaf);
inline void              lisp_addr_set_ip(lisp_addr_t *addr, ip_addr_t *ip);
inline void              lisp_addr_copy(lisp_addr_t *dst, lisp_addr_t *src);
inline uint32_t          lisp_addr_copy_to(void *dst, lisp_addr_t *src);
inline uint8_t           *lisp_addr_copy_to_pkt(void *offset, lisp_addr_t *laddr);
int                      lisp_addr_read_from_pkt(void **offset, lisp_addr_t *laddr);
inline uint8_t           lisp_addr_cmp_iids(lisp_addr_t *addr1, lisp_addr_t *addr2);
inline int               lisp_addr_is_lcaf(lisp_addr_t *laddr);
inline int               lisp_addr_cmp(lisp_addr_t *addr1, lisp_addr_t *addr2);

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
inline int               ip_addr_set_afi(ip_addr_t *ipaddr, lm_afi_t afi);
inline void              ip_addr_set_v4(ip_addr_t *ipaddr, void *src);
inline void              ip_addr_set_v6(ip_addr_t *ipaddr, void *src);
inline void              ip_addr_copy(ip_addr_t *dst, ip_addr_t *src);
inline void              ip_addr_copy_to(void *dst, ip_addr_t *src);
inline uint8_t           *ip_addr_copy_to_pkt(void *dst, ip_addr_t *src, uint8_t convert);
inline int               ip_addr_read_from_pkt(void *offset, uint16_t afi, ip_addr_t *dst);
inline int               ip_addr_cmp(ip_addr_t *ip1, ip_addr_t *ip2);
inline uint16_t          ip_addr_afi_to_iana_afi(uint16_t afi);
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




#endif /* LISPD_ADDRESS_H_ */
