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

#include "lispd_ip.h"
#include "lispd_lcaf.h"
#include <lisp_messages.h>


/*
 * Lisp address structure
 */

typedef uint32_t    lisp_iid_t;

typedef enum {
    LM_AFI_NO_ADDR = 0,
    LM_AFI_IP,
    LM_AFI_IPPREF,
    LM_AFI_LCAF,
    /* compatibiliy */
    LM_AFI_IP6 = AF_INET6
} lm_afi_t;


/* TODO fcoras: The cool thing about the new lisp_addr_t
 * is that we can access in 2 ways the same data
 * either as old struct or as ip_addr_t. Still, would be nice
 * to deprecate the old struct
 */

typedef struct _lisp_addr_t lisp_addr_t;
//typedef struct _lcaf_addr_t lcaf_addr_t;

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
                lcaf_addr_t     lcaf;
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
inline lisp_addr_t       *lisp_addr_new_afi(uint8_t afi);
inline void              lisp_addr_del(lisp_addr_t *laddr);
inline lm_afi_t          lisp_addr_get_afi(lisp_addr_t *addr);
inline uint16_t          lisp_addr_ip_get_afi(lisp_addr_t *addr);
inline ip_addr_t         *lisp_addr_ip_get_addr(lisp_addr_t *laddr);
inline uint8_t           lisp_addr_ip_get_plen(lisp_addr_t *laddr);
inline void              lisp_addr_ip_set_afi(lisp_addr_t *laddr, int afi);
inline ip_addr_t         *lisp_addr_get_ip(lisp_addr_t *addr);
inline ip_prefix_t       *lisp_addr_get_ippref(lisp_addr_t *addr);
inline lcaf_addr_t       *lisp_addr_get_lcaf(lisp_addr_t *addr);
inline uint16_t           lisp_addr_get_iana_afi(lisp_addr_t *laddr);
inline uint16_t           lisp_addr_get_plen(lisp_addr_t *laddr);

//inline uint16_t          lisp_addr_get_plen(lisp_addr_t *laddr);
inline uint32_t          lisp_addr_get_size_in_field(lisp_addr_t *laddr);
char                     *lisp_addr_to_char(lisp_addr_t *addr);

inline void              lisp_addr_set_afi(lisp_addr_t *addr, lm_afi_t afi);
inline void              lisp_addr_set_lcaf(lisp_addr_t *laddr, lcaf_addr_t *lcaf);
inline void              lisp_addr_ip_to_ippref(lisp_addr_t *laddr);
//inline uint8_t           lisp_addr_get_plen(lisp_addr_t *laddr);
inline void              lisp_addr_set_plen(lisp_addr_t *laddr, uint8_t plen);
inline void              lisp_addr_set_ip(lisp_addr_t *addr, ip_addr_t *ip);
void                     lisp_addr_copy(lisp_addr_t *dst, lisp_addr_t *src);
lisp_addr_t              *lisp_addr_clone(lisp_addr_t *src);
inline uint32_t          lisp_addr_copy_to(void *dst, lisp_addr_t *src);
inline int               lisp_addr_write(void *offset, lisp_addr_t *laddr);
int                      lisp_addr_read_from_pkt(uint8_t *offset, lisp_addr_t *laddr);
inline uint8_t           lisp_addr_cmp_iids(lisp_addr_t *addr1, lisp_addr_t *addr2);
inline uint8_t           lisp_addr_cmp_for_mcache_install(lisp_addr_t *old, lisp_addr_t *new);
inline int               lisp_addr_is_lcaf(lisp_addr_t *laddr);
inline void              lisp_addr_lcaf_set_addr(lisp_addr_t *laddr, void *addr);
inline void              *lisp_addr_lcaf_get_addr(lisp_addr_t *laddr);
inline void              lisp_addr_lcaf_set_type(lisp_addr_t *laddr, int type);
inline int               lisp_addr_cmp(lisp_addr_t *addr1, lisp_addr_t *addr2);
inline lisp_addr_t       *lisp_addr_init_ip(ip_addr_t *ip);
inline lisp_addr_t       *lisp_addr_init_ippref(ip_addr_t *ip, uint8_t plen);
inline lisp_addr_t       *lisp_addr_init_lcaf(lcaf_addr_t *lcaf);
inline uint16_t          lisp_addr_iana_afi_to_lm_afi(uint16_t afi);
inline int              lisp_addr_is_mc(lisp_addr_t *addr);
lisp_addr_t             *lisp_addr_init_from_field(address_field *paddr);
inline int              lisp_addr_write_to_field(lisp_addr_t *addr, address_field *afield);
address_field           *lisp_addr_to_field(lisp_addr_t *addr);



#endif /* LISPD_ADDRESS_H_ */
