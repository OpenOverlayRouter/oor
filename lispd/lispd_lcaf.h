/*
 * lispd_lcaf.h
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

#ifndef LISPD_LCAF_H_
#define LISPD_LCAF_H_

#include "defs_re.h"

typedef struct {
    void        *addr;
    uint8_t     type;
    void        (*del)(void *);
} lcaf_addr_t;

typedef struct {
    uint8_t     dir;
    uint16_t    deg;
    uint8_t     min;
    uint8_t     sec;
} coordinates;

/*
 * Multicast address type
 */
//typedef struct {
//    ip_addr_t    src;
//    ip_addr_t    grp;
//} mc_addr_t;

typedef struct {
    uint8_t         src_plen;
    uint8_t         grp_plen;
    uint32_t        iid;
    lisp_addr_t     *src;
    lisp_addr_t     *grp;
} mc_addr_t;

typedef struct {
    coordinates latitude;
    coordinates longitude;
    uint32_t    altitude;
    lisp_addr_t addr;
} geo_addr_t;


typedef struct {
    uint32_t    iid;
    uint8_t     mlen;
    lisp_addr_t *iidaddr;
} iid_addr_t;

typedef struct {
    lcaf_addr_t   ip;
    uint8_t       level;
} level_addr_t;

typedef struct {
    uint32_t        nb_levels;
    level_addr_t    **rlist;
} rle_addr_t;

typedef struct {
    uint16_t    ms_port_number;
    uint16_t    etr_port_number;
    lisp_addr_t global_etr_rloc;
    lisp_addr_t ms_rloc;
    lisp_addr_t private_etr_rloc;
    //lisp_addr_list *rtr_rloc_list;
} lcaf_nat_traversal_addr_t;

#define MAX_LCAFS 17
void del_fcts[MAX_LCAFS] = {0, 0,
        iid_addr_del, 0, 0, 0, 0, 0, 0,
        mc_addr_del, 0, 0,
        rle_addr_del, 0, 0, 0};


lcaf_addr_t     *lcaf_addr_new();
lcaf_addr_t     *lcaf_addr_new_afi(lcaf_addr_t *lcaf, uint8_t type);
void            lcaf_addr_del(lcaf_addr_t *lcaf);

inline uint8_t lcaf_addr_get_type(lcaf_addr_t *lcaf);
inline void *lcaf_addr_get_addr(lcaf_addr_t *lcaf);

inline void lcaf_addr_set(lcaf_addr_t *lcaf, void *newaddr, uint8_t type);
inline void lcaf_addr_set_addr(lcaf_addr_t *lcaf, void *addr);
inline void lcaf_addr_set_type(lcaf_addr_t *lcaf, uint8_t type);
inline uint32_t lcaf_addr_read_from_pkt(void *offset, lcaf_addr_t *lcaf_addr);

inline uint32_t lcaf_addr_get_size_in_pkt(lcaf_addr_t *lcaf);
inline uint8_t  *lcaf_addr_copy_to_pkt(void *offset, lcaf_addr_t *lcaf);
inline int lcaf_addr_cmp(lcaf_addr_t *addr1, lcaf_addr_t *addr2);
inline uint8_t lcaf_addr_cmp_iids(lcaf_addr_t *addr1, lcaf_addr_t *addr2);

#endif /* LISPD_LCAF_H_ */
