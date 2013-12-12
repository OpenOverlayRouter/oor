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

#include "lispd_address.h"
#include "defs.h"


/*
 * LCAF types
 */

typedef enum {
    LCAF_NULL = 0,
    LCAF_AFI_LIST,
    LCAF_IID,
    LCAF_ASN,
    LCAF_APP_DATA,
    LCAF_GEO = 5,
    LCAF_OKEY,
    LCAF_NATT,
    LCAF_NONCE_LOC,
    LCAF_MCAST_INFO,
    LCAF_EXPL_LOC_PATH = 10,
    LCAF_SEC_KEY,
    LCAF_TUPLE,
    LCAF_RLE,
    LCAF_DATA_MODEL,
    LCAF_KEY_VALUE
} lcaf_type;

#define MAX_LCAFS 16



struct _lcaf_addr_t {
    void        *addr;
    lcaf_type   type;
};

#define MAX_IID             16777215

//typedef struct _lisp_addr_t lisp_addr_t;

/*
 * LISP Canonical Address Format
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |           AFI = 16387         |    Rsvd1     |     Flags      |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |    Type       |     Rsvd2     |            Length             |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


typedef struct lispd_pkt_lcaf_t_ {
    uint8_t  rsvd1;
    uint8_t  flags;
    uint8_t  type;
    uint8_t  rsvd2;
    uint16_t len;
} PACKED lispd_pkt_lcaf_t;


/* Instance ID
 * Only the low order 24 bits should be used
 * Using signed integer, negative value means "don't send LCAF/IID field"
 * resulting in a non-explicit default IID value of 0
 */

/*
 * Instance ID
 *
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |           AFI = 16387         |    Rsvd1      |    Flags      |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 2    | IID mask-len  |             4 + n             |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                         Instance ID                           |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |              AFI = x          |         Address  ...          |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct lispd_pkt_lcaf_iid_t_ {
    uint32_t    iid;
    uint16_t    afi;
} PACKED lispd_pkt_lcaf_iid_t;

typedef struct {
    uint8_t  rsvd1;
    uint8_t  flags;
    uint8_t  type;
    uint8_t  mlen;
    uint16_t len;
    uint32_t iid;
    uint16_t afi;
} PACKED lispd_pkt_iid_hdr_t;



/*   Multicast Info Canonical Address Format:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 9    |  Rsvd2  |R|L|J|             8 + n             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Instance-ID                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Reserved           | Source MaskLen| Group MaskLen |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |   Source/Subnet Address  ...  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |       Group Address  ...      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct lispd_lcaf_mcinfo_hdr_t_{
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
#ifdef LITTLE_ENDIANS
    uint8_t     jbit:1;
    uint8_t     lbit:1;
    uint8_t     rbit:1;
    uint8_t     rsvd2:5;
#else
    uint8_t     rsvd2:5;
    uint8_t     rbit:1;
    uint8_t     lbit:1;
    uint8_t     jbit:1;
#endif
    uint16_t    len;
    uint32_t    iid;
    uint16_t    reserved;
    uint8_t     src_mlen;
    uint8_t     grp_mlen;
    uint16_t    src_afi;
} PACKED lispd_lcaf_mcinfo_hdr_t;

typedef struct {
    uint8_t rbit;
    uint8_t jbit;
    uint8_t lbit;
} mrsignaling_flags_t;


/* Geo Coordinate LISP Canonical Address Format:
 *
 *      0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 5    |     Rsvd2     |            12 + n             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |N|     Latitude Degrees        |    Minutes    |    Seconds    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |E|     Longitude Degrees       |    Minutes    |    Seconds    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                            Altitude                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |         Address  ...          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct {
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    length;
#ifdef LITTLE_ENDIANS
    uint16_t    latitude_deg:15;
    uint16_t    latitude_dir:1;
#else
    uint16_t    latitude_dir:1;
    uint16_t    latitude_deg:15;
#endif
    uint8_t     latitude_min;
    uint8_t     latitude_sec;
#ifdef LITTLE_ENDIANS
    uint16_t    longitude_deg:15;
    uint16_t    longitude_dir:1;
#else
    uint16_t    longitude_dir:1;
    uint16_t    longitude_deg:15;
#endif
    uint8_t     longitude_min;
    uint8_t     longitude_sec;
    uint32_t    altitude;
    uint16_t    afi;
} PACKED lispd_lcaf_geo_hdr_t;

typedef struct {
    uint8_t     dir;
    uint16_t    deg;
    uint8_t     min;
    uint8_t     sec;
} geo_coordinates;

typedef struct {
    uint8_t         src_plen;
    uint8_t         grp_plen;
    uint32_t        iid;
    lisp_addr_t     *src;
    lisp_addr_t     *grp;
} mc_addr_t;

typedef struct {
    geo_coordinates latitude;
    geo_coordinates longitude;
    uint32_t    altitude;
    lisp_addr_t *addr;
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

lcaf_addr_t             *lcaf_addr_new();
lcaf_addr_t             *lcaf_addr_new_afi(lcaf_addr_t *lcaf, uint8_t type);
void                    lcaf_addr_del(lcaf_addr_t *lcaf);

inline lcaf_type        lcaf_addr_get_type(lcaf_addr_t *lcaf);
inline void             *lcaf_addr_get_addr(lcaf_addr_t *lcaf);
inline mc_addr_t        *lcaf_addr_get_mc(lcaf_addr_t *lcaf);
inline geo_addr_t       *lcaf_addr_get_geo(lcaf_addr_t *lcaf);
inline iid_addr_t       *lcaf_addr_get_iid(lcaf_addr_t *lcaf);

inline int              lcat_addr_is_mc(lcaf_addr_t *lcaf);

inline void             lcaf_addr_set(lcaf_addr_t *lcaf, void *newaddr, uint8_t type);
inline void             lcaf_addr_set_addr(lcaf_addr_t *lcaf, void *addr);
inline void             lcaf_addr_set_type(lcaf_addr_t *lcaf, uint8_t type);
int                     lcaf_addr_read_from_pkt(void *offset, lcaf_addr_t *lcaf_addr);

inline char             *lcaf_addr_to_char(lcaf_addr_t *lcaf);

inline uint32_t         lcaf_addr_get_size_in_pkt(lcaf_addr_t *lcaf);
inline int              lcaf_addr_copy(lcaf_addr_t *dst, lcaf_addr_t *src);
inline uint8_t          *lcaf_addr_copy_to_pkt(void *offset, lcaf_addr_t *lcaf);
inline int              lcaf_addr_cmp(lcaf_addr_t *addr1, lcaf_addr_t *addr2);
inline uint8_t          lcaf_addr_cmp_iids(lcaf_addr_t *addr1, lcaf_addr_t *addr2);

inline uint8_t              is_lcaf_mcast_info(uint8_t *offset);
inline mrsignaling_flags_t  lcaf_mcinfo_get_flags(uint8_t *cur_ptr);


/*
 * mc_addr_t functions
 */

inline mc_addr_t         *mc_addr_new();
inline void              mc_addr_del(void *mcaddr);
inline mc_addr_t         *mc_addr_init(ip_addr_t *src, ip_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);
inline void              mc_addr_set_src(mc_addr_t *mc, ip_addr_t *ip);
inline void              mc_addr_set_grp(mc_addr_t *mc, ip_addr_t *ip);

inline lisp_addr_t       *mc_addr_get_src(mc_addr_t *mc);
inline lisp_addr_t       *mc_addr_get_grp(mc_addr_t *mc);
inline uint32_t          *mc_addr_get_iid(mc_addr_t *mc);
inline uint8_t           mc_addr_get_src_plen(mc_addr_t *mc);
inline uint8_t           mc_addr_get_grp_plen(mc_addr_t *mc);
inline uint16_t          mc_addr_get_src_afi(mc_addr_t *mc);
inline uint16_t          mc_addr_get_grp_afi(mc_addr_t *mc);

char                    *mc_addr_to_char (void *mc);
inline uint32_t         mc_addr_get_size_in_pkt(mc_addr_t *mc);
inline uint8_t          *mc_addr_copy_to_pkt(void *offset, mc_addr_t *mc);
inline void             mc_addr_copy(void *dst, void *src);
inline void             mc_addr_set(mc_addr_t *dst, ip_addr_t *src, ip_addr_t *grp);
int                     mc_addr_read_from_pkt(void *offset, void *mc);



/*
 * iid_addr_t functions
 */

inline iid_addr_t        *iid_addr_new();
inline void              iid_addr_del(void *addr);
inline uint8_t           iid_addr_get_mlen(iid_addr_t *addr);
inline inline uint32_t   iid_addr_get_iidaddr(iid_addr_t *addr);

inline void              iid_addr_set_iid(iid_addr_t *addr, uint32_t iid);
inline void              iid_addr_set_iidaddr(iid_addr_t *addr, lisp_addr_t *iidaddr);
inline void              iid_addr_set_mlen(iid_addr_t *addr, uint8_t mlen);
inline int               iid_addr_cmp(iid_addr_t *iid1, iid_addr_t *iid2);
inline uint32_t          iid_addr_get_size_in_pkt(iid_addr_t *iid);
inline uint8_t           *iid_addr_copy_to_pkt(void *offset, iid_addr_t *iid);
int                      iid_addr_read_from_pkt(void *offset, void *iid);
char                    *iid_addr_to_char(void *iid);
void                     iid_addr_copy(void *dst, void *src);





/*
 * geo_addr_t functions
 */
inline void              geo_addr_del(void *geo);
inline void              geo_addr_set_lat(geo_addr_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
inline void              geo_addr_set_long(geo_addr_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
inline void              geo_addr_set_lat_from_coord(geo_addr_t *geo, geo_coordinates coord);
inline void              geo_addr_set_long_from_coord(geo_addr_t *geo, geo_coordinates coord);
inline void              geo_addr_set_altitude(geo_addr_t *geo, uint32_t altitude);
inline geo_coordinates   geo_addr_get_lat(geo_addr_t *geo);
inline geo_coordinates   geo_addr_get_long(geo_addr_t *geo);
inline geo_coordinates   geo_addr_get_altitude(geo_addr_t *geo);
int                      geo_addr_read_from_pkt(void *offset, void *geo);

inline lisp_addr_t       *geo_addr_get_addr(geo_addr_t *geo);
char                    *geo_addr_to_char(void *geo);
void                    geo_addr_copy(void *dst, void *src);


/*
 * geo_addr_t functions
 */
inline rle_addr_t       *rle_addr_new();
inline void             rle_addr_del(void *rleaddr);
int                     rle_addr_read_from_pkt(void *offset, void *rle);
char                    *rle_addr_to_char(void *rle);
void                    rle_addr_copy(void *dst, void *src);


typedef void    (*del_fct)(void *);
typedef int     (*read_from_pkt_fct)(void *, void *);
typedef char    *(*to_char_fct)(void *);
typedef void    (*copy_fct)(void *, void *);

del_fct del_fcts[MAX_LCAFS] = {
        0, 0,
        iid_addr_del,
        0, 0, 0,
        geo_addr_del, 0, 0,
        mc_addr_del, 0, 0,
        rle_addr_del, 0, 0, 0};

read_from_pkt_fct read_from_pkt_fcts[MAX_LCAFS] = {
        0, 0,
        iid_addr_read_from_pkt, 0, 0, 0,
        geo_addr_read_from_pkt, 0, 0,
        mc_addr_read_from_pkt, 0, 0,
        rle_addr_read_from_pkt, 0, 0, 0};

to_char_fct to_char_fcts[MAX_LCAFS] = {
        0, 0,
        iid_addr_to_char, 0, 0, 0,
        geo_addr_to_char, 0, 0,
        mc_addr_to_char, 0, 0,
        rle_addr_to_char, 0, 0, 0
};

copy_fct copy_fcts[MAX_LCAFS] = {
        0, 0,
        iid_addr_copy, 0, 0, 0,
        geo_addr_copy, 0, 0,
        mc_addr_copy, 0, 0,
        rle_addr_copy, 0, 0, 0
};

#endif /* LISPD_LCAF_H_ */
