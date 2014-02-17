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

#include "lispd_ip.h"
#include <lisp_messages.h>


#define MAX_LCAFS 16

typedef struct _lisp_addr_t lisp_addr_t;
//typedef struct _lcaf_addr_t lcaf_addr_t;

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

typedef struct _lcaf_addr_t {
    lcaf_type   type;
    void        *addr;
} lcaf_addr_t;

#define MAX_IID             16777215

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


typedef struct _lcaf_hdr_t {
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    len;
} __attribute__ ((__packed__)) lcaf_hdr_t;


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
} __attribute__ ((__packed__)) lispd_pkt_lcaf_iid_t;

typedef struct _lcaf_iid_hdr_t{
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     mlen;
    uint16_t    len;
    uint32_t    iid;
} __attribute__ ((__packed__)) lcaf_iid_hdr_t;



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

typedef struct _lcaf_mcinfo_hdr_t{
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
#ifdef LITTLE_ENDIANS
    uint8_t     J:1;
    uint8_t     L:1;
    uint8_t     R:1;
    uint8_t     rsvd2:5;
#else
    uint8_t     rsvd2:5;
    uint8_t     R:1;
    uint8_t     L:1;
    uint8_t     J:1;
#endif
    uint16_t    len;
    uint32_t    iid;
    uint16_t    reserved;
    uint8_t     src_mlen;
    uint8_t     grp_mlen;
} __attribute__ ((__packed__)) lcaf_mcinfo_hdr_t;

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

typedef struct _lcaf_geo_hdr_t{
    uint16_t    afi;
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
} __attribute__ ((__packed__)) lcaf_geo_hdr_t;


/* Explicit Locator Path (ELP)
 *
 *      0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 10   |     Rsvd2     |               n               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Rsvd3         |L|P|S|              AFI = x          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Reencap Hop 1  ...                    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Rsvd3         |L|P|S|              AFI = x          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Reencap Hop k  ...                    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

typedef struct _lcaf_elp_hdr_t {
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    length;
} __attribute__ ((__packed__)) lcaf_elp_hdr_t;


typedef struct _elp_node_flags {
    uint8_t rsvd1;
#ifdef LITTLE_ENDIANS
    uint8_t S:1;
    uint8_t P:1;
    uint8_t L:1;
    uint8_t rsvd2:5;
#else
    uint8_t rsvd2:5;
    uint8_t L:1;
    uint8_t P:1;
    uint8_t S:1;
#endif
} elp_node_flags;


/*
 * AFI-list LCAF type
 */

typedef struct _lcaf_afi_list_hdr_t {
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    length;
} __attribute__ ((__packed__)) lcaf_afi_list_hdr_t;





/*
 * Abstract representation of LCAFs
 */

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
} mc_t;

typedef struct {
    geo_coordinates latitude;
    geo_coordinates longitude;
    uint32_t    altitude;
    lisp_addr_t *addr;
} geo_t;


typedef struct _iit_t {
    uint32_t    iid;
    uint8_t     mlen;
    lisp_addr_t *iidaddr;
} iid_t;

/* RLE */
typedef struct _level_addr_t {
    lisp_addr_t   *ip;
    uint8_t       level;
} level_addr_t;

typedef struct _rle_t {
    uint32_t        nb_levels;
    level_addr_t    **rlist;
} rle_t;


/* ELP */
typedef struct _elp_node_t{
    uint8_t             L:1;
    uint8_t             P:1;
    uint8_t             S:1;
    lisp_addr_t         *addr;
    struct _elp_node_t  *next;
} elp_node_t;

typedef struct _elp_t {
    uint16_t    nb_nodes;
    elp_node_t  *nodes;
} elp_t;

/* AFI-list */
typedef struct _afi_list_node {
    lisp_addr_t             *addr;
    struct _afi_list_node   *next;
} afi_list_node;

typedef struct _afi_list_t {
    afi_list_node   *list;
} afi_list_t;

lcaf_addr_t             *lcaf_addr_new();
lcaf_addr_t             *lcaf_addr_new_type(uint8_t type);
void                    lcaf_addr_del(lcaf_addr_t *lcaf);

inline lcaf_type        lcaf_addr_get_type(lcaf_addr_t *lcaf);
inline void             *lcaf_addr_get_addr(lcaf_addr_t *lcaf);
inline mc_t             *lcaf_addr_get_mc(lcaf_addr_t *lcaf);
inline geo_t            *lcaf_addr_get_geo(lcaf_addr_t *lcaf);
inline iid_t            *lcaf_addr_get_iid(lcaf_addr_t *lcaf);

inline int              lcaf_addr_is_mc(lcaf_addr_t *lcaf);

inline void             lcaf_addr_set(lcaf_addr_t *lcaf, void *newaddr, uint8_t type);
inline void             lcaf_addr_set_addr(lcaf_addr_t *lcaf, void *addr);
inline void             lcaf_addr_set_type(lcaf_addr_t *lcaf, uint8_t type);
int                     lcaf_addr_read_from_pkt(uint8_t *offset, lcaf_addr_t *lcaf_addr);

inline char             *lcaf_addr_to_char(lcaf_addr_t *lcaf);

inline uint32_t         lcaf_addr_get_size_to_write(lcaf_addr_t *lcaf);
int                     lcaf_addr_copy(lcaf_addr_t **dst, lcaf_addr_t *src);
inline int              lcaf_addr_write_to_pkt(void *offset, lcaf_addr_t *lcaf);
inline int              lcaf_addr_cmp(lcaf_addr_t *addr1, lcaf_addr_t *addr2);
inline uint8_t          lcaf_addr_cmp_iids(lcaf_addr_t *addr1, lcaf_addr_t *addr2);




/*
 * mc type  functions
 */

inline lisp_addr_t      *lcaf_mc_get_src(lcaf_addr_t *mc);
inline lisp_addr_t      *lcaf_mc_get_grp(lcaf_addr_t *mc);
inline uint32_t         lcaf_mc_get_iid(lcaf_addr_t *mc);
inline uint8_t          lcaf_mc_get_src_plen(lcaf_addr_t *mc);
inline uint8_t          lcaf_mc_get_grp_plen(lcaf_addr_t *mc);
inline uint8_t          lcaf_mc_get_afi(lcaf_addr_t *mc);
inline lcaf_mcinfo_hdr_t  *address_field_get_mc_hdr(address_field *cur_ptr);


inline mc_t             *mc_type_new();
inline void              mc_type_del(void *mc);
inline mc_t             *mc_type_init(lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);
inline void              mc_type_set_src(void *mc, lisp_addr_t *src);
inline void              mc_type_set_grp(mc_t *mc, lisp_addr_t *grp);

inline lisp_addr_t       *mc_type_get_src(mc_t *mc);
inline lisp_addr_t       *mc_type_get_grp(mc_t *mc);
inline uint8_t           mc_type_get_afi(mc_t *mc);
inline uint32_t          mc_type_get_iid(void *mc);
inline uint8_t           mc_type_get_src_plen(mc_t *mc);
inline uint8_t           mc_type_get_grp_plen(mc_t *mc);


char                    *mc_type_to_char (void *mc);
int                     mc_type_get_size_to_write(void *mc);
inline int              mc_type_write_to_pkt(uint8_t *offset, void *mc);
inline void             mc_type_copy(void **dst, void *src);
inline int              mc_type_cmp(void *mc1, void *mc2);
inline void             mc_type_set(mc_t *dst, lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);
int                     mc_type_read_from_pkt(uint8_t *offset, void **mc);
int                     lcaf_addr_set_mc(lcaf_addr_t *lcaf, lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);



/*
 * iid type functions
 */

inline iid_t                *iid_type_new();
inline void                 iid_type_del(void *iid);
inline uint8_t              iid_type_get_mlen(iid_t *iid);
inline uint32_t             lcaf_iid_get_iid(lcaf_addr_t *iid);
inline uint32_t             iid_type_get_iid(iid_t *iid);
inline lisp_addr_t          *iid_type_get_addr(void *iid);

inline void                 iid_type_set_iid(iid_t *addr, uint32_t iid);
inline void                 iid_type_set_addr(iid_t *addr, lisp_addr_t *iidaddr);
inline void                 iid_type_set_mlen(iid_t *addr, uint8_t mlen);
inline int                  iid_type_cmp(void *iid1, void *iid2);
int                         iid_type_get_size_to_write(void *iid);
inline int                  iid_type_write_to_pkt(uint8_t *offset, void *iid);
int                         iid_type_read_from_pkt(uint8_t *offset, void **iid);
char                        *iid_type_to_char(void *iid);
void                        iid_type_copy(void **dst, void *src);





/*
 * geo type functions
 */
inline void             geo_type_del(void *geo);
inline void             geo_type_set_addr(geo_t *geo, lisp_addr_t *addr);
inline void             geo_type_set_lat(geo_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
inline void             geo_type_set_long(geo_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
inline void             geo_type_set_lat_from_coord(geo_t *geo, geo_coordinates *coord);
inline void             geo_type_set_long_from_coord(geo_t *geo, geo_coordinates *coord);
inline void             geo_type_set_altitude(geo_t *geo, uint32_t altitude);

inline lisp_addr_t      *geo_type_get_addr(geo_t *geo);
inline geo_coordinates  *geo_type_get_lat(geo_t *geo);
inline geo_coordinates  *geo_type_get_long(geo_t *geo);
inline uint32_t         geo_type_get_altitude(geo_t *geo);
int                     geo_type_read_from_pkt(uint8_t *offset, void **geo);



char                    *geo_type_to_char(void *geo);
void                    geo_type_copy(void **dst, void *src);
char                    *geo_coord_to_char(geo_coordinates *coord);

/*
 * rle type functions
 */
inline rle_t            *rle_type_new();
inline void             rle_type_del(void *rleaddr);
int                     rle_type_read_from_pkt(uint8_t *offset, void **rle);
char                    *rle_type_to_char(void *rle);
void                    rle_type_copy(void **dst, void *src);


/*
 *  ELP type functions
 */

inline elp_t                *elp_type_new();
void                        elp_type_del(void *elp);
int                         elp_type_get_size_to_write(void *elp);
int                         elp_type_write_to_pkt(uint8_t *offset, void *elp);
int                         elp_type_read_from_pkt(uint8_t *offset, void **elp);
char                        *elp_type_to_char(void *elp);
void                        elp_type_copy(void **dst, void *src);
int                         elp_type_cmp(void *elp1, void *elp2);

static inline elp_node_t *lcaf_elp_get_node_list(lcaf_addr_t *lcaf) {
    return(((elp_t *)lcaf->addr)->nodes);
}


/*
 * AFI-list type functions
 */

inline afi_list_t           *afi_list_type_new();
void                        afi_list_type_del(void *afil);
int                         afi_list_type_get_size_to_write(void *afil);
int                         afi_list_type_write_to_pkt(uint8_t *offset, void *afil);
int                         afi_list_type_read_from_pkt(uint8_t *offset, void **afil);
char                        *afi_list_type_to_char(void *afil);
void                        afi_list_type_copy(void **dst, void *src);
int                         afi_list_type_cmp(void *afil1, void *afil2);
#endif /* LISPD_LCAF_H_ */
