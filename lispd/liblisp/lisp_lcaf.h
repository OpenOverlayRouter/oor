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

#include "lisp_ip.h"
#include "generic_list.h"
#include <lisp_messages.h>


#define MAX_LCAFS 16

typedef struct _lisp_addr_t lisp_addr_t;


typedef struct _lcaf_addr_t {
    lcaf_type_e type;
    void *addr;
} lcaf_addr_t;

#define MAX_IID             16777215


/*
 * Abstract representation of LCAFs
 */

/* AFI-list */
typedef struct afi_list_node {
    lisp_addr_t            *addr;
    struct afi_list_node   *next;
} afi_list_node_t;

typedef struct afi_list {
    afi_list_node_t   *list;
} afi_list_t;


typedef struct _iid_t {
    uint32_t    iid;
    uint8_t     mlen;
    lisp_addr_t *iidaddr;
} iid_t;


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


/* ELP */
typedef struct elp_node {
    uint8_t             L:1;
    uint8_t             P:1;
    uint8_t             S:1;
    lisp_addr_t         *addr;
} elp_node_t;

typedef struct _elp_t {
    glist_t     *nodes;
} elp_t;


/* RLE */
typedef struct _rle_node_t {
    lisp_addr_t   *addr;
    uint8_t       level;
} rle_node_t;

typedef struct _rle_t {
    glist_t     *nodes;
} rle_t;


lcaf_addr_t             *lcaf_addr_new();
lcaf_addr_t             *lcaf_addr_new_type(uint8_t type);
void                    lcaf_addr_del_addr(lcaf_addr_t *lcaf);

inline lcaf_type_e        lcaf_addr_get_type(lcaf_addr_t *lcaf);
inline void             *lcaf_addr_get_addr(lcaf_addr_t *lcaf);
inline mc_t             *lcaf_addr_get_mc(lcaf_addr_t *lcaf);
inline geo_t            *lcaf_addr_get_geo(lcaf_addr_t *lcaf);
inline iid_t            *lcaf_addr_get_iid(lcaf_addr_t *lcaf);

inline int              lcaf_addr_is_mc(lcaf_addr_t *lcaf);

inline void             lcaf_addr_set(lcaf_addr_t *lcaf, void *newaddr, uint8_t type);
inline void             lcaf_addr_set_addr(lcaf_addr_t *lcaf, void *addr);
inline void             lcaf_addr_set_type(lcaf_addr_t *lcaf, uint8_t type);
int                     lcaf_addr_parse(uint8_t *offset, lcaf_addr_t *lcaf_addr);

inline char             *lcaf_addr_to_char(lcaf_addr_t *lcaf);

inline uint32_t         lcaf_addr_get_size_to_write(lcaf_addr_t *lcaf);
int                     lcaf_addr_copy(lcaf_addr_t *dst, lcaf_addr_t *src);
inline int              lcaf_addr_write(void *offset, lcaf_addr_t *lcaf);
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
int                     mc_type_parse(uint8_t *offset, void **mc);
int                     lcaf_addr_set_mc(lcaf_addr_t *lcaf, lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);
lisp_addr_t             *lisp_addr_build_mc(lisp_addr_t *src, lisp_addr_t *grp);
inline int              lisp_addr_is_mcinfo(lisp_addr_t *addr);


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
int                         iid_type_parse(uint8_t *offset, void **iid);
char                        *iid_type_to_char(void *iid);
void                        iid_type_copy(void **dst, void *src);
iid_t                       *iid_type_init(int iid, lisp_addr_t *addr, uint8_t mlen);
lcaf_addr_t                 *lcaf_iid_init(int iid, lisp_addr_t *addr, uint8_t mlen);





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
int                     geo_type_parse(uint8_t *offset, void **geo);



char                    *geo_type_to_char(void *geo);
void                    geo_type_copy(void **dst, void *src);
char                    *geo_coord_to_char(geo_coordinates *coord);

/*
 * RLE type functions
 */
inline rle_t *rle_type_new();
inline void rle_type_del(void *rleaddr);
int rle_type_parse(uint8_t *offset, void **rle);
int rle_type_write_to_pkt(uint8_t *offset, void *rle);
int rle_type_get_size_to_write(void *elp);
char *rle_type_to_char(void *rle);
void rle_type_copy(void **dst, void *src);
int rle_type_cmp(void *elp1, void *elp2);

rle_node_t *rle_node_clone(rle_node_t *srn);
inline rle_node_t *rle_node_new();
inline void rle_node_del(rle_node_t *rnode);

static inline glist_t *lcaf_rle_node_list(lcaf_addr_t *lcaf)
{
    return(((rle_t *)lcaf->addr)->nodes);
}



/*
 *  ELP type functions
 */

inline elp_t                *elp_type_new();
void                        elp_type_del(void *elp);
int                         elp_type_get_size_to_write(void *elp);
int                         elp_type_write_to_pkt(uint8_t *offset, void *elp);
int                         elp_type_parse(uint8_t *offset, void **elp);
char                        *elp_type_to_char(void *elp);
void                        elp_type_copy(void **dst, void *src);
int                         elp_type_cmp(void *elp1, void *elp2);

inline void                 elp_node_del(elp_node_t *enode);
inline void                 lcaf_elp_add_node(lcaf_addr_t *lcaf, elp_node_t *enode);

static inline glist_t *lcaf_elp_node_list(lcaf_addr_t *lcaf) {
    return(((elp_t *)lcaf->addr)->nodes);
}



/*
 * AFI-list type functions
 */

inline afi_list_t           *afi_list_type_new();
void                        afi_list_type_del(void *afil);
int                         afi_list_type_get_size_to_write(void *afil);
int                         afi_list_type_write_to_pkt(uint8_t *offset, void *afil);
int                         afi_list_type_parse(uint8_t *offset, void **afil);
char                        *afi_list_type_to_char(void *afil);
void                        afi_list_type_copy(void **dst, void *src);
int                         afi_list_type_cmp(void *afil1, void *afil2);

lisp_addr_t *lcaf_eid_get_ip_addr(lcaf_addr_t *lcaf);
lisp_addr_t *lcaf_rloc_get_ip_addr(lisp_addr_t *addr);
int lcaf_rloc_set_ip_addr(lisp_addr_t *, lisp_addr_t *if_addr);
#endif /* LISPD_LCAF_H_ */
