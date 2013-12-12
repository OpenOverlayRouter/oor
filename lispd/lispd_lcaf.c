/*
 * lispd_lcaf.c
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

#include "defs.h"
#include "lispd_lcaf.h"

lcaf_addr_t *lcaf_addr_new() {
    return(calloc(1, sizeof(lcaf_addr_t)));
}

lcaf_addr_t *lcaf_addr_new_afi(uint8_t type) {
    lcaf_addr_t *lcaf;
    void        *addr;

    lcaf = calloc(1, sizeof(lcaf_addr_t));
    lcaf_addr_set_type(lcaf, type);
    addr = lcaf_addr_get_addr(lcaf);

    switch(type) {
        case LCAF_IID:
            addr = iid_addr_new();
            break;
        case LCAF_MCAST_INFO:
            addr = mc_addr_new();
            break;
        case LCAF_GEO:
            break;
        default:
            break;
    }

    return(lcaf);
}

void lcaf_addr_del(lcaf_addr_t *lcaf) {
    assert(lcaf);
    (*del_fcts[lcaf_addr_get_type(lcaf)])(lcaf_addr_get_addr(lcaf));
    free(lcaf);
}

/*
 * lcaf_addr_t functions
 */

int lcaf_addr_read_from_pkt(void *offset, lcaf_addr_t *lcaf_addr) {

    int len = 0;

    lcaf_addr_set_type(lcaf_addr, ntohs(((lispd_pkt_lcaf_t *)offset)->type));
    if (!read_from_pkt_fcts[caf_addr_get_type(lcaf_addr)])
        return(BAD);
    len = read_from_pkt_fcts[caf_addr_get_type(lcaf_addr)](offset, lcaf_addr_get_addr(lcaf_addr));
    if (len != ntohs(((lispd_pkt_lcaf_t *)offset)->len)) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "lcaf_addr_read_from_pkt: len field and the number of bytes read are different!");
        return(BAD);
    }

    return(len);

//    switch(lcaf_addr_get_type(lcaf_addr)) {
//        case LCAF_IID:
//            return(iid_addr_read_from_pkt(offset, lcaf_addr_get_iid(lcaf_addr)));
//            break;
//        case LCAF_MCAST_INFO:
//            return(mc_addr_read_from_pkt(offset, lcaf_addr_get_mc(lcaf_addr)));
//            break;
//        case LCAF_GEO:
//            return(geo_addr_read_from_pkt(offset, lcaf_addr_get_geo(lcaf_addr)));
//            break;
//        default:
//            lispd_log_msg(LISP_LOG_DEBUG_2,"lcaf_addr_read_from_pkt:  Unknown LCAF type %d in EID",
//                    lcaf_addr_get_type(lcaf_addr));
//            break;
//    }
//    return(0);

}


char *lcaf_addr_to_char(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return((*to_char_fcts[lcaf_addr_get_type(lcaf)])(lcaf_addr_get_addr(lcaf)));
}


inline lcaf_type lcaf_addr_get_type(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return(lcaf->type);
}

inline mc_addr_t *lcaf_addr_get_mc(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return((mc_addr_t *)lcaf_addr_get_addr(lcaf));
}

inline geo_addr_t *lcaf_addr_get_geo(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return((geo_addr_t *)lcaf_addr_get_addr(lcaf));
}

inline iid_addr_t *lcaf_addr_get_iid(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return((iid_addr_t *)lcaf_addr_get_addr(lcaf));
}

inline void *lcaf_addr_get_addr(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return(lcaf->addr);
}

inline int lcat_addr_is_mc(lcaf_addr_t *lcaf) {
    if (lcaf_addr_get_type(lcaf) == LCAF_MCAST_INFO)
        return(1);
    else
        return(0);
}


inline void lcaf_addr_set(lcaf_addr_t *lcaf, void *newaddr, uint8_t type) {
    void *addr;
    addr = lcaf_addr_get_addr(lcaf);
    if (addr)
        lcaf_addr_del(addr);
    lcaf_addr_set_type(lcaf, type);
    lcaf_addr_set_addr(lcaf, newaddr);
}

inline void lcaf_addr_set_addr(lcaf_addr_t *lcaf, void *addr) {
    assert(lcaf);
    assert(addr);
    lcaf->addr = addr;
}
inline void lcaf_addr_set_type(lcaf_addr_t *lcaf, uint8_t type) {
    assert(lcaf);
    lcaf->type = type;
}

inline uint32_t lcaf_addr_get_size_in_pkt(lcaf_addr_t *lcaf) {
    /*NOTE: This returns size in packet of the lcaf */
    switch(lcaf_addr_get_type(lcaf)) {
        case LCAF_IID:
            return(iid_addr_get_size_in_pkt(lcaf_addr_get_iid(lcaf)));
            break;
        case LCAF_MCAST_INFO:
            return(mc_addr_get_size_in_pkt(lcaf_addr_get_mc(lcaf)));
        /* TODO: to be finished */
        case LCAF_GEO:
            break;
        default:
            break;
    }

    return(0);
}

inline void lcaf_addr_copy(lcaf_addr_t *dst, lcaf_addr_t *src) {

    assert(src);
    if (!copy_fcts[lcaf_addr_get_type(src)])
        lispd_log_msg(LISP_LOG_WARNING, "lcaf_addr_copy: copy not implemented for type %s",lcaf_addr_get_type(src));

    if (!dst)
        dst = lcaf_addr_new();
    lcaf_addr_set_type(dst, lcaf_addr_get_type(src));
    (*copy_fcts[lcaf_addr_get_type(src)])(dst, src);
}

inline uint8_t *lcaf_addr_copy_to_pkt(void *offset, lcaf_addr_t *lcaf) {
    switch(lcaf_addr_get_type(lcaf)) {
    case LCAF_IID:
        return(iid_addr_copy_to_pkt(offset, lcaf_addr_get_iid(lcaf)));
        break;
    case LCAF_MCAST_INFO:
        return(mc_addr_copy_to_pkt(offset, lcaf_addr_get_mc(lcaf)));
        break;
    default:
        break;
    }
    return(0);
}

inline int lcaf_addr_cmp(lcaf_addr_t *addr1, lcaf_addr_t *addr2) {
    if (lcaf_addr_get_type(addr1) != lcaf_addr_get_type(addr2))
        return(-1);
    switch (lcaf_addr_get_type(addr1)) {
        case LCAF_IID:
            return(iid_addr_cmp(lcaf_addr_to_iid(addr1), lcaf_addr_to_mc(addr2)));
            break;
        case LCAF_MCAST_INFO:
            return(mc_addr_cmp(lcaf_addr_to_mc(addr1), lcaf_addr_to_mc(addr2)));
            break;
        case LCAF_GEO:
            break;
    }

    return(0);
}

inline uint8_t lcaf_addr_cmp_iids(lcaf_addr_t *addr1, lcaf_addr_t *addr2) {
    if (lcaf_addr_get_type(addr1) != lcaf_addr_get_type(addr2))
        return(0);
    switch(lcaf_addr_get_type(addr1)) {
        case LCAF_IID:
            return(iid_addr_get_iid(lcaf_addr_get_iid(addr1)) == iid_addr_get_iid(lcaf_addr_get_iid(addr2)));
        case LCAF_MCAST_INFO:
            return(mc_addr_get_iid(lcaf_addr_get_iid(addr1)) == mc_addr_get_iid(lcaf_addr_get_iid(addr2)));
        default:
            return(0);
    }
}

uint8_t is_lcaf_mcast_info(uint8_t *offset) {
    uint16_t    lisp_afi;
    uint8_t     *cur_ptr;

    cur_ptr  = *offset;
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);

    return(lisp_afi == LISP_AFI_LCAF && ntohs(((lispd_pkt_lcaf_t *)cur_ptr)->type) == LCAF_MCAST_INFO);
}

inline mrsignaling_flags_t lcaf_mcinfo_get_flags(uint8_t *cur_ptr) {
    mrsignaling_flags_t  flags;

    cur_ptr = CO(cur_ptr, sizeof(uint16_t));
    flags.jbit = ((lispd_lcaf_mcinfo_hdr_t *)cur_ptr)->jbit;
    flags.lbit = ((lispd_lcaf_mcinfo_hdr_t *)cur_ptr)->lbit;
    flags.rbit = ((lispd_lcaf_mcinfo_hdr_t *)cur_ptr)->rbit;

    return(flags);
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

inline void mc_addr_copy(void *dst, void *src) {
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

char *mc_addr_to_char(void *mc){
    static char address[INET6_ADDRSTRLEN*2+4];
    sprintf(address, "(%s/%d,%s/%d)",
            ip_addr_to_char(mc_addr_get_src((mc_addr_t *)mc)),
            mc_addr_get_src_plen((mc_addr_t *)mc),
            ip_addr_to_char(mc_addr_get_grp((mc_addr_t *)mc)),
            mc_addr_get_src_plen((mc_addr_t *)mc));
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

int mc_addr_read_from_pkt(void *offset, void *mc) {
    mc = calloc(1, sizeof(mc_addr_t));
    mc_addr_set_iid((mc_addr_t *)mc, ((lispd_lcaf_mcinfo_hdr_t *)offset)->iid);
    mc_addr_set_src_plen((mc_addr_t *)mc, ((lispd_lcaf_mcinfo_hdr_t *)offset)->src_mlen);
    mc_addr_set_grp_plen((mc_addr_t *)mc, ((lispd_lcaf_mcinfo_hdr_t *)offset)->grp_mlen);

    offset = CO(offset, sizeof(lispd_lcaf_mcinfo_hdr_t));

    return(sizeof(lispd_lcaf_mcinfo_hdr_t) +
            lisp_addr_read_from_pkt(&offset, mc_addr_get_src((mc_addr_t  *)mc)) +
            lisp_addr_read_from_pkt(&offset, mc_addr_get_grp((mc_addr_t *)mc)));
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

inline void iid_addr_del(void *iidaddr) {
    lisp_addr_del(iid_addr_get_addr((iid_addr_t *)iidaddr));
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

inline void iid_addr_set_iidaddr(iid_addr_t *addr, lisp_addr_t *iidaddr) {
    assert(addr);
    assert(iidaddr);
    addr->iidaddr = iidaddr;
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

int iid_addr_read_from_pkt(void *offset, void *iid) {
    iid = calloc(1, sizeof(iid_addr_t));
    iid_addr_set_mlen(iid, ((lispd_pkt_iid_hdr_t *)offset)->mlen);
    iid_addr_set_iid(iid, ((lispd_pkt_iid_hdr_t *)offset)->iid);

    offset = CO(offset, sizeof(lispd_pkt_iid_hdr_t));
    return(lisp_addr_read_from_pkt(&offset, iid_addr_get((iid_addr_t *)iid)) + sizeof(lispd_pkt_iid_hdr_t));
}

char *iid_addr_to_char(void *iid) {
    static char buf[INET6_ADDRSTRLEN*2+4];
    sprintf(buf, "(IID %s/%d, EID %s)",
            iid_addr_get_iidaddr((iid_addr_t *)iid),
            iid_addr_get_mlen((iid_addr_t *)iid),
            ip_addr_to_char(iid_addr_get_addr((iid_addr_t *)iid)));
    return(buf);
}

void iid_addr_copy(void *dst, void *src) {
    if (!dst)
        dst = iid_addr_new();
    lisp_addr_copy(iid_addr_get_iidaddr((iid_addr_t *)dst), iid_addr_get_iidaddr((iid_addr_t *)src));
    iid_addr_set_iid((iid_addr_t *)dst, iid_addr_get_iid((iid_addr_t *)src));
    iid_addr_set_mlen((iid_addr_t*)dst, iid_addr_get_mlen(src));
}






/*
 * geo_addr_t functions
 */

inline geo_addr_t *geo_addr_new() {
    geo_addr_t *geo;
    geo = (geo_addr_t *)calloc(1, sizeof(geo_addr_t));
    geo->addr = lisp_addr_new();
    return(geo);
}

inline void geo_addr_del(void *geo) {
    lisp_addr_del(geo_addr_get_addr((geo_addr_t *)geo));
    free(geo);
}

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

inline void geo_addr_set_lat_from_coord(geo_addr_t *geo, geo_coordinates coord) {
    assert(geo);
    geo->latitude.dir = coord.dir;
    geo->latitude.deg = coord.deg;
    geo->latitude.min = coord.min;
    geo->latitude.sec = coord.sec;
}

inline void geo_addr_set_long_from_coord(geo_addr_t *geo, geo_coordinates coord) {
    assert(geo);
    geo->longitude.dir = coord.dir;
    geo->longitude.deg = coord.deg;
    geo->longitude.min = coord.min;
    geo->longitude.sec = coord.sec;
}

inline void geo_addr_set_altitude(geo_addr_t *geo, uint32_t altitude) {
    assert(geo);
    geo->altitude = altitude;
}

inline geo_coordinates geo_addr_get_lat(geo_addr_t *geo) {
    assert(geo);
    return(geo->latitude);
}

inline geo_coordinates geo_addr_get_long(geo_addr_t *geo) {
    assert(geo);
    return(geo->longitude);
}

inline geo_coordinates geo_addr_get_altitude(geo_addr_t *geo) {
    assert(geo);
    return(geo->altitude);
}

inline int geo_addr_read_from_pkt(void *offset, void *geo) {
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

inline lisp_addr_t *geo_addr_get_addr(geo_addr_t *geo) {
    assert(geo);
    return(geo->addr);
}

char *geo_addr_to_char(void *geo) {
    static char buf[INET6_ADDRSTRLEN*2+4];
    sprintf(buf, "(lat %d long %d alt %d, EID %s)",
            geo_addr_get_latitude((geo_addr_t *)geo),
            geo_addr_get_longitude((geo_addr_t *)geo),
            lisp_addr_to_char(geo_addr_get_addr((geo_addr_t *)geo)));
    return(buf);
}

void geo_addr_copy(void *dst, void *src) {
    assert(src);
    if(!dst)
        dst = geo_addr_new();
    geo_addr_set_lat_from_coord((geo_addr_t *)dst, geo_addr_get_lat((geo_addr_t *)src));
    geo_addr_set_long_from_coord((geo_addr_t *)dst, geo_addr_get_long((geo_addr_t *)src));
    geo_addr_set_altitude((geo_addr_t *)dst, geo_addr_get_altitude((geo_addr_t *)src));
    lisp_addr_copy(geo_addr_get_addr((geo_addr_t *)dst), geo_addr_get_addr((geo_addr_t *)src));
}


/*
 * rle_addr_t functions
 */
inline rle_addr_t *rle_addr_new() {
    return((rle_addr_t *)calloc(1, sizeof(iid_addr_t)));
}

inline void rle_addr_del(void *rleaddr) {
    uint32_t lvls;
    lvls = rle_addr_get_nb_levels((rle_addr_t*)rleaddr);

    free(rleaddr);
}

int rle_addr_read_from_pkt(void *offset, void *rle) {

    // XXX: to implement
    return(0);
}

char *rle_addr_to_char(void *rle) {
    static char buf[INET6_ADDRSTRLEN*2+4];
    /* XXX: to implement */
    return(buf);
}

void rle_addr_copy(void *dst, void *src) {
    /* XXX: to implement */
}


