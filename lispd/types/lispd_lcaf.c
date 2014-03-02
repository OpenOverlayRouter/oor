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
#include "lispd_address.h"


typedef void    (*del_fct)(void *);
typedef int     (*read_from_pkt_fct)(uint8_t *, void **);
typedef char    *(*to_char_fct)(void *);
typedef void    (*copy_fct)(void **, void *);
typedef int     (*cmp_fct)(void *, void *);
typedef int     (*write_to_pkt_fct)(uint8_t *, void *);
typedef int     (*size_in_pkt_fct)(void *);

del_fct del_fcts[MAX_LCAFS] = {
        0, afi_list_type_del,
        iid_type_del,
        0, 0, 0,
        geo_type_del, 0, 0,
        mc_type_del, elp_type_del, 0, 0,
        rle_type_del, 0, 0};

read_from_pkt_fct read_from_pkt_fcts[MAX_LCAFS] = {
        0, afi_list_type_read_from_pkt,
        iid_type_read_from_pkt, 0, 0, 0,
        geo_type_read_from_pkt, 0, 0,
        mc_type_read_from_pkt, elp_type_read_from_pkt, 0, 0,
        rle_type_read_from_pkt, 0, 0};

to_char_fct to_char_fcts[MAX_LCAFS] = {
        0, afi_list_type_to_char,
        iid_type_to_char, 0, 0, 0,
        geo_type_to_char, 0, 0,
        mc_type_to_char, elp_type_to_char, 0, 0,
        rle_type_to_char, 0, 0 };

write_to_pkt_fct write_to_pkt_fcts[MAX_LCAFS] = {
        0, afi_list_type_write_to_pkt,
        iid_type_write_to_pkt, 0, 0, 0,
        0, 0, 0,
        mc_type_write_to_pkt, elp_type_write_to_pkt, 0, 0,
        rle_type_write_to_pkt, 0, 0};

copy_fct copy_fcts[MAX_LCAFS] = {
        0, afi_list_type_copy,
        iid_type_copy, 0, 0, 0,
        geo_type_copy, 0, 0,
        mc_type_copy, elp_type_copy, 0, 0,
        rle_type_copy, 0, 0};

cmp_fct cmp_fcts[MAX_LCAFS] = {
        0, afi_list_type_cmp,
        iid_type_cmp, 0, 0, 0,
        0, 0, 0,
        mc_type_cmp, elp_type_cmp, 0, 0,
        rle_type_cmp, 0, 0};

size_in_pkt_fct size_in_pkt_fcts[MAX_LCAFS] = {
        0, afi_list_type_get_size_to_write,
        iid_type_get_size_to_write, 0, 0, 0,
        0, 0, 0,
        mc_type_get_size_to_write, elp_type_get_size_to_write, 0, 0,
        rle_type_get_size_to_write, 0, 0};

static inline lcaf_type _get_type(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return(lcaf->type);
}

static inline void *_get_addr(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return(lcaf->addr);
}



lcaf_addr_t *lcaf_addr_new() {
    return(calloc(1, sizeof(lcaf_addr_t)));
}

lcaf_addr_t *lcaf_addr_new_type(uint8_t type) {
    lcaf_addr_t *lcaf;

    lcaf = calloc(1, sizeof(lcaf_addr_t));
    lcaf_addr_set_type(lcaf, type);

    switch(type) {
        case LCAF_IID:
            lcaf->addr = iid_type_new();
            break;
        case LCAF_MCAST_INFO:
            lcaf->addr = mc_type_new();
            break;
        case LCAF_GEO:
            break;
        default:
            break;
    }

    return(lcaf);
}

/* free only the address part */
void lcaf_addr_del_addr(lcaf_addr_t *lcaf) {
    assert(lcaf);
    if (!lcaf->addr)
        return;
    if (!del_fcts[_get_type(lcaf)]) {
        return;
    }
    (*del_fcts[_get_type(lcaf)])(lcaf_addr_get_addr(lcaf));
}

/* free an lcaf pointer */
void lcaf_addr_del(lcaf_addr_t *lcaf) {
    assert(lcaf);
    if (!del_fcts[_get_type(lcaf)]) {
        return;
    }
    (*del_fcts[_get_type(lcaf)])(lcaf_addr_get_addr(lcaf));
    free(lcaf);
}

/*
 * lcaf_addr_t functions
 */

int lcaf_addr_read_from_pkt(uint8_t *offset, lcaf_addr_t *lcaf_addr) {

    int len = 0;

    lcaf_addr_set_type(lcaf_addr, ((lcaf_hdr_t *)offset)->type);
    if (!read_from_pkt_fcts[lcaf_addr_get_type(lcaf_addr)]) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "lcaf_addr_read_from_pkt: Cannot parse LCAF type %d:",
                lcaf_addr_get_type(lcaf_addr));
        return(BAD);
    }
    len = read_from_pkt_fcts[lcaf_addr_get_type(lcaf_addr)](offset, &lcaf_addr->addr);
    if (len != ntohs(((lcaf_hdr_t *)offset)->len) + sizeof(lcaf_hdr_t)) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "lcaf_addr_read_from_pkt: len field %d, without header, and the number of "
                "bytes read %d don't differ by 8 bytes!", ntohs(((lcaf_hdr_t *)offset)->len), len);
        return(BAD);
    }

    return(len);
}


char *lcaf_addr_to_char(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return((*to_char_fcts[_get_type(lcaf)])(lcaf_addr_get_addr(lcaf)));
}


inline lcaf_type lcaf_addr_get_type(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return(lcaf->type);
}

inline mc_t *lcaf_addr_get_mc(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return((mc_t *)lcaf_addr_get_addr(lcaf));
}

inline geo_t *lcaf_addr_get_geo(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return((geo_t *)lcaf_addr_get_addr(lcaf));
}

inline iid_t *lcaf_addr_get_iid(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return((iid_t *)lcaf_addr_get_addr(lcaf));
}

inline void *lcaf_addr_get_addr(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return(lcaf->addr);
}

inline int lcaf_addr_is_mc(lcaf_addr_t *lcaf) {
    if (lcaf_addr_get_type(lcaf) == LCAF_MCAST_INFO)
        return(1);
    else
        return(0);
}


inline void lcaf_addr_set(lcaf_addr_t *lcaf, void *newaddr, uint8_t type) {
    void *addr;
    addr = lcaf_addr_get_addr(lcaf);
    if (addr)
        lcaf_addr_del_addr(addr);
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

inline uint32_t lcaf_addr_get_size_to_write(lcaf_addr_t *lcaf) {

    if (!size_in_pkt_fcts[_get_type(lcaf)]) {
        lispd_log_msg(LISP_LOG_WARNING, "lcaf_addr_get_size_to_write: size not implemented for LCAF type %d",
                _get_type(lcaf));
        return(BAD);
    }

    return((*size_in_pkt_fcts[_get_type(lcaf)])(_get_addr(lcaf)));
}

int lcaf_addr_copy(lcaf_addr_t *dst, lcaf_addr_t *src) {

    assert(src);
    if (!copy_fcts[lcaf_addr_get_type(src)]) {
        lispd_log_msg(LISP_LOG_WARNING, "lcaf_addr_copy: copy not implemented for LCAF type %s",lcaf_addr_get_type(src));
        return(BAD);
    }

    if (_get_type(dst) != _get_type(src))
        lcaf_addr_del_addr(dst);

    lcaf_addr_set_type(dst, _get_type(src));
    (*copy_fcts[_get_type(src)])(&dst->addr, src->addr);

    return(GOOD);
}

inline int lcaf_addr_write_to_pkt(void *offset, lcaf_addr_t *lcaf) {
    assert(lcaf);
    if (!write_to_pkt_fcts[_get_type(lcaf)]) {
        lispd_log_msg(LISP_LOG_WARNING, "lcaf_addr_write_to_pkt: write not implemented for LCAF type %d",
                _get_type(lcaf));
        return(BAD);
    }

    return((*write_to_pkt_fcts[_get_type(lcaf)])(offset, _get_addr(lcaf)));
}

inline int lcaf_addr_cmp(lcaf_addr_t *addr1, lcaf_addr_t *addr2) {
    if (lcaf_addr_get_type(addr1) != lcaf_addr_get_type(addr2))
        return(-1);
    if (!(cmp_fcts[lcaf_addr_get_type(addr1)])) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "lcaf_addr_cmp: cmp not implemented for type %d", lcaf_addr_get_type(addr1));
        return(-1);
    }
    return((*cmp_fcts[lcaf_addr_get_type(addr1)])(lcaf_addr_get_addr(addr1), lcaf_addr_get_addr(addr2)));

}

inline uint8_t lcaf_addr_cmp_iids(lcaf_addr_t *addr1, lcaf_addr_t *addr2) {
    if (_get_type(addr1) != _get_type(addr2))
        return(0);
    switch(_get_type(addr1)) {
        case LCAF_IID:
            return(lcaf_iid_get_iid(addr1) == lcaf_iid_get_iid(addr2));
        case LCAF_MCAST_INFO:
            return(mc_type_get_iid(_get_addr(addr1)) == mc_type_get_iid(addr2));
        default:
            return(0);
    }
}







/*
 * mc_addr_t functions
 */

/* external */
inline lisp_addr_t *lcaf_mc_get_src(lcaf_addr_t *mc) {
    assert(mc);
    if (lcaf_addr_get_type(mc) != LCAF_MCAST_INFO)
        return(NULL);
    return(mc_type_get_src(lcaf_addr_get_mc(mc)));
}

inline lisp_addr_t *lcaf_mc_get_grp(lcaf_addr_t *mc) {
    assert(mc);
    if (lcaf_addr_get_type(mc) != LCAF_MCAST_INFO)
        return(NULL);
    return(mc_type_get_grp(lcaf_addr_get_mc(mc)));
}

inline uint32_t lcaf_mc_get_iid(lcaf_addr_t *mc) {
    assert(mc);
    return(mc_type_get_iid(lcaf_addr_get_mc(mc)));
}

inline uint8_t lcaf_mc_get_src_plen(lcaf_addr_t *mc) {
    assert(mc);
    return(mc_type_get_src_plen(mc->addr));
}

inline uint8_t lcaf_mc_get_grp_plen(lcaf_addr_t *mc) {
    assert(mc);
    return(mc_type_get_grp_plen(mc->addr));
}

inline uint8_t lcaf_mc_get_afi(lcaf_addr_t *mc) {
    assert(mc);
    return(mc_type_get_afi(mc->addr));
}


inline lcaf_mcinfo_hdr_t *address_field_get_mc_hdr(address_field *addr) {
    return((lcaf_mcinfo_hdr_t *)address_field_data(addr));
}




/* these shouldn't be called from outside */

inline mc_t *mc_type_new() {
    mc_t *mc = calloc(1, sizeof(mc_t));
    mc->src = lisp_addr_new();
    mc->grp = lisp_addr_new();
    return(mc);
}

inline void mc_type_del(void *mc) {
    lisp_addr_del(mc_type_get_src(mc));
    lisp_addr_del(mc_type_get_grp(mc));

    free(mc);
}

inline void mc_type_set_src_plen(mc_t *mc, uint8_t plen) {
    assert(mc);
    mc->src_plen = plen;
}

inline void mc_type_set_grp_plen(mc_t *mc, uint8_t plen) {
    assert(mc);
    mc->grp_plen = plen;
}

inline void mc_type_set_iid(mc_t *mc, uint32_t iid) {
    assert(mc);
    mc->iid = iid;
}

inline void mc_type_set_src(void *mc, lisp_addr_t *src) {
    assert(mc);
    assert(src);
    lisp_addr_copy(mc_type_get_src(mc), src);
}

inline void mc_type_set_grp(mc_t *mc, lisp_addr_t *grp) {
    assert(mc);
    assert(grp);
    lisp_addr_copy(mc_type_get_grp(mc), grp);
}

inline void mc_type_copy(void **dst, void *src) {
    if (!(*dst))
        *dst = mc_type_new();
    mc_type_set_iid(*dst, mc_type_get_iid(src));
    mc_type_set_src_plen(*dst, mc_type_get_src_plen(src));
    mc_type_set_grp_plen(*dst, mc_type_get_grp_plen(src));
    lisp_addr_copy(mc_type_get_src(*dst), mc_type_get_src(src));
    lisp_addr_copy(mc_type_get_grp(*dst), mc_type_get_grp(src));
}

inline int mc_type_cmp(void *mc1, void *mc2) {
    if (    (mc_type_get_iid(mc1) != mc_type_get_iid(mc2)) ||
            (mc_type_get_src_plen(mc1) != mc_type_get_src_plen(mc2)) ||
            (mc_type_get_grp_plen(mc1) != mc_type_get_grp_plen(mc2)))
        return(-1);

    /* XXX: rushed implementation
     * (S, G) comparison
     * First compare S and then G*/
    int res = lisp_addr_cmp(mc_type_get_src(mc1), mc_type_get_src(mc2));
    if (res == 0)
        return(lisp_addr_cmp(mc_type_get_grp(mc1), mc_type_get_grp(mc2)));
    else
        return(res);

}

inline void mc_type_set(mc_t *dst, lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid) {
    assert(src);
    assert(dst);
    assert(grp);
    mc_type_set_src(dst, src);
    mc_type_set_grp(dst, grp);
    mc_type_set_src_plen(dst, splen);
    mc_type_set_grp_plen(dst, gplen);
    mc_type_set_iid(dst, iid);
}

/**
 * mc_addr_init - makes an mc_addr_t from the parameters passed
 * @ src: source ip
 * @ grp: group ip
 * @ splen: source prefix length
 * @ gplen: group prefix length
 * @ iid: iid of the address
 */
mc_t *mc_type_init(lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid) {
    mc_t *mc;

    assert(src);
    assert(grp);

    mc = mc_type_new();
    lisp_addr_copy(mc_type_get_src(mc), src);
    lisp_addr_copy(mc_type_get_grp(mc), grp);
    mc_type_set_src_plen(mc, splen);
    mc_type_set_grp_plen(mc, gplen);
    mc_type_set_iid(mc, iid);
    return(mc);
}

inline lisp_addr_t *mc_type_get_src(mc_t *mc) {
    assert(mc);
    return(mc->src);
}

inline lisp_addr_t *mc_type_get_grp(mc_t *mc) {
    assert(mc);
    return(mc->grp);
}

inline uint8_t mc_type_get_afi(mc_t *mc) {
    assert(mc);
    return(lisp_addr_ip_get_afi(mc_type_get_grp(mc)));
}

inline uint32_t mc_type_get_iid(void *mc) {
    assert(mc);
    return(((mc_t *)mc)->iid);
}

inline uint8_t mc_type_get_src_plen(mc_t *mc) {
    assert(mc);
    return(mc->src_plen);
}

inline uint8_t mc_type_get_grp_plen(mc_t *mc) {
    assert(mc);
    return(mc->grp_plen);
}

/* set functions common to all types */

char *mc_type_to_char(void *mc){
    static char buf[10][INET6_ADDRSTRLEN*2+4];
    static unsigned int i;

    i++; i = i % 10;
    sprintf(buf[i], "(%s/%d,%s/%d)",
            lisp_addr_to_char(mc_type_get_src((mc_t *)mc)),
            mc_type_get_src_plen((mc_t *)mc),
            lisp_addr_to_char(mc_type_get_grp((mc_t *)mc)),
            mc_type_get_src_plen((mc_t *)mc));
    return(buf[i]);
}

int mc_type_get_size_to_write(void *mc) {
    return( sizeof(lcaf_mcinfo_hdr_t)+
            lisp_addr_get_size_in_field(mc_type_get_src(mc)) +
//            sizeof(uint16_t)+ /* grp afi */
            lisp_addr_get_size_in_field(mc_type_get_grp(mc)) );
}

inline int mc_type_write_to_pkt(uint8_t *offset, void *mc) {
    int     lena1 = 0, lena2 = 0;
    uint8_t *cur_ptr = NULL;
    ((lcaf_mcinfo_hdr_t *)offset)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_mcinfo_hdr_t *)offset)->rsvd1 = 0;
    ((lcaf_mcinfo_hdr_t *)offset)->flags = 0;
    ((lcaf_mcinfo_hdr_t *)offset)->type = LCAF_MCAST_INFO;
    ((lcaf_mcinfo_hdr_t *)offset)->rsvd2 = 0;
    ((lcaf_mcinfo_hdr_t *)offset)->R = 0;
    ((lcaf_mcinfo_hdr_t *)offset)->L = 0;
    ((lcaf_mcinfo_hdr_t *)offset)->J = 0;
    ((lcaf_mcinfo_hdr_t *)offset)->iid = htonl(mc_type_get_iid(mc));
    ((lcaf_mcinfo_hdr_t *)offset)->reserved = 0;
    ((lcaf_mcinfo_hdr_t *)offset)->src_mlen = mc_type_get_src_plen(mc);
    ((lcaf_mcinfo_hdr_t *)offset)->grp_mlen = mc_type_get_grp_plen(mc);
    cur_ptr = CO(offset, sizeof(lcaf_mcinfo_hdr_t));
    cur_ptr = CO(cur_ptr, (lena1 = lisp_addr_write(cur_ptr, mc_type_get_src(mc))));
    lena2 = lisp_addr_write(cur_ptr, mc_type_get_grp(mc));
    ((lcaf_mcinfo_hdr_t *)offset)->len = htons(lena1+lena2+8*sizeof(uint8_t));
    return(sizeof(lcaf_mcinfo_hdr_t)+lena1+lena2);
}

int mc_type_read_from_pkt(uint8_t *offset, void **mc) {
    int srclen, grplen;
    srclen = grplen =0;

    *mc = mc_type_new();
    mc_type_set_iid(*mc, ntohl(((lcaf_mcinfo_hdr_t *)offset)->iid));
    mc_type_set_src_plen(*mc, ((lcaf_mcinfo_hdr_t *)offset)->src_mlen);
    mc_type_set_grp_plen(*mc, ((lcaf_mcinfo_hdr_t *)offset)->grp_mlen);

    offset = CO(offset, sizeof(lcaf_mcinfo_hdr_t));
    srclen = lisp_addr_read_from_pkt(offset, mc_type_get_src(*mc));
    offset = CO(offset, srclen);
    grplen = lisp_addr_read_from_pkt(offset, mc_type_get_grp(*mc));
    return(sizeof(lcaf_mcinfo_hdr_t) + srclen + grplen);

}


/* Function that builds mc packets from packets on the wire. */
int lcaf_addr_set_mc(lcaf_addr_t *lcaf, lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid) {
    mc_t            *mc;

    if (lcaf->addr)
        lcaf_addr_del_addr(lcaf);
    mc  = mc_type_init(src, grp, splen, gplen, iid);
    lcaf_addr_set_type(lcaf, LCAF_MCAST_INFO);
    lcaf_addr_set_addr(lcaf, mc);
    return(GOOD);
}

lisp_addr_t *lisp_addr_build_mc(lisp_addr_t *src, lisp_addr_t *grp) {
    lisp_addr_t     *mceid;
    uint8_t         mlen;

    mlen = (lisp_addr_ip_get_afi(src) == AF_INET) ? 32 : 128;
    mceid = lisp_addr_new_afi(LM_AFI_LCAF);
    lcaf_addr_set_mc(lisp_addr_get_lcaf(mceid), src, grp, mlen, mlen, 0);
    return(mceid);
}

inline int lisp_addr_is_mcinfo(lisp_addr_t *addr) {
    return(lisp_addr_get_afi(addr) == LM_AFI_LCAF && lisp_addr_lcaf_get_type(addr) == LCAF_MCAST_INFO);
}









/*
 * iid_addr_t functions
 */
inline iid_t *iid_type_new() {
    iid_t *iid;
    iid = (iid_t *)calloc(1, sizeof(iid_t));
    iid->iidaddr = lisp_addr_new();
    return(iid);
}

inline void iid_type_del(void *iid) {
    lisp_addr_del(iid_type_get_addr((iid_t *)iid));
    free(iid);
}

inline uint8_t iid_type_get_mlen(iid_t *iid) {
    assert(iid);
    return(iid->mlen);
}

inline uint32_t lcaf_iid_get_iid(lcaf_addr_t *iid) {
    return(iid_type_get_iid(_get_addr(iid)));
}

inline uint32_t iid_type_get_iid(iid_t *iid) {
    assert(iid);
    return(iid->iid);
}

inline lisp_addr_t *iid_type_get_addr(void *iid) {
    assert(iid);
    return(((iid_t *)iid)->iidaddr);
}



inline void iid_type_set_iid(iid_t *iidt, uint32_t iid) {
    assert(iidt);
    iidt->iid = iid;
}

inline void iid_type_set_addr(iid_t *iidt, lisp_addr_t *iidaddr) {
    assert(iidt);
    assert(iidaddr);
    iidt->iidaddr = iidaddr;
}

inline void iid_type_set_mlen(iid_t *iid, uint8_t mlen) {
    assert(iid);
    iid->mlen = mlen;
}

inline int iid_type_cmp(void *iid1, void *iid2) {
    if ((iid_type_get_iid((iid_t *)iid1) != iid_type_get_iid((iid_t *)iid2)))
        return( (iid_type_get_iid((iid_t *)iid1) >  iid_type_get_iid((iid_t *)iid2)) ? 1: 2);

    if ((iid_type_get_mlen((iid_t *)iid1) != iid_type_get_mlen((iid_t *)iid2)))
        return((iid_type_get_mlen((iid_t *)iid1) > iid_type_get_mlen((iid_t *)iid2)) ? 1 :2);

    return(lisp_addr_cmp(iid_type_get_addr((iid_t *)iid1), iid_type_get_addr((iid_t *)iid2)));
}

int iid_type_get_size_to_write(void *iid) {
    return( sizeof(lcaf_iid_hdr_t)+
            lisp_addr_get_size_in_field(iid_type_get_addr(iid)));
}

inline int iid_type_write_to_pkt(uint8_t *offset, void *iid) {
    ((lcaf_iid_hdr_t *)offset)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_iid_hdr_t *)offset)->rsvd1 = 0;
    ((lcaf_iid_hdr_t *)offset)->flags = 0;
    ((lcaf_iid_hdr_t *)offset)->type = LCAF_IID;
    ((lcaf_iid_hdr_t *)offset)->mlen = iid_type_get_mlen(iid);
    ((lcaf_iid_hdr_t *)offset)->len = htons(iid_type_get_size_to_write(iid));
    ((lcaf_iid_hdr_t *)offset)->iid = htonl(iid_type_get_iid(iid));
    return(sizeof(lcaf_iid_hdr_t) +
            lisp_addr_write(CO(offset, sizeof(lcaf_iid_hdr_t)), iid_type_get_addr(iid)));
}

int iid_type_read_from_pkt(uint8_t *offset, void **iid) {
    *iid = iid_type_new();
    iid_type_set_mlen(*iid, ((lcaf_iid_hdr_t *)offset)->mlen);
    iid_type_set_iid(*iid, ((lcaf_iid_hdr_t *)offset)->iid);

    offset = CO(offset, sizeof(lcaf_iid_hdr_t));
    return(lisp_addr_read_from_pkt(offset, iid_type_get_addr(*iid)) + sizeof(lcaf_iid_hdr_t));
}

char *iid_type_to_char(void *iid) {
    static char buf[10][INET6_ADDRSTRLEN*2+4];
    static unsigned int i;

    i++; i = i % 10;
    sprintf(buf[i], "(IID %d/%d, EID %s)",
            iid_type_get_iid(iid),
            iid_type_get_mlen(iid),
            lisp_addr_to_char(iid_type_get_addr(iid)));
    return(buf[i]);
}

void iid_type_copy(void **dst, void *src) {
    if (!(*dst))
        *dst = iid_type_new();
    lisp_addr_copy(iid_type_get_addr((iid_t *)*dst), iid_type_get_addr((iid_t *)src));
    iid_type_set_iid((iid_t *)*dst, iid_type_get_iid((iid_t *)src));
    iid_type_set_mlen((iid_t*)*dst, iid_type_get_mlen(src));
}

iid_t *iid_type_init(int iid, lisp_addr_t *addr, uint8_t mlen) {
    iid_t *iidt = iid_type_new();
    iidt->iid = iid;
    iidt->iidaddr = addr;
    iidt->mlen = mlen;
    return(iidt);
}

lcaf_addr_t *lcaf_iid_init(int iid, lisp_addr_t *addr, uint8_t mlen) {
    lcaf_addr_t *iidaddr    = lcaf_addr_new();

    iidaddr->type = LCAF_IID;
    iidaddr->addr = iid_type_init(iid, addr, mlen);

    return(iidaddr);
}






/*
 * geo_addr_t functions
 */

inline geo_t *geo_type_new() {
    geo_t *geo;
    geo = (geo_t *)calloc(1, sizeof(geo_t));
    geo->addr = lisp_addr_new();
    return(geo);
}

inline void geo_type_del(void *geo) {
    lisp_addr_del(geo_type_get_addr((geo_t *)geo));
    free(geo);
}

inline void geo_type_set_addr(geo_t *geo, lisp_addr_t *addr){
    assert(addr);
    assert(geo);
    geo->addr = addr;
}

inline void geo_type_set_lat(geo_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec) {
    assert(geo);
    geo->latitude.dir = dir;
    geo->latitude.deg = deg;
    geo->latitude.min = min;
    geo->latitude.sec = sec;
}

inline void geo_type_set_long(geo_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec) {
    assert(geo);
    geo->longitude.dir = dir;
    geo->longitude.deg = deg;
    geo->longitude.min = min;
    geo->longitude.sec = sec;
}

inline void geo_type_set_lat_from_coord(geo_t *geo, geo_coordinates *coord) {
    assert(geo);
    geo->latitude.dir = coord->dir;
    geo->latitude.deg = coord->deg;
    geo->latitude.min = coord->min;
    geo->latitude.sec = coord->sec;
}

inline void geo_type_set_long_from_coord(geo_t *geo, geo_coordinates *coord) {
    assert(geo);
    geo->longitude.dir = coord->dir;
    geo->longitude.deg = coord->deg;
    geo->longitude.min = coord->min;
    geo->longitude.sec = coord->sec;
}

inline void geo_type_set_altitude(geo_t *geo, uint32_t altitude) {
    assert(geo);
    geo->altitude = altitude;
}

inline geo_coordinates *geo_type_get_lat(geo_t *geo) {
    assert(geo);
    return(&(geo->latitude));
}

inline geo_coordinates *geo_type_get_long(geo_t *geo) {
    assert(geo);
    return(&(geo->longitude));
}

inline uint32_t geo_type_get_altitude(geo_t *geo) {
    assert(geo);
    return(geo->altitude);
}

inline int geo_type_read_from_pkt(uint8_t *offset, void **geo) {
    *geo = geo_type_new();
    geo_type_set_lat(*geo,
            ((lcaf_geo_hdr_t *)offset)->latitude_dir,
            ((lcaf_geo_hdr_t *)offset)->latitude_deg,
            ((lcaf_geo_hdr_t *)offset)->latitude_min,
            ((lcaf_geo_hdr_t *)offset)->latitude_sec);
    geo_type_set_long(*geo,
            ((lcaf_geo_hdr_t *)offset)->longitude_dir,
            ((lcaf_geo_hdr_t *)offset)->longitude_deg,
            ((lcaf_geo_hdr_t *)offset)->longitude_min,
            ((lcaf_geo_hdr_t *)offset)->longitude_sec);
    geo_type_set_altitude(*geo, ((lcaf_geo_hdr_t *)offset)->altitude);

    offset = CO(offset, sizeof(lcaf_geo_hdr_t));
    return(sizeof(lcaf_geo_hdr_t) +
            lisp_addr_read_from_pkt(offset, geo_type_get_addr(*geo)));
}

inline lisp_addr_t *geo_type_get_addr(geo_t *geo) {
    return(geo->addr);
}


char *geo_type_to_char(void *geo) {
    static char buf[10][INET6_ADDRSTRLEN*2+4];
    static unsigned int i;

    i++; i = i % 10;
    sprintf(buf[i], "(latitude: %s | longitude: %s | altitude: %d, EID %s)",
            geo_coord_to_char(geo_type_get_lat(geo)),
            geo_coord_to_char(geo_type_get_long(geo)),
            geo_type_get_altitude(geo),
            lisp_addr_to_char(geo_type_get_addr(geo)));
    return(buf[i]);
}

char *geo_coord_to_char(geo_coordinates *coord) {
    static char buf[INET6_ADDRSTRLEN*2+4];
    sprintf(buf, "dir %d deg %d min %d sec %d",
            coord->dir, coord->deg, coord->min, coord->sec);
    return(buf);
}

void geo_type_copy(void **dst, void *src) {
    assert(src);
    if(!(*dst))
        *dst = geo_type_new();
    geo_type_set_lat_from_coord((geo_t *)*dst, geo_type_get_lat(src));
    geo_type_set_long_from_coord((geo_t *)*dst, geo_type_get_long(src));
    geo_type_set_altitude((geo_t *)*dst, geo_type_get_altitude(src));
    lisp_addr_copy(geo_type_get_addr((geo_t *)*dst), geo_type_get_addr(src));
}



/*
 * elp_addr_t functions
 */

elp_t *elp_type_new() {
    elp_t *elp;
    elp = calloc(1, sizeof(elp_t));
    elp->nodes = glist_new(NO_CMP, (glist_del_fct)elp_node_del);
    return(elp);
}

void elp_type_del(void *elp) {
    glist_destroy(((elp_t *)elp)->nodes);
    free(elp);
}

int elp_type_get_size_to_write(void *elp) {
    glist_entry_t   *it     = NULL;
    elp_node_t      *node   = NULL;
    uint32_t len = 0;

    len += sizeof(lcaf_hdr_t);
    glist_for_each_entry(it, ((elp_t *)elp)->nodes) {
        node = glist_entry_data(it);
        len += sizeof(elp_node_flags) + lisp_addr_get_size_in_field(node->addr);
    }

    return(len);
}

int elp_type_write_to_pkt(uint8_t *offset, void *elp) {
    uint32_t        len = 0, addrlen;
    elp_node_t      *node    = NULL;
    uint8_t         *cur_ptr = NULL;
    glist_entry_t   *it     = NULL;

    cur_ptr = offset;
    ((lcaf_hdr_t*)cur_ptr)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_hdr_t*)cur_ptr)->flags = 0;
    ((lcaf_hdr_t*)cur_ptr)->rsvd1 = 0;
    ((lcaf_hdr_t*)cur_ptr)->rsvd2 = 0;
    ((lcaf_hdr_t*)cur_ptr)->type = LCAF_EXPL_LOC_PATH;
    len += sizeof(lcaf_hdr_t);
    cur_ptr = CO(cur_ptr, sizeof(lcaf_hdr_t));

    glist_for_each_entry(it, ((elp_t *)elp)->nodes) {
        node = glist_entry_data(it);
        ((elp_node_flags *)cur_ptr)->L = node->L;
        ((elp_node_flags *)cur_ptr)->P = node->P;
        ((elp_node_flags *)cur_ptr)->S = node->S;
        ((elp_node_flags *)cur_ptr)->rsvd1 = 0;
        ((elp_node_flags *)cur_ptr)->rsvd2 = 0;
        cur_ptr = CO(cur_ptr, sizeof(elp_node_flags));
        addrlen = lisp_addr_write(cur_ptr, node->addr);
        if (addrlen <=0)
            return(BAD);
        cur_ptr = CO(cur_ptr, addrlen);
        len += sizeof(elp_node_flags) + addrlen;
    }
    /* length is only what follows the first 8 bytes of the lcaf hdr */
    ((lcaf_hdr_t*)offset)->len = htons(len-sizeof(lcaf_hdr_t));
    return(len);
}

int elp_type_read_from_pkt(uint8_t *offset, void **elp) {
    int                 len = 0, totallen = 0, readlen=0;
    elp_node_t          *enode = NULL;
    elp_node_flags      *flags = NULL;
    elp_t               *elp_ptr = NULL;

    *elp = elp_type_new();
    elp_ptr = *elp;

    totallen = ntohs(((lcaf_hdr_t *)offset)->len);
    readlen = sizeof(lcaf_hdr_t);
    offset = CO(offset, sizeof(lcaf_hdr_t));

    while(totallen > 0) {
        enode = calloc(1, sizeof(elp_node_t));
        flags = (elp_node_flags *)offset;
        enode->L = flags->L;
        enode->P = flags->P;
        enode->S = flags->S;
        offset = CO(offset, sizeof(elp_node_flags));
        enode->addr = lisp_addr_new();
        len = lisp_addr_read_from_pkt(offset, enode->addr);
        if (len <= 0)
            goto err;
        offset = CO(offset, len);
        totallen = totallen - sizeof(elp_node_flags) - len;
        readlen += sizeof(elp_node_flags) + len;

        glist_add_tail(enode, elp_ptr->nodes);

    }
    if (totallen !=0)
        lispd_log_msg(LISP_LOG_DEBUG_1, "elp_type_read_from_pkt: Error encountered!");

    return(readlen);

err:
    glist_destroy(elp_ptr->nodes);
    return(BAD);
}

char *elp_type_to_char(void *elp) {
    static char buf[3][500];
    static unsigned int i;
    i++; i = i % 10;

    glist_entry_t *it;
    elp_node_t *node;
    int j = 0;

    sprintf(buf[i], "ELP:");

    glist_for_each_entry(it, ((elp_t *)elp)->nodes) {
        j++;
        node = glist_entry_data(it);
//        sprintf(buf[i]+strlen(buf[i]), "[%d] %s f: %s%s%s", j, lisp_addr_to_char(node->addr),
//                (node->L) ? "L" : "l", (node->P) ? "P" : "p", (node->S) ? "S" : "s");
        sprintf(buf[i]+strlen(buf[i]), "[%d] %s ", j, lisp_addr_to_char(node->addr));
    }
    return(buf[i]);
}

elp_node_t *elp_node_clone(elp_node_t *sen) {
    elp_node_t *en = calloc(1, sizeof(elp_node_t));
    en->L = sen->L;
    en->P = sen->P;
    en->S = sen->S;
    en->addr = lisp_addr_clone(sen->addr);
    return(en);
}

void elp_type_copy(void **dst, void *src) {
    elp_t       *elp_ptr    = NULL;
    elp_node_t  *node       = NULL;
    elp_node_t  *cp_node    = NULL;
    glist_entry_t *it       = NULL;

    if (!*dst)
        *dst = elp_type_new();
    elp_ptr = *dst;

    glist_for_each_entry(it, ((elp_t *)src)->nodes) {
        node = glist_entry_data(it);
        cp_node = elp_node_clone(node);
        glist_add_tail(cp_node, elp_ptr->nodes);
    }
}


int elp_type_cmp(void *elp1, void *elp2) {
    elp_node_t  *node1      = NULL;
    elp_node_t  *node2      = NULL;
    glist_entry_t   *it1    = NULL;
    glist_entry_t   *it2    = NULL;
    int ret = 0;


    it1 = glist_first(((elp_t*)elp1)->nodes);
    it2 = glist_first(((elp_t*)elp2)->nodes);

    while(it1 != glist_head(((elp_t*)elp1)->nodes) && it2 != glist_head(((elp_t*)elp2)->nodes)) {
        node1 = glist_entry_data(it1);
        node2 = glist_entry_data(it2);
        if (node1->L != node2->L || node1->S != node2->S || node1->P != node2->P)
            return(1);
        if ((ret = lisp_addr_cmp(node1->addr, node2->addr)) != 0)
            return(ret);
        it1 = glist_next(it1);
        it2 = glist_next(it2);
    }

    return(0);
}

inline void elp_node_del(elp_node_t *enode) {
    lisp_addr_del(enode->addr);
    free(enode);
}

inline void lcaf_elp_add_node(lcaf_addr_t *lcaf, elp_node_t *enode) {
    if (!((elp_t *)lcaf->addr)->nodes)
        ((elp_t *)lcaf->addr)->nodes = glist_new(NO_CMP, (glist_del_fct)elp_node_del);
    glist_add_tail(enode, ((elp_t *)lcaf->addr)->nodes);
}




/*
 * rle_addr_t functions
 */
inline rle_t *rle_type_new() {
    rle_t *rle = calloc(1, sizeof(iid_t));
    rle->nodes = glist_new(NO_CMP, (glist_del_fct)rle_node_del);
    return(rle);
}

inline void rle_type_del(void *rleaddr) {
    if (!rleaddr)
        return;
    glist_destroy(((rle_t *)rleaddr)->nodes);
    free(rleaddr);
}

int rle_type_read_from_pkt(uint8_t *offset, void **rle) {
    int                 len = 0, totallen = 0, readlen=0;
    rle_node_t          *rnode      = NULL;
    rle_node_hdr_t      *rhdr       = NULL;
    rle_t               *rle_ptr    = NULL;

    *rle = rle_type_new();
    rle_ptr = *rle;

    totallen = ntohs(((lcaf_hdr_t *)offset)->len);
    readlen = sizeof(lcaf_hdr_t);
    offset = CO(offset, sizeof(lcaf_hdr_t));

    while(totallen > 0) {
        rnode = calloc(1, sizeof(rle_node_t));
        rhdr = (rle_node_hdr_t *)offset;
        rnode->level = rhdr->level;
        offset = CO(offset, sizeof(rle_node_hdr_t));
        rnode->addr = lisp_addr_new();
        len = lisp_addr_read_from_pkt(offset, rnode->addr);
        if (len <= 0)
            goto err;
        offset = CO(offset, len);
        totallen = totallen - sizeof(rle_node_hdr_t) -len;
        readlen += sizeof(rle_node_hdr_t) + len;

        glist_add_tail(rnode, rle_ptr->nodes);
    }
    if (totallen !=0)
        lispd_log_msg(LISP_LOG_DEBUG_1, "rle_type_read_from_pkt: Error encountered!");

    return(readlen);

err:
    glist_destroy(rle_ptr->nodes);
    return(BAD);
}

int rle_type_write_to_pkt(uint8_t *offset, void *rle) {
    uint32_t        len = 0, addrlen;
    rle_node_t      *node    = NULL;
    uint8_t         *cur_ptr = NULL;
    glist_entry_t   *it     = NULL;

    cur_ptr = offset;
    ((lcaf_hdr_t*)cur_ptr)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_hdr_t*)cur_ptr)->flags = 0;
    ((lcaf_hdr_t*)cur_ptr)->rsvd1 = 0;
    ((lcaf_hdr_t*)cur_ptr)->rsvd2 = 0;
    ((lcaf_hdr_t*)cur_ptr)->type = LCAF_RLE;
    len += sizeof(lcaf_hdr_t);
    cur_ptr = CO(cur_ptr, sizeof(lcaf_hdr_t));

    glist_for_each_entry(it, ((rle_t *)rle)->nodes) {
        node = glist_entry_data(it);
        ((rle_node_hdr_t *)cur_ptr)->level = node->level;
        memset(((rle_node_hdr_t *)cur_ptr)->rsvd, 0, 3*sizeof(uint8_t));
        cur_ptr = CO(cur_ptr, sizeof(rle_node_hdr_t));
        addrlen = lisp_addr_write(cur_ptr, node->addr);
        if (addrlen <=0)
            return(BAD);
        cur_ptr = CO(cur_ptr, addrlen);
        len += sizeof(rle_node_hdr_t) + addrlen;
    }
    /* length is only what follows the first 8 bytes of the lcaf hdr */
    ((lcaf_hdr_t*)offset)->len = htons(len-sizeof(lcaf_hdr_t));
    return(len);
}

int rle_type_get_size_to_write(void *elp) {
    glist_entry_t   *it     = NULL;
    rle_node_t      *node   = NULL;
    uint32_t len = 0;

    len += sizeof(lcaf_hdr_t);
    glist_for_each_entry(it, ((rle_t *)elp)->nodes) {
        node = glist_entry_data(it);
        len += sizeof(rle_node_hdr_t) + lisp_addr_get_size_in_field(node->addr);
    }

    return(len);
}

char *rle_type_to_char(void *rle) {
    static char buf[3][500];
    static unsigned int i;
    i++; i = i % 10;

    glist_entry_t   *it     = NULL;
    rle_node_t      *node   = NULL;
    int j = 0;

    sprintf(buf[i], "RLE:");

    glist_for_each_entry(it, ((rle_t *)rle)->nodes) {
        j++;
        node = glist_entry_data(it);
        sprintf(buf[i]+strlen(buf[i]), "[%d] %s ", node->level, lisp_addr_to_char(node->addr));
    }
    return(buf[i]);
}

rle_node_t *rle_node_clone(rle_node_t *srn) {
    rle_node_t *rn = calloc(1, sizeof(rle_node_t));
    rn->level = srn->level;
    rn->addr = lisp_addr_clone(srn->addr);
    return(rn);
}

inline rle_node_t *rle_node_new() {
    rle_node_t *rnode = calloc(1, sizeof(rle_node_t));
    rnode->addr = lisp_addr_new();
    return(rnode);
}

inline void rle_node_del(rle_node_t *rnode) {
    lisp_addr_del(rnode->addr);
    free(rnode);
}

void rle_type_copy(void **dst, void *src) {
    rle_t       *rle_ptr    = NULL;
    rle_node_t  *node       = NULL;
    rle_node_t  *cp_node    = NULL;
    glist_entry_t *it       = NULL;

    if (!*dst)
        *dst = elp_type_new();
    rle_ptr = *dst;

    glist_for_each_entry(it, ((rle_t *)src)->nodes) {
        node = glist_entry_data(it);
        cp_node = rle_node_clone(node);
        glist_add_tail(cp_node, rle_ptr->nodes);
    }
}


int rle_type_cmp(void *elp1, void *elp2) {
    rle_node_t  *node1      = NULL;
    rle_node_t  *node2      = NULL;
    glist_entry_t   *it1    = NULL;
    glist_entry_t   *it2    = NULL;
    int ret = 0;


    it1 = glist_first(((rle_t*)elp1)->nodes);
    it2 = glist_first(((rle_t*)elp2)->nodes);

    while(it1 != glist_head(((elp_t*)elp1)->nodes) && it2 != glist_head(((elp_t*)elp2)->nodes)) {
        node1 = glist_entry_data(it1);
        node2 = glist_entry_data(it2);
        if (node1->level != node2->level) {
            /* nodes closer to ITR are "more important" */
            return(node1->level < node2->level ? 1 : 2);
        }

        if ((ret = lisp_addr_cmp(node1->addr, node2->addr)) != 0)
            return(ret);
        it1 = glist_next(it1);
        it2 = glist_next(it2);
    }

    return(0);
}






/*
 * AFI-list type functions
 */

inline afi_list_t *afi_list_type_new() {
    return(calloc(1, sizeof(afi_list_t)));
}

void afi_list_type_del(void *afil) {
    afi_list_node *node = NULL, *aux_node = NULL;
    node = ((afi_list_t *)afil)->list;
    while(node) {
        aux_node = node->next;
        if (node->addr) {
            lisp_addr_del(node->addr);
            free(node);
        }
        node = aux_node;
    }
    free(afil);
}

int afi_list_type_get_size_to_write(void *afil) {
    int len = 0;
    afi_list_node *node = NULL;
    len += sizeof(lcaf_afi_list_hdr_t);
    while(node) {
        len += lisp_addr_get_size_in_field(node->addr);
        node = node->next;
    }
    return(len);
}

int afi_list_type_write_to_pkt(uint8_t *offset, void *afil) {
    afi_list_node   *node = NULL;
    uint8_t         *cur_ptr = NULL;
    int             len = 0, lenw = 0;

    cur_ptr = offset;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_afi_list_hdr_t *)cur_ptr)->flags = 0;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->rsvd1 = 0;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->rsvd2 = 0;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->type = LCAF_AFI_LIST;

    cur_ptr = CO(cur_ptr, sizeof(lcaf_afi_list_hdr_t));

    node = ((afi_list_t *)afil)->list;
    while(node) {
        lenw = lisp_addr_write(cur_ptr, node->addr);
        if (lenw <= 0)
            return(BAD);
        cur_ptr = CO(cur_ptr, lenw);
    }
    len = cur_ptr-offset;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->length = htons(len-sizeof(lcaf_afi_list_hdr_t));
    return(len);
}

int afi_list_type_read_from_pkt(uint8_t *offset, void **afilptr) {
    afi_list_node   *node   = NULL;
    afi_list_t      *afil   = NULL;
    uint8_t         *cur_ptr = NULL;
    int len = 0, rlen = 0;

    cur_ptr = offset;
    afil = *afilptr;
    if (!afil)
        if(!(afil = afi_list_type_new()))
            return(BAD);

    len = ntohs(((lcaf_afi_list_hdr_t *)offset)->length);
    cur_ptr = CO(cur_ptr, sizeof(lcaf_afi_list_hdr_t));
    node = afil->list;
    while(len > 0) {
        node = calloc(1,sizeof(afi_list_node));
        node->addr = lisp_addr_new();
        if (!node->addr)
            goto err;
        rlen = lisp_addr_read_from_pkt(cur_ptr, node->addr);
        if (rlen <= 0)
           goto err;
        cur_ptr = CO(cur_ptr, rlen);
        len -= rlen;
        node = node->next;
    }

    return(cur_ptr - offset);

err:
    afi_list_type_del(afil);
    return(BAD);
}

char *afi_list_type_to_char(void *afil) {
    static char buf[3][500];
    static int i;
    int j = 0;
    afi_list_node *node = NULL;

    i++; i = i % 10;

    node = ((afi_list_t *)afil)->list;
    while (node) {
        sprintf(buf[i]+strlen(buf[i]), "AFI %d: %s", j, lisp_addr_to_char(node->addr));
        node = node->next;
        j++;
    }
    return(buf[i]);
}

void afi_list_type_copy(void **dst, void *src) {
    afi_list_node *node = NULL;
    afi_list_node *dnode = NULL;

    if (!*dst)
        *dst = afi_list_type_new();
    node = ((afi_list_t *)src)->list;
    dnode =((afi_list_t *)*dst)->list;
    while (node) {
        dnode->addr = lisp_addr_clone(node->addr);
        node = node->next;
        dnode = dnode->next;
    }
}

int afi_list_type_cmp(void *elp1, void *elp2) {
    afi_list_node *node1 = NULL;
    afi_list_node *node2 = NULL;
    int ret = 0;

    node1 = ((afi_list_t *)elp1)->list;
    node2 = ((afi_list_t *)elp2)->list;

    while(node1) {
        ret = lisp_addr_cmp(node1->addr, node2->addr);
        if (ret!=0)
            return(ret);
        node1 = node1->next;
        node2 = node2->next;
    }

    if (node2->next)
        return(2); /* the second has more elements so > than first */

    return(0);
}

/* obtain IP address from LCAF EIDs */
lisp_addr_t *lcaf_eid_get_ip_addr(lcaf_addr_t *lcaf) {
    switch(lcaf_addr_get_type(lcaf)) {
    case LCAF_MCAST_INFO:
        return(lcaf_mc_get_src(lcaf));
    default:
        return(NULL);
    }

    return(NULL);
}

/* obtain IP address from LCAF RLOCs */
lisp_addr_t *lcaf_rloc_get_ip_addr(lisp_addr_t *addr) {
    lisp_addr_t     *rloc = NULL;
    lcaf_addr_t     *lcaf = lisp_addr_get_lcaf(addr);
    glist_entry_t   *it = NULL;
    rle_node_t      *rnode  = NULL;
    int             level   = -1;

    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_EXPL_LOC_PATH:
        rloc = ((elp_node_t *)glist_last_data(lcaf_elp_node_list(lcaf)))->addr;
        break;
    case LCAF_RLE:
        /* find the first highest level replication node */
        glist_for_each_entry(it, lcaf_rle_node_list(lcaf)) {
            rnode = glist_entry_data(it);
            if (rnode->level > level) {
                level = rnode->level;
                rloc = rnode->addr;
            }
        }
        break;
    case LCAF_MCAST_INFO:
        rloc = lcaf_mc_get_grp(lcaf);
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_1, "lcaf_rloc_get_ip_addr: lcaf type %d not supported",
                lcaf_addr_get_type(lcaf));
    }
    return(rloc);
}
