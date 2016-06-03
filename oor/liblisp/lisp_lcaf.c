/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <assert.h>

#include "lisp_lcaf.h"
#include "lisp_address.h"
#include "../defs.h"
#include "../lib/mem_util.h"
#include "../lib/oor_log.h"


typedef void (*del_fct)(void *);
typedef int (*parse_fct)(uint8_t *, void **);
typedef char *(*to_char_fct)(void *);
typedef void (*copy_fct)(void **, void *);
typedef int (*cmp_fct)(void *, void *);
typedef int (*write_fct)(uint8_t *, void *);
typedef int (*size_in_pkt_fct)(void *);
typedef lisp_addr_t	*(*get_ip_addr_fct)(void *);
typedef lisp_addr_t *(*get_ip_pref_addr_fct)(void *);


del_fct del_fcts[MAX_LCAFS] = {
        0, afi_list_type_del,
        iid_type_del,
        0, 0, 0,
        geo_type_del, nat_type_del, 0,
        mc_type_del, elp_type_del, 0, 0,
        rle_type_del, 0, 0};

parse_fct parse_fcts[MAX_LCAFS] = {
        0, afi_list_type_parse,
        iid_type_parse, 0, 0, 0,
        geo_type_parse, nat_type_parse, 0,
        mc_type_parse, elp_type_parse, 0, 0,
        rle_type_parse, 0, 0};

to_char_fct to_char_fcts[MAX_LCAFS] = {
        0, afi_list_type_to_char,
        iid_type_to_char, 0, 0, 0,
        geo_type_to_char, nat_type_to_char, 0,
        mc_type_to_char, elp_type_to_char, 0, 0,
        rle_type_to_char, 0, 0 };

write_fct write_fcts[MAX_LCAFS] = {
        0, afi_list_type_write_to_pkt,
        iid_type_write_to_pkt, 0, 0, 0,
        0, nat_type_write_to_pkt, 0,
        mc_type_write_to_pkt, elp_type_write_to_pkt, 0, 0,
        rle_type_write_to_pkt, 0, 0};

copy_fct copy_fcts[MAX_LCAFS] = {
        0, afi_list_type_copy,
        iid_type_copy, 0, 0, 0,
        geo_type_copy, nat_type_copy, 0,
        mc_type_copy, elp_type_copy, 0, 0,
        rle_type_copy, 0, 0};

cmp_fct cmp_fcts[MAX_LCAFS] = {
        0, afi_list_type_cmp,
        iid_type_cmp, nat_type_cmp, 0, 0,
        0, 0, 0,
        mc_type_cmp, elp_type_cmp, 0, 0,
        rle_type_cmp, 0, 0};

size_in_pkt_fct size_in_pkt_fcts[MAX_LCAFS] = {
        0, afi_list_type_get_size_to_write,
        iid_type_get_size_to_write, 0, 0, 0,
        0, nat_type_get_size_to_write, 0,
        mc_type_get_size_to_write, elp_type_get_size_to_write, 0, 0,
        rle_type_get_size_to_write, 0, 0};

get_ip_addr_fct get_ip_addr_fcts[MAX_LCAFS] = {
        0, afi_list_type_get_ip_addr,
        iid_type_get_ip_addr, 0, 0, 0,
        0, nat_type_get_ip_addr, 0,
        mc_type_get_ip_addr, elp_type_get_ip_addr, 0, 0,
        0, 0, 0};

get_ip_pref_addr_fct get_ip_pref_addr_fcts[MAX_LCAFS] = {
        0, afi_list_type_get_ip_pref_addr,
        iid_type_get_ip_pref_addr, 0, 0, 0,
        0, nat_type_get_ip_pref_addr, 0,
        mc_type_get_ip_pref_addr,0, 0, 0,
        0, 0, 0};


static inline lcaf_type_e get_type_(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return(lcaf->type);
}

static inline void *get_addr_(lcaf_addr_t *lcaf) {
    assert(lcaf);
    return(lcaf->addr);
}


lcaf_addr_t *
lcaf_addr_new()
{
    return(xzalloc(sizeof(lcaf_addr_t)));
}

lcaf_addr_t *
lcaf_addr_new_type(uint8_t type)
{
    lcaf_addr_t *lcaf;

    lcaf = xzalloc(sizeof(lcaf_addr_t));
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
void
lcaf_addr_del_addr(lcaf_addr_t *lcaf)
{
    if (!lcaf->addr) {
        return;
    }

    if (!del_fcts[get_type_(lcaf)]) {
        return;
    }
    (*del_fcts[get_type_(lcaf)])(get_addr_(lcaf));
}

/* free an lcaf pointer */
void
lcaf_addr_del(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    if (!del_fcts[get_type_(lcaf)]) {
        return;
    }
    (*del_fcts[get_type_(lcaf)])(get_addr_(lcaf));
    free(lcaf);
}

/*
 * lcaf_addr_t functions
 */

int
lcaf_addr_parse(uint8_t *offset, lcaf_addr_t *lcaf)
{

    int len = 0;

    /* about to ovewrite 'addr', just free the old one */
    if (get_addr_(lcaf)) {
        lcaf_addr_del_addr(lcaf);
    }

    lcaf_addr_set_type(lcaf, ((lcaf_hdr_t *)offset)->type);
    if (!parse_fcts[lcaf_addr_get_type(lcaf)]) {
        OOR_LOG(LDBG_3, "lcaf_addr_read_from_pkt: Cannot parse LCAF type %d:",
                lcaf_addr_get_type(lcaf));
        return(BAD);
    }

    len = parse_fcts[lcaf_addr_get_type(lcaf)](offset, &lcaf->addr);
    if (len != ntohs(((lcaf_hdr_t *)offset)->len) + sizeof(lcaf_hdr_t)) {
        OOR_LOG(LDBG_3, "lcaf_addr_read_from_pkt: len field %d, without header, and the number of "
                "bytes read %d don't differ by 8 bytes!", ntohs(((lcaf_hdr_t *)offset)->len), len);
        return(BAD);
    }

    return(len);
}


char *
lcaf_addr_to_char(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    if (!to_char_fcts[get_type_(lcaf)]) {
        return ("LCAF not supported");
    }
    return((*to_char_fcts[get_type_(lcaf)])(lcaf_addr_get_addr(lcaf)));
}


inline lcaf_type_e
lcaf_addr_get_type(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    return(lcaf->type);
}

inline mc_t *
lcaf_addr_get_mc(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    return((mc_t *)lcaf_addr_get_addr(lcaf));
}

inline geo_t *
lcaf_addr_get_geo(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    return((geo_t *)lcaf_addr_get_addr(lcaf));
}

inline iid_t *
lcaf_addr_get_iid(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    return((iid_t *)lcaf_addr_get_addr(lcaf));
}

inline nat_t *
lcaf_addr_get_nat(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    return((nat_t *)lcaf_addr_get_addr(lcaf));
}

inline void *
lcaf_addr_get_addr(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    return(lcaf->addr);
}

inline int
lcaf_addr_is_mc(lcaf_addr_t *lcaf)
{
    if (lcaf_addr_get_type(lcaf) == LCAF_MCAST_INFO)
        return(TRUE);
    else
        return(FALSE);
}

inline int
lcaf_addr_is_iid(lcaf_addr_t *lcaf)
{
    if (lcaf_addr_get_type(lcaf) == LCAF_IID)
        return(TRUE);
    else
        return(FALSE);
}


inline void
lcaf_addr_set(lcaf_addr_t *lcaf, void *newaddr, uint8_t type)
{
    void *addr;
    addr = lcaf_addr_get_addr(lcaf);
    if (addr)
        lcaf_addr_del_addr(addr);
    lcaf_addr_set_type(lcaf, type);
    lcaf_addr_set_addr(lcaf, newaddr);
}

inline void
lcaf_addr_set_addr(lcaf_addr_t *lcaf, void *addr)
{
    assert(lcaf);
    assert(addr);
    lcaf->addr = addr;
}
inline void
lcaf_addr_set_type(lcaf_addr_t *lcaf, uint8_t type)
{
    assert(lcaf);
    lcaf->type = type;
}

inline uint32_t
lcaf_addr_get_size_to_write(lcaf_addr_t *lcaf)
{

    if (!size_in_pkt_fcts[get_type_(lcaf)]) {
        OOR_LOG(LWRN, "lcaf_addr_get_size_to_write: size not implemented for LCAF type %d",
                get_type_(lcaf));
        return(BAD);
    }

    return((*size_in_pkt_fcts[get_type_(lcaf)])(get_addr_(lcaf)));
}

int
lcaf_addr_copy(lcaf_addr_t *dst, lcaf_addr_t *src)
{

    assert(src);
    if (!copy_fcts[lcaf_addr_get_type(src)]) {
        OOR_LOG(LWRN, "lcaf_addr_copy: copy not implemented for LCAF type %s",lcaf_addr_get_type(src));
        return(BAD);
    }

    /* if 'addr' set, free it */
    if (get_addr_(dst)) {
        lcaf_addr_del_addr(dst);
    }

    lcaf_addr_set_type(dst, get_type_(src));
    (*copy_fcts[get_type_(src)])(&dst->addr, src->addr);

    return(GOOD);
}

inline int
lcaf_addr_write(void *offset, lcaf_addr_t *lcaf)
{
    assert(lcaf);
    if (!write_fcts[get_type_(lcaf)]) {
        OOR_LOG(LWRN, "lcaf_addr_write_to_pkt: write not implemented for LCAF type %d",
                get_type_(lcaf));
        return(BAD);
    }

    return((*write_fcts[get_type_(lcaf)])(offset, get_addr_(lcaf)));
}

inline int
lcaf_addr_cmp(lcaf_addr_t *addr1, lcaf_addr_t *addr2)
{
    if (lcaf_addr_get_type(addr1) != lcaf_addr_get_type(addr2)){
        OOR_LOG(LDBG_1,"lcaf_addr_cmp: Addresses with different lcaf type: %d - %d",
                lcaf_addr_get_type(addr1),lcaf_addr_get_type(addr2));
        return(-1);
    }
    if (!(cmp_fcts[lcaf_addr_get_type(addr1)])) {
        OOR_LOG(LDBG_1, "lcaf_addr_cmp: cmp not implemented for type %d", lcaf_addr_get_type(addr1));
        return(-1);
    }
    return((*cmp_fcts[lcaf_addr_get_type(addr1)])(lcaf_addr_get_addr(addr1), lcaf_addr_get_addr(addr2)));

}

inline uint8_t
lcaf_addr_cmp_iids(lcaf_addr_t *addr1, lcaf_addr_t *addr2)
{
    if (get_type_(addr1) != get_type_(addr2))
        return(0);
    switch(get_type_(addr1)) {
        case LCAF_IID:
            return(lcaf_iid_get_iid(addr1) == lcaf_iid_get_iid(addr2));
        case LCAF_MCAST_INFO:
            return(mc_type_get_iid(get_addr_(addr1)) == mc_type_get_iid(addr2));
        default:
            return(0);
    }
}


/*
 * mc_addr_t functions
 */

/* external */
inline lisp_addr_t *
lcaf_mc_get_src(lcaf_addr_t *mc)
{
    assert(mc);
    if (lcaf_addr_get_type(mc) != LCAF_MCAST_INFO)
        return(NULL);
    return(mc_type_get_src(lcaf_addr_get_mc(mc)));
}

inline lisp_addr_t *
lcaf_mc_get_grp(lcaf_addr_t *mc)
{
    assert(mc);
    if (lcaf_addr_get_type(mc) != LCAF_MCAST_INFO)
        return(NULL);
    return(mc_type_get_grp(lcaf_addr_get_mc(mc)));
}

inline uint32_t
lcaf_mc_get_iid(lcaf_addr_t *mc)
{
    assert(mc);
    return(mc_type_get_iid(lcaf_addr_get_mc(mc)));
}

inline uint8_t
lcaf_mc_get_src_plen(lcaf_addr_t *mc)
{
    assert(mc);
    return(mc_type_get_src_plen(mc->addr));
}

inline uint8_t
lcaf_mc_get_grp_plen(lcaf_addr_t *mc)
{
    assert(mc);
    return(mc_type_get_grp_plen(mc->addr));
}

inline uint8_t
lcaf_mc_get_afi(lcaf_addr_t *mc)
{
    assert(mc);
    return(mc_type_get_afi(mc->addr));
}



/* these shouldn't be called from outside */

inline mc_t *
mc_type_new()
{
    mc_t *mc = calloc(1, sizeof(mc_t));
    mc->src = lisp_addr_new();
    mc->grp = lisp_addr_new();
    return(mc);
}

inline void
mc_type_del(void *mc)
{
    lisp_addr_del(mc_type_get_src(mc));
    lisp_addr_del(mc_type_get_grp(mc));

    free(mc);
}

inline void
mc_type_set_src_plen(mc_t *mc, uint8_t plen)
{
    assert(mc);
    mc->src_plen = plen;
}

inline void
mc_type_set_grp_plen(mc_t *mc, uint8_t plen)
{
    assert(mc);
    mc->grp_plen = plen;
}

inline void
mc_type_set_iid(mc_t *mc, uint32_t iid)
{
    assert(mc);
    mc->iid = iid;
}

inline void
mc_type_set_src(void *mc, lisp_addr_t *src)
{
    assert(mc);
    assert(src);
    lisp_addr_copy(mc_type_get_src(mc), src);
}

inline void
mc_type_set_grp(mc_t *mc, lisp_addr_t *grp)
{
    assert(mc);
    assert(grp);
    lisp_addr_copy(mc_type_get_grp(mc), grp);
}

inline void
mc_type_copy(void **dst, void *src)
{
    if (!(*dst))
        *dst = mc_type_new();
    mc_type_set_iid(*dst, mc_type_get_iid(src));
    mc_type_set_src_plen(*dst, mc_type_get_src_plen(src));
    mc_type_set_grp_plen(*dst, mc_type_get_grp_plen(src));
    lisp_addr_copy(mc_type_get_src(*dst), mc_type_get_src(src));
    lisp_addr_copy(mc_type_get_grp(*dst), mc_type_get_grp(src));
}

inline int
mc_type_cmp(void *mc1, void *mc2)
{
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

inline void
mc_type_set(mc_t *dst, lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen,
        uint8_t gplen, uint32_t iid)
{
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
mc_t *
mc_type_init(lisp_addr_t *src, lisp_addr_t *grp, uint8_t splen, uint8_t gplen,
        uint32_t iid)
{
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

inline lisp_addr_t
*mc_type_get_src(mc_t *mc)
{
    assert(mc);
    return(mc->src);
}

inline lisp_addr_t *
mc_type_get_grp(mc_t *mc)
{
    assert(mc);
    return(mc->grp);
}

inline uint8_t
mc_type_get_afi(mc_t *mc)
{
    assert(mc);
    return(lisp_addr_ip_afi(mc_type_get_grp(mc)));
}

inline uint32_t
mc_type_get_iid(void *mc)
{
    assert(mc);
    return(((mc_t *)mc)->iid);
}

inline uint8_t
mc_type_get_src_plen(mc_t *mc)
{
    assert(mc);
    return(mc->src_plen);
}

inline uint8_t
mc_type_get_grp_plen(mc_t *mc)
{
    assert(mc);
    return(mc->grp_plen);
}

/* set functions common to all types */

char *
mc_type_to_char(void *mc)
{
    static char buf[10][INET6_ADDRSTRLEN*2+4];
    static unsigned int i   = 0;

    i++;
    i = i % 10;
    *buf[i] = '\0';
    sprintf(buf[i], "(%s/%d,%s/%d)",
            lisp_addr_to_char(mc_type_get_src((mc_t *)mc)),
            mc_type_get_src_plen((mc_t *)mc),
            lisp_addr_to_char(mc_type_get_grp((mc_t *)mc)),
            mc_type_get_src_plen((mc_t *)mc));
    return(buf[i]);
}

int
mc_type_get_size_to_write(void *mc)
{
    return( sizeof(lcaf_mcinfo_hdr_t)+
            lisp_addr_size_to_write(mc_type_get_src(mc)) +
//            sizeof(uint16_t)+ /* grp afi */
            lisp_addr_size_to_write(mc_type_get_grp(mc)) );
}

inline int
mc_type_write_to_pkt(uint8_t *offset, void *mc)
{
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

int
mc_type_parse(uint8_t *offset, void **mc)
{
    int srclen, grplen;
    srclen = grplen =0;

    *mc = mc_type_new();
    mc_type_set_iid(*mc, ntohl(((lcaf_mcinfo_hdr_t *)offset)->iid));
    mc_type_set_src_plen(*mc, ((lcaf_mcinfo_hdr_t *)offset)->src_mlen);
    mc_type_set_grp_plen(*mc, ((lcaf_mcinfo_hdr_t *)offset)->grp_mlen);

    offset = CO(offset, sizeof(lcaf_mcinfo_hdr_t));
    srclen = lisp_addr_parse(offset, mc_type_get_src(*mc));
    offset = CO(offset, srclen);
    grplen = lisp_addr_parse(offset, mc_type_get_grp(*mc));
    return(sizeof(lcaf_mcinfo_hdr_t) + srclen + grplen);

}


/* Function that builds mc packets from packets on the wire. */
int
lcaf_addr_set_mc(lcaf_addr_t *lcaf, lisp_addr_t *src, lisp_addr_t *grp,
        uint8_t splen, uint8_t gplen, uint32_t iid)
{
    mc_t            *mc;

    if (get_addr_(lcaf)) {
        lcaf_addr_del_addr(lcaf);
    }

    mc = mc_type_init(src, grp, splen, gplen, iid);
    lcaf_addr_set_type(lcaf, LCAF_MCAST_INFO);
    lcaf_addr_set_addr(lcaf, mc);
    return(GOOD);
}

lisp_addr_t *
lisp_addr_build_mc(lisp_addr_t *src, lisp_addr_t *grp)
{
    lisp_addr_t     *mceid;
    uint8_t         mlen;

    mlen = (lisp_addr_ip_afi(src) == AF_INET) ? 32 : 128;
    mceid = lisp_addr_new_lafi(LM_AFI_LCAF);
    lcaf_addr_set_mc(lisp_addr_get_lcaf(mceid), src, grp, mlen, mlen, 0);
    return(mceid);
}

inline int
lisp_addr_is_mcinfo(lisp_addr_t *addr)
{
    return(lisp_addr_lafi(addr) == LM_AFI_LCAF && lisp_addr_lcaf_type(addr) == LCAF_MCAST_INFO);
}


lisp_addr_t *
mc_type_get_ip_addr (void *mc)
{
	lisp_addr_t *addr = mc_type_get_src((mc_t*)(mc));
	return(lisp_addr_get_ip_addr(addr));
}

lisp_addr_t *
mc_type_get_ip_pref_addr (void *mc)
{
    lisp_addr_t *addr = mc_type_get_src((mc_t*)(mc));
    return(lisp_addr_get_ip_pref_addr(addr));
}

/*
 * iid_addr_t functions
 */
inline iid_t *
iid_type_new()
{
    iid_t *iid;
    iid = xzalloc(sizeof(iid_t));
    iid->iidaddr = lisp_addr_new();
    return(iid);
}

iid_t *
iid_type_new_init(int iid, lisp_addr_t *addr, uint8_t mlen)
{
    iid_t *iidt = iid_type_new();
    iidt->iid = iid;
    lisp_addr_copy(iidt->iidaddr, addr);
    iidt->mlen = mlen;
    return(iidt);
}

inline void
iid_type_del(void *iid)
{
    lisp_addr_del(iid_type_get_addr((iid_t *)iid));
    free(iid);
    iid = NULL;
}

inline uint8_t
iid_type_get_mlen(iid_t *iid)
{
    assert(iid);
    return(iid->mlen);
}

inline uint32_t
lcaf_iid_get_iid(lcaf_addr_t *iid)
{
    return(iid_type_get_iid(get_addr_(iid)));
}

inline uint32_t
iid_type_get_iid(iid_t *iid)
{
    assert(iid);
    return(iid->iid);
}

inline lisp_addr_t *
iid_type_get_addr(void *iid)
{
    assert(iid);
    return(((iid_t *)iid)->iidaddr);
}



inline void iid_type_set_iid(iid_t *iidt, uint32_t iid) {
    assert(iidt);
    iidt->iid = iid;
}

inline void
iid_type_set_addr(iid_t *iidt, lisp_addr_t *iidaddr)
{
    assert(iidt);
    assert(iidaddr);
    lisp_addr_copy (iidt->iidaddr,iidaddr);
}

inline void
iid_type_set_mlen(iid_t *iid, uint8_t mlen)
{
    assert(iid);
    iid->mlen = mlen;
}

inline int
iid_type_cmp(void *iid1, void *iid2)
{
    if ((iid_type_get_iid((iid_t *)iid1) != iid_type_get_iid((iid_t *)iid2)))
        return( (iid_type_get_iid((iid_t *)iid1) >  iid_type_get_iid((iid_t *)iid2)) ? 1: 2);

    if ((iid_type_get_mlen((iid_t *)iid1) != iid_type_get_mlen((iid_t *)iid2)))
        return((iid_type_get_mlen((iid_t *)iid1) > iid_type_get_mlen((iid_t *)iid2)) ? 1 :2);

    return(lisp_addr_cmp(iid_type_get_addr((iid_t *)iid1), iid_type_get_addr((iid_t *)iid2)));
}

int
iid_type_get_size_to_write(void *iid)
{
    return( sizeof(lcaf_iid_hdr_t)+
            lisp_addr_size_to_write(iid_type_get_addr(iid)));
}

inline int
iid_type_write_to_pkt(uint8_t *offset, void *iid)
{
    int len;
    uint8_t *cur_ptr = offset;
    ((lcaf_iid_hdr_t *)cur_ptr)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_iid_hdr_t *)cur_ptr)->rsvd1 = 0;
    ((lcaf_iid_hdr_t *)cur_ptr)->flags = 0;
    ((lcaf_iid_hdr_t *)cur_ptr)->type = LCAF_IID;
    ((lcaf_iid_hdr_t *)cur_ptr)->mlen = iid_type_get_mlen(iid);
    ((lcaf_iid_hdr_t *)cur_ptr)->iid = htonl(iid_type_get_iid(iid));
    offset = CO(offset, sizeof(lcaf_iid_hdr_t));
    len = lisp_addr_write(offset, iid_type_get_addr(iid));
    ((lcaf_iid_hdr_t *)cur_ptr)->len = htons(len + sizeof(uint32_t));
    len += sizeof(lcaf_iid_hdr_t);

    return(len);
}

int
iid_type_parse(uint8_t *offset, void **iid)
{
    int len;
    *iid = iid_type_new();

    iid_type_set_mlen(*iid, ((lcaf_iid_hdr_t *)offset)->mlen);
    iid_type_set_iid(*iid, ntohl(((lcaf_iid_hdr_t *)offset)->iid));

    offset = CO(offset, sizeof(lcaf_iid_hdr_t));
    len = lisp_addr_parse(offset, iid_type_get_addr(*iid)) + sizeof(lcaf_iid_hdr_t);
    return(len);
}

char *
iid_type_to_char(void *iid)
{
    static char buf[10][INET6_ADDRSTRLEN*2+4];
    static unsigned int i   = 0;

    i++;
    i = i % 10;
    *buf[i] = '\0';
    sprintf(buf[i], "(IID %d/%d, EID %s)",
            iid_type_get_iid(iid),
            iid_type_get_mlen(iid),
            lisp_addr_to_char(iid_type_get_addr(iid)));
    return(buf[i]);
}

void
iid_type_copy(void **dst, void *src)
{
    if (!(*dst)){
        *dst = iid_type_new_init(
                iid_type_get_iid((iid_t *)src),
                iid_type_get_addr((iid_t *)src),
                iid_type_get_mlen(src));
    }else{
        lisp_addr_copy(iid_type_get_addr((iid_t *)*dst), iid_type_get_addr((iid_t *)src));
        iid_type_set_iid((iid_t *)*dst, iid_type_get_iid((iid_t *)src));
        iid_type_set_mlen((iid_t*)*dst, iid_type_get_mlen(src));
    }
}

lisp_addr_t *
iid_type_get_ip_addr(void *iid)
{
	return (lisp_addr_get_ip_addr(((iid_t *)iid)->iidaddr));
}

lisp_addr_t *
iid_type_get_ip_pref_addr(void *iid)
{
    return (lisp_addr_get_ip_pref_addr(((iid_t *)iid)->iidaddr));
}

inline int
lisp_addr_is_iid(lisp_addr_t *addr)
{
    return(lisp_addr_lafi(addr) == LM_AFI_LCAF && lisp_addr_lcaf_type(addr) == LCAF_IID);
}



void
lcaf_iid_init(lcaf_addr_t *iidaddr, int iid, lisp_addr_t *addr, uint8_t mlen)
{
    if (!iidaddr->addr){
        lcaf_addr_del_addr(iidaddr);
    }
    iidaddr->type = LCAF_IID;
    iidaddr->addr = iid_type_new_init(iid, addr, mlen);
}


inline lisp_addr_t *
lisp_addr_new_init_iid(int iid, lisp_addr_t *addr, uint8_t mlen)
{
    lisp_addr_t *iid_addr;

    iid_addr = lisp_addr_new_lafi(LM_AFI_LCAF);
    lcaf_iid_init(&iid_addr->lcaf, iid, addr,mlen);

    return (iid_addr);
}


/*
 * geo_addr_t functions
 */

inline geo_t *
geo_type_new()
{
    geo_t *geo;
    geo = (geo_t *)calloc(1, sizeof(geo_t));
    geo->addr = lisp_addr_new();
    return(geo);
}

inline void
geo_type_del(void *geo)
{
    lisp_addr_del(geo_type_get_addr((geo_t *)geo));
    free(geo);
}

inline void
geo_type_set_addr(geo_t *geo, lisp_addr_t *addr)
{
    assert(addr);
    assert(geo);
    lisp_addr_copy(geo->addr, addr);
}

inline void
geo_type_set_lat(geo_t *geo, uint8_t dir, uint16_t deg, uint8_t min,
        uint8_t sec)
{
    assert(geo);
    geo->latitude.dir = dir;
    geo->latitude.deg = deg;
    geo->latitude.min = min;
    geo->latitude.sec = sec;
}

inline void
geo_type_set_long(geo_t *geo, uint8_t dir, uint16_t deg, uint8_t min,
        uint8_t sec)
{
    assert(geo);
    geo->longitude.dir = dir;
    geo->longitude.deg = deg;
    geo->longitude.min = min;
    geo->longitude.sec = sec;
}

inline void
geo_type_set_lat_from_coord(geo_t *geo, geo_coordinates *coord)
{
    assert(geo);
    geo->latitude.dir = coord->dir;
    geo->latitude.deg = coord->deg;
    geo->latitude.min = coord->min;
    geo->latitude.sec = coord->sec;
}

inline void
geo_type_set_long_from_coord(geo_t *geo, geo_coordinates *coord)
{
    assert(geo);
    geo->longitude.dir = coord->dir;
    geo->longitude.deg = coord->deg;
    geo->longitude.min = coord->min;
    geo->longitude.sec = coord->sec;
}

inline void
geo_type_set_altitude(geo_t *geo, uint32_t altitude)
{
    assert(geo);
    geo->altitude = altitude;
}

inline geo_coordinates *
geo_type_get_lat(geo_t *geo)
{
    assert(geo);
    return(&(geo->latitude));
}

inline geo_coordinates *
geo_type_get_long(geo_t *geo)
{
    assert(geo);
    return(&(geo->longitude));
}

inline uint32_t
geo_type_get_altitude(geo_t *geo)
{
    assert(geo);
    return(geo->altitude);
}

inline int
geo_type_parse(uint8_t *offset, void **geo)
{
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
            lisp_addr_parse(offset, geo_type_get_addr(*geo)));
}

inline lisp_addr_t *
geo_type_get_addr(geo_t *geo)
{
    return(geo->addr);
}


char *
geo_type_to_char(void *geo)
{
    static char buf[10][INET6_ADDRSTRLEN*2+4];
    static unsigned int i   = 0;

    i++;
    i = i % 10;
    *buf[i] = '\0';
    sprintf(buf[i], "(latitude: %s | longitude: %s | altitude: %d, EID %s)",
            geo_coord_to_char(geo_type_get_lat(geo)),
            geo_coord_to_char(geo_type_get_long(geo)),
            geo_type_get_altitude(geo),
            lisp_addr_to_char(geo_type_get_addr(geo)));
    return(buf[i]);
}

char *
geo_coord_to_char(geo_coordinates *coord)
{
    static char buf[INET6_ADDRSTRLEN*2+4];
    *buf= '\0';
    sprintf(buf, "dir %d deg %d min %d sec %d",
            coord->dir, coord->deg, coord->min, coord->sec);
    return(buf);
}

void
geo_type_copy(void **dst, void *src)
{
    assert(src);
    if(!(*dst))
        *dst = geo_type_new();
    geo_type_set_lat_from_coord((geo_t *)*dst, geo_type_get_lat(src));
    geo_type_set_long_from_coord((geo_t *)*dst, geo_type_get_long(src));
    geo_type_set_altitude((geo_t *)*dst, geo_type_get_altitude(src));
    lisp_addr_copy(geo_type_get_addr((geo_t *)*dst), geo_type_get_addr(src));
}


/*
 * nat_addr_t functions
 */

inline nat_t *
nat_type_new()
{
    nat_t *nat;
    nat = (nat_t*)xzalloc(sizeof(nat_t));
    nat->ms_addr = lisp_addr_new();
    nat->etr_pub_addr = lisp_addr_new();
    nat->etr_prv_addr = lisp_addr_new();
    nat->rtr_addr_lst = glist_new_managed((glist_del_fct)lisp_addr_del);
    return (nat);
}

nat_t *
nat_type_new_init(uint16_t ms_port, lisp_addr_t *ms_addr, uint16_t etr_pub_port,
        lisp_addr_t *etr_pub_addr, lisp_addr_t *etr_prv_addr, glist_t *rtr_addr_lst)
{
    nat_t *nat;

    nat = (nat_t*)xzalloc(sizeof(nat_t));
    nat->ms_port = ms_port;
    nat->etr_pub_port = etr_pub_port;
    nat->ms_addr = lisp_addr_clone(ms_addr);
    nat->etr_pub_addr = lisp_addr_clone(etr_pub_addr);
    nat->etr_prv_addr = lisp_addr_clone(etr_prv_addr);
    nat->rtr_addr_lst = glist_clone(rtr_addr_lst, (glist_clone_obj)lisp_addr_clone);
    glist_set_del_fct(nat->rtr_addr_lst, (glist_del_fct)lisp_addr_del);

    return (nat);
}

inline void
nat_type_del(void *nat)
{
    lisp_addr_del(((nat_t *)nat)->ms_addr);
    lisp_addr_del(((nat_t *)nat)->etr_pub_addr);
    lisp_addr_del(((nat_t *)nat)->etr_prv_addr);
    glist_destroy(((nat_t *)nat)->rtr_addr_lst);
    free (nat);
    nat = NULL;
}

inline uint16_t
nat_type_get_ms_port(nat_t *nat)
{
    return (nat->ms_port);
}

inline uint16_t
nat_type_get_etr_pub_port(nat_t *nat)
{
    return (nat->etr_pub_port);
}

inline lisp_addr_t *
nat_type_get_ms_addr(nat_t *nat)
{
   return(nat->ms_addr);
}

inline lisp_addr_t *
nat_type_get_etr_pub_addr(nat_t *nat)
{
    return(nat->etr_pub_addr);
}

inline lisp_addr_t *
nat_type_get_etr_priv_addr(nat_t *nat)
{
    return(nat->etr_prv_addr);
}

inline glist_t *
nat_type_get_rtr_addr_lst(nat_t *nat)
{
    return(nat->rtr_addr_lst);
}

inline void
nat_type_set_ms_port(nat_t *nat, uint16_t ms_port)
{
    nat->ms_port = ms_port;
}

inline void
nat_type_set_etr_pub_port(nat_t *nat, uint16_t etr_pub_port)
{
    nat->etr_pub_port = etr_pub_port;
}

inline void
nat_type_set_ms_addr(nat_t *nat, lisp_addr_t * ms_addr)
{
    lisp_addr_copy(nat->ms_addr,ms_addr);
}

inline void
nat_type_set_etr_pub_addr(nat_t *nat, lisp_addr_t * etr_pub_addr)
{
    lisp_addr_copy(nat->etr_pub_addr, etr_pub_addr);
}

inline void
nat_type_set_etr_priv_addr(nat_t *nat, lisp_addr_t * etr_prv_addr){
    lisp_addr_copy(nat->etr_prv_addr, etr_prv_addr);
}

inline void
nat_type_set_rtr_addr_lst(nat_t *nat, glist_t * rtr_addr_lst)
{
    glist_destroy(nat->rtr_addr_lst);
    nat->rtr_addr_lst = glist_clone(rtr_addr_lst, (glist_clone_obj)lisp_addr_clone);
    glist_set_del_fct(nat->rtr_addr_lst, (glist_del_fct)lisp_addr_del);
}

inline int
nat_type_cmp(void *nat1, void *nat2)
{
    glist_entry_t *it_rtr;
    lisp_addr_t *rtr_addr;
    nat_t *n1 = (nat_t*)nat1;
    nat_t *n2 = (nat_t*)nat2;
    int ret = 0;

    if ((ret = lisp_addr_cmp(n1->etr_pub_addr,n2->etr_pub_addr)) != 0){
        return (ret);
    }
    if ((ret = lisp_addr_cmp(n1->etr_prv_addr,n2->etr_prv_addr)) != 0){
        return (ret);
    }
    if ((ret = lisp_addr_cmp(n1->ms_addr,n2->ms_addr)) != 0){
        return (ret);
    }
    if (n1->etr_pub_port != n2->etr_pub_port){
        return (n1->etr_pub_port > n2->etr_pub_port ? 1 : 2);
    }
    if (glist_size(n1->rtr_addr_lst) != glist_size(n2->rtr_addr_lst)){
        return (glist_size(n1->rtr_addr_lst) > glist_size(n2->rtr_addr_lst) ? 1 : 2);
    }
    glist_for_each_entry(it_rtr,n1->rtr_addr_lst){
        rtr_addr = (lisp_addr_t *)glist_entry_data(it_rtr);
        if (glist_contain_using_cmp_fct(rtr_addr, n1->rtr_addr_lst,(glist_cmp_fct)lisp_addr_cmp) != 0){
            return (1);
        }
    }
    if (n1->ms_port != n2->ms_port){
        return  (n1->ms_port > n2->ms_port ? 1 : 2);
    }
    return (0);
}

int
nat_type_get_size_to_write(void *nat)
{
    uint32_t len;
    nat_t *nat_addr = (nat_t *)nat;
    glist_entry_t *it_rtr;

    len = sizeof (lcaf_nat_hdr_t);
    len += lisp_addr_size_to_write(nat_addr->etr_pub_addr);
    len += lisp_addr_size_to_write(nat_addr->ms_addr);
    len += lisp_addr_size_to_write(nat_addr->etr_prv_addr);
    glist_for_each_entry(it_rtr, nat_addr->rtr_addr_lst) {
        len += lisp_addr_size_to_write((lisp_addr_t *)glist_entry_data(it_rtr));
    }

    return (len);
}

int
nat_type_write_to_pkt(uint8_t *offset, void *nat)
{
    uint32_t len, addrlen;
    uint8_t *cur_ptr = offset;
    nat_t *nat_addr = (nat_t *)nat;
    glist_entry_t *it_rtr;

    ((lcaf_nat_hdr_t*)cur_ptr)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_nat_hdr_t*)cur_ptr)->flags = 0;
    ((lcaf_nat_hdr_t*)cur_ptr)->rsvd1 = 0;
    ((lcaf_nat_hdr_t*)cur_ptr)->rsvd2 = 0;
    ((lcaf_nat_hdr_t*)cur_ptr)->type = LCAF_NATT;
    NAT_MS_PORT(cur_ptr) = htons(nat_addr->ms_port);
    NAT_ETR_PORT(cur_ptr) = htons(nat_addr->etr_pub_port);
    len = sizeof (lcaf_nat_hdr_t);
    cur_ptr = CO(cur_ptr, sizeof(lcaf_nat_hdr_t));
    addrlen = lisp_addr_write(cur_ptr, nat_addr->etr_pub_addr);
    if (addrlen <=0)
        return(BAD);
    len += addrlen;
    cur_ptr = CO(cur_ptr, addrlen);
    addrlen = lisp_addr_write(cur_ptr, nat_addr->ms_addr);
    if (addrlen <=0)
        return(BAD);
    len += addrlen;
    cur_ptr = CO(cur_ptr, addrlen);
    addrlen = lisp_addr_write(cur_ptr, nat_addr->etr_prv_addr);
    if (addrlen <=0)
        return(BAD);
    len += addrlen;
    cur_ptr = CO(cur_ptr, addrlen);
    glist_for_each_entry(it_rtr, nat_addr->rtr_addr_lst) {
        addrlen = lisp_addr_write(cur_ptr, (lisp_addr_t *)glist_entry_data(it_rtr));
        if (addrlen <=0)
            return(BAD);
        len += addrlen;
        cur_ptr = CO(cur_ptr, addrlen);
    }
    /* length is only what follows the first 8 bytes of the lcaf hdr */
    ((lcaf_hdr_t*)offset)->len = htons(len-sizeof(lcaf_hdr_t));

    return (len);
}

int
nat_type_parse(uint8_t *offset, void **nat)
{
    int totallen, readlen, len;
    nat_t *nat_addr;
    lisp_addr_t *rtr_addr;

    *nat = nat_type_new();
    nat_addr = *nat;
    totallen  = ntohs((NAT_LEN(offset))) + sizeof(lcaf_hdr_t);
    nat_addr->ms_port = NAT_MS_PORT(offset);
    nat_addr->etr_pub_port = NAT_ETR_PORT(offset);
    readlen = sizeof(lcaf_nat_hdr_t);
    offset = CO(offset, readlen);
    len = lisp_addr_parse(offset, nat_addr->etr_pub_addr);
    if (len <= 0){
        goto err;
    }
    readlen += len;
    offset = CO(offset, len);
    len = lisp_addr_parse(offset, nat_addr->ms_addr);
    if (len <= 0){
        goto err;
    }
    readlen += len;
    offset = CO(offset, len);
    len = lisp_addr_parse(offset, nat_addr->etr_prv_addr);
    if (len <= 0){
        goto err;
    }
    readlen += len;
    offset = CO(offset, len);

    while (totallen > readlen){
        rtr_addr = lisp_addr_new();
        len = lisp_addr_parse(offset, rtr_addr);
        if (len <= 0){
            goto err;
        }
        readlen += len;
        offset = CO(offset, len);
        glist_add_tail(rtr_addr,nat_addr->rtr_addr_lst);
    }
    return (readlen);
err:
    nat_type_del(nat_addr);
    return (BAD);
}

char *
nat_type_to_char(void *nat)
{
    static char buf[5][500];
    static unsigned int i = 0;
    nat_t *nat_addr = (nat_t *)nat;
    int j = 0;
    glist_entry_t * it_rtr;

    i++;
    i = i % 5;
    *buf[i] = '\0';
    sprintf(buf[i], "ETR Pub: %s:%d, ETR Prv: %s, MS: %s:%d - RTR list:",
            lisp_addr_to_char(nat_addr->etr_pub_addr),nat_addr->etr_pub_port,
            lisp_addr_to_char(nat_addr->etr_prv_addr),lisp_addr_to_char(nat_addr->ms_addr),
            nat_addr->ms_port);

    glist_for_each_entry(it_rtr, nat_addr->rtr_addr_lst) {
        j++;
        sprintf(buf[i]+strlen(buf[i]), "[%d] %s ",
                j, lisp_addr_to_char((lisp_addr_t *)glist_entry_data(it_rtr)));
    }
    return(buf[i]);
}

void
nat_type_copy(void **dst, void *src)
{
    nat_t *snat_addr, *dnat_addr;
    glist_entry_t *rtr_it;
    lisp_addr_t *rtr_addr;

    if (!*dst){
        *dst = nat_type_new();
    }
    dnat_addr = (nat_t *)(*dst);
    snat_addr = (nat_t *)src;
    dnat_addr->etr_pub_port = snat_addr->etr_pub_port;
    dnat_addr->ms_port = snat_addr->ms_port;
    lisp_addr_copy(dnat_addr->etr_pub_addr, snat_addr->etr_pub_addr);
    lisp_addr_copy(dnat_addr->ms_addr, snat_addr->ms_addr);
    lisp_addr_copy(dnat_addr->etr_prv_addr, snat_addr->etr_prv_addr);
    glist_remove_all(dnat_addr->rtr_addr_lst);
    glist_for_each_entry(rtr_it, snat_addr->rtr_addr_lst) {
        rtr_addr = lisp_addr_clone((lisp_addr_t *)glist_entry_data(rtr_it));
        glist_add(rtr_addr,dnat_addr->rtr_addr_lst);
    }
}

lisp_addr_t *
nat_type_get_ip_addr(void *nat)
{
    return (lisp_addr_get_ip_addr(((nat_t *)nat)->etr_prv_addr));
}

lisp_addr_t *
nat_type_get_ip_pref_addr(void *nat)
{
    return (lisp_addr_get_ip_pref_addr(((nat_t *)nat)->etr_prv_addr));
}

void
lcaf_nat_init(lcaf_addr_t *nat_addr, uint16_t ms_port, lisp_addr_t *ms_addr,
        uint16_t etr_pub_port, lisp_addr_t *etr_pub_addr, lisp_addr_t *etr_prv_addr,
        glist_t *rtr_addr_lst)
{
    if (!nat_addr->addr){
        lcaf_addr_del_addr(nat_addr);
    }
    nat_addr->type = LCAF_NATT;
    nat_addr->addr = nat_type_new_init(ms_port, ms_addr, etr_pub_port, etr_pub_addr,
            etr_prv_addr, rtr_addr_lst);
}
inline int
lisp_addr_is_nat(lisp_addr_t *addr)
{
    return (lisp_addr_is_lcaf(addr) && lisp_addr_lcaf_type(addr) == LCAF_NATT);
}

lisp_addr_t *
lisp_addr_new_init_nat(uint16_t ms_port, lisp_addr_t *ms_addr,
        uint16_t etr_pub_port, lisp_addr_t *etr_pub_addr, lisp_addr_t *etr_prv_addr,
        glist_t *rtr_addr_lst)
{
    lisp_addr_t *nat_addr;

        nat_addr = lisp_addr_new_lafi(LM_AFI_LCAF);
        lcaf_nat_init(&nat_addr->lcaf,ms_port,ms_addr,etr_pub_port,etr_pub_addr,
                etr_prv_addr,rtr_addr_lst);

        return (nat_addr);
}




/*
 * elp_addr_t functions
 */

lisp_addr_t *
lisp_addr_elp_new()
{
    lisp_addr_t *address = NULL;
    elp_t *elp_list = NULL;

    elp_list = elp_type_new();
    if(elp_list == NULL){
        return (NULL);
    }
    address = lisp_addr_new_lafi(LM_AFI_LCAF);
    if (address == NULL){
        elp_type_del(elp_list);
        return (NULL);
    }
    lisp_addr_lcaf_set_type(address, LCAF_EXPL_LOC_PATH);
    lisp_addr_lcaf_set_addr(address, elp_list);

    return (address);
}

inline elp_t *
lcaf_elp_get_elp(lcaf_addr_t *elp)
{
    return((elp_t *)(get_addr_(elp)));
}


elp_t *
elp_type_new()
{
    elp_t *elp;
    elp = xzalloc(sizeof(elp_t));
    elp->nodes = glist_new_managed((glist_del_fct)elp_node_del);
    return(elp);
}

void
elp_type_del(void *elp)
{
    glist_destroy(((elp_t *)elp)->nodes);
    free(elp);
}

int
elp_type_get_size_to_write(void *elp)
{
    glist_entry_t   *it     = NULL;
    elp_node_t      *node   = NULL;
    uint32_t len = 0;

    len += sizeof(lcaf_hdr_t);
    glist_for_each_entry(it, ((elp_t *)elp)->nodes) {
        node = glist_entry_data(it);
        len += sizeof(elp_node_flags) + lisp_addr_size_to_write(node->addr);
    }

    return(len);
}

int
elp_type_write_to_pkt(uint8_t *offset, void *elp)
{
    uint32_t len = 0, addrlen;
    elp_node_t *node = NULL;
    uint8_t *cur_ptr = NULL;
    glist_entry_t *it = NULL;

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

int
elp_type_parse(uint8_t *offset, void **elp)
{
    int len = 0, totallen = 0, readlen=0;
    elp_node_t *enode = NULL;
    elp_node_flags *flags = NULL;
    elp_t *elp_ptr = NULL;

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
        len = lisp_addr_parse(offset, enode->addr);
        if (len <= 0)
            goto err;
        offset = CO(offset, len);
        totallen = totallen - sizeof(elp_node_flags) - len;
        readlen += sizeof(elp_node_flags) + len;

        glist_add_tail(enode, elp_ptr->nodes);

    }
    if (totallen !=0)
        OOR_LOG(LDBG_1, "elp_type_read_from_pkt: Error encountered!");

    return(readlen);

err:
    glist_destroy(elp_ptr->nodes);
    return(BAD);
}

char *
elp_type_to_char(void *elp)
{
    static char buf[5][500];
    static unsigned int i = 0;
    int j = 0;
    glist_entry_t * it = NULL;
    elp_node_t * node = NULL;

    i++;
    i = i % 5;
    *buf[i] = '\0';
    sprintf(buf[i], "ELP:");

    glist_for_each_entry(it, ((elp_t *)elp)->nodes) {
        j++;
        node = (elp_node_t *)glist_entry_data(it);
//        sprintf(buf[i]+strlen(buf[i]), "[%d] %s f: %s%s%s", j, lisp_addr_to_char(node->addr),
//                (node->L) ? "L" : "l", (node->P) ? "P" : "p", (node->S) ? "S" : "s");
        sprintf(buf[i]+strlen(buf[i]), "[%d] %s ", j, lisp_addr_to_char(node->addr));
    }
    return(buf[i]);
}

elp_node_t *
elp_node_clone(elp_node_t *sen)
{
    elp_node_t *en = xzalloc(sizeof(elp_node_t));
    en->L = sen->L;
    en->P = sen->P;
    en->S = sen->S;
    en->addr = lisp_addr_clone(sen->addr);
    return(en);
}

void
elp_type_copy(void **dst, void *src)
{
    elp_t       *elp_ptr    = NULL;
    elp_node_t  *node       = NULL;
    elp_node_t  *cp_node    = NULL;
    glist_entry_t *it       = NULL;

    if (!*dst){
        *dst = elp_type_new();
    }
    elp_ptr = *dst;

    glist_for_each_entry(it, ((elp_t *)src)->nodes) {
        node = (elp_node_t  *)glist_entry_data(it);
        cp_node = elp_node_clone(node);
        glist_add_tail(cp_node, elp_ptr->nodes);
    }
}


int
elp_type_cmp(void *elp1, void *elp2)
{
    elp_node_t  *node1      = NULL;
    elp_node_t  *node2      = NULL;
    glist_entry_t   *it1    = NULL;
    glist_entry_t   *it2    = NULL;
    int ret = 0;

    if (glist_size (((elp_t*)elp1)->nodes) != glist_size (((elp_t*)elp1)->nodes)){
        return (1);
    }

    it1 = glist_first(((elp_t*)elp1)->nodes);
    it2 = glist_first(((elp_t*)elp2)->nodes);

    while(it1 != glist_head(((elp_t*)elp1)->nodes)
          && it2 != glist_head(((elp_t*)elp2)->nodes)) {
        node1 = glist_entry_data(it1);
        node2 = glist_entry_data(it2);

        if ((ret = lisp_addr_cmp(node1->addr, node2->addr)) != 0){
           if (ret < 0){
               return (lisp_addr_cmp_afi(node1->addr,node2->addr));
           }
           return (ret);
        }
        if (node1->L != node2->L
            || node1->S != node2->S
            || node1->P != node2->P)
            return(1);
        it1 = glist_prev(it1);
        it2 = glist_prev(it2);
    }

    return(0);
}

inline elp_node_t *
elp_node_new_init(lisp_addr_t *addr, uint8_t lookup, uint8_t rloc_probe,
        uint8_t strict)
{
    elp_node_t *node = NULL;

    node = xzalloc(sizeof(elp_node_t));
    if (node == NULL){
        return (NULL);
    }
    node->addr = lisp_addr_clone(addr);
    node->L = lookup;
    node->P = rloc_probe;
    node->S = strict;

    return (node);
}


inline lisp_addr_t *
elp_node_addr(elp_node_t *enode)
{
    return (enode->addr);
}

inline void
elp_node_del(elp_node_t *enode)
{
    lisp_addr_del(enode->addr);
    free(enode);
    enode = NULL;
}

inline void
elp_add_node(elp_t *elp, elp_node_t *enode)
{
    if (!elp->nodes)
        elp->nodes = glist_new_managed((glist_del_fct)elp_node_del);
    glist_add_tail(enode, elp->nodes);
}


inline int
lisp_addr_is_elp(lisp_addr_t *addr)
{
    return(lisp_addr_lafi(addr) == LM_AFI_LCAF && lisp_addr_lcaf_type(addr) == LCAF_EXPL_LOC_PATH);
}


lisp_addr_t *
elp_type_get_ip_addr(void *elp)
{
    elp_node_t *elp_node = NULL;
	lisp_addr_t *addr = NULL;
	elp_node = (elp_node_t *)glist_last_data(((elp_t *)elp)->nodes);
	if (elp_node == NULL){
	    return (NULL);
	}
	addr = elp_node->addr;
	return (lisp_addr_get_ip_addr(addr));
}

/*
 * rle_addr_t functions
 */
inline rle_t *
rle_type_new()
{
    rle_t *rle = xzalloc(sizeof(rle_t));
    rle->nodes = glist_new_managed((glist_del_fct)rle_node_del);
    return(rle);
}

inline void
rle_type_del(void *rleaddr)
{
    if (!rleaddr) {
        return;
    }

    glist_destroy(((rle_t *)rleaddr)->nodes);
    free(rleaddr);
    rleaddr = NULL;
}

int
rle_type_parse(uint8_t *offset, void **rle)
{
    int len = 0, totallen = 0, readlen = 0;
    rle_node_t *rnode = NULL;
    rle_node_hdr_t *rhdr = NULL;
    rle_t *rle_ptr = NULL;

    *rle = rle_type_new();
    rle_ptr = *rle;

    totallen = ntohs(((lcaf_hdr_t *)offset)->len);
    readlen = sizeof(lcaf_hdr_t);
    offset = CO(offset, sizeof(lcaf_hdr_t));

    while (totallen > 0) {
        rnode = xzalloc(sizeof(rle_node_t));
        rhdr = (rle_node_hdr_t *)offset;
        rnode->level = rhdr->level;
        offset = CO(offset, sizeof(rle_node_hdr_t));
        rnode->addr = lisp_addr_new();
        len = lisp_addr_parse(offset, rnode->addr);
        if (len <= 0) {
            goto err;
        }
        offset = CO(offset, len);
        totallen = totallen - sizeof(rle_node_hdr_t) -len;
        readlen += sizeof(rle_node_hdr_t) + len;

        glist_add_tail(rnode, rle_ptr->nodes);
    }
    if (totallen !=0) {
        OOR_LOG(LDBG_1, "rle_type_read_from_pkt: Error encountered!");
    }

    return(readlen);

err:
    glist_destroy(rle_ptr->nodes);
    return(BAD);
}

int
rle_type_write_to_pkt(uint8_t *offset, void *rle)
{
    uint32_t len = 0, addrlen;
    rle_node_t *node = NULL;
    uint8_t *cur_ptr = NULL;
    glist_entry_t *it = NULL;

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

int
rle_type_get_size_to_write(void *rle)
{
    glist_entry_t *it = NULL;
    rle_node_t *node = NULL;
    uint32_t len = 0;

    len += sizeof(lcaf_hdr_t);
    glist_for_each_entry(it, ((rle_t *)rle)->nodes) {
        node = glist_entry_data(it);
        len += sizeof(rle_node_hdr_t) + lisp_addr_size_to_write(node->addr);
    }

    return(len);
}

char *
rle_type_to_char(void *rle)
{
    static char buf[3][500];
    static unsigned int i = 0;
    int j = 0;
    glist_entry_t * it = NULL;
    rle_node_t * node = NULL;

    i++;
    i = i % 10;
    *buf[i] = '\0';
    sprintf(buf[i], "RLE:");

    glist_for_each_entry(it, ((rle_t *)rle)->nodes) {
        j++;
        node = glist_entry_data(it);
        sprintf(buf[i]+strlen(buf[i]), "[%d] %s ", node->level,
                lisp_addr_to_char(node->addr));
    }
    return(buf[i]);
}

rle_node_t *
rle_node_clone(rle_node_t *srn)
{
    rle_node_t *rn = xzalloc(sizeof(rle_node_t));
    rn->level = srn->level;
    rn->addr = lisp_addr_clone(srn->addr);
    return(rn);
}

inline rle_node_t *
rle_node_new()
{
    rle_node_t *rnode = xzalloc(sizeof(rle_node_t));
    rnode->addr = lisp_addr_new();
    return(rnode);
}

inline void
rle_node_del(rle_node_t *rnode)
{
    lisp_addr_del(rnode->addr);
    free(rnode);
    rnode = NULL;
}

void
rle_type_copy(void **dst, void *src)
{
    rle_t *rle_ptr = NULL;
    rle_node_t *node = NULL;
    rle_node_t *cp_node = NULL;
    glist_entry_t *it = NULL;

    if (!*dst) {
        *dst = rle_type_new();
    }
    rle_ptr = *dst;

    glist_for_each_entry(it, ((rle_t *)src)->nodes) {
        node = glist_entry_data(it);
        cp_node = rle_node_clone(node);
        glist_add_tail(cp_node, rle_ptr->nodes);
    }
}


int
rle_type_cmp(void *rle1, void *rle2)
{
    rle_node_t *node1 = NULL;
    rle_node_t *node2 = NULL;
    glist_entry_t *it1 = NULL;
    glist_entry_t *it2 = NULL;
    int ret = 0;

    it1 = glist_first(((rle_t*)rle1)->nodes);
    it2 = glist_first(((rle_t*)rle2)->nodes);

    while(it1 != glist_head(((rle_t*)rle1)->nodes)
          && it2 != glist_head(((rle_t*)rle2)->nodes)) {
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

inline afi_list_t *
afi_list_type_new()
{
	afi_list_t *afi_list = xzalloc(sizeof(afi_list_t));
	afi_list->list_addr = glist_new_managed((glist_del_fct)lisp_addr_del);
    return(afi_list);
}

void
afi_list_type_del(void *afil)
{
	glist_destroy(((afi_list_t *)afil)->list_addr);
}

int
afi_list_type_get_size_to_write(void *afil)
{
    int len = 0;
	lisp_addr_t *addr = NULL;
	glist_entry_t *it = NULL;

	len = sizeof(lcaf_afi_list_hdr_t);

	glist_for_each_entry(it, ((afi_list_t *)afil)->list_addr){
		addr = (lisp_addr_t *)glist_entry_data(it);
		len += lisp_addr_size_to_write(addr);
	}
    return(len);
}

int
afi_list_type_write_to_pkt(uint8_t *offset, void *afil)
{
    lisp_addr_t *addr = NULL;
    glist_entry_t *it = NULL;
    uint8_t *cur_ptr = NULL;
    int len = 0, lenw = 0;

    cur_ptr = offset;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_afi_list_hdr_t *)cur_ptr)->flags = 0;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->rsvd1 = 0;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->rsvd2 = 0;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->type = LCAF_AFI_LIST;

    cur_ptr = CO(cur_ptr, sizeof(lcaf_afi_list_hdr_t));

    glist_for_each_entry(it, ((afi_list_t *)afil)->list_addr){
    	addr = (lisp_addr_t *)glist_entry_data(it);
    	lenw = lisp_addr_write(cur_ptr, addr);
        if (lenw <= 0)
            return(BAD);
        cur_ptr = CO(cur_ptr, lenw);
    }
    len = cur_ptr-offset;
    ((lcaf_afi_list_hdr_t *)cur_ptr)->length = htons(len-sizeof(lcaf_afi_list_hdr_t));
    return(len);
}

int
afi_list_type_parse(uint8_t *offset, void **afilptr)
{
    lisp_addr_t *addr = NULL;
    afi_list_t *afil = NULL;
    uint8_t *cur_ptr = NULL;
    int len = 0, rlen = 0;

    cur_ptr = offset;
    afil = *afilptr;
    if (!afil){
        if(!(afil = afi_list_type_new()))
            return(BAD);
    }

    len = ntohs(((lcaf_afi_list_hdr_t *)offset)->length);
    cur_ptr = CO(cur_ptr, sizeof(lcaf_afi_list_hdr_t));
    while(len > 0) {
        addr = lisp_addr_new();
        if (!addr)
            goto err;
        rlen = lisp_addr_parse(cur_ptr, addr);
        glist_add_tail(addr, afil->list_addr);
        if (rlen <= 0)
           goto err;
        cur_ptr = CO(cur_ptr, rlen);
        len -= rlen;
    }

    return(cur_ptr - offset);

err:
    afi_list_type_del(afil);
    return(BAD);
}

char *
afi_list_type_to_char(void *afil)
{
    lisp_addr_t * addr = NULL;
    glist_entry_t * it = NULL;
    static char buf[3][500];
    static int i = 0;
    int j = 0;

    i++;
    i = i % 10;
    *buf[i] = '\0';
    glist_for_each_entry(it, ((afi_list_t *)afil)->list_addr){
    	addr = (lisp_addr_t *)glist_entry_data(it);
    	sprintf(buf[i]+strlen(buf[i]), "AFI %d: %s", j, lisp_addr_to_char(addr));
    	j++;
    }
    return(buf[i]);
}

void
afi_list_type_copy(void **dst, void *src)
{
	lisp_addr_t *addr_src = NULL;
	lisp_addr_t *addr_dst = NULL;
	glist_entry_t *it = NULL;

    if (!*dst){
        *dst = afi_list_type_new();
    }

    glist_for_each_entry(it, ((afi_list_t *)src)->list_addr){
        	addr_src = (lisp_addr_t *)glist_entry_data(it);
        	addr_dst = lisp_addr_clone(addr_src);
        	glist_add_tail(addr_dst, ((afi_list_t *)(*dst))->list_addr);
    }
}

int
afi_list_type_cmp(void *al1, void *al2)
{
	glist_entry_t *it_addr1 = NULL;
	glist_entry_t *it_addr2 = NULL;
	lisp_addr_t *addr1 = NULL;
	lisp_addr_t *addr2 = NULL;
	glist_t	*list1 = ((afi_list_t *)al1)->list_addr;
	glist_t	*list2 = ((afi_list_t *)al2)->list_addr;
	int	l1_size = glist_size (list1);
	int	l2_size = glist_size (list2);

	if (l1_size > l2_size){
		return (1);
	}else if (l1_size < l2_size){
		return (2);
	}

    int ret = 0;

    it_addr2 = glist_first(((afi_list_t *)al2)->list_addr);

    glist_for_each_entry(it_addr1, ((afi_list_t *)al1)->list_addr){
    	addr1 = (lisp_addr_t *)glist_entry_data(it_addr1);
    	addr2 = (lisp_addr_t *)glist_entry_data(it_addr2);
    	ret = lisp_addr_cmp(addr1, addr2);
    	if (ret!=0){
    		return(ret);
    	}
    	it_addr2 = glist_next(it_addr2);
    }

    return(0);
}

/*
 * Returns the first IPv4 or IPv6 address of the list
 */
lisp_addr_t *
afi_list_type_get_ip_addr(void *afi_list)
{
	glist_entry_t *it = NULL;
	lisp_addr_t *addr = NULL;
	lisp_addr_t *ip_addr = NULL;

	glist_for_each_entry(it, ((afi_list_t *)afi_list)->list_addr){
		addr = (lisp_addr_t *)glist_entry_data(it);
		ip_addr = lisp_addr_get_ip_addr(addr);
		if (ip_addr != NULL){
			// XXX Study if this behaviour is correct
			return (ip_addr);
		}
	}
	return (NULL);
}

/*
 * Returns the first IPv4 or IPv6 prefix of the list
 */
lisp_addr_t *
afi_list_type_get_ip_pref_addr(void *afi_list)
{
    glist_entry_t *it = NULL;
    lisp_addr_t *addr = NULL;
    lisp_addr_t *ip_pref = NULL;

    glist_for_each_entry(it, ((afi_list_t *)afi_list)->list_addr){
        addr = (lisp_addr_t *)glist_entry_data(it);
        ip_pref = lisp_addr_get_ip_pref_addr(addr);
        if (ip_pref != NULL){
            // XXX Study if this behaviour is correct
            return (ip_pref);
        }
    }
    return (NULL);
}

/* obtain IP address from LCAF */
lisp_addr_t *
lcaf_get_ip_addr(lcaf_addr_t *lcaf)
{
	if (!get_ip_addr_fcts[get_type_(lcaf)]) {
		OOR_LOG(LDBG_1, "lcaf_get_ip_addr: lcaf type %d not supported", get_type_(lcaf));
		return (NULL);
	}

	return (*get_ip_addr_fcts[get_type_(lcaf)])(get_addr_(lcaf));
}


/* obtain IP Prefix from LCAF */
lisp_addr_t *
lcaf_get_ip_pref_addr(lcaf_addr_t *lcaf)
{
    if (!get_ip_pref_addr_fcts[get_type_(lcaf)]) {
        OOR_LOG(LDBG_1, "lcaf_get_ip_pref_addr: lcaf type %d not supported", get_type_(lcaf));
        return (NULL);
    }

    return (*get_ip_pref_addr_fcts[get_type_(lcaf)])(get_addr_(lcaf));
}



/* Set IP address in LCAF RLOCs. When LCAFs are used as local locators, the
 * address that determines the interface to which the LCAF is associated, must
 * be updated to point to the interface, instead of being static */
int
lcaf_rloc_set_ip_addr(lisp_addr_t *addr, lisp_addr_t *if_addr)
{
    lcaf_addr_t     *lcaf = lisp_addr_get_lcaf(addr);

    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_EXPL_LOC_PATH: {
        elp_node_t *enode;
        enode = ((elp_node_t *)glist_last_data(lcaf_elp_node_list(lcaf)));
        lisp_addr_del(enode->addr);
        enode->addr = if_addr;
        break;
    }
    case LCAF_RLE: {
        rle_node_t *rit = NULL, *rnode = NULL;
        int level = -1;
        glist_entry_t   *it = NULL;

        /* Find the first highest level replication node */
        glist_for_each_entry(it, lcaf_rle_node_list(lcaf)) {
            rit = glist_entry_data(it);
            if (rit->level > level) {
                rnode = rit;
            }
            lisp_addr_del(rnode->addr);
            rnode->addr = if_addr;
        }
        break;
    }
    default:
        OOR_LOG(LDBG_1, "lcaf_rloc_set_ip_addr: lcaf type %d not supported",
                lcaf_addr_get_type(lcaf));
        return(BAD);
    }
    return(GOOD);
}
