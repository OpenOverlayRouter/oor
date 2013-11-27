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
    lcaf->del(lcaf_addr_get_addr(lcaf));
    free(lcaf);
}

/*
 * lcaf_addr_t functions
 */

inline uint32_t lcaf_addr_read_from_pkt(void *offset, lcaf_addr_t *lcaf_addr) {
    void *inaddr;

    lcaf_addr_set_type(lcaf_addr, ntohs(((lispd_pkt_lcaf_t *)offset)->type));
    switch(lcaf_addr_get_type(lcaf_addr)) {
        case LCAF_IID:
            return(iid_addr_read_from_pkt(offset, lcaf_addr_get_iid(lcaf_addr)));
            break;
        case LCAF_MCAST_INFO:
            return(mc_addr_read_from_pkt(offset, lcaf_addr_get_mc(lcaf_addr)));
            break;
        case LCAF_GEO:
            return(geo_addr_read_from_pkt(offset, lcaf_addr_get_geo(lcaf_addr)));
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2,"pkt_process_eid_afi:  Unknown LCAF type %d in EID",
                    lcaf_addr_get_type(lcaf_addr));
            break;
    }
    return(0);

}



inline uint8_t lcaf_addr_get_type(lcaf_addr_t *lcaf) {
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


inline void lcaf_addr_set(lcaf_addr_t *lcaf, void *newaddr, uint8_t type) {
    void *addr;
    addr = lcaf_addr_get_addr(lcaf);
    if (addr)
        lcaf->del(addr);
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
    lcaf->del = del_fcts[type];
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
}

inline uint8_t lcaf_addr_cmp_iids(lcaf_addr_t *addr1, lcaf_addr_t *addr2) {
    if (lcaf_addr_get_type(addr1) != lcaf_addr_get_type(addr2))
        return(0);
    switch(lcaf_addr_get_type(addr1)) {
        case LCAST_IID:
            return(iid_addr_get_iid(lcaf_addr_get_iid(addr1)) == iid_addr_get_iid(lcaf_addr_get_iid(addr2)));
        case LCAST_MCAST_INFO:
            return(mc_addr_get_iid(lcaf_addr_get_iid(addr1)) == mc_addr_get_iid(lcaf_addr_get_iid(addr2)));
        default:
            return(0);
    }
}
