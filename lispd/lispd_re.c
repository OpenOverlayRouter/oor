/*
 * lispd_re.c
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

#include "defs_re.h"

/*
 * Interface to end-hosts
 */

int re_join_channel(ip_addr_t *src, ip_addr_t *grp) {
    lisp_addr_t *mceid = re_build_mceid(src, grp);
    re_send_join_request(mceid);

    lisp_addr_del(mceid);
    return(GOOD);
}

int re_leave_channel(ip_addr_t *src, ip_addr_t *grp) {
    lisp_addr_t *mceid = re_build_mceid(src, grp);
    re_send_leave_request(mceid);

    lisp_addr_del(mceid);
    return(GOOD);
}



/*
 * Interface to lisp-re overlay
 */

int re_process_join_request(mc_addr_t *ch, lisp_addr_t *rloc_pair) {
    /* add dst (S-RLOC, DG/RLOC) to jib */

    lispd_mapping_elt   *mapping    = NULL;
    lispd_jib_t         *jib        = NULL;
    lispd_locators_list *loc_list   = NULL;

    /* TODO: implement real multicast FIB instead of using the mapping db */
    mapping = lookup_eid_in_db(ch);

    if (!mapping) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "mrsignaling_process_join_request: No map-cache entry found for EID %s. This shouldn't happen!",
                lisp_addr_to_char(dst_addr));
        return(BAD);
    }

    jib = mapping_get_jib(mapping);
    loc_list  = calloc(1, sizeof(lispd_locators_list));
    loc_list->next = NULL;

    /* the pair is of the type (S-RLOC, D-RLOC)
     * If the join will carry in the future more D-RLOCs for TE
     * add them one by one to the locator list
     */
    loc_list->locator = rloc_pair;

    jib_add_locator_list(loc_list, jib);


    return(GOOD);
}

int re_process_leave_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair) {
    /* remove dst (S-RLOC, DG/RLOC) from jib */

    lispd_mapping_elt   *mapping    = NULL;
    lispd_jib_t         *jib        = NULL;
    lispd_locators_list *loc_list   = NULL;

    mapping = lookup_eid_in_db(ch);

    if (!mapping) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "mrsignaling_process_join_request: No map-cache entry found for EID %s. This shouldn't happen!",
                lisp_addr_to_char(dst_addr));
        return(BAD);
    }

    jib = mapping_get_jib(mapping);
    /* XXX NEED PROPER DELETE */
    jib_del_locator_list(rloc_pair, jib);
}

int re_send_join_request(lisp_addr_t *mceid) {

}

int re_send_leave_request() {

}

lisp_addr_t *re_build_mceid(ip_addr_t *src, ip_addr_t *grp) {
    lisp_addr_t     *mceid;
    mc_addr_t       *mc;
    lcaf_addr_t     *lcaf;

    mceid = lisp_addr_new_afi(LM_AFI_LCAF);
    lcaf = lisp_addr_get_lcaf(mceid);

    mc = mc_addr_init(src, grp,
            (ip_addr_get_afi(src) == AF_INET) ? 32 : 128,
            (ip_addr_get_afi(grp) == AF_INET) ? 32 : 128,
            0);

    lcaf_addr_set(lcaf, mc, LCAF_MCAST_INFO);
    return(mceid);
}

/*
 * Interface to data plane
 */
lispd_generic_list_t *re_get_orlist(mc_addr_t *dst_addr) {

    lispd_map_cache_entry   *mcentry    = NULL;
    lispd_mapping_elt       *mapping    = NULL;
    lispd_generic_list_t    *or_list    = NULL;

    /* TODO: implement real multicast FIB instead of using the mapping db */
    mcentry = lookup_eid_in_db(dst_addr);

    if (!mcentry) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "get_re_orlist: No map-cache "
                "entry found for EID %s. This shouldn't happen!",
                lisp_addr_to_char(dst_addr));
        return(BAD);
    }

    /* get output RLOC list (subset of the jib - joinig information base)
     * Current implementation: the jib is pointed to from  the mapping
     * extended info of mcinfo type.  */
    mapping = mcache_entry_get_mapping(mcentry);
    or_list = jib_get_orlist(mapping_get_jib(mapping));

    /* packets with no active mapping are dropped */
    if (mcache_entry_get_active(mcentry) == NO_ACTIVE || lispd_generic_list_size(or_list) == 0){
        lispd_log_msg(LISP_LOG_DEBUG_1, "lisp_output_multicast: Packet for EID "
                "%s dropped because map-cache entry is not active or has no "
                "output RLOCs !",  lisp_addr_to_char(dst_addr));
        /* fcoras TODO: what should we return here? */
        return (NULL);
    }

    return(or_list);
}

lispd_locator_elt *re_get_src_locator(mc_addr_t *dst_addr) {
    lispd_map_cache_entry   *mcentry    = NULL;
    lispd_mapping_elt       *mapping    = NULL;

    /* (S,G) stored in the local mapping database */
    mcentry = lookup_eid_in_db(dst_addr);

    if (mcentry == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "get_re_src_locator: No map-cache "
                "entry found for EID %s. This shouldn't happen!",
                lisp_addr_to_char(dst_addr));
        return(BAD);
    }

    mapping = mcache_entry_get_mapping(mcentry);
    return(((mcinfo_mapping_extended_info*)mapping->extended_info)->src_rloc);
}






/*
 * General Multicast Functions
 */

void multicast_join_channel(ip_addr_t *src, ip_addr_t *grp) {
    re_join_channel(src, grp);
}

void multicast_leave_channel(ip_addr_t *src, ip_addr_t *grp) {
    re_leave_channel(src, grp);
}

/*
 * This should manage the joins for all multicast protocols (lisp-re, lisp-multicast ...)
 * For the time being, we have only lisp-re
 */
void mrsignaling_process_mreq_message(uint8_t **offset) {

    mrsignaling_flags_t     mc_flags;
    uint8_t                 *cur_ptr;

    cur_ptr = *offset;
    mc_flags = lcaf_mcinfo_get_flags((uint8_t *)&((record)->eid_prefix_afi));

    if (mc_flags->jbit == 1 && mc_flags->lbit == 1) {
        lisd_log_msg(LISP_LOG_DEBUG_1, "re_process_mrsignaling: Both join and leave flags are set!");
        return;
    }

    if (mc_flags->jbit == 1)
        re_process_join_request(ch, rloc_pair);

    if (mc_flags->lbit == 1)
        re_process_leave_request(ch, rloc_pair);


    if (mc_flags->rbit == 1) {
        lisd_log_msg(LISP_LOG_WARNING, "re_process_mrsignaling: PIM join received, not implemented!");
        return;
    }

    *offset = cur_ptr;
}

void mrsignaling_process_mrep_message(uint8_t **offset) {

}

