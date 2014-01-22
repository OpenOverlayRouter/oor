/*
 * lispd_map_reply.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 *    Kari Okamoto	    <okamotok@stanford.edu>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

/*
 * Map-Reply Message Format from lisp draft-ietf-lisp-08
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=2 |P|E|           Reserved                | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   |                          Record  TTL                          |
 *  |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *  e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *  o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r   |                          EID-prefix                           |
 *  d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *  | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  \|                            Locator                            |
 *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


#include <time.h>
#include "cksum.h"
#include "lispd_afi.h"
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_cache_db.h"
#include "lispd_pkt_lib.h"
#include "lispd_rloc_probing.h"
#include "lispd_sockets.h"
#include "lispd_re.h"
#include "defs.h"







































//static lispd_locators_list *_read_locators(uint8_t **offset, uint8_t count)
//{
//    uint8_t                             *cur_ptr        = NULL;
//    locator_hdr             *pkt_locator    = NULL;
//    lispd_locator_elt                   *locator        = NULL;
//    lispd_locators_list                 *locators       = NULL;
//    uint8_t                             status          = UP;
//    uint8_t                             ctr             = 0;
//
//    cur_ptr = *offset;
//
//    for (ctr=0 ; ctr < count; ctr++){
//        pkt_locator = (locator_hdr *)(cur_ptr);
////        cur_ptr = (uint8_t *)&(pkt_locator->locator_afi);
//
//        /*
//         * We only consider the reachable bit if the information comes from the owner of the locator (local)
//         */
//        if (pkt_locator->reachable == DOWN && pkt_locator->local == UP){
//            status = DOWN;
//        }
//
//        locator = new_rmt_locator (&cur_ptr,status,
//                pkt_locator->priority, pkt_locator->weight,
//                pkt_locator->mpriority, pkt_locator->mweight);
//
//        if (!locator) {
//            lispd_log_msg(LISP_LOG_DEBUG_3, "_read_map_reply_locators: Couldn't read locator!");
//            return(NULL);
//        }
//
//        add_locator_to_list(&locators, locator);
//    }
//
//    *offset = cur_ptr;
//    return(locators);
//}

//int process_map_reply_locator(uint8_t  **offset, lispd_mapping_elt *mapping);


/*
 * Return the locator from tha mapping that match with the locator of the packet.
 * Retun null if no match found. Offset is updated to point the next locator of the packet.
 */

//int process_map_reply_probe_locator1(
//        uint8_t                 **offset,
//        lispd_mapping_elt       *mapping,
//        uint64_t                nonce,
//        lispd_locator_elt       **locator);
//


/****************************************************************************************/



//
//int process_map_reply_record1(uint8_t **offset, uint64_t nonce)
//{
//    mapping_record_hdr              *record                 = NULL;
//    lispd_locators_list                     *locators               = NULL;
//    lisp_addr_t                             *eid                    = NULL;
//    int                                     len                     = 0;
//
//    record = (mapping_record_hdr *)(*offset);
//    *offset = (uint8_t *)&(record->eid_prefix_afi);
//
//    eid = lisp_addr_new();
//    if((len=lisp_addr_read_from_pkt(*offset, eid)) <= 0) {
//        lisp_addr_del(eid);
//        return(err);
//    }
//
//    *offset = CO(*offset, len);
//
//    /* Save prefix length only if the entry is an IP */
//    if (lisp_addr_get_afi(eid) == LM_AFI_IP) {
//        lisp_addr_ip_to_ippref(eid);
//        lisp_addr_set_plen(eid, record->eid_prefix_length);
//    }
//
//    if (record->locator_count !=0 && !(locators=_read_locators(offset, record->locator_count))) {
//        lispd_log_msg(LISP_LOG_DEBUG_2, "Couldn't read locators for EID %s", lisp_addr_to_char(eid));
//        return(BAD);
//    }
//
//    /* TODO: this should be moved higher in the call chain. The function that reads a mapping_record_hdr
//     * shouldn't know what a mapping is */
//    if (mcache_activate_mapping(eid, nonce, locators, record->action, ntohl(record->ttl))!=GOOD) {
//        lispd_log_msg(LISP_LOG_DEBUG_2, "Couldn't activate mapping for EID %s", lisp_addr_to_char(eid));
//        return(BAD);
//    }
//
//    return(GOOD);
//}


//int process_map_reply_locator(
//        uint8_t                 **offset,
//        lispd_mapping_elt       *mapping)
//{
//    lispd_pkt_mapping_record_locator_t  *pkt_locator    = NULL;
//    lispd_locator_elt                   *locator        = NULL;
//    uint8_t                             *cur_ptr        = NULL;
//    uint8_t                             status          = UP;
//
//    cur_ptr = *offset;
//    pkt_locator = (lispd_pkt_mapping_record_locator_t *)(cur_ptr);
//
//    cur_ptr = (uint8_t *)&(pkt_locator->locator_afi);
//
//    /*
//     * We only consider the reachable bit if the information comes from the owner of the locator (local)
//     */
//    if (pkt_locator->reachable == DOWN && pkt_locator->local == UP){
//        status = DOWN;
//    }
//
//    locator = new_rmt_locator (&cur_ptr,status,
//            pkt_locator->priority, pkt_locator->weight,
//            pkt_locator->mpriority, pkt_locator->mweight);
//
//    if (locator != NULL){
//        if ((err=add_locator_to_mapping (mapping, locator)) != GOOD){
//            return (BAD);
//        }
//    }else{
//        return (BAD);
//    }
//
//    *offset = cur_ptr;
//    return (GOOD);
//}

/*
 * Return the locator from tha mapping that match with the locator of the packet.
 * Retun null if no match found. Offset is updated to point the next locator of the packet.
 */










/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
