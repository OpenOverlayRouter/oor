/*
 * lisp_map_reply.h
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
 *    Kari Okamoto      <okamotok@stanford.edu>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */


#ifndef LISP_MAP_REPLY_H_
#define LISP_MAP_REPLY_H_

#include "lisp_message_fields.h"
//#include "lispd_lcaf.h"

/*
 *  Map Reply action codes
 */

#define LISP_ACTION_NO_ACTION           0
#define LISP_ACTION_FORWARD             1
#define LISP_ACTION_DROP                2
#define LISP_ACTION_SEND_MAP_REQUEST    3

/*
 * Map-Reply Message Format
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=2 |P|E|S|         Reserved                | Record Count  |
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




/*
 * Fixed size portion of the map reply.
 */
typedef struct map_reply_hdr_ {
#ifdef LITTLE_ENDIANS
    uint8_t reserved1:1;
    uint8_t security:1;
    uint8_t echo_nonce:1;
    uint8_t rloc_probe:1;
    uint8_t type:4;
#else
    uint8_t type:4;
    uint8_t rloc_probe:1;
    uint8_t echo_nonce:1;
    uint8_t reserved1:2;
#endif
    uint8_t reserved2;
    uint8_t reserved3;
    uint8_t record_count;
    uint64_t nonce;
} PACKED map_reply_hdr_t;


typedef struct lispd_map_reply_pkt_ {
    uint8_t             *data;
    glist_t             *records;
    /* TODO map reply data */
} map_reply_msg;

inline map_reply_msg    *map_reply_msg_new();
map_reply_msg           *map_reply_msg_parse(uint8_t *offset);
void                    map_reply_msg_del(map_reply_msg *pkt);


/*
 * Accessors
 */


static inline map_reply_hdr_t *mrep_get_hdr(map_reply_msg *mrp) {
    return((map_reply_hdr_t *)mrp->data);
}

static inline glist_t *mrep_msg_get_records(map_reply_msg *mrp) {
    return(mrp->records);
}


/*
 * Macros
 */

#define mrep_msg_foreach_mapping_record(it, mrep) \
    glist_for_each_entry(it, (mrep)->records)




#define MREP_HDR_CAST(h) ((map_reply_hdr_t *)(h))
#define MREP_REC_COUNT(h) ((map_reply_hdr_t *)(h))->record_count
#define MREP_RLOC_PROBE(h) ((map_reply_hdr_t *)(h))->rloc_probe
#define MREP_NONCE(h) ((map_reply_hdr_t *)(h))->nonce

#endif /* LISP_MAP_REPLY_H_ */
