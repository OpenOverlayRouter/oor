/*
 * lisp_map_request.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send a map request.
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
 *    David Meyer       <dmm@cisco.com>
 *    Vina Ermagan      <vermagan@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Pranathi Mamidi   <pranathi.3961@gmail.com>
 *
 */

#ifndef LISP_MAP_REQUEST_H_
#define LISP_MAP_REQUEST_H_


#include "lisp_message_fields.h"

/*
 * Map-Request Message Format
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=1 |A|M|P|S|p|s|    Reserved     |   IRC   | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         Source-EID-AFI        |   Source EID Address  ...     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                              ...                              |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                       EID-prefix  ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                   Map-Reply Record  ...                       |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


/*
 * Fixed size portion of the map request. Variable size source EID
 * address, originating ITR RLOC AFIs and addresses and then map
 * request records follow.
 */
typedef struct _map_request_msg_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t solicit_map_request:1;
    uint8_t rloc_probe:1;
    uint8_t map_data_present:1;
    uint8_t authoritative:1;
    uint8_t type:4;
#else
    uint8_t type:4;
    uint8_t authoritative:1;
    uint8_t map_data_present:1;
    uint8_t rloc_probe:1;
    uint8_t solicit_map_request:1;
#endif
#ifdef LITTLE_ENDIANS
    uint8_t reserved1:6;
    uint8_t smr_invoked:1;
    uint8_t pitr:1;
#else
    uint8_t pitr:1;
    uint8_t smr_invoked:1;
    uint8_t reserved1:6;
#endif
#ifdef LITTLE_ENDIANS
    uint8_t additional_itr_rloc_count:5;
    uint8_t reserved2:3;
#else
    uint8_t reserved2:3;
    uint8_t additional_itr_rloc_count:5;
#endif
    uint8_t record_count;
    uint64_t nonce;
} __attribute__ ((__packed__)) map_request_hdr_t;

typedef struct _map_request_msg {
    uint8_t                 *data;
    address_field           *src_eid;
    glist_t                 *itr_rlocs;
    glist_t                 *eids;
    mapping_record          *mrep_record;
} map_request_msg;


inline map_request_msg *map_request_msg_new();
map_request_msg *map_request_msg_parse(uint8_t *offset);
void map_request_msg_del(map_request_msg *msg);


static inline map_request_hdr_t *mreq_msg_get_hdr(map_request_msg *mrp) {
    return((map_request_hdr_t *)mrp->data);
}

static inline address_field *mreq_msg_get_src_eid(map_request_msg *mreq) {
    return(mreq->src_eid);
}

static inline glist_t *mreq_msg_get_itr_rlocs(map_request_msg *mreq) {
    return(mreq->itr_rlocs);
}

static inline glist_t *mreq_msg_get_eids(map_request_msg *mreq) {
    return(mreq->eids);
}


#define mreq_msg_foreach_itr_rloc(it, msg) \
    glist_for_each_entry(it, (msg)->itr_rlocs)

#define mreq_msg_foreach_eid_record(it, msg) \
    glist_for_each_entry(it, (msg)->eids)



char *mreq_hdr_to_char(map_request_hdr_t *);

#define MREQ_HDR_CAST(h_) ((map_request_hdr_t *)(h_))
#define MREQ_REC_COUNT(h_) (MREQ_HDR_CAST(h_))->record_count
#define MREQ_RLOC_PROBE(h_) (MREQ_HDR_CAST(h_))->rloc_probe
#define ITR_RLOC_COUNT(h_) (MREQ_HDR_CAST(h_))->additional_itr_rloc_count
#define MREQ_NONCE(h_) (MREQ_HDR_CAST(h_))->nonce
#define MREQ_SMR(h_) (MREQ_HDR_CAST(h_))->solicit_map_request
#define MREQ_SMR_INVOKED(h_) (MREQ_HDR_CAST(h_))->smr_invoked



#endif /*LISPD_MAP_REQUEST_H_*/
