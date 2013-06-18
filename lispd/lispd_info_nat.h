/*
 * lispd_info_nat.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send registration messages for each database mapping to
 * configured map-servers.
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
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 */

#ifndef LISPD_INFO_NAT_H_
#define LISPD_INFO_NAT_H_

#include "lispd.h"


#define NAT_REPLY                        1
#define NAT_NO_REPLY                     0 

extern  timer *info_reply_ttl_timer;


/* NAT traversal Info-Request message
 * auth_data may be variable length in the future
 */

typedef struct lispd_pkt_info_nat_t_ {
#ifdef LITTLE_ENDIANS
    uint8_t reserved1:3;
    uint8_t rbit:1;
    uint8_t lisp_type:4;
#else
    uint8_t lisp_type:4;
    uint8_t rbit:1;
    uint8_t reserved1:3;
#endif
    uint8_t reserved2;
    uint16_t reserved3;

    uint64_t nonce;
    uint16_t key_id;
    uint16_t auth_data_len;
    uint8_t auth_data[LISP_SHA1_AUTH_DATA_LEN];
} PACKED lispd_pkt_info_nat_t;

/* EID fixed part of an Info-Request message
 * variable length EID address follows
 */

typedef struct lispd_pkt_info_nat_eid_t_ {
    uint32_t ttl;
    uint8_t reserved;
    uint8_t eid_mask_length;
    uint16_t eid_prefix_afi;
} PACKED lispd_pkt_info_nat_eid_t;


/* Global NAT variables*/ //XXX should be there?

extern int nat_aware;
extern int behind_nat;



int extract_info_nat_header(
        uint8_t     *offset,
        uint8_t     *type,
        uint8_t     *reply,
        uint64_t    *nonce,
        uint16_t    *key_id,
        uint16_t    *auth_data_len,
        uint8_t     **auth_data,
        uint32_t    *ttl,
        uint8_t     *eid_mask_len,
        lisp_addr_t *eid_prefix,
        uint32_t    *hdr_len);

lispd_pkt_info_nat_t *create_and_fill_info_nat_header(
        int         lisp_type,
        int         reply,
        uint64_t    nonce,
        uint16_t    auth_data_len,
        uint32_t    ttl,
        uint8_t     eid_mask_length,
        lisp_addr_t *eid_prefix,
        uint32_t    *header_len);

int process_info_nat_msg(
        uint8_t         *packet,
        lisp_addr_t     local_rloc);

#endif /*LISPD_INFO_NAT_H_*/
