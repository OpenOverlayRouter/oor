/*
 * lispd_map_referral.h
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
 *    Albert Lopez      <alopez@ac.upc.edu>
 */

#ifndef LISPD_MAP_REFERRAL_H_
#define LISPD_MAP_REFERRAL_H_

/* Action field of the map referral */

#define NODE_REFERRAL           0
#define MS_REFERRAL             1
#define MS_ACK                  2
#define MS_NOT_REGISTERED       3
#define DELEGATION_HOLE         4
#define NOT_AUTHORITATIVE       5

 /*
  * Map-Referral Message Format
  *
  *
  *         0                   1                   2                   3
  *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *        |Type=6 |                Reserved               | Record Count  |
  *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *        |                         Nonce . . .                           |
  *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *        |                         . . . Nonce                           |
  *    +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *    |   |                          Record  TTL                          |
  *    |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *    R   | Locator Count | EID mask-len  | ACT |A|I|     Reserved        |
  *    e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *    c   |SigCnt |   Map Version Number  |            EID-AFI            |
  *    o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *    r   |                          EID-prefix ...                       |
  *    d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *    |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
  *    | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *    | o |        Unused Flags         |R|         Loc/LCAF-AFI          |
  *    | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *    |  \|                             Locator ...                       |
  *    +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


typedef struct lispd_pkt_map_referral_t_ {
#ifdef LITTLE_ENDIANS
    uint8_t  reserved1:4;
    uint8_t  lisp_type:4;
#else
    uint8_t  lisp_type:4;
    uint8_t  reserved1:4;
#endif
    uint16_t reserved2;
    uint8_t  record_count;
    uint64_t nonce;
} PACKED lispd_pkt_map_referral_t;

/*
 * Fixed portion of the mapping record. EID prefix address and
 * locators follow.
 */

typedef struct lispd_pkt_referral_mapping_record_t {
    uint32_t ttl;
    uint8_t locator_count;
    uint8_t eid_prefix_length;
#ifdef LITTLE_ENDIANS
    uint8_t reserved1:3;
    uint8_t incomplete:1;
    uint8_t authoritative:1;
    uint8_t action:3;
#else
    uint8_t action:3;
    uint8_t authoritative:1;
    uint8_t incomplete:1;
    uint8_t reserved1:3;
#endif
    uint8_t reserved2;
#ifdef LITTLE_ENDIANS
    uint8_t version_hi:4;
    uint8_t sig_cnt:4;
#else
    uint8_t sig_cnt:4;
    uint8_t version_hi:4;
#endif
    uint8_t version_low;
    uint16_t eid_prefix_afi;
} PACKED lispd_pkt_referral_mapping_record_t;


/*
 * Fixed portion of the mapping record locator. Variable length
 * locator address follows.
 */
typedef struct lispd_pkt_referral_mapping_record_locator_t_ {
    uint8_t priority;
    uint8_t weight;
    uint8_t mpriority;
    uint8_t mweight;
    uint8_t unused1;
#ifdef LITTLE_ENDIANS
    uint8_t reachable:1;
    uint8_t unused2:7;
#else
    uint8_t unused2:7;
    uint8_t reachable:1;
#endif
    uint16_t locator_afi;
} PACKED lispd_pkt_referral_mapping_record_locator_t;



int process_map_referral(uint8_t *packet);

#endif /* LISPD_MAP_REFERRAL_H_ */
