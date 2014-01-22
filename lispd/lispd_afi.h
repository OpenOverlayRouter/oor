/*
 * lispd_afi.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
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
 *
 */
#ifndef LISPD_AFI_H_
#define LISPD_AFI_H_

#include "lispd.h"
#include "lispd_mapping.h"


/*
 * LISP AFI codes
 */

#define LISP_AFI_NO_ADDR                0
#define LISP_AFI_IP                     1
#define LISP_AFI_IPV6                   2
#define LISP_AFI_LCAF                   16387


/*
 * LCAF types
 */

#define LCAF_NULL           0
#define LCAF_AFI_LIST       1
#define LCAF_IID            2
#define LCAF_ASN            3
#define LCAF_APP_DATA       4
#define LCAF_GEO            5
#define LCAF_OKEY           6
#define LCAF_NATT           7
#define LCAF_NONCE_LOC      8
#define LCAF_MCAST_INFO     9
#define LCAF_EXPL_LOC_PATH  10
#define LCAF_SEC_KEY        11


#define MAX_IID 16777215

/*
 * LISP Canonical Address Format
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |           AFI = 16387         |    Rsvd1     |     Flags      |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |    Type       |     Rsvd2     |            Length             |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct lispd_pkt_lcaf_t_ {
    uint8_t  rsvd1;
    uint8_t  flags;
    uint8_t  type;
    uint8_t  rsvd2;
    uint16_t len;
} PACKED lispd_pkt_lcaf_t;


/* Instance ID
 * Only the low order 24 bits should be used
 * Using signed integer, negative value means "don't send LCAF/IID field"
 * resulting in a non-explicit default IID value of 0
 */
typedef int32_t lispd_iid_t;

/*
 * Instance ID
 *
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |           AFI = 16387         |    Rsvd1      |    Flags      |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 2    | IID mask-len  |             4 + n             |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                         Instance ID                           |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |              AFI = x          |         Address  ...          |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct lispd_pkt_lcaf_iid_t_ {
    lispd_iid_t iid;
    uint16_t    afi;
} PACKED lispd_pkt_lcaf_iid_t;




/* Fixed part of NAT LCAF.
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |           AFI = 16387         |     Rsvd1     |     Flags     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |   Type = 7    |     Rsvd2     |             4 + n             |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |       MS UDP Port Number      |      ETR UDP Port Number      |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |              AFI = x          |  Global ETR RLOC Address  ... |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |              AFI = x          |       MS RLOC Address  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |              AFI = x          | Private ETR RLOC Address  ... |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |              AFI = x          |      RTR RLOC Address 1 ...   |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |              AFI = x          |      RTR RLOC Address k ...   |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct lispd_pkt_nat_lcaf_t_ {
    uint16_t ms_udp_port;
    uint16_t etr_udp_port;
} PACKED lispd_pkt_nat_lcaf_t;

/*
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 10   |     Rsvd2     |               n               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |           Rsvd3         |L|P|S|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Reencap Hop 1  ...                    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |           Rsvd3         |L|P|S|
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Reencap Hop k  ...                    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct lispd_pkt_elp_lcaf_t_ {
    uint16_t afi;
    uint8_t reserved1;
#ifdef LITTLE_ENDIANS
    uint8_t lookup_bit:1;
    uint8_t probe_bit:1;
    uint8_t strict_bit:1;
    uint8_t reserved2:5;
#else
    uint8_t reserved2:5;
    uint8_t strict_bit:1;
    uint8_t probe_bit:1;
    uint8_t lookup_bit:1;
#endif
} PACKED lispd_pkt_elp_lcaf_t;

/*
 * Reads the address information from the packet and fill the lispd_mapping_elt element
 */
int pkt_process_eid_afi(
        uint8_t             **offset,
        lispd_mapping_elt   *mapping);

/*
 * Reads the address information from the packet and fill the lispd_locator_elt structure
 */
int pkt_process_rloc_afi(
        uint8_t             **offset,
        lispd_locator_elt   *locator);


/**
 * Read an afi from a packet according to the afi
 * @param **offset Pointer to the pointer to the position from where the address should be extracted.
 *        The pointer is updated to next position to read.
 * @param lisp_afi Afi of the address to be extracted. IPv4 or IPv6
 * @param *addr Pointer to the lisp_addr_t structure that should be filed
 * @return GOOD if finish correctly or an error code otherwise
 */
int pkt_get_ip_address(
        uint8_t                 **offset,
        int                     lisp_afi,
        lisp_addr_t             *addr);


/*
 * Extract the nat lcaf address information from the packet.
 */

int extract_nat_lcaf_data(
        uint8_t                         *offset,
        uint16_t                        *ms_udp_port,
        uint16_t                        *etr_udp_port,
        lisp_addr_t                     *global_etr_rloc,
        lisp_addr_t                     *ms_rloc,
        lisp_addr_t                     *private_etr_rloc,
        lispd_rtr_locators_list         **rtr_list,
        uint32_t                        *length);



#endif /*LISPD_AFI_H_*/
