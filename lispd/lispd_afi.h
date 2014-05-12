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
 *    Florin Coras      <fcoras@ac.upc.edu>
 *
 */
#ifndef LISPD_AFI_H_
#define LISPD_AFI_H_

#include "defs.h"
//#include "lispd_lcaf.h"
#include "lisp_mapping.h"



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

typedef struct {
    uint16_t    ms_port_number;
    uint16_t    etr_port_number;
    lisp_addr_t global_etr_rloc;
    lisp_addr_t ms_rloc;
    lisp_addr_t private_etr_rloc;
    //lisp_addr_list *rtr_rloc_list;
} lcaf_nat_traversal_addr_t;


/*
 * Reads the address information from the packet and fill the lispd_mapping_elt element
 */
int pkt_process_eid_afi(
        uint8_t             **offset,
        mapping_t   *mapping);

/*
 * Builds, reads from offset and returns a pointer to a lisp_addr_t
 */
lisp_addr_t *pkt_read_lisp_addr(uint8_t **offset);

/*
 * Reads the address information from the packet and fill the lispd_locator_elt structure
 */
int pkt_process_rloc_afi(
        uint8_t             **offset,
        locator_t   *locator);


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
        rtr_locators_list         **rtr_list,
        uint32_t                        *length);


int extract_mcast_info_lcaf_data (
        uint8_t             **offset,
        mapping_t   *mapping);


#endif /*LISPD_AFI_H_*/
