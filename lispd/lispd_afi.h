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

#ifndef LISPD_AFI_H_
#define LISPD_AFI_H_

#include "defs.h"
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
        rtr_locators_list_t         **rtr_list,
        uint32_t                        *length);

int extract_mcast_info_lcaf_data (
        uint8_t             **offset,
        mapping_t   *mapping);


#endif /*LISPD_AFI_H_*/
