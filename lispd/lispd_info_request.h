/*
 * lispd_info_request.h
 *
 * This file is part of LISP Mobile Node Implementation.
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
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 *    Albert López Brescó <alopez@ac.upc.edu>
 */

#ifndef LISPD_INFO_REQUEST_H_
#define LISPD_INFO_REQUEST_H_

#include "lispd.h"

#include "lispd_info_nat.h"


#define DEFAULT_INFO_REQUEST_TIMEOUT    10 

/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Type=7 |R|            Reserved                                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Nonce . . .                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      . . . Nonce                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |              Key ID           |  Authentication Data Length   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ~                     Authentication Data                       ~
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                              TTL                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                          EID-prefix                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             AFI = 0           |   <Nothing Follows AFI=0>     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                LISP Info-Request Message Format

 */

/* NAT traversal Info-Request message
 * auth_data may be variable length in the future
 */

/* EID fixed part of an Info-Request message
 * variable length EID address follows
 */


/* LCAF part of an Info-Request message
 *
 */

typedef struct lispd_pkt_info_request_lcaf_t_ {
    uint16_t afi;
/*
    uint16_t lcaf_afi;
    uint8_t reserved1;
    uint8_t flags;
    uint8_t lcaf_type;
    uint8_t reserved2;
    uint16_t length;
*/ 
} PACKED lispd_pkt_info_request_lcaf_t;

typedef struct _timer_info_request_argument{
    lispd_mapping_elt   *mapping;
    lispd_locator_elt   *src_locator;
} timer_info_request_argument;

int  build_and_send_info_request(
        lispd_map_server_list_t     *map_server,
        uint32_t                    ttl,
        uint8_t                     eid_mask_length,
        lisp_addr_t                 *eid_prefix,
        lisp_addr_t		            *src_rloc,
        uint64_t                    *nonce);

/*
 * Initiate procedure to know status of each locator of every EID
 */
int initial_info_request_process();


/* Send initial Info Request message to know nat status*/
void restart_info_request_process(
		lispd_mapping_list 	*mapping_list,
		lisp_addr_t 		*src_addr);

/* Send Info Request */
int info_request(
        timer   *ttl_timer,
        void    *arg);


timer_info_request_argument * new_timer_inf_req_arg(
		lispd_mapping_elt *mapping,
		lispd_locator_elt *src_locator);

#endif /* LISPD_INFO_REQUEST_H_*/
