/*
 * lispd_pkt_lib.h
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
 *    Lorand Jakab  <ljakab@ac.upc.edu>
 *
 */

#ifndef LISPD_PKT_LIB_H_
#define LISPD_PKT_LIB_H_

#include "lispd.h"
#include "lispd_local_db.h"

int pkt_get_mapping_record_length(lispd_identifier_elt *identifier);


void *pkt_fill_eid(void *offset, lispd_identifier_elt *identifier);

void *pkt_fill_mapping_record(
    lispd_pkt_mapping_record_t              *rec,
    lispd_identifier_elt                    *identifier,
    lisp_addr_t                             *probed_rloc);

void *pkt_read_eid(
    void                    *offset,
    lisp_addr_t            **eid,
    int                     *eid_afi,
    lispd_iid_t             *iid);
/*
 * Send a ipv4 control packet to the destination address
 */
int send_ctrl_ipv4_packet(lisp_addr_t *destination, uint16_t src_port, uint16_t dst_port, void *packet, int packet_len);

/*
 * Send a ipv6 control packet to the destination address
 */
int send_ctrl_ipv6_packet(lisp_addr_t *destination,uint16_t src_port, uint16_t dst_port, void *packet, int packet_len);

#endif /*LISPD_PKT_LIB_H_*/
