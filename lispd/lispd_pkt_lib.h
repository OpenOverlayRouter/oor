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

int pkt_get_mapping_record_length(lispd_mapping_elt *mapping);


void *pkt_fill_eid(void *offset, lispd_mapping_elt *mapping);

void *pkt_fill_mapping_record(
    lispd_pkt_mapping_record_t              *rec,
    lispd_mapping_elt                       *mapping,
    lisp_addr_t                             *probed_rloc);

/*
 *  get_mapping_length
 *
 *  Compute the lengths of the mapping to be use in a record
 *  so we can allocate  memory for the packet....
 */

int get_mapping_length(lispd_mapping_elt *mapping);


/*
 *  get_up_locators_length
 *
 *  Compute the sum of the lengths of the locators that has the status up
 *  so we can allocate  memory for the packet....
 *  Loc_count return the number of UP locators.
 */

int get_up_locators_length(lispd_locators_list *locators_list, int *loc_count);

/*
 * Fill the tuple with the 5 tuples of a packet: (SRC IP, DST IP, PROTOCOL, SRC PORT, DST PORT)
 */

int extract_5_tuples_from_packet (
        char *packet ,
        packet_tuple *tuple);


#endif /*LISPD_PKT_LIB_H_*/
