/*
 * lispd_local_db.h
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
#pragma once

#include "lispd.h"

typedef struct {
    uint8_t     retransmits;
    uint64_t    nonce[LISPD_MAX_PROBE_RETRANSMIT];
}nonces_list;


/*
 * Locator information
 */
typedef struct lispd_locator_elt_ {
    lisp_addr_t                 locator_addr;
    uint8_t                     locator_type:2;
    uint8_t                     priority;
    uint8_t                     weight;
    uint8_t                     mpriority;
    uint8_t                     mweight;
    uint8_t                     state:2;    /* UP , DOWN */
    uint32_t                    data_packets_in;
    uint32_t                    data_packets_out;
    nonces_list          *rloc_probing_nonces;
}lispd_locator_elt;


/*
 * list of locators.
 */
typedef struct lispd_locators_list_ {
    lispd_locator_elt           *locator;
    struct lispd_locators_list_ *next;
} lispd_locators_list;


/*
 * lispd identifier entry.
 */
typedef struct lispd_identifier_elt_ {
    lisp_addr_t                     eid_prefix;
    uint8_t                         eid_prefix_length;
    uint32_t                        iid;
    uint16_t                        locator_count;
    lispd_locators_list             *head_locators_list;
    lispd_locator_elt               *locator_has_table[100]; /* Used to do traffic balancing between RLOCs*/
} lispd_identifier_elt;


/*
 * Initialize lispd_identifier_elt with default parameters
 */

void init_identifier (lispd_identifier_elt *identifier);

/*
 * Generets a empty locator element and add it to locators list
 */

lispd_locator_elt   *make_and_add_locator (lispd_identifier_elt *identifier);

/*
 * Free memory of lispd_locator_list
 */
void free_locator_list(lispd_locators_list *list);


