/*
 * lispd_mapping.h
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

#ifndef LISPD_MAPPING_H_
#define LISPD_MAPPING_H_

#include "lispd_locator.h"


/****************************************  STRUCTURES **************************************/

/*
 * lispd mapping entry.
 */
typedef struct lispd_mapping_elt_ {
    lisp_addr_t                     eid_prefix;
    uint8_t                         eid_prefix_length;
    int                             iid;
    uint16_t                        locator_count;
    lispd_locators_list             *head_v4_locators_list;
    lispd_locators_list             *head_v6_locators_list;
    /*
     * Used to do traffic balancing between RLOCs
     *  v4_locator_hash_table: If we just have IPv4 RLOCs
     *  v6_locator_hash_table: If we just hace IPv6 RLOCs
     *  locator_hash_table: If we have IPv4 & IPv6 RLOCs
     */
    lispd_locator_elt               *v4_locator_hash_table[20]; /* Used to do traffic balancing between RLOCs.*/
    lispd_locator_elt               *v6_locator_hash_table[20]; /* Used to do traffic balancing between RLOCs*/
    lispd_locator_elt               *locator_hash_table[20];
} lispd_mapping_elt;

/*
 * list of mappings.
 */
typedef struct lispd_mappings_list_ {
    lispd_mapping_elt               *identifier;
    struct lispd_mappings_list_     *next;
} lispd_mappings_list;

/****************************************  FUNCTIONS **************************************/

/*
 * Creates a mapping
 */

lispd_mapping_elt *new_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid);

/*
 * Initialize lispd_mapping_elt with default parameters
 */

void init_mapping (lispd_mapping_elt *mapping);

/*
 * Add a locator into the locators list of the mapping.
 */

int add_locator_to_mapping(
        lispd_mapping_elt           *mapping,
        lispd_locator_elt           *locator);

/*
 * Free memory of lispd_mapping_elt.
 */
void free_lispd_mapping_elt(lispd_mapping_elt *identifier);

/*
 * dump mapping
 */
void dump_mapping_entry(
        lispd_mapping_elt       *mapping,
        int                     log_level);


#endif /* LISPD_MAPPING_H_ */
