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
    void                            *extended_info;
} lispd_mapping_elt;


/*
 * Used to select the locator to be used for an identifier according to locators' priority and weight.
 *  v4_balancing_locators_vec: If we just have IPv4 RLOCs
 *  v6_balancing_locators_vec: If we just hace IPv6 RLOCs
 *  balancing_locators_vec: If we have IPv4 & IPv6 RLOCs
 *  For each packet, a hash of its tuppla is calculaed. The result of this hash is one position of the array.
 */

typedef struct balancing_locators_vecs_ {
    lispd_locator_elt               **v4_balancing_locators_vec;
    lispd_locator_elt               **v6_balancing_locators_vec;
    lispd_locator_elt               **balancing_locators_vec;
    int v4_locators_vec_length;
    int v6_locators_vec_length;
    int locators_vec_length;
}balancing_locators_vecs;


/*
 * Structure to expand the lispd_mapping_elt used in lispd_map_cache_entry
 */

typedef struct lcl_mapping_extended_info_ {
    balancing_locators_vecs               outgoing_balancing_locators_vecs;
}lcl_mapping_extended_info;

/*
 * Structure to expand the lispd_mapping_elt used in lispd_map_cache_entry
 */
typedef struct rmt_mapping_extended_info_ {
    balancing_locators_vecs               rmt_balancing_locators_vecs;
}rmt_mapping_extended_info;



/*
 * list of mappings.
 */
typedef struct lispd_mappings_list_ {
    lispd_mapping_elt               *mapping;
    struct lispd_mappings_list_     *next;
} lispd_mappings_list;

/****************************************  FUNCTIONS **************************************/

/*
 * Generates a mapping with the local extended info
 */

lispd_mapping_elt *new_local_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid);

/*
 * Generates a mapping with the remote extended info
 */

lispd_mapping_elt *new_map_cache_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid);

/*
 * Add a locator into the locators list of the mapping.
 */

int add_locator_to_mapping(
        lispd_mapping_elt           *mapping,
        lispd_locator_elt           *locator);

/*
 * Free memory of lispd_mapping_elt.
 */
void free_mapping_elt(lispd_mapping_elt *mapping, int local);

/*
 * dump mapping
 */
void dump_mapping_entry(
        lispd_mapping_elt       *mapping,
        int                     log_level);

/*
 * Calculate the vectors used to distribute the load from the priority and weight of the locators of the mapping
 */
int calculate_balancing_vectors (
        lispd_mapping_elt           *mapping,
        balancing_locators_vecs     *b_locators_vecs);

/*
 * Print balancing locators vector information
 */

void dump_balancing_locators_vec(
        balancing_locators_vecs b_locators_vecs,
        lispd_mapping_elt *mapping,
        int log_level);

#endif /* LISPD_MAPPING_H_ */
