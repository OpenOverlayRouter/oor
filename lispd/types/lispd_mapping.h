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
#include "lispd_address.h"
#include "lispd_remdb.h"



/****************************************  STRUCTURES **************************************/

/*
 * lispd mapping entry.
 */
typedef struct lispd_mapping_elt_ {
    lisp_addr_t                     eid_prefix;
    uint8_t                         eid_prefix_length;
    lisp_iid_t                      iid;
    uint16_t                        locator_count;
    lispd_locators_list             *head_v4_locators_list;
    lispd_locators_list             *head_v6_locators_list;
    void                            *extended_info;
} mapping_t;


/*
 * Used to select the locator to be used for an identifier according to locators' priority and weight.
 *  v4_balancing_locators_vec: If we just have IPv4 RLOCs
 *  v6_balancing_locators_vec: If we just hace IPv6 RLOCs
 *  balancing_locators_vec: If we have IPv4 & IPv6 RLOCs
 *  For each packet, a hash of its tuppla is calculaed. The result of this hash is one position of the array.
 */

typedef struct balancing_locators_vecs_ {
    locator_t               **v4_balancing_locators_vec;
    locator_t               **v6_balancing_locators_vec;
    locator_t               **balancing_locators_vec;
    int v4_locators_vec_length;
    int v6_locators_vec_length;
    int locators_vec_length;
}balancing_locators_vecs;


/*
 * Structure to expand the lispd_mapping_elt used in lispd_map_cache_entry
 */

typedef struct lcl_mapping_extended_info_ {
    balancing_locators_vecs               outgoing_balancing_locators_vecs;
    lispd_locators_list                   *head_not_init_locators_list; //List of locators not initialized: interface without ip
}lcl_mapping_extended_info;

/*
 * Structure to expand the lispd_mapping_elt used in lispd_map_cache_entry
 */
typedef struct rmt_mapping_extended_info_ {
    balancing_locators_vecs               rmt_balancing_locators_vecs;
}rmt_mapping_extended_info;

/*
 * Structure to expand the lispd_mapping_elt to support multicast info AFI
 */

typedef struct mcinfo_mapping_exteded_info_ {
    lispd_remdb_t       *jib;       /* joining information base - the joined downstreams */
    lispd_upstream_t    *upstream;  /* the overlay parent */
} mcinfo_mapping_extended_info;

/****************************************  FUNCTIONS **************************************/

/*
 * Generates a mapping with the local extended info
 */

mapping_t *new_local_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid);

/*
 * Generates a mapping with the remote extended info
 */

mapping_t *new_map_cache_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid);

/*
 * Add a locator into the locators list of the mapping.
 */

int add_locator_to_mapping(
        mapping_t           *mapping,
        locator_t           *locator);

/*
 * This function sort the locator list elt with IP = changed_loc_addr
 */

void sort_locators_list_elt (
        mapping_t   *mapping,
        lisp_addr_t         *changed_loc_addr);

/*
 * Returns the locators with the address passed as a parameter
 */

locator_t *get_locator_from_mapping(
        mapping_t   *mapping,
        lisp_addr_t         *address);

/*
 * Free memory of lispd_mapping_elt.
 */
void free_mapping_elt(mapping_t *mapping, int local);

/*
 * dump mapping
 */
void dump_mapping_entry(
        mapping_t       *mapping,
        int                     log_level);

/*
 * Calculate the vectors used to distribute the load from the priority and weight of the locators of the mapping
 */
int calculate_balancing_vectors (
        mapping_t           *mapping,
        balancing_locators_vecs     *b_locators_vecs);

/*
 * Print balancing locators vector information
 */

void dump_balancing_locators_vec(
        balancing_locators_vecs b_locators_vecs,
        mapping_t *mapping,
        int log_level);






/*
 * Introduce a record information in the packet. This information is extracted from the mapping structure
 * It returns the position to the next position of the packet
 */

uint8_t *mapping_fill_record_in_pkt(mapping_record_hdr_t *rec, mapping_t *mapping, lisp_addr_t *probed_rloc);



/*
 * lispd_mapping_elt functions
 */
inline mapping_t    *mapping_new();
inline mapping_t    *mapping_init(lisp_addr_t *eid);
mapping_t           *mapping_init_local(lisp_addr_t *eid);
mapping_t           *mapping_init_learned(lisp_addr_t *eid, lispd_locators_list *locators);
inline void                 mapping_set_extended_info(mapping_t *mapping, void *extended_info);
inline void                 mapping_set_eid_addr(mapping_t *mapping, lisp_addr_t *addr);
inline void                 mapping_set_eid_plen(mapping_t *mapping, uint8_t plen);
inline lisp_addr_t          *mapping_eid(mapping_t *mapping);
lispd_remdb_t               *mapping_get_jib(mapping_t *mapping);
int                         mapping_add_locators(mapping_t *mapping, lispd_locators_list *locators);
inline uint16_t             mapping_get_locator_count(mapping_t *mapping);
int                         mapping_get_size_in_record(mapping_t *mapping);

//inline void                 mapping_set_iid(lispd_mapping_elt *mapping, uint16_t iid);
//inline uint8_t              get_mapping_eid_plen(lispd_mapping_elt *mapping);
//inline lisp_iid_t           get_mapping_iid(lispd_mapping_elt *mapping, lisp_iid_t iid);

mapping_t           *mapping_init_from_record(mapping_record *record);
void                mapping_write_to_record(mapping_record *record, mapping_t *mapping);
void                mapping_update_locators(mapping_t *mapping, lispd_locators_list *locv4, lispd_locators_list *locv6);

void mapping_del(mapping_t *mapping);
void mapping_del_local(mapping_t *mapping);
void mapping_del_remote(mapping_t *mapping);

#endif /* LISPD_MAPPING_H_ */
