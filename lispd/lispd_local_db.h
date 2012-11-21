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
#ifndef LISPD_LOCAL_DB_H_
#define LISPD_LOCAL_DB_H_

#include "lispd.h"
#include "lispd_nonce.h"


/*
 * Locator information
 */
typedef struct lispd_locator_elt_ {
    lisp_addr_t                 *locator_addr;
    uint8_t                     *state;    /* UP , DOWN */
    uint8_t                     locator_type:2;
    uint8_t                     priority;
    uint8_t                     weight;
    uint8_t                     mpriority;
    uint8_t                     mweight;
    uint32_t                    data_packets_in;
    uint32_t                    data_packets_out;
    nonces_list          		*rloc_probing_nonces;
}lispd_locator_elt;


/*
 * Initialize databases
 */

int db_init(void);


/*
 * Returns the local data base according ton afi
 */
patricia_tree_t* get_local_db(int afi);

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
} lispd_identifier_elt;

/*
 * list of identifiers.
 */
typedef struct lispd_identifiers_list_ {
	lispd_identifier_elt        	*identifier;
    struct lispd_identifiers_list_ 	*next;
} lispd_identifiers_list;



/*
 * Initialize lispd_identifier_elt with default parameters
 */

void init_identifier (lispd_identifier_elt *identifier);


/*
 * Creates an identifier and add it into the database
 */

lispd_identifier_elt *new_identifier(lisp_addr_t    eid_prefix,
        uint8_t                                     eid_prefix_length,
        int                                         iid);


/*
 * Generets a locator element and add it to locators list.
 * The locator address and the state must be initialized before calling this function.
 */

lispd_locator_elt   *new_locator (
		lispd_identifier_elt 		*identifier,
		lisp_addr_t                 *locator_addr,
		uint8_t                     *state,    /* UP , DOWN */
		uint8_t                     locator_type,
		uint8_t                     priority,
		uint8_t                     weight,
		uint8_t                     mpriority,
		uint8_t                     mweight
		);


/*
 * del_identifier_entry()
 *
 * Delete an EID mapping from the data base
 */
void del_identifier_entry(lisp_addr_t eid,
        int prefixlen);


/*
 * Free memory of lispd_locator_list
 */
void free_locator_list(lispd_locators_list *list);

/*
 * Free memory of lispd_identifier_elt
 */
void free_lispd_identifier_elt(lispd_identifier_elt *identifier);

/*
 * lookup_eid_in_db
 *
 * Look up a given eid in the database, returning true and
 * filling in the entry pointer if found, or false if not found.
 */
int lookup_eid_in_db(lisp_addr_t eid, lispd_identifier_elt **identifier);

/*
 * lookup_eid_in_db
 *
 * Look up a given ipv4 eid in the database, returning true and
 * filling in the entry pointer if found the exact entry, or false if not found.
 */
int lookup_eid_exact_in_db(lisp_addr_t eid_prefix, int eid_prefix_length, lispd_identifier_elt **identifier);

/*
 * dump local identifier list
 */
void dump_local_eids();


lisp_addr_t get_main_eid(int afi);

#endif /*LISPD_LOCAL_DB_H_*/
