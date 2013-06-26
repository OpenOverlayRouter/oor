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
#include "lispd_mapping.h"
#include "lispd_nonce.h"
#include "patricia/patricia.h"



/*
 * Initialize databases
 */

void db_init(void);


/*
 * Returns the local data base according ton afi
 */
patricia_tree_t* get_local_db(int afi);

/*
 *  Add a mapping entry to the database.
 */
int add_mapping_to_db(lispd_mapping_elt *mapping);

/*
 * Delete an EID mapping from the data base. We indicate if it is local or not
 */
void del_mapping_entry_from_db(lisp_addr_t eid,
        int prefixlen);

/*
 * lookup_eid_in_db
 *
 * Look up a given eid in the database, returning the
 * lispd_mapping_elt of this EID if it exists or NULL.
 */
lispd_mapping_elt *lookup_eid_in_db(lisp_addr_t eid);

/*
 * lookup_eid_in_db
 *
 *  Look up a given eid in the database, returning the
 * lispd_mapping_elt containing the exact EID if it exists or NULL.
 */
lispd_mapping_elt *lookup_eid_exact_in_db(lisp_addr_t eid_prefix, int eid_prefix_length);


lisp_addr_t *get_main_eid(int afi);

/*
 * Return the number of entries of the database
 */
int num_entries_in_db(patricia_tree_t *database);

/*
 * dump the mapping list of the database
 */
void dump_local_db(int log_level);

#endif /*LISPD_LOCAL_DB_H_*/
