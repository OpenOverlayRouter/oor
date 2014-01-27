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

#include <defs.h>
#include <lispd_types.h>
#include <lispd_mdb.h>
//#include "lispd_mapping.h"
//#include "lispd_nonce.h"
//#include <patricia/patricia.h>


mdb_t *local_mdb;

/*
 * Initialize databases
 */

void local_map_db_init(void);


/*
 * Returns the local data base according ton afi
 */
patricia_tree_t* get_local_db(int afi);

/*
 *  Add a mapping entry to the database.
 */
int local_map_db_add_mapping(lispd_mapping_elt *mapping);

/*
 * Delete an EID mapping from the data base. We indicate if it is local or not
 */
void local_map_db_del_mapping(lisp_addr_t *eid);

/*
 * lookup_eid_in_db
 *
 * Look up a given eid in the database, returning the
 * lispd_mapping_elt of this EID if it exists or NULL.
 */
lispd_mapping_elt *local_map_db_lookup_eid(lisp_addr_t *eid);

/*
 * lookup_eid_in_db
 *
 *  Look up a given eid in the database, returning the
 * lispd_mapping_elt containing the exact EID if it exists or NULL.
 */
lispd_mapping_elt *local_map_db_lookup_eid_exact(lisp_addr_t *eid_prefix);


lisp_addr_t *local_map_db_get_main_eid(int afi);

/*
 * Return the number of IP entries of the given afi in the database
 */
int local_map_db_num_ip_eids(int afi);

/*
 * dump the mapping list of the database
 */
void local_map_db_dump(int log_level);



#define local_map_db_foreach_entry(eit)   \
    mdb_foreach_entry(local_mdb, (eit)) {   \
        if (eit)

#define local_map_db_foreach_end  \
    } mdb_foreach_entry_end

#endif /*LISPD_LOCAL_DB_H_*/
