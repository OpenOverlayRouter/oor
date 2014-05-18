/*
 * lisp_local_db.h
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
 *    Florin Coras      <fcoras@ac.upc.edu>
 */

#ifndef LISP_LOCAL_DB_H_
#define LISP_LOCAL_DB_H_

#include <defs.h>
#include <liblisp.h>
#include <mapping_db.h>


typedef struct local_map_db_t_ {
    mdb_t *db;
} local_map_db_t;


local_map_db_t *local_map_db_new();
void local_map_db_del(local_map_db_t *lmdb);
int local_map_db_add_mapping(local_map_db_t *, mapping_t *);
void local_map_db_del_mapping(local_map_db_t *, lisp_addr_t *);
mapping_t *local_map_db_lookup_eid(local_map_db_t *, lisp_addr_t *);
mapping_t *local_map_db_lookup_eid_exact(local_map_db_t *, lisp_addr_t *);


lisp_addr_t *local_map_db_get_main_eid(local_map_db_t *, int );
int local_map_db_num_ip_eids(local_map_db_t *, int );
void local_map_db_dump(local_map_db_t *, int );

inline int local_map_db_n_entries(local_map_db_t *);



#define local_map_db_foreach_entry(LMDB, EIT)           \
    mdb_foreach_entry((LMDB)->db, (EIT)) {              \
        if ((EIT))

#define local_map_db_foreach_end                        \
    } mdb_foreach_entry_end

#define local_map_db_foreach_ip_entry(LMDB, EIT)        \
    mdb_foreach_ip_entry((LMDB)->db, (EIT)) {           \
        if ((EIT))

#define local_map_db_foreach_ip_end                     \
    } mdb_foreach_ip_entry_end

#endif /*LISP_LOCAL_DB_H_*/
