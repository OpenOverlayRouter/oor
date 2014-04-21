/*
 * lispd_map_cache_db.h
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
#ifndef LISPD_MAP_CACAHE_DB_H_
#define LISPD_MAP_CACAHE_DB_H_

#include <lispd_map_cache_entry.h>
#include <defs.h>
#include <lispd_types.h>
//#include "lisp_address.h"
//#include "lispd_local_db.h"
#include <lispd_timers.h>

typedef struct _map_cache_db {
    mdb_t *mdb1;
} map_cache_db_t;

extern mdb_t *mdb;

void map_cache_init();


int mcache_add_mapping(mapping_t *mapping);
int mcache_add_static_mapping(mapping_t *mapping);
int mcache_del_mapping(lisp_addr_t *laddr);
mapping_t *mcache_lookup_mapping(lisp_addr_t *laddr);
mapping_t *mcache_lookup_mapping_exact(lisp_addr_t *laddr);

/*
 *  Add a map cache entry to the database.
 */
int map_cache_add_entry(mcache_entry_t *entry);

/*
 * del_map_cache_entry()
 *
 * Delete an EID mapping from the cache
 */
void map_cache_del_entry(lisp_addr_t *laddr);


/*
 * lookup_map_cache_exact()
 *
 * Find an exact match for a prefix/prefixlen if possible
 */
mcache_entry_t *map_cache_lookup_exact(lisp_addr_t *addr);


/*
 * lookup_map_cache()
 *
 * Look up a given eid in the database, returning the
 * lispd_map_cache_entry of this EID if it exists or NULL.
 */
mcache_entry_t *map_cache_lookup(lisp_addr_t *addr);


/*
 * Lookup if there is a no active cache entry with the provided nonce and return it
 */

mcache_entry_t *lookup_nonce_in_no_active_map_caches(lisp_addr_t *eid, uint64_t nonce);


///*
// * Remove the map cache entry from the database and reintroduce it with the new eid.
// * This function is used when the map reply report a prefix that includes the requested prefix
// */
//
//int map_cache_replace_entry(
//        lisp_addr_t                             *new_eid_prefix,
//        lispd_map_cache_entry                   *cache_entry);


void map_cache_dump_db(int log_level);

#define mcache_foreach_entry(eit)   \
    mdb_foreach_entry(mdb, (eit))   \

#define mcache_foreach_active_entry(eit)   \
    mdb_foreach_entry(mdb, (eit))   \
        if (((mcache_entry_t *)(eit))->active)

#define mcache_foreach_end  \
    } mdb_foreach_entry_end

/* ugly .. */
#define mcache_foreach_active_entry_in_ip_eid_db(_eid, _eit)   \
    mdb_foreach_entry_in_ip_eid_db(mdb, (_eid), (_eit))  \
        if (((mcache_entry_t *)(_eit))->active)

#define mcache_foreach_active_entry_in_ip_eid_db_end  \
    mdb_foreach_entry_in_ip_eid_db_end


#endif /*LISPD_MAP_CACAHE_DB_H_*/
