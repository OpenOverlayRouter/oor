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
 */
#ifndef LISPD_MAP_CACAHE_DB_H_
#define LISPD_MAP_CACAHE_DB_H_


#include "lispd.h"
#include "lispd_local_db.h"
#include "lispd_map_cache.h"
#include "lispd_timers.h"
#include "patricia/patricia.h"


/*
 * create database
 */
void map_cache_init();

/*
 * Return map cache data base
 */
patricia_tree_t* get_map_cache_db(int afi);

/*
 *  Add a map cache entry to the database.
 */
int add_map_cache_entry_to_db(lispd_map_cache_entry *entry);

/*
 * del_map_cache_entry()
 *
 * Delete an EID mapping from the cache
 */
void del_map_cache_entry_from_db(lisp_addr_t eid, int prefixlen);


/*
 * lookup_map_cache_exact()
 *
 * Find an exact match for a prefix/prefixlen if possible
 */
lispd_map_cache_entry *lookup_map_cache_exact(
        lisp_addr_t             eid,
        int                     prefixlen);


/*
 * lookup_map_cache()
 *
 * Look up a given eid in the database, returning the
 * lispd_map_cache_entry of this EID if it exists or NULL.
 */
lispd_map_cache_entry *lookup_map_cache(lisp_addr_t eid);


/*
 * Lookup if there is a no active cache entry with the provided nonce and return it
 */

lispd_map_cache_entry *lookup_nonce_in_no_active_map_caches(int eid_afi, uint64_t nonce);


/*
 * Remove the map cache entry from the database and reintroduce it with the new eid.
 * This function is used when the map reply report a prefix that includes the requested prefix
 */

int change_map_cache_prefix_in_db(lisp_addr_t         new_eid_prefix,
        int                                     new_eid_prefix_length,
        lispd_map_cache_entry                   *cache_entry);

void map_cache_entry_expiration(timer *t, void *arg);


void dump_map_cache_db(int log_level);


#endif /*LISPD_MAP_CACAHE_DB_H_*/
