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
#include "lispd_timers.h"


/*
 * Map cache entry
 */
typedef struct lispd_map_cache_entry_ {
    lispd_identifier_elt        *identifier;
    uint8_t                     how_learned:2;
    uint8_t                     actions:2;
    uint8_t                     active:1;   /* TRUE if we have received a map reply for this entry */
    uint8_t                     active_witin_period:1;
    uint8_t                     probe_left; /* Counter to indicate number of RLOCs that has not been probed /put status down
                                             * in this period of probe*/
    uint16_t                    ttl;
    uint64_t                    timestamp;
    timer                       *expiry_cache_timer;
    timer                       *probe_timer;
    timer                       *request_retry_timer;
    timer                       *smr_timer;
    nonces_list                 *nonces;
}lispd_map_cache_entry;


/*
 * create_tables
 */
void map_cache_init();

/*
 * Return map cache data base
 */
patricia_tree_t* get_map_cache_db(int afi);

/*
 * Create a map cache entry and save it in the database
 */

lispd_map_cache_entry *new_map_cache_entry (lisp_addr_t eid_prefix, int eid_prefix_length, int how_learned, uint16_t ttl);

/*
 * del_eid_cache_entry()
 *
 * Delete an EID mapping from the cache
 */
void del_eid_cache_entry(lisp_addr_t eid, int prefixlen);


/*
 * lookup_eid_cache_exact()
 *
 * Find an exact match for a prefix/prefixlen if possible
 */
int lookup_eid_cache_exact(lisp_addr_t eid, int prefixlen, lispd_map_cache_entry **entry);


/*
 * lookup_eid_cache_v4()
 *
 * Look up a given ipv4 eid in the cache, returning true and
 * filling in the entry pointer if found, or false if not found.
 */
int lookup_eid_cache(lisp_addr_t eid, lispd_map_cache_entry **entry);


/*
 * Lookup if there is a no active cache entry with the provided nonce and return it
 */

lispd_map_cache_entry *lookup_nonce_in_no_active_map_caches(int eid_afi, uint64_t nonce);


/*
 * Remove the map cache entry from the database and reintroduce it with the new eid.
 * This function is used when the map reply report a prefix that includes the requested prefix
 */

int change_eid_prefix_in_db(lisp_addr_t         new_eid_prefix,
        int                                     new_eid_prefix_length,
        lispd_map_cache_entry                   *cache_entry);

void eid_entry_expiration(timer *t, void *arg);


void dump_map_cache();


#endif /*LISPD_MAP_CACAHE_DB_H_*/
