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
#include <lispd_timers.h>

typedef struct _map_cache_db {
    mdb_t *db;
} map_cache_db_t;

map_cache_db_t *mcache_new();
int mcache_add_mapping(map_cache_db_t *, mapping_t *);
int mcache_add_static_mapping(map_cache_db_t *, mapping_t *);
int mcache_remove_mapping(map_cache_db_t *, lisp_addr_t *);
mapping_t *mcache_lookup_mapping(map_cache_db_t *, lisp_addr_t *);
mapping_t *mcache_lookup_mapping_exact(map_cache_db_t *, lisp_addr_t *);
void macache_start_expiration_timer_entry(lisp_ctrl_dev_t *, mcache_entry_t *);


int map_cache_add_entry(map_cache_db_t *, mcache_entry_t *entry);
void map_cache_del_entry(map_cache_db_t *, lisp_addr_t *laddr);
mcache_entry_t *map_cache_lookup_exact(map_cache_db_t *, lisp_addr_t *addr);
mcache_entry_t *map_cache_lookup(map_cache_db_t *, lisp_addr_t *addr);

/* Lookup if there is a no active cache entry with the provided nonce and
 * return it */
mcache_entry_t *lookup_nonce_in_no_active_map_caches(lisp_addr_t *, uint64_t);

void map_cache_dump_db(map_cache_db_t *, int log_level);

#define mcache_foreach_entry(MC, EIT)               \
    mdb_foreach_entry((MC)->db, (EIT))

#define mcache_foreach_active_entry(MC, EIT)        \
    mdb_foreach_entry((MC)->db, (EIT))              \
        if (((mcache_entry_t *)(EIT))->active)

#define mcache_foreach_end                          \
    } mdb_foreach_entry_end

/* ugly .. */
#define mcache_foreach_active_entry_in_ip_eid_db(MC, EID, EIT)  \
    mdb_foreach_entry_in_ip_eid_db((MC)->db, (EID), (EIT))     \
        if ((EIT)->active)

#define mcache_foreach_active_entry_in_ip_eid_db_end  \
    mdb_foreach_entry_in_ip_eid_db_end


#endif /*LISPD_MAP_CACAHE_DB_H_*/
