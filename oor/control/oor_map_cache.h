/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef OOR_MAP_CACAHE_DB_H_
#define OOR_MAP_CACAHE_DB_H_

#include "../defs.h"
#include "../lib/map_cache_entry.h"
#include "../lib/mapping_db.h"
#include "../liblisp/liblisp.h"

typedef struct map_cache_db {
    mdb_t *db;
} map_cache_db_t;

map_cache_db_t *mcache_new();
void mcache_del(map_cache_db_t *mcdb);


int mcache_add_entry(map_cache_db_t *, lisp_addr_t *key, mcache_entry_t *entry);
void *mcache_remove_entry(map_cache_db_t *, lisp_addr_t *key);
void map_cache_del_entry(map_cache_db_t *, lisp_addr_t *laddr);
mcache_entry_t *mcache_lookup_exact(map_cache_db_t *, lisp_addr_t *addr);
mcache_entry_t *mcache_lookup(map_cache_db_t *, lisp_addr_t *addr);

void mcache_dump_db(map_cache_db_t *, int log_level);

#define mcache_foreach_entry(MC, EIT)               \
    mdb_foreach_entry((MC)->db, (EIT)) {

#define mcache_foreach_active_entry(MC, EIT)        \
    mdb_foreach_entry((MC)->db, (EIT))              \
        if (((mcache_entry_t *)(EIT))->active){

#define mcache_foreach_not_active_entry(MC, EIT)        \
    mdb_foreach_entry((MC)->db, (EIT))              \
        if (((mcache_entry_t *)(EIT))->active == FALSE){

#define mcache_foreach_end          \
        }                           \
    mdb_foreach_entry_end

/* ugly .. */
#define mcache_foreach_active_entry_in_ip_eid_db(_MC_, _EID_, _EIT_)  \
    mdb_foreach_entry_in_ip_eid_db((_MC_)->db, (_EID_), (_EIT_)){     \
        if ((_EIT_)->active) {

#define mcache_foreach_active_entry_in_ip_eid_db_end  \
        }                                             \
    }mdb_foreach_entry_in_ip_eid_db_end


#endif /*OOR_MAP_CACAHE_DB_H_*/
