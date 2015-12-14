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

#ifndef OOR_LOCAL_DB_H_
#define OOR_LOCAL_DB_H_

#include "../defs.h"
#include "../liblisp/liblisp.h"
#include "../lib/map_local_entry.h"
#include "../lib/mapping_db.h"



typedef struct local_map_db_t_ {
    mdb_t *db;
} local_map_db_t;


local_map_db_t *local_map_db_new();
void local_map_db_del(local_map_db_t *lmdb);
int local_map_db_add_entry(local_map_db_t *, map_local_entry_t *);
void local_map_db_del_entry(local_map_db_t *, lisp_addr_t *);
map_local_entry_t *local_map_db_lookup_eid(local_map_db_t *, lisp_addr_t *);
map_local_entry_t *local_map_db_lookup_eid_exact(local_map_db_t *, lisp_addr_t *);


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

#endif /*OOR_LOCAL_DB_H_*/
