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

#ifndef DDT_MAP_CACHE_ENTRY_H_
#define DDT_MAP_CACHE_ENTRY_H_

#include "timers.h"
#include "../liblisp/lisp_mref_mapping.h"

/*
 *  ddt-map-cache entry types (how_learned)
 */

typedef enum ddt_mce_type {
    DDT_MCE_= 0,
    DDT_MCE_DYNAMIC,
    DDT_MCE_STATIC
} ddt_mce_type_e;

/*
 *  map-cache entry activated  (received map reply)
 */

typedef void (*routing_info_del_fct)(void *);

typedef struct ddt_map_cache_entry_ {
    uint8_t how_learned;

    mref_mapping_t *mapping;

    /* mapping validity information */

    time_t timestamp;

} ddt_mcache_entry_t;

ddt_mcache_entry_t *ddt_mcache_entry_new();
void ddt_mcache_entry_init(ddt_mcache_entry_t *, mref_mapping_t *);
void ddt_mcache_entry_init_static(ddt_mcache_entry_t *, mref_mapping_t *);


void ddt_mcache_entry_del(ddt_mcache_entry_t *entry);
void ddt_map_cache_entry_dump(ddt_mcache_entry_t *entry, int log_level);

static inline mref_mapping_t *ddt_mcache_entry_mapping(ddt_mcache_entry_t*);
static inline void ddt_mcache_entry_set_mapping(ddt_mcache_entry_t* , mref_mapping_t *);
uint8_t ddt_mcache_has_referrals(ddt_mcache_entry_t *m);

lisp_addr_t *ddt_mcache_entry_eid(ddt_mcache_entry_t *mce);


static inline mref_mapping_t *
ddt_mcache_entry_mapping(ddt_mcache_entry_t* mce)
{
    return (mce->mapping);
}

static inline void
ddt_mcache_entry_set_mapping(ddt_mcache_entry_t* mce,
        mref_mapping_t *m)
{
    mce->mapping = m;
}

static inline int
ddt_mcache_entry_type(ddt_mcache_entry_t *m){
    return(m->mapping->action);
}


#endif /* DDT_MAP_CACHE_ENTRY_H_ */
