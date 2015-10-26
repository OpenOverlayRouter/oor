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

#ifndef MAP_CACHE_ENTRY_H_
#define MAP_CACHE_ENTRY_H_

#include "timers.h"
#include "../liblisp/lisp_mapping.h"

/*
 *  map-cache entry types (how_learned)
 */

typedef enum mce_type {
    MCE_= 0,
    MCE_DYNAMIC,
    MCE_STATIC
} mce_type_e;

/*
 *  map-cache entry activated  (received map reply)
 */
#define NOT_ACTIVE                      0
#define ACTIVE                          1

typedef void (*routing_info_del_fct)(void *);

typedef struct map_cache_entry_ {
    uint8_t how_learned;

    mapping_t *mapping;

    /* mapping validity information */

    /* TRUE if we have received a map reply for this entry */
    uint8_t active;
    uint8_t active_witin_period;
    time_t timestamp;

    /* Routing info */
    void *                  routing_info;
    routing_info_del_fct    routing_inf_del;

    /* timers */
    lmtimer_t *expiry_cache_timer;
    lmtimer_t *request_retry_timer;
    lmtimer_t *smr_inv_timer;

    nonces_list_t *nonces;

    /* EID that requested the mapping. Helps with timers */
    lisp_addr_t *requester;
} mcache_entry_t;

mcache_entry_t *mcache_entry_new();
void mcache_entry_init(mcache_entry_t *, mapping_t *);
void mcache_entry_init_static(mcache_entry_t *, mapping_t *);


void mcache_entry_del(mcache_entry_t *entry);
void map_cache_entry_dump(mcache_entry_t *entry, int log_level);

static inline mapping_t *mcache_entry_mapping(mcache_entry_t*);
static inline void mcache_entry_set_mapping(mcache_entry_t* , mapping_t *);
static inline nonces_list_t *mcache_entry_nonces(mcache_entry_t *);
static inline uint8_t mcache_entry_active(mcache_entry_t *);
static inline void mcache_entry_set_active(mcache_entry_t *, int);
inline uint8_t mcache_has_locators(mcache_entry_t *m);
static inline void mcache_entry_init_nonces(mcache_entry_t *);
static inline void mcache_entry_destroy_nonces(mcache_entry_t *);
static inline void mcache_entry_set_requester(mcache_entry_t *,
        lisp_addr_t *);
static inline lisp_addr_t *mcache_entry_requester(mcache_entry_t *);
static inline void *mcache_entry_routing_info(mcache_entry_t *);
static inline void mcache_entry_set_routing_info(mcache_entry_t *, void *,
        routing_info_del_fct);

/* timer accessors */
static inline lmtimer_t *mcache_entry_req_retry_timer(mcache_entry_t *);
inline void mcache_entry_stop_req_retry_timer(mcache_entry_t *m);
inline lmtimer_t *mcache_entry_init_req_retry_timer(mcache_entry_t *);
static inline lmtimer_t *mcache_entry_smr_inv_timer(mcache_entry_t *);
inline void  mcache_entry_stop_smr_inv_timer(mcache_entry_t *);
inline lmtimer_t *mcache_entry_init_smr_inv_timer(mcache_entry_t *);
static inline void mcache_entry_requester_del(mcache_entry_t *m);


static inline mapping_t *
mcache_entry_mapping(mcache_entry_t* mce)
{
    return (mce->mapping);
}

static inline void
mcache_entry_set_mapping(mcache_entry_t* mce,
        mapping_t *m)
{
    mce->mapping = m;
}

static inline nonces_list_t *
mcache_entry_nonces(mcache_entry_t *mce)
{
    return (mce->nonces);
}

static inline void
mcache_entry_init_nonces(mcache_entry_t *mce)
{
    if (mce->nonces) {
        free(mce->nonces);
    }
    mce->nonces = nonces_list_new();
}

static inline uint8_t
mcache_entry_active(mcache_entry_t *mce)
{
    return (mce->active);
}

static inline void
mcache_entry_set_active(mcache_entry_t *mce, int state)
{
    mce->active = state;
}

static inline void
mcache_entry_destroy_nonces(mcache_entry_t *mce)
{
    free(mce->nonces);
    mce->nonces = NULL;
}

static inline void
mcache_entry_set_requester(mcache_entry_t *m,
        lisp_addr_t *addr)
{
    if (m->requester) {
        lisp_addr_del(m->requester);
    }
    m->requester = addr;
}

static inline void
mcache_entry_requester_del(mcache_entry_t *m)
{
    lisp_addr_del(m->requester);
}

static inline lisp_addr_t *
mcache_entry_requester(mcache_entry_t *m)
{
    return(m->requester);
}

static inline void *
mcache_entry_routing_info(mcache_entry_t *m)
{
    return (m->routing_info);
}

static inline void
mcache_entry_set_routing_info(mcache_entry_t *m, void *routing_inf, routing_info_del_fct del_fct)
{
    m->routing_info = routing_inf;
    m->routing_inf_del = del_fct;
}

static inline lmtimer_t *
mcache_entry_req_retry_timer(mcache_entry_t *m)
{
    return(m->request_retry_timer);
}


static inline lmtimer_t *
mcache_entry_smr_inv_timer(mcache_entry_t *m)
{
    return(m->smr_inv_timer);
}

#endif /* MAP_CACHE_ENTRY_H_ */
