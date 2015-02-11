/*
 * map_cache_entry.h
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

#ifndef MAP_CACHE_ENTRY_H_
#define MAP_CACHE_ENTRY_H_

#include "timers.h"
#include "../liblisp/lisp_mapping.h"

/*
 *  map-cache entry types (how_learned)
 */

#define STATIC_MAP_CACHE_ENTRY          0
#define DYNAMIC_MAP_CACHE_ENTRY         1

typedef enum mce_type {
    MCE_STATIC = 0,
    MCE_DYNAMIC
} mce_type_e;

/*
 *  map-cache entry activated  (received map reply)
 */
#define NOT_ACTIVE                      0
#define ACTIVE                          1

typedef struct map_cache_entry_ {
    uint8_t how_learned;

    mapping_t *mapping;

    /* mapping validity information */

    /* TRUE if we have received a map reply for this entry */
    uint8_t active;
    uint8_t active_witin_period;
    time_t timestamp;

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
void map_cache_entry_to_char(mcache_entry_t *entry, int log_level);

static inline mapping_t *mcache_entry_mapping(mcache_entry_t*);
static inline void mcache_entry_set_mapping(mcache_entry_t* , mapping_t *);
static inline nonces_list_t *mcache_entry_nonces(mcache_entry_t *);
static inline uint8_t mcache_entry_active(mcache_entry_t *);
static inline void mcache_entry_set_active(mcache_entry_t *, int);
static inline void mcache_entry_init_nonces(mcache_entry_t *);
static inline void mcache_entry_destroy_nonces(mcache_entry_t *);
static inline void mcache_entry_set_requester(mcache_entry_t *,
        lisp_addr_t *);
static inline lisp_addr_t *mcache_entry_requester(mcache_entry_t *);

/* timer accessors */
static inline lmtimer_t *mcache_entry_req_retry_timer(mcache_entry_t *);
static inline lmtimer_t *mcache_entry_init_req_retry_timer(mcache_entry_t *);
static inline lmtimer_t *mcache_entry_smr_inv_timer(mcache_entry_t *);
static inline void  mcache_entry_stop_smr_inv_timer(mcache_entry_t *);
static inline lmtimer_t *mcache_entry_init_smr_inv_timer(mcache_entry_t *);
static inline void mcache_entry_requester_del(mcache_entry_t *m);

static inline mapping_t *mcache_entry_mapping(mcache_entry_t* mce)
{
    return (mce->mapping);
}

static inline void mcache_entry_set_mapping(mcache_entry_t* mce,
        mapping_t *m)
{
    mce->mapping = m;
}

static inline nonces_list_t *mcache_entry_nonces(mcache_entry_t *mce)
{
    return (mce->nonces);
}

static inline void mcache_entry_init_nonces(mcache_entry_t *mce)
{
    if (mce->nonces) {
        free(mce->nonces);
    }
    mce->nonces = nonces_list_new();
}

static inline uint8_t mcache_entry_active(mcache_entry_t *mce)
{
    return (mce->active);
}

static inline void mcache_entry_set_active(mcache_entry_t *mce, int state)
{
    mce->active = state;
}

static inline void mcache_entry_destroy_nonces(mcache_entry_t *mce)
{
    free(mce->nonces);
    mce->nonces = NULL;
}

static inline void mcache_entry_set_requester(mcache_entry_t *m,
        lisp_addr_t *addr)
{
    if (m->requester) {
        lisp_addr_del(m->requester);
    }
    m->requester = addr;
}

static inline void mcache_entry_requester_del(mcache_entry_t *m)
{
    lisp_addr_del(m->requester);
}

static inline lisp_addr_t *mcache_entry_requester(mcache_entry_t *m)
{
    return(m->requester);
}

static inline lmtimer_t *mcache_entry_req_retry_timer(mcache_entry_t *m)
{
    return(m->request_retry_timer);
}

static inline void mcache_entry_stop_req_retry_timer(mcache_entry_t *m)
{
    lmtimer_stop(m->request_retry_timer);
    m->request_retry_timer = NULL;
}

static inline lmtimer_t *mcache_entry_init_req_retry_timer(mcache_entry_t *m)
{
    if (m->request_retry_timer) {
        mcache_entry_stop_req_retry_timer(m);
    }
    m->request_retry_timer = lmtimer_create(MAP_REQUEST_RETRY_TIMER);
    return(m->request_retry_timer);
}


static inline lmtimer_t *mcache_entry_smr_inv_timer(mcache_entry_t *m)
{
    return(m->smr_inv_timer);
}

static inline void  mcache_entry_stop_smr_inv_timer(mcache_entry_t *m)
{
    lmtimer_stop(m->smr_inv_timer);
    m->smr_inv_timer = NULL;
}

static inline lmtimer_t *mcache_entry_init_smr_inv_timer(mcache_entry_t *m)
{
    if (m->smr_inv_timer) {
        mcache_entry_stop_smr_inv_timer(m);
    }
    m->smr_inv_timer = lmtimer_create(SMR_INV_RETRY_TIMER);
    return(m->smr_inv_timer);
}


#endif /* MAP_CACHE_ENTRY_H_ */
