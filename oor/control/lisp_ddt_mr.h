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

#ifndef LISP_DDT_MR_H_
#define LISP_DDT_MR_H_

#include "oor_ctrl_device.h"
#include "../lib/lisp_site.h"
#include "../liblisp/lisp_mref_mapping.h"
#include "../lib/ddt_map_cache_entry.h"


typedef struct _lisp_ddt_mr {
    oor_ctrl_dev_t super;    /* base "class" */

    /* ddt-mr members */
    mdb_t *mref_cache_db; /* mref_cache_db is filled with ddt_mcache_entry_t */
    mdb_t *pending_requests_db; /* pending_requests_db is filled with ddt_pending_request_t */
    ddt_mcache_entry_t *root_entry; /* the cache entry for root is stored separatedly */
} lisp_ddt_mr_t;

#define NOT_GONE_THROUGH_ROOT                      0
#define GONE_THROUGH_ROOT                          1

typedef struct _ddt_pending_request{
    lisp_addr_t *target_address;
    glist_t *original_requests; /*original_requests is filled with ddt_original_request_t*/
    int gone_through_root;
    int recieved_not_registered;
    ddt_mcache_entry_t *current_cache_entry;
    glist_t *current_delegation_rlocs; /*it is filled with lisp_addr_t, corresponding to
    the referrals of the cache entry currently in use*/
    glist_entry_t *current_rloc; /*used to iterate the former list and keep track of which ones
    have been used*/
    int retry_number;
} ddt_pending_request_t;

typedef struct _ddt_original_request{
    uint64_t nonce;
    lisp_addr_t *source_address;
    glist_t *itr_locs; /*itr_locs is filled with lisp_addr_t*/
} ddt_original_request_t;

typedef struct _timer_pendreq_cycle_argument {
    ddt_pending_request_t *pendreq;
    lisp_ddt_mr_t *mapres;
    lisp_addr_t *local_address;
}timer_pendreq_cycle_argument;

/* DDT-MR interface */

void ddt_mr_dump_root_entry(lisp_ddt_mr_t *dev, int log_level);

int ddt_mr_add_cache_entry(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *entry);
int ddt_mr_add_pending_request(lisp_ddt_mr_t *ddt_mr, ddt_pending_request_t *request);
int ddt_mr_set_root_entry(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *root_entry);


ddt_pending_request_t *ddt_pending_request_init(lisp_addr_t *target_address);

void pending_request_set_new_cache_entry(ddt_pending_request_t *pendreq, ddt_mcache_entry_t *current_cache_entry);

void pending_request_set_root_cache_entry(ddt_pending_request_t *pendreq, lisp_ddt_mr_t *mapres);

void pending_request_add_original(ddt_pending_request_t *pending, ddt_original_request_t *original);


void mref_cache_entry_del(ddt_mcache_entry_t *entry);
static inline lisp_addr_t *
cache_entry_xeid(ddt_mcache_entry_t *entry) {
    return(ddt_mcache_entry_eid(entry));
}
void ddt_pending_request_del(ddt_pending_request_t *request);
void map_resolver_remove_ddt_pending_request(lisp_ddt_mr_t *mapres, ddt_pending_request_t *request);
static inline lisp_addr_t *
pending_request_xeid(ddt_pending_request_t *request) {
    return(request->target_address);
}
void send_negative_mrep_to_original_askers(lisp_ddt_mr_t *mapres, ddt_pending_request_t * pendreq);

#endif /* LISP_DDT_MR_H_ */
