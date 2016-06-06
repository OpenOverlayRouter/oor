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


#ifndef LISP_XTR_H_
#define LISP_XTR_H_

#include "oor_ctrl_device.h"
#include "../defs.h"
#include "../fwd_policies/fwd_policy.h"
#include "../lib/shash.h"


typedef enum tr_type {
    xTR_TYPE,
    RTR_TYPE,
    PITR_TYPE,
    PETR_TYPE
} tr_type_e;

typedef enum {
    PREV_DRAF_VER_4,
    AFTER_DRAFT_VER_4
}nat_version;

typedef struct lisp_xtr {
    oor_ctrl_dev_t super; /* base "class" */

    tr_type_e tr_type;

    /* xtr interface */
    mapping_t *(*lookup_eid_map_cache)(lisp_addr_t *eid);
    mapping_t *(*lookup_eid_local_map_db)(lisp_addr_t *eid);
    int (*add_mapping_to_map_cache)(mapping_t *mapping);
    int (*add_mapping_to_local_map_db)(mapping_t *mapping);

    int map_request_retries;
    int probe_interval;
    int probe_retries;
    int probe_retries_interval;

    mcache_entry_t *petrs;
    glist_t *pitrs; // <lisp_addr_t *>

    /* DATABASES */
    map_cache_db_t *map_cache;
    local_map_db_t *local_mdb;

    /* FWD POLICY */
    fwd_policy_class *fwd_policy;
    void *fwd_policy_dev_parm;

    /* MAP RESOLVERS */
    glist_t *map_resolvers; // <lisp_addr_t *>

    /* MAP SERVERs */
    glist_t *map_servers; // <map_server_elt *>

    /* NAT */
    int nat_aware;
    int nat_status;
    lisp_site_id site_id;
    lisp_xtr_id xtr_id;
    mcache_entry_t *rtrs;

    /* TIMERS */
    oor_timer_t *smr_timer;

    /* MAPPING IFACE TO LOCATORS */
    shash_t *iface_locators_table; /* Key: Iface name, Value: iface_locators */

    /* LOCAL IFACE MAPPING */
    /* in case of RTR can be used for outgoing load balancing */
    map_local_entry_t *all_locs_map;

    oor_encap_t encap_type;
} lisp_xtr_t;

typedef struct map_server_elt_t {
    lisp_addr_t *   address;
    uint8_t         key_type;
    char *          key;
    uint8_t         proxy_reply;
} map_server_elt;

typedef struct _timer_rloc_prob_argument {
    mcache_entry_t *mce;
    locator_t      *locator;
} timer_rloc_probe_argument;

typedef struct _timer_map_req_argument {
    mcache_entry_t  *mce;
    lisp_addr_t     *src_eid;
} timer_map_req_argument;

typedef struct _timer_map_reg_argument {
    map_local_entry_t  *mle;
    map_server_elt     *ms;
} timer_map_reg_argument;

typedef struct _timer_encap_map_reg_argument {
    map_local_entry_t  *mle;
    map_server_elt     *ms;
    locator_t          *src_loct;
    lisp_addr_t        *rtr_rloc;
} timer_encap_map_reg_argument;

typedef struct _timer_inf_req_argument {
    map_local_entry_t *mle;
    locator_t *loct;
    map_server_elt *ms;
}timer_inf_req_argument;


map_server_elt * map_server_elt_new_init(lisp_addr_t *address,uint8_t key_type,
        char *key, uint8_t proxy_reply);
void map_server_elt_del (map_server_elt *map_server);
void map_servers_dump(lisp_xtr_t *, int log_level);

int program_map_register(lisp_xtr_t *xtr);

int tr_mcache_add_mapping(lisp_xtr_t *, mapping_t *);
int tr_mcache_add_static_mapping(lisp_xtr_t *, mapping_t *);
int tr_mcache_remove_entry(lisp_xtr_t *xtr, mcache_entry_t *mce);
mapping_t *tr_mcache_lookup_mapping(lisp_xtr_t *, lisp_addr_t *);
mapping_t *tr_mcache_lookup_mapping_exact(lisp_xtr_t *, lisp_addr_t *);


inline oor_encap_t tr_get_encap_type(lisp_xtr_t *tr);
#endif /* LISP_XTR_H_ */
