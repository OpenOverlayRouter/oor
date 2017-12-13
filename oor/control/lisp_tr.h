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


#ifndef OOR_CONTROL_LISP_TR_H_
#define OOR_CONTROL_LISP_TR_H_

#include "oor_ctrl_device.h"
#include "oor_map_cache.h"
#include "../defs.h"
#include "../fwd_policies/fwd_policy.h"
#include "../lib/shash.h"

typedef struct lisp_tr {
    /* xtr interface */
    mapping_t *(*lookup_eid_map_cache)(lisp_addr_t *eid);

    int map_request_retries;
    int probe_interval;
    int probe_retries;
    int probe_retries_interval;

    /* DATABASES */
    map_cache_db_t *map_cache;

    /* FWD POLICY */
    fwd_policy_class *fwd_policy;
    void *fwd_policy_dev_parm;

    /* MAP RESOLVERS */
    glist_t *map_resolvers; // <lisp_addr_t *>

    /* MAPPING IFACE TO LOCATORS */
    shash_t *iface_locators_table; /* Key: Iface name, Value: iface_locators */

    oor_encap_t encap_type;

} lisp_tr_t;


/* Auxiliar structure used to obtain oor_ctrl_dev_t
 * from lisp_tr_t. All tunnel router nodes start with this structure*/
typedef struct tr_abstract_device_ {
    oor_ctrl_dev_t super; /* base "class" ,  Don't change order*/
    lisp_tr_t tr; /* Don't change order */
}tr_abstract_device;

typedef struct _timer_rloc_prob_argument {
    mcache_entry_t *mce;
    locator_t      *locator;
} timer_rloc_probe_argument;

typedef struct _timer_map_req_argument {
    mcache_entry_t  *mce;
    lisp_addr_t     *src_eid;
} timer_map_req_argument;


static inline int tr_map_request_retries(lisp_tr_t *tr){return (tr->map_request_retries);}
static inline int tr_probe_interval(lisp_tr_t *tr){return (tr->probe_interval);}
static inline int tr_probe_retries(lisp_tr_t *tr){return (tr->probe_retries);}
static inline int tr_probe_retries_interval(lisp_tr_t *tr){return (tr->probe_retries_interval);}
static inline map_cache_db_t *tr_map_cache_db(lisp_tr_t *tr){return (tr->map_cache);}
static inline glist_t * tr_map_resolvers(lisp_tr_t *tr){return (tr->map_resolvers);}
static inline oor_encap_t tr_encap_type(lisp_tr_t *tr){return (tr->encap_type);}

/*****************************************************************************/
int lisp_tr_init(lisp_tr_t *tr);
void lisp_tr_uninit(lisp_tr_t *tr);
tr_abstract_device * lisp_tr_abstract_cast(oor_ctrl_dev_t *ctrl_dev);
/*************************** PROCESS MESSAGES ********************************/
int tr_recv_map_reply(lisp_tr_t *tr, lbuf_t *buf, uconn_t *udp_con);
int tr_reply_to_smr(lisp_tr_t *tr, lisp_addr_t *src_eid, lisp_addr_t *req_eid);
int tr_build_and_send_encap_map_request(lisp_tr_t *tr, lisp_addr_t *seid,
        mcache_entry_t *mce, uint64_t nonce);
int tr_build_and_send_mreq_probe(lisp_tr_t *tr, mapping_t *map, locator_t *loc, uint64_t nonce);

/**************************** LOGICAL PROCESSES ******************************/
/************************** Map Cache Expiration *****************************/

int tr_mc_entry_expiration_timer_cb(oor_timer_t *timer);
void tr_mc_entry_program_expiration_timer(lisp_tr_t *tr, mcache_entry_t *mce);
void tr_mc_entry_program_expiration_timer2(lisp_tr_t *tr, mcache_entry_t *mce, int time);

/**************************** SMR invoked timer  *****************************/

int tr_smr_invoked_map_request_cb(oor_timer_t *timer);

/***************************** RLOC Probing **********************************/

/* Program RLOC probing for each locator of the mapping */
void tr_program_mce_rloc_probing(lisp_tr_t *tr, mcache_entry_t *mce);
void tr_program_rloc_probing(lisp_tr_t *tr, mcache_entry_t *mce, locator_t *loc, int time);
int tr_rloc_probing_cb(oor_timer_t *timer);
int handle_locator_probe_reply(lisp_tr_t *tr, mcache_entry_t *mce,
        lisp_addr_t *probed_addr);

/*************************** Map Cache miss **********************************/

int handle_map_cache_miss(lisp_tr_t *tr, lisp_addr_t *requested_eid,
        lisp_addr_t *src_eid);
int send_map_request_retry_cb(oor_timer_t *timer);

/******************************* TIMERS **************************************/
/*********************** Map Cache Expiration timer  *************************/

timer_rloc_probe_argument * timer_rloc_probe_argument_new_init(mcache_entry_t *mce,
        locator_t *locator);
void timer_rloc_probe_argument_free(timer_rloc_probe_argument *timer_arg);
timer_map_req_argument * timer_map_req_arg_new_init(mcache_entry_t *mce,lisp_addr_t *src_eid);
void timer_map_req_arg_free(timer_map_req_argument * timer_arg);

/***************************  Map cache functions ****************************/

mcache_entry_t *tr_mcache_add_mapping(lisp_tr_t *tr, mapping_t *m, mce_type_e how_learned, uint8_t is_active);
int tr_mcache_remove_entry(lisp_tr_t *tr, mcache_entry_t *mce);
int tr_update_mcache_entry(lisp_tr_t *tr, mapping_t *recv_map);
void tr_mcache_entry_program_timers(lisp_tr_t *tr, mcache_entry_t *mce);

/*****************************************************************************/

mcache_entry_t * get_proxy_etrs_for_afi(lisp_tr_t *tr, int afi);
lisp_addr_t * get_map_resolver(lisp_tr_t *tr);




#endif /* OOR_CONTROL_LISP_TR_H_ */
