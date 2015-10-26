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

#ifndef LISP_LOCATOR_H_
#define LISP_LOCATOR_H_

#include "lisp_address.h"
#include "lisp_nonce.h"
#include "../lib/util.h"
#include "../lib/timers.h"

/* locator_types */
#define STATIC_LOCATOR                  0
#define DYNAMIC_LOCATOR                 1
#define PETR_LOCATOR                    2
#define LOCAL_LOCATOR                   3

#define MAX_PRIORITY 0
#define MIN_PRIORITY 254
#define UNUSED_RLOC_PRIORITY 255
#define MIN_WEIGHT 0
#define MAX_WEIGHT 255

typedef struct locator {
    lisp_addr_t *addr;

    /* UP , DOWN */
    uint8_t state;
    uint8_t type;
    uint8_t priority;
    uint8_t weight;
    uint8_t mpriority;
    uint8_t mweight;

    uint32_t data_packets_in;
    uint32_t data_packets_out;
    void *extended_info;
} locator_t;

typedef struct rtr_locator {
    lisp_addr_t address;
    uint8_t state; /* UP , DOWN */
    uint32_t latency;
} rtr_locator_t;

typedef struct rtr_locators_list {
    rtr_locator_t *locator;
    struct rtr_locators_list *next;
} rtr_locators_list_t;

typedef struct lcl_locator_extended_info {
    rtr_locators_list_t *rtr_locators_list;
} lcl_locator_extended_info_t;

/* Structure to expand lispd_locator_elt for remote locators */
typedef struct rmt_locator_extended_info {
    nonces_list_t *rloc_probing_nonces;
    lmtimer_t *probe_timer;
} rmt_locator_extended_info_t;



locator_t *locator_new();
locator_t *
locator_init(
        lisp_addr_t*    addr,
        uint8_t         state,
        uint8_t         priority,
        uint8_t         weight,
        uint8_t         mpriority,
        uint8_t         mweight,
        uint8_t         type
        );
char *locator_to_char(locator_t *);
int locator_cmp(locator_t *l1, locator_t *l2);
int locator_parse(void *ptr, locator_t *loc);

locator_t *locator_init_remote(lisp_addr_t *addr);
locator_t *locator_init_remote_full(lisp_addr_t *, uint8_t, uint8_t, uint8_t,
        uint8_t, uint8_t);
locator_t *locator_init_local(lisp_addr_t *);
locator_t *locator_init_local_full(lisp_addr_t *, uint8_t, uint8_t, uint8_t,
        uint8_t, uint8_t);
void locator_del(locator_t *loc);
locator_t *locator_clone(locator_t *loc);
void locator_list_lafi_type (glist_t *loct_list, int *lafi, int	*type);
locator_t *locator_list_get_locator_with_addr(glist_t *loct_list, lisp_addr_t *addr);
locator_t *locator_list_extract_locator_with_addr(glist_t *loct_list,lisp_addr_t *addr);
int locator_list_extract_locator_with_ptr(glist_t *loct_list,locator_t *locator);
inline int locator_cmp_addr (locator_t *loct1,locator_t *loct2);
glist_t *locator_list_clone(glist_t *llist);
int locator_list_cmp_afi(glist_t *loct_list_a, glist_t *loct_list_b);

static inline lisp_addr_t *locator_addr(locator_t *);
static inline uint8_t locator_type(locator_t *);
static inline uint8_t locator_state(locator_t *);
static inline uint8_t locator_priority(locator_t *);
static inline uint8_t locator_weight(locator_t *);
static inline uint8_t locator_mpriority(locator_t *);
static inline uint8_t locator_mweight(locator_t *);
static inline void locator_set_addr(locator_t *, lisp_addr_t *);
static inline void locator_clone_addr(locator_t *loc, lisp_addr_t *addr);
static inline void locator_set_state(locator_t *locator, uint8_t state);
static inline void locator_set_type(locator_t *, int);
static inline uint8_t locator_is_local(locator_t *);


rtr_locator_t *rtr_locator_new(lisp_addr_t address);
rtr_locators_list_t *rtr_locator_list_new();
int rtr_list_add(rtr_locators_list_t **, rtr_locator_t *);
void rtr_list_del(rtr_locators_list_t *rtr_list_elt);
void rtr_list_remove_locs_with_afi_different_to(rtr_locators_list_t **, int);
rtr_locators_list_t *rtr_locator_list_clone(rtr_locators_list_t *rtr_list);


static inline lisp_addr_t *locator_addr(locator_t *locator)
{
    return (locator->addr);
}

static inline uint8_t locator_type(locator_t *locator){
    return (locator->type);
}

static inline uint8_t locator_state(locator_t *locator)
{
    return (locator->state);
}

static inline uint8_t locator_priority(locator_t *locator)
{
    return (locator->priority);
}

static inline uint8_t locator_weight(locator_t *locator)
{
    return (locator->weight);
}

static inline uint8_t locator_mpriority(locator_t *locator)
{
    return (locator->mpriority);
}

static inline uint8_t locator_mweight(locator_t *locator)
{
    return (locator->mweight);
}

static inline void locator_set_addr(locator_t *loc, lisp_addr_t *addr)
{
    /* Addr is linked to corresponding interface address */
    loc->addr = addr;
}

static inline void locator_clone_addr(locator_t *loc, lisp_addr_t *addr)
{
    if (!loc->addr) {
        loc->addr = lisp_addr_new();
    }
    lisp_addr_copy(loc->addr, addr);
}

static inline void locator_set_state(locator_t *locator, uint8_t state)
{
    locator->state = state;
}

static inline void locator_set_type(locator_t *l, int type)
{
    l->type = type;
}

static inline uint8_t locator_is_local(locator_t *locator)
{
    return (locator->type == LOCAL_LOCATOR);
}


#endif /* LISP_LOCATOR_H_ */
