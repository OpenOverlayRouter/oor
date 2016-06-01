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
#include "../lib/mem_util.h"


#define MAX_PRIORITY 0
#define MIN_PRIORITY 254
#define UNUSED_RLOC_PRIORITY 255
#define MIN_WEIGHT 0
#define MAX_WEIGHT 255

typedef struct locator {
    lisp_addr_t *addr;
    /* UP , DOWN */
    uint8_t state;
    uint8_t L_bit;
    uint8_t R_bit;
    uint8_t priority;
    uint8_t weight;
    uint8_t mpriority;
    uint8_t mweight;
} locator_t;


locator_t *locator_new();
locator_t *
locator_new_init(lisp_addr_t* addr,uint8_t state,uint8_t L_bit,uint8_t R_bit,
        uint8_t priority, uint8_t weight,uint8_t mpriority, uint8_t mweight);
char *locator_to_char(locator_t *);
int locator_cmp(locator_t *l1, locator_t *l2);
int locator_parse(void *ptr, locator_t *loc);
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
static inline uint8_t locator_state(locator_t *);
static inline uint8_t locator_L_bit(locator_t *);
static inline uint8_t locator_R_bit(locator_t *);
static inline uint8_t locator_priority(locator_t *);
static inline uint8_t locator_weight(locator_t *);
static inline uint8_t locator_mpriority(locator_t *);
static inline uint8_t locator_mweight(locator_t *);
static inline void locator_set_addr(locator_t *, lisp_addr_t *);
static inline void locator_clone_addr(locator_t *loc, lisp_addr_t *addr);
static inline void locator_set_state(locator_t *locator, uint8_t state);
static inline void locator_set_L_bit(locator_t *locator, uint8_t L_bit);
static inline void locator_set_R_bit(locator_t *locator, uint8_t R_bit);



static inline lisp_addr_t *locator_addr(locator_t *locator)
{
    return (locator->addr);
}


static inline uint8_t locator_state(locator_t *locator)
{
    return (locator->state);
}

static inline uint8_t locator_L_bit(locator_t *locator)
{
    return (locator->L_bit);
}

static inline uint8_t locator_R_bit(locator_t *locator)
{
    return (locator->R_bit);
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

static inline void locator_set_L_bit(locator_t *locator, uint8_t L_bit)
{
    locator->L_bit = L_bit;
}

static inline void locator_set_R_bit(locator_t *locator, uint8_t R_bit)
{
    locator->R_bit = R_bit;
}

#endif /* LISP_LOCATOR_H_ */
