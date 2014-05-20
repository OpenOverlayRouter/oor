/*
 * lisp_locator.h
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

#ifndef LISP_LOCATOR_H_
#define LISP_LOCATOR_H_

#include "lisp_address.h"
#include "lisp_nonce.h"
#include "util.h"
#include "timers.h"

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
    uint8_t *state;
    uint8_t type;
    uint8_t priority;
    uint8_t weight;
    uint8_t mpriority;
    uint8_t mweight;

    uint32_t data_packets_in;
    uint32_t data_packets_out;
    void *extended_info;
} locator_t;

typedef struct locators_list {
    locator_t *locator;
    struct locators_list *next;
} locators_list_t;

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
    int *out_socket;
    rtr_locators_list_t *rtr_locators_list;
} lcl_locator_extended_info_t;

/* Structure to expand lispd_locator_elt for remote locators */
typedef struct rmt_locator_extended_info {
    nonces_list_t *rloc_probing_nonces;
    timer *probe_timer;
} rmt_locator_extended_info_t;



locator_t *locator_new();
char *locator_to_char(locator_t *);
int locator_cmp(locator_t *l1, locator_t *l2);
int locator_parse(void *ptr, locator_t *loc);

locator_t *locator_init_remote(lisp_addr_t *addr);
locator_t *locator_init_remote_full(lisp_addr_t *, uint8_t, uint8_t, uint8_t,
        uint8_t, uint8_t);
locator_t *locator_init_local(lisp_addr_t *);
locator_t *locator_init_local_full(lisp_addr_t *, uint8_t *, uint8_t, uint8_t,
        uint8_t, uint8_t, int *);
void locator_del(locator_t *locator);

locator_t *locator_list_extract_locator(locators_list_t **, lisp_addr_t);
locator_t *locator_list_get_locator(locators_list_t *, lisp_addr_t *);
void locator_list_del(locators_list_t *list);
int locator_list_add(locators_list_t **, locator_t *);

static inline lisp_addr_t *locator_addr(locator_t *);
static inline void locator_set_addr(locator_t *, lisp_addr_t *);
static inline void locator_set_state(locator_t *locator, uint8_t *state);
static inline void locator_set_state_static(locator_t *locator, uint8_t state);
static inline void locator_set_type(locator_t *, int);


rtr_locator_t *rtr_locator_new(lisp_addr_t address);
rtr_locators_list_t *rtr_locator_list_new();
int rtr_list_add(rtr_locators_list_t **, rtr_locator_t *);
void rtr_list_del(rtr_locators_list_t *rtr_list_elt);
void rtr_list_remove_locs_with_afi_different_to(rtr_locators_list_t **, int);


static inline lisp_addr_t *locator_addr(locator_t *locator)
{
    return (locator->addr);
}

static inline void locator_set_addr(locator_t *locator, lisp_addr_t *addr)
{
    /* TODO: locator_addr should be a static field.
     * The code now acts as if it were because it does a copy @addr. It also
     * the address won't go NULL if by mistake @addr is freed outside */
    if (!locator->addr) {
        locator->addr = lisp_addr_new();
    }
    lisp_addr_copy(locator->addr, addr);
}

static inline void locator_set_state(locator_t *locator, uint8_t *state)
{
    locator->state = state;
}

/* XXX: use with caution! */
static inline void locator_set_state_static(locator_t *locator, uint8_t state)
{
    if (!locator->state) {
        locator->state = xcalloc(1, sizeof(uint8_t));
    }
    *(locator->state) = state;
}

static inline void locator_set_type(locator_t *l, int type)
{
    l->type = type;
}



#endif /* LISP_LOCATOR_H_ */
