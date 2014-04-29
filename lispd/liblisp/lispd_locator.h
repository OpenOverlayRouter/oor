/*
 * lispd_locator.h
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
 */

#ifndef LISPD_LOCATOR_H_
#define LISPD_LOCATOR_H_

#include "lisp_address.h"
#include "lispd_nonce.h"
#include <lispd_timers.h>

typedef struct lispd_locator_elt_ {
    lisp_addr_t *addr;
    uint8_t *state; /* UP , DOWN */
    uint8_t type :2;
    uint8_t priority;
    uint8_t weight;
    uint8_t mpriority;
    uint8_t mweight;

    uint32_t data_packets_in;
    uint32_t data_packets_out;
    void *extended_info;
} locator_t;

typedef struct lispd_locators_list_ {
    locator_t *locator;
    struct lispd_locators_list_ *next;
} locators_list_t;

typedef struct lispd_rtr_locator_ {
    lisp_addr_t address;
    uint8_t state; /* UP , DOWN */
    uint32_t latency;
} rtr_locator;

typedef struct lispd_rtr_locators_list_ {
    rtr_locator *locator;
    struct lispd_rtr_locators_list_ *next;
} rtr_locators_list;

typedef struct lcl_locator_extended_info_ {
    int *out_socket;
    rtr_locators_list *rtr_locators_list;
} lcl_locator_extended_info;

/* Structure to expand lispd_locator_elt for remote locators */
typedef struct rmt_locator_extended_info_ {
    nonces_list_t *rloc_probing_nonces;
    timer *probe_timer;
} rmt_locator_extended_info;



/* Obsolete functions!  */
locator_t *new_local_locator(lisp_addr_t *, uint8_t *, uint8_t, uint8_t,
        uint8_t, uint8_t, int *);
locator_t *new_static_rmt_locator(lisp_addr_t *, uint8_t, uint8_t, uint8_t,
        uint8_t, uint8_t);


locator_t *locator_new();
char *locator_to_char(locator_t *locator);
int locator_cmp(locator_t *l1, locator_t *l2);

locator_t *locator_init_remote(lisp_addr_t *addr);
locator_t *locator_init_remote_full(lisp_addr_t *, uint8_t, uint8_t, uint8_t,
        uint8_t, uint8_t);
locator_t *locator_init_local(lisp_addr_t *);
locator_t *locator_init_local_full(lisp_addr_t *, uint8_t *, uint8_t, uint8_t,
        uint8_t, uint8_t);
void locator_del(locator_t *locator);


/* Extract the locator from a locators list that match with the address.
 * The locator is removed from the list */
locator_t *locator_list_extract_locator(locators_list_t **, lisp_addr_t);
locator_t *locator_list_get_locator(locators_list_t *, lisp_addr_t *);
void locator_list_del(locators_list_t *list);
int locator_list_add(locators_list_t **, locator_t *);

rtr_locator *rtr_locator_new(lisp_addr_t address);
rtr_locators_list *rtr_locator_list_new();
/* Add a rtr localtor to a list of rtr locators */
int rtr_list_add(rtr_locators_list **, rtr_locator *);
void rtr_list_del(rtr_locators_list *rtr_list_elt);

/* Leave in the list, rtr with afi equal to the afi passed as a parameter */
void rtr_list_remove_locs_with_afi_different_to(rtr_locators_list **, int);


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
    if (!locator->state)
        locator->state = calloc(1, sizeof(uint8_t));
    *(locator->state) = state;
}




#endif /* LISPD_LOCATOR_H_ */
