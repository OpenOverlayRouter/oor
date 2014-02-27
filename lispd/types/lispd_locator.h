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

#include "lispd_address.h"
#include "lispd_nonce.h"
#include <lispd_timers.h>

/****************************************  STRUCTURES **************************************/

/*
 * Locator information
 */
typedef struct lispd_locator_elt_ {
    lisp_addr_t                 *locator_addr;
    uint8_t                     *state;    /* UP , DOWN */
    uint8_t                     locator_type:2;
    uint8_t                     priority;
    uint8_t                     weight;
    uint8_t                     mpriority;
    uint8_t                     mweight;

    uint32_t                    data_packets_in;
    uint32_t                    data_packets_out;
    void                        *extended_info;
} locator_t;


/*
 * list of locators.
 */
typedef struct lispd_locators_list_ {
    locator_t           *locator;
    struct lispd_locators_list_ *next;
} lispd_locators_list;

/*
 * Locator information
 */
typedef struct lispd_rtr_locator_ {
    lisp_addr_t                 address;
    uint8_t                     state;    /* UP , DOWN */
    uint32_t                    latency;
}lispd_rtr_locator;

/*
 * list of rtr locators.
 */
typedef struct lispd_rtr_locators_list_ {
    lispd_rtr_locator               *locator;
    struct lispd_rtr_locators_list_ *next;
} lispd_rtr_locators_list;


typedef struct lcl_locator_extended_info_ {
    int                         *out_socket;
    lispd_rtr_locators_list     *rtr_locators_list;
}lcl_locator_extended_info;

/*
 * Structure to expand lispd_locator_elt for remote locators
 */
typedef struct rmt_locator_extended_info_ {
    nonces_list                 *rloc_probing_nonces;
    timer                       *probe_timer;
}rmt_locator_extended_info;


/****************************************  FUNCTIONS **************************************/

/*
 * Generets a locator element
 */

locator_t   *new_local_locator (
        lisp_addr_t                 *locator_addr,
        uint8_t                     *state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight,
        int                         *out_socket);

/*
 * Generets a locator element. For the remote locators, we have to reserve memory for address and state.
 */

locator_t   *new_rmt_locator (
        uint8_t                     **afi_ptr,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight);

locator_t   *new_static_rmt_locator (
        lisp_addr_t                 *rloc_addr,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight);


lispd_rtr_locator *new_rtr_locator(lisp_addr_t address);

/*
 * Leave in the list, rtr with afi equal to the afi passed as a parameter
 */

void remove_rtr_locators_with_afi_different_to(lispd_rtr_locators_list **rtr_list, int afi);

/*
 * Free memory of lispd_locator. If it's a local locator, we don't remove
 * the address as it can be used for other locators of other EIDs
 */

void free_locator(locator_t   *locator);

void free_rtr_list(lispd_rtr_locators_list *rtr_list_elt);

void dump_locator (
        locator_t   *locator,
        int                 log_level);

/**********************************  LOCATORS LISTS FUNCTIONS ******************************************/

/*
 * Add a locator to a locators list
 */
int add_locator_to_list (
        lispd_locators_list **list,
        locator_t           *locator);
/*
 * Add a rtr localtor to a list of rtr locators
 */
int add_rtr_locator_to_list(
        lispd_rtr_locators_list **rtr_list,
        lispd_rtr_locator       *rtr_locator);

/*
 * Extract the locator from a locators list that match with the address.
 * The locator is removed from the list
 */
locator_t *extract_locator_from_list(
        lispd_locators_list     **head_locator_list,
        lisp_addr_t             addr);
/*
 * Return the locator from the list that contains the address passed as a parameter
 */

locator_t *get_locator_from_list(
        lispd_locators_list    *locator_list,
        lisp_addr_t            *addr);

/*
 * Free memory of lispd_locator_list.
 */

void free_locator_list(lispd_locators_list     *list);
void locator_list_free_container(lispd_locators_list *locator_list, uint8_t free_locators_flag);
locator_t *locator_init_from_field(locator_field *lf);
int locator_write_to_field(locator_t *locator, locator_field *lfield);

inline locator_t *locator_new();
char *locator_to_char(locator_t *locator);
int locator_get_size_in_field(locator_t *loc);
int locator_list_get_size_in_field(lispd_locators_list *locators_list);
int locator_cmp(locator_t *l1, locator_t *l2);
locator_t *locator_init_remote(lisp_addr_t *addr);
locator_t *locator_init_remote_full(lisp_addr_t *addr, uint8_t state, uint8_t priority, uint8_t weight,
        uint8_t mpriority, uint8_t mweight);

locator_t *locator_clone_remote(locator_t *locator);
lispd_locators_list *locators_list_clone_remote(lispd_locators_list *lst);

/* accessors */
static inline lisp_addr_t *locator_addr(locator_t *locator) {
    return(locator->locator_addr);
}

static inline void locator_set_addr(locator_t *locator, lisp_addr_t *addr) {
    locator->locator_addr = addr;
}










#endif /* LISPD_LOCATOR_H_ */
