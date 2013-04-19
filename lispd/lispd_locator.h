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

#include "lispd_nonce.h"

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
}lispd_locator_elt;

typedef struct lcl_locator_extended_info_ {
    int out_socket;
}lcl_locator_extended_info;

/*
 * Structure to expand lispd_locator_elt for remote locators
 */
typedef struct rmt_locator_extended_info_ {
    nonces_list                 *rloc_probing_nonces;
}rmt_locator_extended_info;


/*
 * list of locators.
 */
typedef struct lispd_locators_list_ {
    lispd_locator_elt           *locator;
    struct lispd_locators_list_ *next;
} lispd_locators_list;

/****************************************  FUNCTIONS **************************************/

/*
 * Generets a locator element
 */

lispd_locator_elt   *new_local_locator (
        lisp_addr_t                 *locator_addr,
        uint8_t                     *state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight,
        int                         out_socket);

/*
 * Generets a locator element. For the remote locators, we have to reserve memory for address and state.
 */

lispd_locator_elt   *new_rmt_locator (
        uint8_t                     **afi_ptr,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight);

lispd_locator_elt   *new_static_rmt_locator (
        char                        *rloc_addr,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight);


/*
 * Free memory of lispd_locator. If it's a local locator, we don't remove
 * the address as it can be used for other locators of other EIDs
 */

void free_locator(lispd_locator_elt   *locator);


void dump_locator (
        lispd_locator_elt   *locator,
        int                 log_level);

/**********************************  LOCATORS LISTS FUNCTIONS ******************************************/

/*
 * Add a locator to a locators list
 */
int add_locator_to_list (
        lispd_locators_list         **list,
        lispd_locator_elt           *locator);

/*
 * Extract the locator from a locators list that match with the address.
 * The locator is removed from the list
 */
lispd_locator_elt *extract_locator_from_list(
        lispd_locators_list     **head_locator_list,
        lisp_addr_t             addr);


/*
 * Free memory of lispd_locator_list.
 */

void free_locator_list(lispd_locators_list     *list);
#endif /* LISPD_LOCATOR_H_ */
