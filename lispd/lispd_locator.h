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
#include "lispd_timers.h"

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


/*
 * list of locators.
 */
typedef struct lispd_locators_list_ {
    lispd_locator_elt           *locator;
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

typedef struct nat_info_str_ {
    uint8_t                     status;
    lispd_rtr_locators_list     *rtr_locators_list;
    lisp_addr_t                 *public_addr;
    nonces_list                 *inf_req_nonce;
    timer                       *inf_req_timer;
}nat_info_str;


typedef struct lcl_locator_extended_info_ {
    int                         *out_socket;
    nat_info_str                *nat_info;
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
 * Generates the general structure of the locator without extended info
 */
lispd_locator_elt   *new_locator (
        lisp_addr_t                 *locator_addr,
        uint8_t                     *state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight);

/*
 * Generets a local locator element
 */
lispd_locator_elt   *new_local_locator (
        lisp_addr_t                 *locator_addr,
        uint8_t                     *state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight,
        int                         *out_socket);

/*
 * Generets a remote locator element. For the remote locators, we have to reserve memory for address and state.
 */
lispd_locator_elt   *new_rmt_locator (
        uint8_t                     **afi_ptr,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight);

/*
 * Generates a static locator element. This is used when creating static mappings
 */
lispd_locator_elt   *new_static_rmt_locator (
        lisp_addr_t                 *locator_addr,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight);

/*
 * Generates a clone of a locator element. Parameters like timers or nonces are not cloned
 */
lispd_locator_elt *copy_locator_elt(lispd_locator_elt *loc);

/*
 * Generates a lispd_rtr_locator element with the information of a locator of an RTR router.
 */

lispd_rtr_locator *new_rtr_locator(lisp_addr_t address);

/*
 * Generates a new nat status structure
 */

nat_info_str *new_nat_info_str(
        int                         status,
        lisp_addr_t                 *public_address,
        lispd_rtr_locators_list     *rtr_locators_list);

/*
 * Leave in the list, rtr with afi equal to the afi passed as a parameter
 */
void remove_rtr_locators_with_afi_different_to(lispd_rtr_locators_list **rtr_list, int afi);

/*
 * Free memory of lispd_locator. If it's a local locator, we don't remove
 * the address as it can be used for other locators of other EIDs
 */
void free_locator(lispd_locator_elt   *locator);

/*
 * Free memory of all the elements of a lispd_rtr_locators_list structure
 */
void free_rtr_list(lispd_rtr_locators_list *rtr_list_elt);

/*
 * Free memory of a nat_info_str structure
 */
void free_nat_info_str(nat_info_str *nat_info);


/*
 * Generates a clone of a nat_ localtors list. Timers and nonces not cloned
 */
nat_info_str *copy_nat_info_str(nat_info_str *nat_info);

/*
 * Print the information of a locator element
 */
void dump_locator (
        lispd_locator_elt   *locator,
        int                 log_level);

/**********************************  LOCATORS LISTS FUNCTIONS ******************************************/

/*
 * Creates a  lispd_locators_list element
 */
lispd_locators_list *new_locators_list_elt(lispd_locator_elt *locator);

/*
 * Add a locator to a locators list
 */
int add_locator_to_list (
        lispd_locators_list         **list,
        lispd_locator_elt           *locator);

/*
 * Reinsert a locator to a locators list. It take into account the presence of RTRs to sort locators
 */
int reinsert_locator_to_list (
        lispd_locators_list         **list,
        lispd_locator_elt           *locator);

/*
 * Generates a clone of a list of locators.
 */
lispd_locators_list *copy_locators_list(lispd_locators_list *locator_list);

/*
 * Add a rtr localtor to a list of rtr locators
 */
int add_rtr_locator_to_list(
        lispd_rtr_locators_list **rtr_list,
        lispd_rtr_locator       *rtr_locator);


/*
 * Return TRUE if a rtr with specified address is already in the list
 */
int is_rtr_locator_in_the_list(
		lispd_rtr_locators_list *rtr_list,
		lisp_addr_t       		*rtr_addr);

/*
 * Extract the locator from a locators list that match with the address.
 * The locator is removed from the list
 */
lispd_locator_elt *extract_locator_from_list(
        lispd_locators_list     **head_locator_list,
        lisp_addr_t             *addr);

/*
 * Return the locator from the list that contains the address passed as a parameter
 */
lispd_locator_elt *get_locator_from_list(
        lispd_locators_list    *locator_list,
        lisp_addr_t            *addr);

/*
 * Return the locator from the list that contains the nonce passed as a parameter
 */
lispd_locator_elt *nat_get_locator_with_nonce(
        lispd_locators_list    *locator_list,
        uint64_t                nonce);

/*
 * Remove the locator from the list matching the specified address.
 */
int remove_locator_from_list(
        lispd_locators_list    **head_locator_list,
        lisp_addr_t            *addr);

/*
 * Free memory of lispd_locator_list.
 */
void free_locator_list(lispd_locators_list     *list);

#endif /* LISPD_LOCATOR_H_ */
