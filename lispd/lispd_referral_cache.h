/*
 * lispd_referral_cache.h
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

#ifndef LISPD_REFERRAL_CACHE_H_
#define LISPD_REFERRAL_CACHE_H_

#include "lispd_nonce.h"
#include "lispd_map_cache.h"
#include "lispd_mapping.h"
#include "lispd_timers.h"


/*
 * Referral Map cache entry
 * The locators of the mapping are the nodes where the prefix is delegated
 */
typedef struct lispd_referral_cache_entry_{
    lispd_mapping_elt                   *mapping;
    struct lispd_referral_cache_entry_  *parent_node;
    struct lispd_referral_cache_list_   *children_nodes;
    //Locator  from where we receive this referral information. This locator is one of the locators appearing in the parent's list of locators.
    lisp_addr_t                         src_inf_ddt_node_locator_addr;
    int                                 act_entry_type;
    int                                 ttl;
    timer                               *expiry_ddt_cache_timer;
}lispd_referral_cache_entry;

typedef struct lispd_referral_cache_list_ {
    lispd_referral_cache_entry          *referral_cache_entry;
    struct lispd_referral_cache_list_   *next;
}lispd_referral_cache_list;

typedef struct lispd_pending_referral_cache_entry_ {
    lispd_map_cache_entry           *map_cache_entry;
    lisp_addr_t                     src_eid; // EID who started the process
    nonces_list                     *nonces;
    lispd_referral_cache_entry      *previous_referral;
    int                             tried_locators; // Locators from the list of the referral cache entry that has been asked
    timer                           *ddt_request_retry_timer;
    uint8_t                         request_through_root;
}lispd_pending_referral_cache_entry;

typedef struct lispd_pending_referral_cache_list_ {
    lispd_pending_referral_cache_entry              *pending_referral_cache_entry;
    struct lispd_pending_referral_cache_list_       *next;
}lispd_pending_referral_cache_list;

/*
 * Creates a referral_cache_entry. It is inserted to the tree by add_referral_cache_entry_to_tree
 */

lispd_referral_cache_entry *new_referral_cache_entry(
        lispd_mapping_elt                   *mapping,
        int                                 act_entry_type,
        int                                 ttl);

/* We free the referral cache entry but not childs*/

void free_referral_cache_entry(lispd_referral_cache_entry *referral_cache_entry);

/* We free the referral cache entry and all its childs */

void free_referral_cache_entry_recursive(lispd_referral_cache_entry *referral_cache_entry);

/*
 * Copy from the src referral cache to the dst referral cache the following data: mapping, act and ttl
 * @param dst_referral Destination of the data to be copied. The timer should be restarted outside this function
 * @param src_referral Source of the data to be copied
 * @return GOOD if finish correctly or an error code otherwise
 */

int update_referral_cache_data(lispd_referral_cache_entry *dst_referral, lispd_referral_cache_entry *src_referral);

/*
 * Add new referral to the referral tree: Indicate the parent node in the new referral and add it to the children
 * node of the parent
 */

void add_referral_cache_entry_to_tree (lispd_referral_cache_entry *parent, lispd_referral_cache_entry *new_entry);

/**
 * Remove map referral cache from the list of children of its parent node
 * @param referral_cache_entry Referral cache element to be removed from the children list
 */
void remove_referral_cache_entry_from_parent_node(lispd_referral_cache_entry *referral_cache_entry);

lispd_pending_referral_cache_entry *new_pending_referral_cache_entry(
        lispd_map_cache_entry           *map_cache_entry,
        lisp_addr_t                     src_eid,
        lispd_referral_cache_entry      *previous_referral);

int add_pending_referral_cache_entry_to_list(lispd_pending_referral_cache_entry *pending_referral_cache_entry);

int remove_pending_referral_cache_entry_from_list(lispd_pending_referral_cache_entry *pending_referral);

/**
 * Restart from root all pending referrals which its previous referral has expired.
 * @param expired_referral_cache Referral cache entry that has expired
 */
void reset_pending_referrals_with_expired_previous_referral(lispd_referral_cache_entry *expired_referral_cache);

lispd_pending_referral_cache_entry *lookup_pending_referral_cache_entry_by_eid (
        lisp_addr_t eid_prefix,
        int eid_prefix_length);

/*
 *  Search the pending referral cache entry that matches the nonce.
 */

lispd_pending_referral_cache_entry *lookup_pending_referral_cache_entry_by_nonce (uint64_t nonce);


void free_pending_referral_cache_entry(lispd_pending_referral_cache_entry *pending_referral_cache_entry);

void dump_referral_cache_entry(
        lispd_referral_cache_entry      *entry,
        int                             log_level);

/*
 * Sort the list of locators of ddt node by its priority and retuns the locator in the position
 * indicated as a parameter. Only the locators of the specified afi are considered except afi =
 * AF_UNSPEC. In that case, we use all locators.
 */

lisp_addr_t get_ddt_locator_addr_at_position(
        lispd_referral_cache_entry  *referral_cache,
        int                         afi,
        int                         position);

#endif /* LISPD_REFERRAL_CACHE_H_ */
