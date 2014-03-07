/*
 * lispd_referral_cache.c
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

#include "lispd_afi.h"
#include "lispd_lib.h"
#include "lispd_log.h"
#include "lispd_map_referral.h"
#include "lispd_map_request.h"
#include "lispd_nonce.h"
#include "lispd_referral_cache.h"
#include "lispd_referral_cache_db.h"

lispd_pending_referral_cache_list  *pening_referrals_list    = NULL;

static inline lispd_referral_cache_list *new_referral_cache_list_elt(lispd_referral_cache_entry *referral_cache_entry);
static inline void free_lispd_referral_cache_list (lispd_referral_cache_list *referral_cache_list);


/*
 * Creates a referral_cache_entry. It is inserted to the tree by add_referral_cache_entry_to_tree
 */

lispd_referral_cache_entry *new_referral_cache_entry(
        lispd_mapping_elt                   *mapping,
        int                                 act_entry_type,
        int                                 ttl)
{
    lispd_referral_cache_entry *referral_cache_entry = NULL;

    referral_cache_entry = (lispd_referral_cache_entry *)malloc(sizeof(lispd_referral_cache_entry));
    if (referral_cache_entry == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_referral_cache_entry: Unable to allocate memory for a referral cache entry");
        return (NULL);
    }
    referral_cache_entry->mapping                           = mapping;
    referral_cache_entry->act_entry_type                    = act_entry_type;
    referral_cache_entry->ttl                               = ttl;
    referral_cache_entry->parent_node                       = NULL;
    referral_cache_entry->children_nodes                    = NULL;
    referral_cache_entry->expiry_ddt_cache_timer            = NULL;
    referral_cache_entry->src_inf_ddt_node_locator_addr.afi = AF_UNSPEC;

    return (referral_cache_entry);
}

/* We free the referral cache entry but not childs */

void free_referral_cache_entry(lispd_referral_cache_entry *referral_cache_entry)
{
    lispd_referral_cache_list *list_elt          = referral_cache_entry->children_nodes;
    lispd_referral_cache_list *aux_list_elt      = NULL;
    free_mapping_elt (referral_cache_entry->mapping);
    /* We remove the list of childs (lispd_referral_cache_list) but not the childs  (lispd_referral_cache_entry)*/
    while (list_elt != NULL){
        aux_list_elt = list_elt->next;
        free(aux_list_elt);
        list_elt = aux_list_elt;
    }
    if (referral_cache_entry->expiry_ddt_cache_timer != NULL){
        stop_timer(referral_cache_entry->expiry_ddt_cache_timer);
    }
    free (referral_cache_entry);
}


/* We free the referral cache entry and all its childs */

void free_referral_cache_entry_recursive(lispd_referral_cache_entry *referral_cache_entry)
{
    free_mapping_elt (referral_cache_entry->mapping);
    if (referral_cache_entry->expiry_ddt_cache_timer != NULL){
        stop_timer(referral_cache_entry->expiry_ddt_cache_timer);
    }
    remove_referral_cache_entry_from_parent_node(referral_cache_entry);
    free_lispd_referral_cache_list(referral_cache_entry->children_nodes);
    free (referral_cache_entry);
}

/*
 * Copy from the src referral cache to the dst referral cache the following data: mapping, act and ttl
 * @param dst_referral Destination of the data to be copied. The timer should be restarted outside this function
 * @param src_referral Source of the data to be copied
 * @return GOOD if finish correctly or an error code otherwise
 */
int update_referral_cache_data(
        lispd_referral_cache_entry *dst_referral,
        lispd_referral_cache_entry *src_referral)
{
    free_mapping_elt (dst_referral->mapping);
    dst_referral->mapping = copy_mapping_elt(src_referral->mapping);
    if (dst_referral->mapping == NULL){
        return (BAD);
    }
    dst_referral->act_entry_type = src_referral->act_entry_type;
    dst_referral->ttl = src_referral->ttl;
    return (GOOD);
}


/*
 * Add new referral to the referral tree: Indicate the parent node in the new referral and add it to the children
 * node of the parent
 */

void add_referral_cache_entry_to_tree (
        lispd_referral_cache_entry *parent,
        lispd_referral_cache_entry *new_entry)
{
    lispd_referral_cache_list  *children_referral_list = NULL;
    lispd_referral_cache_list  *new_referral_list_elt  = NULL;

    new_entry->parent_node = parent;
    new_referral_list_elt = new_referral_cache_list_elt (new_entry);
    if (parent != NULL){
        if (parent->children_nodes == NULL){
            parent->children_nodes = new_referral_list_elt;
            return;
        }
        children_referral_list = parent->children_nodes;
        while (children_referral_list->next != NULL){
            children_referral_list = children_referral_list->next;
        }
        children_referral_list->next = new_referral_list_elt;
    }
}

/*
 * Remove map referral cache from the list of children of its parent node
 * @param referral_cache_entry Referral cache element to be removed from the children list
 */
void remove_referral_cache_entry_from_parent_node(lispd_referral_cache_entry *referral_cache_entry)
{
    lispd_referral_cache_list   *referral_list_elt        = NULL;
    lispd_referral_cache_list   *prev_referral_list_elt   = NULL;

    if (referral_cache_entry->parent_node != NULL){
        referral_list_elt = referral_cache_entry->parent_node->children_nodes;
        while (referral_list_elt != NULL){
            if (referral_list_elt->referral_cache_entry == referral_cache_entry){
                break;
            }
            prev_referral_list_elt = referral_list_elt;
            referral_list_elt = referral_list_elt->next;
        }
        if (referral_list_elt != NULL){
            if (prev_referral_list_elt == NULL){
                referral_cache_entry->parent_node->children_nodes = referral_list_elt->next;
            }else{
                prev_referral_list_elt->next = referral_list_elt->next;
            }
            free(referral_list_elt);
        }else {
            lispd_log_msg(LISP_LOG_WARNING,"remove_referral_cache_entry_from_parent_node: Referral cache node not present "
                    "in the list of childs nodes of its parent node. It should never happen");
        }
    }
}

static inline lispd_referral_cache_list *new_referral_cache_list_elt(lispd_referral_cache_entry *referral_cache_entry)
{
    lispd_referral_cache_list       *referral_cache_list_elt                = NULL;
    if((referral_cache_list_elt = malloc(sizeof(lispd_referral_cache_list))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_referral_cache_list_elt: Unable to allocate memory for lispd_referral_cache_list: %s", strerror(errno));
        return (NULL);
    }
    referral_cache_list_elt->referral_cache_entry   = referral_cache_entry;
    referral_cache_list_elt->next                   = NULL;

    return (referral_cache_list_elt);
}

static inline void free_lispd_referral_cache_list (lispd_referral_cache_list *referral_cache_list)
{
    lispd_referral_cache_list *referral_list_elt        = NULL;
    lispd_referral_cache_list *aux_referral_list_elt    = NULL;

    referral_list_elt = referral_cache_list;

    while (referral_list_elt != NULL){
        free_referral_cache_entry(referral_list_elt->referral_cache_entry);
        aux_referral_list_elt = referral_list_elt;
        referral_list_elt = referral_list_elt->next;
        free (aux_referral_list_elt);
    }
}



lispd_pending_referral_cache_entry *new_pending_referral_cache_entry(
        lispd_map_cache_entry           *map_cache_entry,
        lisp_addr_t                     src_eid,
        lispd_referral_cache_entry      *previous_referral)
{
    lispd_pending_referral_cache_entry *pending_referral_cache_entry = NULL;

    pending_referral_cache_entry = (lispd_pending_referral_cache_entry *)malloc(sizeof(lispd_pending_referral_cache_entry));
    if (pending_referral_cache_entry == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_pending_referral_cache_entry: Unable to allocate memory for a pending referral cache entry");
        return (NULL);
    }

    pending_referral_cache_entry->map_cache_entry                       = map_cache_entry;
    pending_referral_cache_entry->src_eid                               = src_eid;
    pending_referral_cache_entry->previous_referral                     = previous_referral;
    pending_referral_cache_entry->nonces                                = NULL;
    pending_referral_cache_entry->ddt_request_retry_timer               = NULL;
    pending_referral_cache_entry->tried_locators                        = 0;

    if (previous_referral->parent_node == NULL){
        // The previous referral is a root node
        pending_referral_cache_entry->request_through_root = TRUE;
    }else{
        pending_referral_cache_entry->request_through_root = FALSE;
    }

    return (pending_referral_cache_entry);
}

int add_pending_referral_cache_entry_to_list(lispd_pending_referral_cache_entry *pending_referral_cache_entry)
{
    lispd_pending_referral_cache_list *pending_referral_list_elt = NULL;
    pending_referral_list_elt = (lispd_pending_referral_cache_list *)malloc(sizeof(lispd_pending_referral_cache_list));
    if (pending_referral_list_elt == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"add_pending_referral_cache_entry_to_list: Unable to allocate memory for a lispd_pending_referral_cache_list");
        return (BAD);
    }
    pending_referral_list_elt->pending_referral_cache_entry = pending_referral_cache_entry;
    if (pening_referrals_list == NULL){
        pening_referrals_list = pending_referral_list_elt;
        pending_referral_list_elt->next = NULL;
    }else{
        pending_referral_list_elt->next = pening_referrals_list;
        pening_referrals_list = pending_referral_list_elt;
    }
    return (GOOD);
}

int remove_pending_referral_cache_entry_from_list(lispd_pending_referral_cache_entry *pending_referral)
{
    lispd_pending_referral_cache_list       *list_elt           = NULL;
    lispd_pending_referral_cache_list       *prev_list_elt      = NULL;
    uint8_t                                 entry_found         = FALSE;
    uint8_t                                 result              = FALSE;

    list_elt = pening_referrals_list;

    while (list_elt != NULL){
        if (list_elt->pending_referral_cache_entry == pending_referral){
            if (prev_list_elt == NULL){
                pening_referrals_list = list_elt->next;
            }else{
                prev_list_elt->next = list_elt->next;
            }
            entry_found = TRUE;
            break;
        }
        prev_list_elt = list_elt;
        list_elt = list_elt->next;
    }

    if (entry_found == TRUE){
        free (list_elt);
        result = GOOD;
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1,"remove_pending_referral_cache_entry_from_list: The entry %s/%d has not been found"
                " in the list of pending referral cache entries", get_char_from_lisp_addr_t(pending_referral->map_cache_entry->mapping->eid_prefix),
                pending_referral->map_cache_entry->mapping->eid_prefix_length);
        result = BAD;
    }
    free_pending_referral_cache_entry(pending_referral);

    return (result);
}

/*
 * Restart from root all pending referrals which its previous referral has expired.
 * @param expired_referral_cache Referral cache entry that has expired
 */
void reset_pending_referrals_with_expired_previous_referral(lispd_referral_cache_entry *expired_referral_cache)
{
    lispd_pending_referral_cache_list   *pending_referrals      = pening_referrals_list;
    lispd_pending_referral_cache_entry  *pending_referral_entry = NULL;

    while (pending_referrals != NULL){
        if (pending_referrals->pending_referral_cache_entry->previous_referral == expired_referral_cache){
            pending_referral_entry = pending_referrals->pending_referral_cache_entry;
            pending_referral_entry->previous_referral = get_root_referral_cache(pending_referral_entry->map_cache_entry->mapping->eid_prefix.afi);
            pending_referral_entry->tried_locators = 0;
            pending_referral_entry->request_through_root = TRUE;
            if (pending_referral_entry->nonces != NULL){
                free(pending_referral_entry->nonces);
                pending_referral_entry->nonces = NULL;
            }
            if (pending_referral_entry->ddt_request_retry_timer != NULL){
                stop_timer(pending_referral_entry->ddt_request_retry_timer);
                pending_referral_entry->ddt_request_retry_timer = NULL;
            }
            lispd_log_msg(LISP_LOG_DEBUG_1,"reset_pending_referrals_with_expired_previous_referral: Resetting of pending referral cache "
                    "%s/%d due to expiration of its parent referral node. Restart from root",
                    get_char_from_lisp_addr_t(pending_referral_entry->map_cache_entry->mapping->eid_prefix),
                    pending_referral_entry->map_cache_entry->mapping->eid_prefix_length);
            err = send_ddt_map_request_miss(NULL,(void *)pending_referral_entry);
        }
        pending_referrals = pending_referrals->next;
    }
}


lispd_pending_referral_cache_entry *lookup_pending_referral_cache_entry_by_eid (
        lisp_addr_t eid_prefix,
        int eid_prefix_length)
{
    lispd_pending_referral_cache_entry      *pending_referral   = NULL;
    lispd_mapping_elt                       *mapping            = NULL;


    lispd_pending_referral_cache_list *aux_list = pening_referrals_list;
    while (aux_list != NULL){
        mapping = aux_list->pending_referral_cache_entry->map_cache_entry->mapping;
        if (compare_lisp_addr_t (&(mapping->eid_prefix), &eid_prefix) == 0 &&
                mapping->eid_prefix_length == eid_prefix_length){
            pending_referral = aux_list->pending_referral_cache_entry;
            break;
        }
        aux_list = aux_list->next;
    }
    return (pending_referral);
}

/*
 *  Search the pending referral cache entry that matches the nonce.
 */
lispd_pending_referral_cache_entry *lookup_pending_referral_cache_entry_by_nonce (uint64_t nonce)
{
    lispd_pending_referral_cache_entry      *pending_referral   = NULL;

    lispd_pending_referral_cache_list *aux_list = pening_referrals_list;
    while (aux_list != NULL){
        if (check_nonce(aux_list->pending_referral_cache_entry->nonces, nonce) == GOOD){
            pending_referral = aux_list->pending_referral_cache_entry;
            break;
        }
        aux_list = aux_list->next;
    }
    return (pending_referral);
}


void free_pending_referral_cache_entry(lispd_pending_referral_cache_entry *pending_referral_cache_entry)
{
    //map_cache_entry nad previous referral cache should not be free.
    if (pending_referral_cache_entry->nonces != NULL){
        free (pending_referral_cache_entry->nonces);
    }
    if (pending_referral_cache_entry->ddt_request_retry_timer != NULL){
        stop_timer(pending_referral_cache_entry->ddt_request_retry_timer);
    }
    free (pending_referral_cache_entry);
}


void dump_referral_cache_entry(
        lispd_referral_cache_entry      *entry,
        int                             log_level)
{
    int                         ctr = 0;
    char                        str[400];
    lispd_locators_list         *locator_iterator_array[2]  = {NULL,NULL};
    lispd_locators_list         *locator_iterator           = NULL;
    lispd_locator_elt           *locator                    = NULL;

    if (is_loggable(log_level) == FALSE){
        return;
    }


    sprintf(str,"IDENTIFIER (EID): %s/%d (IID = %d), TTL: %d", get_char_from_lisp_addr_t(entry->mapping->eid_prefix),
            entry->mapping->eid_prefix_length, entry->mapping->iid, entry->ttl);

    switch (entry->act_entry_type){
    case NODE_REFERRAL:
        sprintf(str + strlen(str),"   Type: Node Referral ");
        break;
    case MS_REFERRAL:
        sprintf(str + strlen(str),"   Type: MS Referral ");
        break;
    case MS_ACK:
        sprintf(str + strlen(str),"   Type: MS ACK ");
        break;
    case MS_NOT_REGISTERED:
        sprintf(str + strlen(str),"   Type: Not Registered ");
        break;
    case DELEGATION_HOLE:
        sprintf(str + strlen(str),"   Type: Delegation hole ");
        break;
    case NOT_AUTHORITATIVE:
        sprintf(str + strlen(str),"   Type: Not authoritative ");
        break;
    default:
        sprintf(str + strlen(str),"   Type: %d ", entry->act_entry_type);
        break;
    }


    if (entry->parent_node != NULL){
        sprintf(str + strlen(str)," Parent (EID): %s/%d ", get_char_from_lisp_addr_t(entry->parent_node->mapping->eid_prefix),
                entry->parent_node->mapping->eid_prefix_length);
    }

    lispd_log_msg(log_level,"%s",str);

    if (entry->mapping->locator_count > 0){

        locator_iterator_array[0] = entry->mapping->head_v4_locators_list;
        locator_iterator_array[1] = entry->mapping->head_v6_locators_list;
        lispd_log_msg(log_level, "|               Locator (RLOC)            | Status | Priority/Weight |");
        // Loop through the locators and print each
        for (ctr = 0 ; ctr < 2 ; ctr++){
            locator_iterator = locator_iterator_array[ctr];
            while (locator_iterator != NULL) {
                locator = locator_iterator->locator;
                dump_locator(locator, log_level);
                locator_iterator = locator_iterator->next;
            }
        }
        lispd_log_msg(log_level,"\n");
    }
}

/*
 * Sort the list of locators of ddt node by its priority and retuns the locator in the position
 * indicated by the parameter "position". Only the locators of the specified afi are considered except afi =  AF_UNSPEC.
 * In that case, we use all locators.
 */

lisp_addr_t get_ddt_locator_addr_at_position(
        lispd_referral_cache_entry *referral_cache,
        int afi,
        int position)
{
    lisp_addr_t             ddt_locator_addr        = {.afi=AF_UNSPEC};
    lispd_locator_elt       *ddt_locator            = NULL;
    lispd_mapping_elt       *mapping                = referral_cache->mapping;
    lispd_locators_list     *locators_list[2]       = {NULL,NULL};
    lispd_locators_list     *sorted_locators_list   = NULL;
    lispd_locators_list     *locators_list_elt      = NULL;
    lispd_locators_list     *new_locator_list_elt   = NULL;
    lispd_locators_list     *prev_locators_list_elt = NULL;
    int                     locators_list_length    = 0;
    int                     ctr                     = 0;

    if (afi == AFI_SUPPORT_4 || afi == AFI_SUPPORT_4_6){
        locators_list[0] = mapping->head_v4_locators_list;
    }
    if (afi == AFI_SUPPORT_6 || afi == AFI_SUPPORT_4_6){
        locators_list[1] = mapping->head_v6_locators_list;
    }
    /* Generate list of locators sorted by priority */
    for (ctr=0 ; ctr<2 ; ctr++){
        if (locators_list[ctr] == NULL){
            continue;
        }
        while (locators_list[ctr] != NULL){
            new_locator_list_elt = new_locators_list_elt(locators_list[ctr]->locator);
            if (new_locator_list_elt != NULL){
                locators_list_elt = sorted_locators_list;
                while (locators_list_elt != NULL){
                    if (locators_list_elt->locator->priority > locators_list[ctr]->locator->priority){
                        break;
                    }
                    prev_locators_list_elt = locators_list_elt;
                    locators_list_elt = locators_list_elt->next;
                }
                if (prev_locators_list_elt == NULL){
                    new_locator_list_elt->next = sorted_locators_list;
                    sorted_locators_list = new_locator_list_elt;
                }else{
                    prev_locators_list_elt->next = new_locator_list_elt;
                    new_locator_list_elt->next = locators_list_elt;
                }
                locators_list_length ++;
            }
            locators_list[ctr] = locators_list[ctr]->next;
        }
    }

    if (locators_list_length > position){
        /* Free the sorted locator list and get the ddt locator at the same time */
        locators_list_elt = sorted_locators_list;
        ctr = 0;
        while (locators_list_elt != NULL){
            if (ctr == position){
                ddt_locator = locators_list_elt->locator;
                ddt_locator_addr = *(ddt_locator->locator_addr);
            }
            prev_locators_list_elt = locators_list_elt;
            locators_list_elt = locators_list_elt->next;
            free (prev_locators_list_elt);
            ctr ++;
        }
    }

    return (ddt_locator_addr);
}
