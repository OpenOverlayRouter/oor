/*
 * lispd_mapping.c
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

#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_log.h"
#include "lispd_mapping.h"

/*********************************** FUNCTIONS DECLARATION ************************/

/*
 * Reseve and fill the memory required by a lcl_mapping_extended_info
 */
static inline lcl_mapping_extended_info *new_lcl_mapping_extended_info();

/*
 * Generates a copy of a local mapping extended info. Some parameters should be initialized after
 * invoking this method like the "balancing locator vector"
 */
lcl_mapping_extended_info *copy_lcl_mapping_extended_info(lcl_mapping_extended_info *ext_info);

/*
 * Free memory of lcl_mapping_extended_info.
 */
void free_lcl_mapping_extended_info(lcl_mapping_extended_info *extended_info);

/*
 * Reseve and fill the memory required by a rmt_mapping_extended_info
 */
static inline rmt_mapping_extended_info *new_rmt_mapping_extended_info();

/*
 * Generates a copy of a remote mapping extended info. Some parameters should be initialized after
 * invoking this method like the "balancing locator vector"
 */
rmt_mapping_extended_info *copy_rmt_mapping_extended_info(rmt_mapping_extended_info *ext_info);

/*
 * Free memory of rmt_mapping_extended_info.
 */
void free_rmt_mapping_extended_info(rmt_mapping_extended_info *extended_info);

/*
 * Free the dinamic arrays that contains the balancing_locators_vecs structure;
 */
void free_balancing_locators_vecs (balancing_locators_vecs locators_vec);


lispd_locator_elt   **set_balancing_vector(
        lispd_locator_elt   **locators,
        int                 total_weight,
        int                 hcf,
        int                 *locators_vec_length);

int select_best_priority_locators (
        lispd_locators_list     *locators_list_elt,
        lispd_locator_elt       **selected_locators);

static inline void get_hcf_locators_weight (
        lispd_locator_elt   **locators,
        int                 *total_weight,
        int                 *highest_common_factor);

int highest_common_factor  (int a, int b);

/*
 * Initialize to 0 balancing_locators_vecs
 */
void reset_balancing_locators_vecs (balancing_locators_vecs *blv);

/************************************ FUNCTIONS  **********************************/

/*
 * Generates a basic mapping
 */
lispd_mapping_elt *new_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    lispd_mapping_elt *mapping = NULL;

    if ((mapping = (lispd_mapping_elt *)malloc(sizeof(lispd_mapping_elt)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"Couldn't allocate memory for lispd_mapping_elt: %s", strerror(errno));
        return (NULL);
    }
    mapping->eid_prefix =  eid_prefix;
    mapping->eid_prefix_length = eid_prefix_length;
    mapping->iid = iid;
    mapping->locator_count = 0;
    mapping->head_v4_locators_list = NULL;
    mapping->head_v6_locators_list = NULL;
    mapping->extended_info = NULL;

    return (mapping);
}

/*
 * Generates a mapping with the local extended info
 */
lispd_mapping_elt *new_local_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    lispd_mapping_elt           *mapping        = NULL;

    if ((mapping = new_mapping (eid_prefix, eid_prefix_length, iid)) == NULL){
        return (NULL);
    }

    mapping->mapping_type = LOCAL_MAPPING;
    mapping->extended_info = (void *)new_lcl_mapping_extended_info();
    if (mapping->extended_info == NULL){
        free_mapping_elt(mapping);
        return (NULL);
    }
    return (mapping);
}

/*
 * Generates a mapping with the remote extended info
 */
lispd_mapping_elt *new_map_cache_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    lispd_mapping_elt           *mapping        = NULL;

    if ((mapping = new_mapping (eid_prefix, eid_prefix_length, iid)) == NULL){
        return (NULL);
    }

    mapping->mapping_type = REMOTE_MAPPING;
    mapping->extended_info = (void *)new_rmt_mapping_extended_info();
    if (mapping->extended_info == NULL){
        free_mapping_elt(mapping);
        return (NULL);
    }

    return (mapping);
}

/*
 * Generates a clone of a lispd_mapping_elt. Parameters like timers or nonces are not cloned
 */
lispd_mapping_elt *copy_mapping_elt(lispd_mapping_elt *elt)
{
    lispd_mapping_elt *mapping = NULL;
    mapping = new_mapping(elt->eid_prefix,elt->eid_prefix_length,elt->iid);
    if (mapping == NULL){
        return (NULL);
    }
    mapping->locator_count = elt->locator_count;
    if (elt->head_v4_locators_list != NULL){
        mapping->head_v4_locators_list = copy_locators_list(elt->head_v4_locators_list);
        if (mapping->head_v4_locators_list == NULL){
            free_mapping_elt(mapping);
            return (NULL);
        }
    }
    if(elt->head_v6_locators_list != NULL){
        mapping->head_v6_locators_list = copy_locators_list(elt->head_v6_locators_list);
        if (mapping->head_v6_locators_list == NULL){
            free_mapping_elt(mapping);
            return(NULL);
        }
    }
    if (elt->extended_info != NULL){
        if (mapping->mapping_type == LOCAL_MAPPING){
            mapping->extended_info = (void *)copy_lcl_mapping_extended_info((lcl_mapping_extended_info *)elt->extended_info);
            if (mapping->extended_info == NULL){
                free_mapping_elt(mapping);
                return(NULL);
            }
            calculate_balancing_vectors (mapping,&(((lcl_mapping_extended_info *)mapping->extended_info)->outgoing_balancing_locators_vecs));
        }else{
            mapping->extended_info = (void *)copy_rmt_mapping_extended_info((rmt_mapping_extended_info *)elt->extended_info);
            if (mapping->extended_info == NULL){
                free_mapping_elt(mapping);
                return(NULL);
            }
            calculate_balancing_vectors (mapping,&(((rmt_mapping_extended_info *)mapping->extended_info)->rmt_balancing_locators_vecs));
        }
    }

    return (mapping);
}

/*
 * Free memory of lispd_mapping_elt.
 */
void free_mapping_elt(lispd_mapping_elt *mapping)
{
    if (mapping == NULL){
        return;
    }
    /* Free the locators list*/
    free_locator_list(mapping->head_v4_locators_list);
    free_locator_list(mapping->head_v6_locators_list);
    /* Free extended info */
    if (mapping->extended_info != NULL){
        switch (mapping->mapping_type){
        case LOCAL_MAPPING:
            free_lcl_mapping_extended_info((lcl_mapping_extended_info *)mapping->extended_info);
            break;
        case REMOTE_MAPPING:
            free_rmt_mapping_extended_info((rmt_mapping_extended_info *)mapping->extended_info);
            break;
        }
    }
    free(mapping);
}

/*
 * Reseve and fill the memory required by a lcl_mapping_extended_info
 */
static inline lcl_mapping_extended_info *new_lcl_mapping_extended_info()
{
    lcl_mapping_extended_info   *extended_info  = NULL;
    if ((extended_info=(lcl_mapping_extended_info *)calloc(1,sizeof(lcl_mapping_extended_info)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_lcl_mapping_extended_info: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        err = ERR_MALLOC;
        return (NULL);
    }
    extended_info->to_do_smr = TRUE;
    return(extended_info);
}

/*
 * Generates a clone of a lcl_mapping_extended_info.
 */
lcl_mapping_extended_info *copy_lcl_mapping_extended_info(lcl_mapping_extended_info *ext_info)
{
    lcl_mapping_extended_info *extended_info = NULL;
    extended_info=(lcl_mapping_extended_info *)calloc(1,sizeof(lcl_mapping_extended_info));
    if(extended_info == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"copy_lcl_mapping_extended_info: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        return (NULL);
    }
    return (extended_info);
}

/*
 * Free memory of lcl_mapping_extended_info.
 */
void free_lcl_mapping_extended_info(lcl_mapping_extended_info *extended_info)
{
    free_locator_list(extended_info->head_not_init_locators_list);
    free_balancing_locators_vecs(extended_info->outgoing_balancing_locators_vecs);
    if (extended_info->map_reg_timer != NULL){
        stop_timer(extended_info->map_reg_timer);
    }
    if (extended_info->map_reg_nonce != NULL){
        free(extended_info->map_reg_nonce);
    }
    free (extended_info);
}

/*
 * Reseve and fill the memory required by a rmt_mapping_extended_info
 */
static inline rmt_mapping_extended_info *new_rmt_mapping_extended_info()
{
    rmt_mapping_extended_info   *extended_info  = NULL;

    if ((extended_info=(rmt_mapping_extended_info *)malloc(sizeof(rmt_mapping_extended_info)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_rmt_mapping_extended_info: Couldn't allocate memory for rmt_mapping_extended_info: %s", strerror(errno));
        err = ERR_MALLOC;
        return (NULL);
    }

    extended_info->rmt_balancing_locators_vecs.v4_balancing_locators_vec = NULL;
    extended_info->rmt_balancing_locators_vecs.v6_balancing_locators_vec = NULL;
    extended_info->rmt_balancing_locators_vecs.balancing_locators_vec = NULL;
    extended_info->rmt_balancing_locators_vecs.v4_locators_vec_length = 0;
    extended_info->rmt_balancing_locators_vecs.v6_locators_vec_length = 0;
    extended_info->rmt_balancing_locators_vecs.locators_vec_length = 0;

    return (extended_info);
}

/*
 * Generates a clone of a rmt_mapping_extended_info.
 */
rmt_mapping_extended_info *copy_rmt_mapping_extended_info(rmt_mapping_extended_info *ext_info)
{
    rmt_mapping_extended_info *extended_info = NULL;
    extended_info=(rmt_mapping_extended_info *)calloc(1,sizeof(rmt_mapping_extended_info));
    if(extended_info == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"copy_rmt_mapping_extended_info: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        return (NULL);
    }
    return (extended_info);
}

/*
 * Free memory of rmt_mapping_extended_info.
 */
void free_rmt_mapping_extended_info(rmt_mapping_extended_info *extended_info)
{
    free_balancing_locators_vecs(extended_info->rmt_balancing_locators_vecs);
    free (extended_info);
}

/*
 * Add a locator into the locators list of the mapping.
 */
int add_locator_to_mapping(
        lispd_mapping_elt           *mapping,
        lispd_locator_elt           *locator)
{
    int result = GOOD;

    switch (locator->locator_addr->afi){
    case AF_INET:
        err = add_locator_to_list (&(mapping->head_v4_locators_list), locator);
        break;
    case AF_INET6:
        err = add_locator_to_list (&(mapping->head_v6_locators_list), locator);
        break;
    case AF_UNSPEC:
        err = add_locator_to_list (&(((lcl_mapping_extended_info *)(mapping->extended_info))->head_not_init_locators_list), locator);
        if (err == GOOD){
            // The locator_count should not be incremented
            return (GOOD);
        }
    }

    if (err == GOOD){
        mapping->locator_count++;
        lispd_log_msg(LISP_LOG_DEBUG_3, "add_locator_to_mapping: The locator %s has been added to the EID %s/%d.",
                get_char_from_lisp_addr_t(*(locator->locator_addr)),
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length);
        result = GOOD;
    }else if (err == ERR_EXIST){
        lispd_log_msg(LISP_LOG_DEBUG_3, "add_locator_to_mapping: The locator %s already exists for the EID %s/%d.",
                get_char_from_lisp_addr_t(*(locator->locator_addr)),
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length);
        result = GOOD;
    }else{
        result = BAD;
    }

    return (result);
}

/*
 * Reinsert a locator into the locators list of the mapping.
 */
int reinsert_locator_to_mapping(
        lispd_mapping_elt           *mapping,
        lispd_locator_elt           *locator)
{
    switch (locator->locator_addr->afi){
    case AF_INET:
        err = reinsert_locator_to_list (&(mapping->head_v4_locators_list), locator);
        break;
    case AF_INET6:
        err = reinsert_locator_to_list (&(mapping->head_v6_locators_list), locator);
        break;
    }
    if (err == ERR_NO_EXIST){
        return (BAD);
    }
    if (err != GOOD){
        mapping->locator_count--;
        return (BAD);
    }
    lispd_log_msg(LISP_LOG_DEBUG_3, "reinsert_locator_to_mapping: The locator %s has been reinserted to the EID %s/%d.",
                    get_char_from_lisp_addr_t(*(locator->locator_addr)),
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length);

    return (GOOD);
}


int remove_locator_from_mapping(
        lispd_mapping_elt       *mapping,
        lisp_addr_t		 		*loc_addr)
{
	int result = BAD;
	switch (loc_addr->afi){
	case AF_INET:
		result = remove_locator_from_list(&(mapping->head_v4_locators_list),loc_addr);
		break;
	case AF_INET6:
		result = remove_locator_from_list(&(mapping->head_v4_locators_list),loc_addr);
		break;
	default:
		break;
	}
	if (result != GOOD){
		lispd_log_msg(LISP_LOG_DEBUG_2,"remove_locator_from_mapping: The locator %s has not been found in the "
				"mapping with EID prefix %s/%d.", get_char_from_lisp_addr_t(*loc_addr),
				get_char_from_lisp_addr_t(mapping->eid_prefix),	mapping->eid_prefix_length);
	}
	return (result);
}

/*
 * This function sort the locator list elt with IP = changed_loc_addr
 */
void sort_locators_list_elt (
        lispd_mapping_elt   *mapping,
        lisp_addr_t         *changed_loc_addr)
{
    lispd_locators_list     *current_locators_list_elt   = NULL;
    lispd_locators_list     *prev_locators_list_elt      = NULL;
    lispd_locators_list     *changed_locator             = NULL;
    lispd_locators_list     *prev_changed_locator        = NULL;
    lispd_locators_list     *new_prev_changed_locator    = NULL;
    int                     changed_locator_updated      = FALSE;
    int                     new_prev_changed_lct_updated = FALSE;
    int                     afi_length                   = 0;
    int                     cmp                          = 0;


    switch (changed_loc_addr->afi){
    case AF_INET:
        current_locators_list_elt = mapping->head_v4_locators_list;
        afi_length = sizeof (struct in_addr);
        break;
    case AF_INET6:
        current_locators_list_elt = mapping->head_v6_locators_list;
        afi_length = sizeof (struct in6_addr);
        break;
    }

    if (current_locators_list_elt == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_1, "sort_locators_list_elt: It should nevear reach this point");
        return;
    }

    while (current_locators_list_elt != NULL){
        cmp = memcmp(
                &(current_locators_list_elt->locator->locator_addr->address),
                &(changed_loc_addr->address),
                afi_length);
        if (cmp == 0){
            changed_locator = current_locators_list_elt;
            prev_changed_locator = prev_locators_list_elt;
            changed_locator_updated = TRUE;
            if (new_prev_changed_lct_updated == TRUE){
                break;
            }

        }else if (cmp > 0 && new_prev_changed_lct_updated == FALSE){
            new_prev_changed_locator = prev_locators_list_elt;
            new_prev_changed_lct_updated = TRUE;
            if (changed_locator_updated == TRUE){
                break;
            }
        }
        prev_locators_list_elt = current_locators_list_elt;
        current_locators_list_elt = current_locators_list_elt->next;
    }

    // The new locator goes to the last position
    if (new_prev_changed_locator == NULL && new_prev_changed_lct_updated == FALSE){
       new_prev_changed_locator = prev_locators_list_elt;
    }

    if (new_prev_changed_locator == changed_locator){
        new_prev_changed_locator = prev_changed_locator;
    }

    if (prev_changed_locator != NULL){
        prev_changed_locator->next = changed_locator->next;
    }else{
        switch (changed_loc_addr->afi){
        case AF_INET:
            mapping->head_v4_locators_list = changed_locator->next;
            break;
        case AF_INET6:
            mapping->head_v6_locators_list = changed_locator->next;
            break;
        }
    }
    if (new_prev_changed_locator != NULL){
        changed_locator->next = new_prev_changed_locator->next;
        new_prev_changed_locator->next = changed_locator;
    }else{
        switch (changed_loc_addr->afi){
        case AF_INET:
            changed_locator->next = mapping->head_v4_locators_list;
            mapping->head_v4_locators_list = changed_locator;
            break;
        case AF_INET6:
            changed_locator->next = mapping->head_v6_locators_list;
            mapping->head_v6_locators_list = changed_locator;
            break;
        }
    }
}


/*
 * Returns the locators with the address passed as a parameter
 */
lispd_locator_elt *get_locator_from_mapping(
        lispd_mapping_elt   *mapping,
        lisp_addr_t         *address)
{
    lispd_locator_elt   *locator        = NULL;
    lispd_locators_list *locator_list   = NULL;

    switch (address->afi){
    case AF_INET:
        locator_list = mapping->head_v4_locators_list;
        break;
    case AF_INET6:
        locator_list = mapping->head_v6_locators_list;
        break;
    }

    locator = get_locator_from_list(locator_list, address);

    return (locator);
}


/*
 * Free the dinamic arrays that contains the balancing_locators_vecs structure;
 */
void free_balancing_locators_vecs (balancing_locators_vecs locators_vec)
{
    if (locators_vec.balancing_locators_vec != NULL &&
            locators_vec.balancing_locators_vec != locators_vec.v4_balancing_locators_vec && //IPv4 locators more priority -> IPv4_IPv6 vector = IPv4 locator vector
            locators_vec.balancing_locators_vec != locators_vec.v6_balancing_locators_vec){  //IPv6 locators more priority -> IPv4_IPv6 vector = IPv4 locator vector
            free (locators_vec.balancing_locators_vec);
    }
    if (locators_vec.v4_balancing_locators_vec != NULL){
        free (locators_vec.v4_balancing_locators_vec);
    }
    if (locators_vec.v6_balancing_locators_vec != NULL){
        free (locators_vec.v6_balancing_locators_vec);
    }
}

/*
 * Initialize to 0 balancing_locators_vecs
 */
void reset_balancing_locators_vecs (balancing_locators_vecs *blv)
{
    free_balancing_locators_vecs(*blv);
    blv->v4_balancing_locators_vec = NULL;
    blv->v4_locators_vec_length = 0;
    blv->v6_balancing_locators_vec = NULL;
    blv->v6_locators_vec_length = 0;
    blv->balancing_locators_vec = NULL;
    blv->locators_vec_length = 0;
}

/*
 * dump mapping
 */
void dump_mapping_entry(
        lispd_mapping_elt       *mapping,
        int                     log_level)
{
    lispd_locators_list         *locator_iterator_array[2]  = {NULL,NULL};
    lispd_locators_list         *locator_iterator           = NULL;
    lispd_locator_elt           *locator                    = NULL;
    int                         ctr                         = 0;

    if (is_loggable(log_level) == FALSE){
        return;
    }

    lispd_log_msg(log_level,"IDENTIFIER (EID): %s/%d (IID = %d)\n ", get_char_from_lisp_addr_t(mapping->eid_prefix),
            mapping->eid_prefix_length, mapping->iid);

    lispd_log_msg(log_level, "|               Locator (RLOC)            | Status | Priority/Weight |");

    if (mapping->locator_count > 0){
        locator_iterator_array[0] = mapping->head_v4_locators_list;
        locator_iterator_array[1] = mapping->head_v6_locators_list;
        // Loop through the locators and print each

        for (ctr = 0 ; ctr < 2 ; ctr++){
            locator_iterator = locator_iterator_array[ctr];
            while (locator_iterator != NULL) {
                locator = locator_iterator->locator;
                dump_locator (locator,log_level);
                locator_iterator = locator_iterator->next;
            }
        }
        lispd_log_msg(log_level,"\n");
    }
}

/**************************************** TRAFFIC BALANCING FUNCTIONS ************************/

/*
 * Calculate the vectors used to distribute the load from the priority and weight of the locators of the mapping
 */
int calculate_balancing_vectors (
        lispd_mapping_elt           *mapping,
        balancing_locators_vecs     *b_locators_vecs)
{
    // Store locators with same priority. Maximum 32 locators (33 to no get out of array)
    lispd_locator_elt       *locators[3][33];

    int                     min_priority[2]         = {255,255};
    int                     total_weight[3]         = {0,0,0};
    int                     hcf[3]                  = {0,0,0};
    int                     ctr                     = 0;
    int                     ctr1                    = 0;
    int                     pos                     = 0;

    locators[0][0] = NULL;
    locators[1][0] = NULL;

    reset_balancing_locators_vecs(b_locators_vecs);

    /* Fill the locator balancing vec using only IPv4 locators and according to their priority and weight */
    if (mapping->head_v4_locators_list != NULL){
        min_priority[0] = select_best_priority_locators (mapping->head_v4_locators_list,locators[0]);
        if (min_priority[0] != UNUSED_RLOC_PRIORITY){
            get_hcf_locators_weight (locators[0], &total_weight[0], &hcf[0]);
            b_locators_vecs->v4_balancing_locators_vec =  set_balancing_vector(locators[0], total_weight[0], hcf[0], &(b_locators_vecs->v4_locators_vec_length));
        }
    }
    /* Fill the locator balancing vec using only IPv6 locators and according to their priority and weight*/
    if (mapping->head_v6_locators_list != NULL){
        min_priority[1] = select_best_priority_locators (mapping->head_v6_locators_list,locators[1]);
        if (min_priority[1] != UNUSED_RLOC_PRIORITY){
            get_hcf_locators_weight (locators[1], &total_weight[1], &hcf[1]);
            b_locators_vecs->v6_balancing_locators_vec =  set_balancing_vector(locators[1], total_weight[1], hcf[1], &(b_locators_vecs->v6_locators_vec_length));
        }
    }
    /* Fill the locator balancing vec using IPv4 and IPv6 locators and according to their priority and weight*/
    if (b_locators_vecs->v4_balancing_locators_vec != NULL && b_locators_vecs->v6_balancing_locators_vec != NULL){
        //Only IPv4 locators are involved (due to priority reasons)
        if (min_priority[0] < min_priority[1]){
            b_locators_vecs->balancing_locators_vec = b_locators_vecs->v4_balancing_locators_vec;
            b_locators_vecs->locators_vec_length = b_locators_vecs->v4_locators_vec_length;
        }//Only IPv6 locators are involved (due to priority reasons)
        else if (min_priority[0] > min_priority[1]){
            b_locators_vecs->balancing_locators_vec = b_locators_vecs->v6_balancing_locators_vec;
            b_locators_vecs->locators_vec_length = b_locators_vecs->v6_locators_vec_length;
        }//IPv4 and IPv6 locators are involved
        else {
            hcf[2] = highest_common_factor (hcf[0], hcf[1]);
            total_weight[2] = total_weight[0] + total_weight[1];
            for (ctr=0 ;ctr<2; ctr++){
                ctr1 = 0;
                while (locators[ctr][ctr1]!=NULL){
                    locators[2][pos] = locators[ctr][ctr1];
                    ctr1++;
                    pos++;
                }
            }
            locators[2][pos] = NULL;
            b_locators_vecs->balancing_locators_vec =  set_balancing_vector(locators[2], total_weight[2], hcf[2], &(b_locators_vecs->locators_vec_length));
        }
    }

    dump_balancing_locators_vec(*b_locators_vecs,mapping,LISP_LOG_DEBUG_1);

    return (GOOD);
}

lispd_locator_elt   **set_balancing_vector(
        lispd_locator_elt   **locators,
        int                 total_weight,
        int                 hcf,
        int                 *locators_vec_length)
{
    lispd_locator_elt   **balancing_locators_vec    = NULL;
    int                 vector_length               = 0;
    int                 used_pos                    = 0;
    int                 ctr                         = 0;
    int                 ctr1                        = 0;
    int                 pos                         = 0;

    if ( total_weight != 0 ){
        /* Length of the dynamic vector */
        vector_length = total_weight / hcf;
    }else{ // If all locators has weight equal to 0, we assign one position for each locator
        while (locators[ctr] != NULL){
            ctr++;
        }
        vector_length = ctr;
        ctr = 0;
    }

    /* Reserve memory for the dynamic vector */
    if ((balancing_locators_vec = (lispd_locator_elt **)malloc(vector_length*sizeof(lispd_locator_elt *))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "calculate_balancing_vector: Unable to allocate memory for lispd_locator_elt *: %s", strerror(errno));
        *locators_vec_length = 0;
        return(NULL);
    }
    *locators_vec_length = vector_length;

    while (locators[ctr] != NULL){
        if (total_weight != 0 ){
            used_pos = locators[ctr]->weight/hcf;
        }else{
            used_pos = 1; // If all locators has weight equal to 0, we assign one position for each locator. Simetric balancing
        }
        ctr1 = 0;
        for (ctr1=0;ctr1<used_pos;ctr1++){
            balancing_locators_vec[pos] = locators[ctr];
            pos++;
        }
        ctr++;
    }

    return (balancing_locators_vec);
}

int select_best_priority_locators (
        lispd_locators_list     *locators_list_elt,
        lispd_locator_elt       **selected_locators)
{
    lispd_locators_list     *list_elt       = locators_list_elt;
    int                     min_priority    = UNUSED_RLOC_PRIORITY;
    int                     pos             = 0;

    while (list_elt!=NULL){
        /* Only use locators with status UP */
        if (*(list_elt->locator->state)==DOWN || list_elt->locator->priority == UNUSED_RLOC_PRIORITY){
            list_elt = list_elt->next;
            continue;
        }
        /* If priority of the locator equal to min_priority, then add the locator to the list */
        if (list_elt->locator->priority == min_priority){
            selected_locators[pos] = list_elt->locator;
            pos++;
            selected_locators[pos] = NULL;
        }
        /* If priority of the locator is minor than the min_priority, then min_priority and list of rlocs is updated */
        if (list_elt->locator->priority < min_priority){
            pos = 0;
            min_priority  = list_elt->locator->priority;
            selected_locators[pos] = list_elt->locator;
            pos ++;
            selected_locators[pos] = NULL;
        }
        list_elt = list_elt->next;
    }

    return (min_priority);
}

static inline void get_hcf_locators_weight (
        lispd_locator_elt   **locators,
        int                 *total_weight,
        int                 *hcf)
{
    int ctr     = 0;
    int weight  = 0;
    int tmp_hcf     = 0;

    if (locators[0] != NULL){
        tmp_hcf = locators[0]->weight;
        while (locators[ctr] != NULL){
            weight  = weight + locators[ctr]->weight;
            tmp_hcf = highest_common_factor (tmp_hcf, locators[ctr]->weight);
            ctr++;
        }
    }
    *total_weight = weight;
    *hcf = tmp_hcf;
}

int highest_common_factor  (int a, int b)
{
    int c;
    if ( b == 0 ){
        return a;
    }
    if ( a == 0 ){
        return b;
    }

    if (a < b){
        c = a;
        a = b;
        a = c;
    }
    c = 1;
    while (b != 0){
        c = a % b;
        a = b;
        b = c;
    }

    return (a);
}


/*
 * Print balancing locators vector information
 */
void dump_balancing_locators_vec(
        balancing_locators_vecs     b_locators_vecs,
        lispd_mapping_elt           *mapping,
        int                         log_level)
{
    int     ctr         = 0;
    char    str[3000];

    if ( is_loggable(log_level)){
        lispd_log_msg(log_level,"Balancing locator vector for %s/%d: ",
                        get_char_from_lisp_addr_t(mapping->eid_prefix),mapping->eid_prefix_length);

        sprintf(str,"  IPv4 locators vector (%d locators):  ",b_locators_vecs.v4_locators_vec_length);
        for (ctr = 0; ctr< b_locators_vecs.v4_locators_vec_length; ctr++){
            if (strlen(str) > 2850){
                sprintf(str + strlen(str)," ...");
                break;
            }
            sprintf(str + strlen(str)," %s  ",get_char_from_lisp_addr_t(*b_locators_vecs.v4_balancing_locators_vec[ctr]->locator_addr));
        }
        lispd_log_msg(log_level,"%s",str);
        sprintf(str,"  IPv6 locators vector (%d locators):  ",b_locators_vecs.v6_locators_vec_length);
        for (ctr = 0; ctr< b_locators_vecs.v6_locators_vec_length; ctr++){
            if (strlen(str) > 2900){
                sprintf(str + strlen(str)," ...");
                break;
            }
            sprintf(str + strlen(str)," %s  ",get_char_from_lisp_addr_t(*b_locators_vecs.v6_balancing_locators_vec[ctr]->locator_addr));
        }
        lispd_log_msg(log_level,"%s",str);
        sprintf(str,"  IPv4 & IPv6 locators vector (%d locators):  ", b_locators_vecs.locators_vec_length);
        for (ctr = 0; ctr< b_locators_vecs.locators_vec_length; ctr++){
            if (strlen(str) > 2950){
                sprintf(str + strlen(str)," ...");
                break;
            }
            sprintf(str + strlen(str)," %s  ",get_char_from_lisp_addr_t(*b_locators_vecs.balancing_locators_vec[ctr]->locator_addr));
        }
        lispd_log_msg(log_level,"%s",str);
    }
}

/********************************************************************************************/
/********************************************* MAPPINGS LIST ********************************/
/*
 * Add a mapping to a mapping list
 * @param mapping Mapping element to be added
 * @param list Pointer to the first element of the list where to add the mapping
 * @retun GOOD if finish correctly or an error code otherwise
 */
int add_mapping_to_list(
        lispd_mapping_elt    *mapping,
        lispd_mapping_list   **list)
{
    lispd_mapping_list   *list_elt   = NULL;

    if(mapping == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_1, "add_mapping_to_list: Empty data");
        return (BAD);
    }

    if ((list_elt = (lispd_mapping_list *)calloc(1,sizeof(lispd_mapping_list))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "add_mapping_to_list: Unable to allocate memory for lisp_mapping_list: %s", strerror(errno));
        return(ERR_MALLOC);
    }

    list_elt->mapping = mapping;
    if (*list != NULL) {
        list_elt->next = *list;
        *list = list_elt;
    } else {
        *list = list_elt;
    }

    return (GOOD);
}

/*
 * Remove a mapping from a mapping list
 * @param mapping Mapping to be removed
 * @param list Pointer to the first element of the list where to remove the mapping list elt
 */
void remove_mapping_from_list(
        lispd_mapping_elt    *mapping,
        lispd_mapping_list   **list)
{
    lispd_mapping_list *list_elt        = *list;
    lispd_mapping_list *prev_list_elt   = NULL;

    while(list_elt != NULL){
        if (list_elt->mapping == mapping){
            break;
        }
        prev_list_elt = list_elt;
        list_elt =  list_elt->next;
    }

    if(list_elt == NULL){
        return;
    }

    if (prev_list_elt == NULL){
        *list = list_elt->next;
        free(list_elt);
        return;
    }

    prev_list_elt->next = list_elt->next;
    free(list_elt);
    return;
}

/*
 * Check if a mapping is already in the list
 * @param mapping Mapping element to be found
 * @param list List where to find the mapping
 * @retun TRUE if the mapping belongs to the list
 */
uint8_t	is_mapping_in_the_list(
		lispd_mapping_elt    *mapping,
        lispd_mapping_list   *list)
{
	while (list != NULL){
		if (list->mapping == mapping){
			return (TRUE);
		}
		list = list->next;
	}
	return (FALSE);
}

/*
 * Retun the number of mappings of the list
 * @param list Mapping element to be added
 * @param list Pointer to the first element of the list where to add the mapping
 * @retun Number of mappings of the list
 */
int get_mapping_list_length(lispd_mapping_list   *list)
{
	int ctr = 0;
	while (list != NULL){
		ctr++;
		list = list->next;
	}

	return (ctr);
}

/*
 * Release the memory of a list of mappings
 * @param list First element of the list to be released
 * @param free_mappings If TRUE the elements stored in the list are also released
 */
void free_mapping_list(
        lispd_mapping_list   *list,
        uint8_t             free_mappings)
{
    lispd_mapping_list *aux_list = NULL;

    while (list != NULL) {
        aux_list = list->next;

        if (free_mappings == TRUE){
            free_mapping_elt(list->mapping);
        }
        free(list);
        list = aux_list;
    }
}

/*
 * Return the list of unique RTRs of the mapping
 */
lispd_rtr_locators_list *get_rtr_list_from_mapping(lispd_mapping_elt *mapping)
{
	lispd_rtr_locators_list     *rtr_list           = NULL;
	lispd_rtr_locators_list     *aux_rtr_list       = NULL;
	lispd_locators_list         *locator_list[2]    = {mapping->head_v4_locators_list, mapping->head_v6_locators_list};
	int                         ctr                 = 0;
	lispd_locator_elt           *locator            = NULL;
	lcl_locator_extended_info   *loct_ext_inf       = NULL;

	for (ctr = 0 ; ctr < 2 ; ctr++){
		while (locator_list[ctr] != NULL){
			locator = locator_list[ctr]->locator;
			loct_ext_inf = (lcl_locator_extended_info *)(locator->extended_info);
			if (loct_ext_inf != NULL && loct_ext_inf->nat_info->rtr_locators_list != NULL){
				aux_rtr_list = loct_ext_inf->nat_info->rtr_locators_list;
				while (aux_rtr_list != NULL){
					if (is_rtr_locator_in_the_list(rtr_list, &(aux_rtr_list->locator->address)) == FALSE){
						add_rtr_locator_to_list(&rtr_list, aux_rtr_list->locator);
					}
					aux_rtr_list = aux_rtr_list->next;
				}
			}
			locator_list[ctr] = locator_list[ctr]->next;
		}
	}
	return (rtr_list);
}
