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
#include "lispd_lcaf.h"

/*********************************** FUNCTIONS DECLARATION ************************/

/*
 * Generates a basic mapping
 */

inline mapping_t *new_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid);

/*
 * Free the dinamic arrays that contains the balancing_locators_vecs structure;
 */

void free_balancing_locators_vecs (balancing_locators_vecs locators_vec);


locator_t   **set_balancing_vector(
        locator_t   **locators,
        int                 total_weight,
        int                 hcf,
        int                 *locators_vec_length);

int select_best_priority_locators (
        lispd_locators_list     *locators_list_elt,
        locator_t       **selected_locators);

inline void get_hcf_locators_weight (
        locator_t   **locators,
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

inline mapping_t *new_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    mapping_t *mapping = NULL;

    if ((mapping = (mapping_t *)malloc(sizeof(mapping_t)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"Couldn't allocate memory for lispd_mapping_elt: %s", strerror(errno));
        return (NULL);
    }

    if (lisp_addr_get_afi(&eid_prefix) == LM_AFI_IP)
        lisp_addr_set_plen(&eid_prefix, eid_prefix_length);
    lisp_addr_copy(mapping_eid(mapping), &eid_prefix);
//    ip_prefix_set(lisp_addr_get_ippref(&mapping->eid_prefix), lisp_addr_get_ip(&eid_prefix), eid_prefix_length);
    mapping->eid_prefix_length = eid_prefix_length;
    mapping->iid = iid;
    mapping->locator_count = 0;
    mapping->head_v4_locators_list = NULL;
    mapping->head_v6_locators_list = NULL;

    return (mapping);
}

/*
 * Generates a mapping with the local extended info
 */

mapping_t *new_local_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    mapping_t           *mapping        = NULL;
    lcl_mapping_extended_info   *extended_info  = NULL;

    lisp_addr_set_plen(&eid_prefix, eid_prefix_length);
    if ((mapping = new_mapping (eid_prefix, eid_prefix_length, iid)) == NULL)
        return (NULL);

    mapping->type = MAPPING_LOCAL;

    if ((extended_info=(lcl_mapping_extended_info *)malloc(sizeof(lcl_mapping_extended_info)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_local_mapping: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        free (mapping);
        return (NULL);
    }
    mapping->extended_info = (void *)extended_info;

    extended_info->outgoing_balancing_locators_vecs.v4_balancing_locators_vec = NULL;
    extended_info->outgoing_balancing_locators_vecs.v6_balancing_locators_vec = NULL;
    extended_info->outgoing_balancing_locators_vecs.balancing_locators_vec = NULL;
    extended_info->outgoing_balancing_locators_vecs.v4_locators_vec_length = 0;
    extended_info->outgoing_balancing_locators_vecs.v6_locators_vec_length = 0;
    extended_info->outgoing_balancing_locators_vecs.locators_vec_length = 0;

    extended_info->head_not_init_locators_list = NULL;

    return (mapping);
}

/*
 * Generates a mapping with the remote extended info
 */

mapping_t *new_map_cache_mapping(
        lisp_addr_t     eid_prefix,
        uint8_t         eid_prefix_length,
        int             iid)
{
    mapping_t                   *mapping        = NULL;
    rmt_mapping_extended_info   *extended_info  = NULL;

    if ((mapping = new_mapping (eid_prefix, eid_prefix_length, iid)) == NULL)
        return (NULL);

    mapping->type = MAPPING_REMOTE;
    if ((extended_info=(rmt_mapping_extended_info *)calloc(1, sizeof(rmt_mapping_extended_info)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_rmt_mapping: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        free (mapping);
        return (NULL);
    }
    mapping->extended_info = (void *)extended_info;
//
//    extended_info->rmt_balancing_locators_vecs.v4_balancing_locators_vec = NULL;
//    extended_info->rmt_balancing_locators_vecs.v6_balancing_locators_vec = NULL;
//    extended_info->rmt_balancing_locators_vecs.balancing_locators_vec = NULL;
//    extended_info->rmt_balancing_locators_vecs.v4_locators_vec_length = 0;
//    extended_info->rmt_balancing_locators_vecs.v6_locators_vec_length = 0;
//    extended_info->rmt_balancing_locators_vecs.locators_vec_length = 0;

    return (mapping);
}

/*
 * Add a locator into the locators list of the mapping.
 */

int mapping_add_locators(mapping_t *mapping, lispd_locators_list *locators) {
    lispd_locators_list *it;

    it = locators;
    while(it) {
        add_locator_to_mapping(mapping, it->locator);
        it = it->next;
    }

    return(GOOD);
}

int add_locator_to_mapping(mapping_t *mapping, locator_t *locator)
{
//    lcaf_addr_t *lcaf       = NULL;
//    glist_t     *enodes     = NULL;
//    elp_node_t  *elp_node   = NULL;
    lisp_addr_t *addr       = NULL;
    lisp_addr_t *auxaddr    = NULL;

    int result = GOOD;

    addr = locator_addr(locator);
    switch(lisp_addr_get_afi(addr)){
    case LM_AFI_IP:
        auxaddr = addr;
        break;
    case LM_AFI_LCAF:
        auxaddr = lcaf_rloc_get_ip_addr(addr);
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_1, "add_locator_to_mapping: AFI %d not supported", lisp_addr_get_afi(addr));
    }

    switch (lisp_addr_ip_get_afi(auxaddr)) {
        case AF_INET:
            err = add_locator_to_list (&(mapping->head_v4_locators_list), locator);
            break;
        case AF_INET6:
            err = add_locator_to_list (&(mapping->head_v6_locators_list), locator);
            break;
        case AF_UNSPEC:
            err = add_locator_to_list (&(((lcl_mapping_extended_info *)(mapping->extended_info))->head_not_init_locators_list), locator);
            if (err == GOOD){
                return (GOOD);
            }else{
                free_locator(locator);
                return (BAD);
            }
        default:
            lispd_log_msg(LISP_LOG_DEBUG_1, "Unknown locator afi %d", lisp_addr_ip_get_afi(auxaddr));
            err = BAD;
    }
//
//    switch (lisp_addr_get_afi(locator_addr(locator))){
//        case LM_AFI_IP:
//            switch (lisp_addr_ip_get_afi(locator_addr(locator))) {
//                case AF_INET:
//                    err = add_locator_to_list (&(mapping->head_v4_locators_list), locator);
//                    break;
//                case AF_INET6:
//                    err = add_locator_to_list (&(mapping->head_v6_locators_list), locator);
//                    break;
//                case AF_UNSPEC:
//                    err = add_locator_to_list (&(((lcl_mapping_extended_info *)(mapping->extended_info))->head_not_init_locators_list), locator);
//                    if (err == GOOD){
//                        return (GOOD);
//                    }else{
//                        free_locator (locator);
//                        return (BAD);
//                    }
//            }
//            break;
//        case LM_AFI_LCAF:
//            lcaf = lisp_addr_get_lcaf(locator_addr(locator));
//
//            switch (lcaf_addr_get_type(lcaf)) {
//                case LCAF_MCAST_INFO:
//                    /* use G because S might be undefined */
//                    if (lcaf_mc_get_afi(lcaf)!= LM_AFI_IP){
//                        lispd_log_msg(LISP_LOG_DEBUG_2, "add_locator_to_mapping: Unsupported mcast afi for address %s",
//                                lcaf_addr_to_char(lcaf));
//                        return(BAD);
//                    }
//                    switch(lcaf_mc_get_afi(lcaf)) {
//                        case AF_INET:
//                            err = add_locator_to_list (&(mapping->head_v4_locators_list), locator);
//                            break;
//                        case AF_INET6:
//                            err = add_locator_to_list (&(mapping->head_v6_locators_list), locator);
//                            break;
//                        default:
//                            lispd_log_msg(LISP_LOG_DEBUG_2, "add_locator_to_mapping: Unsupported mcast afi for address %d",
//                                    lcaf_addr_to_char(lcaf));
//                            err = BAD;
//                            break;
//                    }
//                    break;
//                case LCAF_EXPL_LOC_PATH:
//                    enodes = lcaf_elp_node_list(lcaf);
//                    elp_node = glist_first_data(enodes);
//                    switch (lisp_addr_ip_get_afi(elp_node->addr)) {
//                    case AF_INET:
//                        add_locator_to_list(&(mapping->head_v4_locators_list), locator);
//                        break;
//                    case AF_INET6:
//                        add_locator_to_list(&(mapping->head_v6_locators_list), locator);
//                        break;
//                    default:
//                        lispd_log_msg(LISP_LOG_DEBUG_1, "add_locator_to_mapping: elp node afi %d not supported. The node %s",
//                                lisp_addr_ip_get_afi(elp_node->addr), lisp_addr_to_char(elp_node->addr));
//                        break;
//                    }
//                    break;
//                default:
//                    lispd_log_msg(LISP_LOG_DEBUG_1, "add_locator_to_mapping: lcaf type %d not supported",
//                            lcaf_addr_get_type(lcaf));
//                    return(BAD);
//            }
//            break;
//        default:
//            lispd_log_msg(LISP_LOG_DEBUG_3, "add_locator_to_mapping: afi not supported %d",
//                    lisp_addr_get_afi(locator->locator_addr));
//            break;
//    }

    if (err == GOOD){
        mapping->locator_count++;
        lispd_log_msg(LISP_LOG_DEBUG_3, "add_locator_to_mapping: The locator %s has been added for the EID %s.",
                lisp_addr_to_char(locator->locator_addr),
                lisp_addr_to_char(mapping_eid(mapping)));

        result = GOOD;
    }else if (err == ERR_EXIST){
        lispd_log_msg(LISP_LOG_DEBUG_3, "add_locator_to_mapping: The locator %s already exists for the EID %s.",
                lisp_addr_to_char(locator->locator_addr),
                lisp_addr_to_char(mapping_eid(mapping)));
        free_locator (locator);
        result = GOOD;
    }else{
        free_locator (locator);
        result = BAD;
    }

    return (result);
}


/*
 * This function sort the locator list elt with IP = changed_loc_addr
 */

void sort_locators_list_elt (
        mapping_t   *mapping,
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

locator_t *get_locator_from_mapping(
        mapping_t   *mapping,
        lisp_addr_t         *address)
{
    locator_t   *locator        = NULL;
    lispd_locators_list *locator_list   = NULL;

    switch (lisp_addr_ip_get_afi(address)){
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
 * Free memory of lispd_mapping_elt.
 */
void free_mapping_elt(mapping_t *mapping, int local)
{
    /* Free the locators list*/
    free_locator_list(mapping->head_v4_locators_list);
    free_locator_list(mapping->head_v6_locators_list);
    /* Free extended info */
    if (local == TRUE){
        free_locator_list(((lcl_mapping_extended_info *)mapping->extended_info)->head_not_init_locators_list);
        free_balancing_locators_vecs(((lcl_mapping_extended_info *)mapping->extended_info)->outgoing_balancing_locators_vecs);
        free ((lcl_mapping_extended_info *)mapping->extended_info);
    }else{
        free_balancing_locators_vecs(((rmt_mapping_extended_info *)mapping->extended_info)->rmt_balancing_locators_vecs);
        free ((rmt_mapping_extended_info *)mapping->extended_info);
    }
    /* XXX ^2: lisp_addr_t unfortunately is not a pointer in mapping, need hack to free lcaf addr */
    if (lisp_addr_get_afi(mapping_eid(mapping)) == LM_AFI_LCAF)
        lcaf_addr_del_addr(lisp_addr_get_lcaf(mapping_eid(mapping)));
    free(mapping);

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
        mapping_t       *mapping,
        int                     log_level)
{
    lispd_locators_list         *locator_iterator_array[2]  = {NULL,NULL};
    lispd_locators_list         *locator_iterator           = NULL;
    locator_t           *locator                    = NULL;
    int                         ctr                         = 0;

    if (is_loggable(log_level) == FALSE){
        return;
    }

    lispd_log_msg(log_level,"IDENTIFIER (EID): %s (IID = %d)\n ",
            lisp_addr_to_char(mapping_eid(mapping)), mapping->iid);

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
        mapping_t                   *mapping,
        balancing_locators_vecs     *b_locators_vecs)
{
    // Store locators with same priority. Maximum 32 locators (33 to no get out of array)
    locator_t       *locators[3][33];

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

locator_t   **set_balancing_vector(
        locator_t   **locators,
        int                 total_weight,
        int                 hcf,
        int                 *locators_vec_length)
{
    locator_t   **balancing_locators_vec    = NULL;
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
    if ((balancing_locators_vec = (locator_t **)malloc(vector_length*sizeof(locator_t *))) == NULL){
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
        locator_t               **selected_locators)
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

inline void get_hcf_locators_weight (
        locator_t   **locators,
        int         *total_weight,
        int         *hcf)
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
        mapping_t           *mapping,
        int                         log_level)
{
    int     ctr         = 0;
    char    str[3000];

    if ( is_loggable(log_level)){
        lispd_log_msg(log_level,"Balancing locator vector for %s: ",
                        lisp_addr_to_char(mapping_eid(mapping)));

        sprintf(str,"  IPv4 locators vector (%d locators):  ",b_locators_vecs.v4_locators_vec_length);
        for (ctr = 0; ctr< b_locators_vecs.v4_locators_vec_length; ctr++){
            if (strlen(str) > 2850){
                sprintf(str + strlen(str)," ...");
                break;
            }
            sprintf(str + strlen(str)," %s  ",lisp_addr_to_char(b_locators_vecs.v4_balancing_locators_vec[ctr]->locator_addr));
        }
        lispd_log_msg(log_level,"%s",str);
        sprintf(str,"  IPv6 locators vector (%d locators):  ",b_locators_vecs.v6_locators_vec_length);
        for (ctr = 0; ctr< b_locators_vecs.v6_locators_vec_length; ctr++){
            if (strlen(str) > 2900){
                sprintf(str + strlen(str)," ...");
                break;
            }
            sprintf(str + strlen(str)," %s  ",lisp_addr_to_char(b_locators_vecs.v6_balancing_locators_vec[ctr]->locator_addr));
        }
        lispd_log_msg(log_level,"%s",str);
        sprintf(str,"  IPv4 & IPv6 locators vector (%d locators):  ", b_locators_vecs.locators_vec_length);
        for (ctr = 0; ctr< b_locators_vecs.locators_vec_length; ctr++){
            if (strlen(str) > 2950){
                sprintf(str + strlen(str)," ...");
                break;
            }
            sprintf(str + strlen(str)," %s  ",lisp_addr_to_char(b_locators_vecs.balancing_locators_vec[ctr]->locator_addr));
        }
        lispd_log_msg(log_level,"%s",str);
    }
}

/********************************************************************************************/

uint8_t *mapping_fill_record_in_pkt(
    mapping_record_hdr_t        *rec,
    mapping_t                   *mapping,
    lisp_addr_t                 *probed_rloc)
{
    uint8_t                     *cur_ptr            = NULL;
    int                         cpy_len             = 0;
    locator_hdr_t                 *loc_ptr            = NULL;
    lispd_locators_list         *locators_list[2]   = {NULL,NULL};
    locator_t                   *locator            = NULL;
    lcl_locator_extended_info   *lct_extended_info  = NULL;
    lisp_addr_t                 *itr_address        = NULL;
    int                         ctr                 = 0;
    lisp_addr_t                 *eid                = NULL;


    if ((rec == NULL) || (mapping == NULL))
        return NULL;


    eid = mapping_eid(mapping);

    rec->ttl                    = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
    rec->locator_count          = mapping->locator_count;
    rec->eid_prefix_length      = lisp_addr_get_plen(eid);
    rec->action                 = 0;
    rec->authoritative          = 1;
    rec->version_hi             = 0;
    rec->version_low            = 0;

    cur_ptr = CO(rec, sizeof(mapping_record_hdr_t));
    cur_ptr = CO(cur_ptr, lisp_addr_write(cur_ptr, eid));
    loc_ptr = (locator_hdr_t *)cur_ptr;

    if (loc_ptr == NULL)
        return(NULL);

    locators_list[0] = mapping->head_v4_locators_list;
    locators_list[1] = mapping->head_v6_locators_list;
    for (ctr = 0 ; ctr < 2 ; ctr++){
        while (locators_list[ctr]) {
            locator              = locators_list[ctr]->locator;

            if (*(locator->state) == UP){
                loc_ptr->priority    = locator->priority;
            }else{
                /* If the locator is DOWN, set the priority to 255 -> Locator should not be used */
                loc_ptr->priority    = UNUSED_RLOC_PRIORITY;
            }
            loc_ptr->weight      = locator->weight;
            loc_ptr->mpriority   = locator->mpriority;
            loc_ptr->mweight     = locator->mweight;
            loc_ptr->local       = 1;
            if (probed_rloc != NULL && lisp_addr_cmp(locator->locator_addr,probed_rloc)==0)
                loc_ptr->probed  = 1;

            loc_ptr->reachable   = *(locator->state);

            lct_extended_info = (lcl_locator_extended_info *)(locator->extended_info);
            if (lct_extended_info->rtr_locators_list != NULL){
                itr_address = &(lct_extended_info->rtr_locators_list->locator->address);
            }else{
                itr_address = locator->locator_addr;
            }

            if ((cpy_len = lisp_addr_write(CO(loc_ptr, sizeof(locator_hdr_t)), itr_address)) <= 0) {
                lispd_log_msg(LISP_LOG_DEBUG_3, "pkt_fill_mapping_record: copy_addr failed for locator %s",
                        lisp_addr_to_char(locator->locator_addr));
                return(NULL);
            }

            loc_ptr = (locator_hdr_t *)CO(loc_ptr, sizeof(locator_hdr_t)+cpy_len);
            locators_list[ctr] = locators_list[ctr]->next;

        }
    }
    return ((void *)loc_ptr);
}


/*
 * lispd_mapping_elt set/get functions
 */

inline mapping_t *mapping_new() {
    mapping_t *mapping;
    mapping = calloc(1, sizeof(mapping_t));
    return(mapping);
}

inline mapping_t *mapping_init(lisp_addr_t *eid) {
    mapping_t *mapping;
    mapping = mapping_new();
    if (!mapping)
        return(NULL);

    lisp_addr_copy(&(mapping->eid_prefix), eid);
    if (lisp_addr_get_afi(&mapping->eid_prefix) == LM_AFI_IP)
        lisp_addr_ip_to_ippref(&mapping->eid_prefix);
    return(mapping);
}

mapping_t *mapping_init_local(lisp_addr_t *eid) {
    mapping_t                   *mapping        = NULL;
    lcl_mapping_extended_info   *extended_info  = NULL;

    mapping = mapping_init(eid);

    if (!mapping) {
        lispd_log_msg(LISP_LOG_WARNING, "mapping_init_local: Can't allocate mapping!");
        return(NULL);
    }

    mapping->type = MAPPING_LOCAL;

    if (!(extended_info=(lcl_mapping_extended_info *)malloc(sizeof(lcl_mapping_extended_info)))){
        lispd_log_msg(LISP_LOG_WARNING,"mapping_init_local: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        free(mapping);
        return(NULL);
    }

    mapping->extended_info = (void *)extended_info;

    extended_info->outgoing_balancing_locators_vecs.v4_balancing_locators_vec = NULL;
    extended_info->outgoing_balancing_locators_vecs.v6_balancing_locators_vec = NULL;
    extended_info->outgoing_balancing_locators_vecs.balancing_locators_vec = NULL;
    extended_info->outgoing_balancing_locators_vecs.v4_locators_vec_length = 0;
    extended_info->outgoing_balancing_locators_vecs.v6_locators_vec_length = 0;
    extended_info->outgoing_balancing_locators_vecs.locators_vec_length = 0;
    extended_info->head_not_init_locators_list = NULL;

    return (mapping);
}

mapping_t *mapping_init_static(lisp_addr_t *eid) {
    mapping_t                   *mapping        = NULL;
    rmt_mapping_extended_info   *extended_info  = NULL;

    mapping = mapping_init(eid);

    if (!mapping) {
        lispd_log_msg(LISP_LOG_WARNING, "mapping_init_static: Can't allocate mapping!");
        return(NULL);
    }

    /* although static, it contains remote data */
    mapping->type = MAPPING_REMOTE;

    if ((extended_info=(rmt_mapping_extended_info *)malloc(sizeof(rmt_mapping_extended_info)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"mapping_init_learned: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        free (mapping);
        return (NULL);
    }

    mapping->extended_info = (void *)extended_info;
    extended_info->rmt_balancing_locators_vecs.v4_balancing_locators_vec = NULL;
    extended_info->rmt_balancing_locators_vecs.v6_balancing_locators_vec = NULL;
    extended_info->rmt_balancing_locators_vecs.balancing_locators_vec = NULL;
    extended_info->rmt_balancing_locators_vecs.v4_locators_vec_length = 0;
    extended_info->rmt_balancing_locators_vecs.v6_locators_vec_length = 0;
    extended_info->rmt_balancing_locators_vecs.locators_vec_length = 0;

    return (mapping);
}

mapping_t *mapping_init_remote(lisp_addr_t *eid) {
    mapping_t                   *mapping        = NULL;
    rmt_mapping_extended_info   *extended_info  = NULL;

    mapping = mapping_init(eid);

    if (!mapping) {
        lispd_log_msg(LISP_LOG_WARNING, "mapping_init_learned: Can't allocate mapping!");
        return(NULL);
    }

    mapping->type = MAPPING_REMOTE;

    if ((extended_info=(rmt_mapping_extended_info *)malloc(sizeof(rmt_mapping_extended_info)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"mapping_init_learned: Couldn't allocate memory for lcl_mapping_extended_info: %s", strerror(errno));
        free (mapping);
        return (NULL);
    }

    mapping->extended_info = (void *)extended_info;
    extended_info->rmt_balancing_locators_vecs.v4_balancing_locators_vec = NULL;
    extended_info->rmt_balancing_locators_vecs.v6_balancing_locators_vec = NULL;
    extended_info->rmt_balancing_locators_vecs.balancing_locators_vec = NULL;
    extended_info->rmt_balancing_locators_vecs.v4_locators_vec_length = 0;
    extended_info->rmt_balancing_locators_vecs.v6_locators_vec_length = 0;
    extended_info->rmt_balancing_locators_vecs.locators_vec_length = 0;

//    if (locators) {
//        mapping_add_locators(mapping, locators);
//
//        /* [re]Calculate balancing locator vectors  if it is not a negative map reply*/
//        if (mapping->locator_count != 0){
//            calculate_balancing_vectors(mapping,
//                    &(((rmt_mapping_extended_info *)mapping->extended_info)->rmt_balancing_locators_vecs));
//        }
//    }

    return (mapping);
}

inline void *mapping_extended_info(mapping_t *mapping) {
    return(mapping->extended_info);
}

inline void mapping_set_extended_info(mapping_t *mapping, void *extended_info, extended_info_del_fct ei_del_fct) {
    mapping->extended_info = extended_info;
    mapping->extended_info_del = ei_del_fct;
}

inline void mapping_set_iid(mapping_t *mapping, lisp_iid_t iid) {
    assert(mapping);
    mapping->iid = iid;
}

inline void mapping_set_eid_addr(mapping_t *mapping, lisp_addr_t *addr) {
    lisp_addr_copy(mapping_eid(mapping), addr);
}

inline void mapping_set_eid_plen(mapping_t *mapping, uint8_t plen) {
    assert(mapping);
    mapping->eid_prefix_length = plen;
}

inline lisp_addr_t *mapping_eid(mapping_t *mapping) {
    assert(mapping);
    return(&(mapping->eid_prefix));
}

inline uint16_t mapping_get_locator_count(mapping_t *mapping) {
    assert(mapping);
    return(mapping->locator_count);
}


int mapping_get_size_in_record(mapping_t *mapping) {
    int locs_length = 0;

    if (!mapping)
        return(0);
    if (mapping->head_v4_locators_list)
        locs_length += locator_list_get_size_in_field(mapping->head_v4_locators_list);
    if (mapping->head_v6_locators_list)
        locs_length += locator_list_get_size_in_field(mapping->head_v6_locators_list);

    return(sizeof(mapping_record_hdr_t) + lisp_addr_get_size_in_field(mapping_eid(mapping)) + locs_length);
}

mapping_t *mapping_init_from_record(mapping_record *record) {
    mapping_t           *mapping    = NULL;
    lisp_addr_t         *eid        = NULL;
    glist_t             *locs       = NULL;
    glist_entry_t       *it         = NULL;
    locator_t           *loc        = NULL;

    eid = lisp_addr_init_from_field(mapping_record_eid(record));
    if (!eid)
        goto err;
    if (lisp_addr_get_afi(eid) == LM_AFI_IP)
        lisp_addr_set_plen(eid, mapping_record_hdr(record)->eid_prefix_length);
    lispd_log_msg(LISP_LOG_DEBUG_1, "  EID: %s", lisp_addr_to_char(eid));

    mapping = mapping_init(eid);
    if (!mapping)
        goto err;

    locs = mapping_record_locators(record);
    glist_for_each_entry(it, locs) {
        if (!(loc = locator_init_from_field(glist_entry_data(it))))
            goto err;
        lispd_log_msg(LISP_LOG_DEBUG_1, "    RLOC: %s", locator_to_char(loc));
        if (add_locator_to_mapping(mapping, loc) != GOOD)
            goto err;
    }
    return(mapping);

err:
    if (eid)
        lisp_addr_del(eid);
    if (mapping)
        mapping_del(mapping);
    return(NULL);
}

void mapping_del(mapping_t *mapping)
{
    /* Free the locators list*/
    free_locator_list(mapping->head_v4_locators_list);
    free_locator_list(mapping->head_v6_locators_list);

    if (mapping->extended_info) {
        switch (mapping->type) {
        case MAPPING_LOCAL:
            free_locator_list(((lcl_mapping_extended_info *)mapping->extended_info)->head_not_init_locators_list);
            free_balancing_locators_vecs(((lcl_mapping_extended_info *)mapping->extended_info)->outgoing_balancing_locators_vecs);
            free ((lcl_mapping_extended_info *)mapping->extended_info);
            break;
        case MAPPING_REMOTE:
            free_balancing_locators_vecs(((rmt_mapping_extended_info *)mapping->extended_info)->rmt_balancing_locators_vecs);
            free ((rmt_mapping_extended_info *)mapping->extended_info);
            break;
        case MAPPING_RE:
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_1, "mapping_del: unknown mapping type %d. Can't free extended info!", mapping->type);
            break;
        }
    }

    /* RE is not a type, it sets its own destruct function for the extended info */
    if (mapping->extended_info)
        mapping->extended_info_del(mapping->extended_info);

    /* XXX ^2: lisp_addr_t unfortunately is not a pointer in mapping, need hack to free lcaf */
    if (lisp_addr_get_afi(mapping_eid(mapping)) == LM_AFI_LCAF)
        lcaf_addr_del_addr(lisp_addr_get_lcaf(mapping_eid(mapping)));
    free(mapping);

}


void mapping_update_locators(mapping_t *mapping, lispd_locators_list *locv4, lispd_locators_list *locv6, int nb_locators) {
    if (!mapping)
        return;

    /* TODO: do a comparison first */
    if (mapping->head_v4_locators_list)
        free_locator_list(mapping->head_v4_locators_list);
    if (mapping->head_v6_locators_list)
        free_locator_list(mapping->head_v6_locators_list);
    mapping->head_v4_locators_list = locv4;
    mapping->head_v6_locators_list = locv6;
    mapping->locator_count = nb_locators;
}

/* [re]Calculate balancing locator vectors  if it is not a negative map reply*/
void mapping_compute_balancing_vectors(mapping_t *mapping) {
    if (!mapping->extended_info)
        mapping->extended_info = calloc(1, sizeof(rmt_mapping_extended_info));
    if (mapping->locator_count != 0)
        calculate_balancing_vectors(mapping,
                &(((rmt_mapping_extended_info *)mapping->extended_info)->rmt_balancing_locators_vecs));


}

/*
 * compare two mappings
 * returns 0 if they are the same and 1 otherwise
 */
int mapping_cmp(mapping_t *m1, mapping_t *m2) {
    int                 ret = 0, ctr =0;
    lispd_locators_list *ll1[2] = {NULL, NULL}, *ll2[2] = {NULL, NULL};
    locator_t           *l1 = NULL, *l2 = NULL;

    if ((ret = lisp_addr_cmp(mapping_eid(m1), mapping_eid(m2)))!= 0)
        return(1);
    if (m1->locator_count != m2->locator_count)
        return(1);

    ll1[0] = m1->head_v4_locators_list;
    ll1[1] = m1->head_v6_locators_list;

    ll2[0] = m2->head_v4_locators_list;
    ll2[1] = m2->head_v6_locators_list;

    for (ctr = 0 ; ctr < 2 ; ctr++){
        while (ll1[ctr] && ll2[ctr]) {
            l1  = ll1[ctr]->locator;
            l2  = ll2[ctr]->locator;
            if ((ret = locator_cmp(l1, l2)) != 0 )
                return(ret);
            ll1[ctr] = ll1[ctr]->next;
            ll2[ctr] = ll2[ctr]->next;
        }

        if ((ll1[ctr] && !ll2[ctr]) || (!ll1[ctr] && ll2[ctr]))
            return(1);
    }
    return(0);

}
///* clones a mapping, but copies just eid and locators */
//mapping_t *mapping_clone_simple(mapping_t *mapping) {
//    mapping_t *copy = mapping_init(mapping_eid(mapping));
//    copy->head_v4_locators_list = locator_list_clone(mapping->head_v4_locators_list);
//    copy->head_v6_locators_list = locator_list_clone(mapping->head_v6_locators_list);
//    return(copy);
//}

///* write in an allocated record */
//void mapping_write_to_record(mapping_record *record, mapping_t *mapping) {
//    address_field       *eidf               = NULL;
//    locator_field       *locf               = NULL;
//    lispd_locators_list *locators_list[2]   = {NULL,NULL};
//    int ctr;
//
//    mapping_record_hdr(record)->ttl                    = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
//    mapping_record_hdr(record)->locator_count          = mapping->locator_count;
//    mapping_record_hdr(record)->eid_prefix_length      = lisp_addr_get_plen(mapping_eid(mapping));
//    mapping_record_hdr(record)->action                 = 0;
//    mapping_record_hdr(record)->authoritative          = 0; /* to be filled outside */
//    mapping_record_hdr(record)->version_hi             = 0;
//    mapping_record_hdr(record)->version_low            = 0;
//
//    eidf = mapping_record_eid(record);
//    address_field_set_len(eidf, lisp_addr_write(address_field_data(eidf), mapping_eid(mapping)));
//
//    locators_list[0] = mapping->head_v4_locators_list;
//    locators_list[1] = mapping->head_v6_locators_list;
//    for (ctr = 0 ; ctr < 2 ; ctr++){
//        while (locators_list[ctr]) {
//            locf = mapping_record_allocate_locator(record, locator_get_size_in_field(locators_list[ctr]->locator));
//            locator_write_to_field(locators_list[ctr]->locator, locf);
////            if (probed_rloc != NULL && lisp_addr_cmp(locator->locator_addr,probed_rloc)==0)
////                loc_ptr->probed  = 1;
//            locators_list[ctr] = locators_list[ctr]->next;
//        }
//    }
//
//    mapping_record_update_len(mapping);
//}

