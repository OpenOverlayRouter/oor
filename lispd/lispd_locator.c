/*
 * lispd_locator.c
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
#include "lispd_locator.h"
#include "lispd_log.h"

/*
 * Generets a locator element
 */

lispd_locator_elt   *new_locator (
        lisp_addr_t                 *locator_addr,
        uint8_t                     *state,    /* UP , DOWN */
        uint8_t                     locator_type,
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight)
{
    lispd_locator_elt       *locator                = NULL;

    if ((locator = malloc(sizeof(lispd_locator_elt))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_locator: Unable to allocate memory for lispd_locator_elt: %s", strerror(errno));
        return(NULL);
    }

    /* Initialize locator */
    locator->locator_addr = locator_addr;
    locator->locator_type = locator_type;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    locator->data_packets_in = 0;
    locator->data_packets_out = 0;
    locator->rloc_probing_nonces = NULL;
    locator->state = state;

    return (locator);
}

/*
 * Generets a locator element. For the remote locators, we have to reserve memory for address and state.
 */

lispd_locator_elt   *new_rmt_locator (
        lisp_addr_t                 address,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     locator_type,
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight)
{
    lispd_locator_elt       *locator                = NULL;

    if ((locator = malloc(sizeof(lispd_locator_elt))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_locator: Unable to allocate memory for lispd_locator_elt: %s", strerror(errno));
        return(NULL);
    }

    if((locator->locator_addr = malloc(sizeof(lisp_addr_t))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"process_map_reply_locator: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
        free (locator);
        return (NULL);
    }

    if((locator->state = malloc(sizeof(uint8_t))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"process_map_reply_locator: Unable to allocate memory for uint8_t: %s", strerror(errno));
        free (locator->locator_addr);
        free (locator);
        return (NULL);
    }

    /* Initialize locator */
    copy_lisp_addr_t(locator->locator_addr, &address, FALSE);
    *(locator->state) = state;
    locator->locator_type = locator_type;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    locator->data_packets_in = 0;
    locator->data_packets_out = 0;
    locator->rloc_probing_nonces = NULL;


    return (locator);
}


/*
 * Free memory of lispd_locator.
 */

void free_locator(lispd_locator_elt   *locator)
{

    if (locator->rloc_probing_nonces){
        free (locator->rloc_probing_nonces);
    }
    if (locator->locator_type != LOCAL_LOCATOR){
        free (locator->locator_addr);
        free (locator->state);
    }
    free (locator);
}

void dump_locator (
        lispd_locator_elt   *locator,
        int                 log_level)
{
    lispd_log_msg(log_level," %15s ", get_char_from_lisp_addr_t(*(locator->locator_addr)));
    if (locator->locator_addr->afi == AF_INET)
        lispd_log_msg(log_level," %15s ", locator->state ? "Up" : "Down");
    else
        lispd_log_msg(log_level," %5s ", locator->state ? "Up" : "Down");
    lispd_log_msg(log_level,"         %3d/%-3d \n", locator->priority, locator->weight);
}

/**********************************  LOCATORS LISTS FUNCTIONS ******************************************/

/*
 * Add a locator to a locators list
 */
int add_locator_to_list (
        lispd_locators_list         **list,
        lispd_locator_elt           *locator)
{
    lispd_locators_list     *locator_list           = NULL,
                            *aux_locator_list_prev  = NULL,
                            *aux_locator_list_next  = NULL;
    int                     cmp                     = 0;

    if ((locator_list = malloc(sizeof(lispd_locators_list))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "add_locator_to_list: Unable to allocate memory for lispd_locator_list: %s", strerror(errno));
        return(ERR_MALLOC);
    }

    locator_list->next = NULL;
    locator_list->locator = locator;

    if (locator->locator_type == LOCAL_LOCATOR){/* If it's a local locator, we should store it in order*/
        if (*list == NULL){
            *list = locator_list;
        }else{
            aux_locator_list_prev = NULL;
            aux_locator_list_next = *list;
            while (aux_locator_list_next != NULL){
                if (locator->locator_addr->afi == AF_INET){
                    cmp = memcmp(&(locator->locator_addr->address.ip),&(aux_locator_list_next->locator->locator_addr->address.ip),sizeof(struct in_addr));
                } else {
                    cmp = memcmp(&(locator->locator_addr->address.ipv6),&(aux_locator_list_next->locator->locator_addr->address.ipv6),sizeof(struct in6_addr));
                }
                if (cmp < 0){
                    break;
                }
                if (cmp == 0){
                    lispd_log_msg(LISP_LOG_DEBUG_3, "add_locator_to_list: The locator %s already exists.",
                            get_char_from_lisp_addr_t(*(locator->locator_addr)));
                    free (locator_list);
                    return (ERR_EXIST);
                }
                aux_locator_list_prev = aux_locator_list_next;
                aux_locator_list_next = aux_locator_list_next->next;
            }
            if (aux_locator_list_prev == NULL){
                locator_list->next = aux_locator_list_next;
                *list = locator_list;
            }else{
                aux_locator_list_prev->next = locator_list;
                locator_list->next = aux_locator_list_next;
            }
        }
    }else{
        if (*list == NULL){
            *list = locator_list;
        }else{
            aux_locator_list_prev = *list;
            while (aux_locator_list_prev->next != NULL){
                aux_locator_list_prev = aux_locator_list_prev->next;
            }
            aux_locator_list_prev->next = locator_list;
        }
    }

    return (GOOD);
}



/*
 * Free memory of lispd_locator_list.
 */

void free_locator_list(lispd_locators_list     *list)
{
    lispd_locators_list  * locator_list     = NULL,
                         *aux_locator_list  = NULL;
    /*
     * Free the locators
     */
    locator_list = list;
    while (locator_list)
    {
        free_locator(locator_list->locator);
        aux_locator_list = locator_list;
        locator_list = locator_list->next;
        free (aux_locator_list);
    }
}


