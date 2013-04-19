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

#include "lispd_afi.h"
#include "lispd_lib.h"
#include "lispd_locator.h"
#include "lispd_log.h"


inline lcl_locator_extended_info *new_lcl_locator_extended_info(int out_socket);
inline rmt_locator_extended_info *new_rmt_locator_extended_info();
inline void free_rmt_locator_extended_info(rmt_locator_extended_info *extenden_info);

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
        int                         out_socket)
{
    lispd_locator_elt       *locator                = NULL;

    if ((locator = malloc(sizeof(lispd_locator_elt))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_local_locator: Unable to allocate memory for lispd_locator_elt: %s", strerror(errno));
        return(NULL);
    }



    /* Initialize locator */
    locator->locator_addr = locator_addr;
    locator->locator_type = LOCAL_LOCATOR;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    locator->data_packets_in = 0;
    locator->data_packets_out = 0;
    locator->state = state;

    locator->extended_info = (void *)new_lcl_locator_extended_info(out_socket);
    if (locator->extended_info == NULL){
        free (locator);
        return (NULL);
    }


    return (locator);
}


/*
 * Generets a "remote" locator element. Remote locators should reserve memory for address and state.
 * Afi information (address) is read from the packet (afi_ptr)
 */

lispd_locator_elt   *new_rmt_locator (
        uint8_t                     **afi_ptr,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight)
{
    lispd_locator_elt       *locator                = NULL;

    if ((locator = malloc(sizeof(lispd_locator_elt))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_rmt_locator: Unable to allocate memory for lispd_locator_elt: %s", strerror(errno));
        return(NULL);
    }

    if((locator->locator_addr = malloc(sizeof(lisp_addr_t))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_rmt_locator: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
        free (locator);
        return (NULL);
    }

    if((locator->state = malloc(sizeof(uint8_t))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_rmt_locator: Unable to allocate memory for uint8_t: %s", strerror(errno));
        free (locator->locator_addr);
        free (locator);
        return (NULL);
    }

    /* Read the afi information (locator address) from the packet */
    if ((err=pkt_process_rloc_afi(afi_ptr,locator)) != GOOD){
        free (locator->locator_addr);
        free (locator);
        return (NULL);
    }

    locator->extended_info = (void *)new_rmt_locator_extended_info();
    if (locator->extended_info == NULL){
        free (locator->locator_addr);
        free (locator->state);
        free (locator);
        return (NULL);
    }

    *(locator->state) = state;
    locator->locator_type = DYNAMIC_LOCATOR;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    locator->data_packets_in = 0;
    locator->data_packets_out = 0;

    return (locator);
}

lispd_locator_elt   *new_static_rmt_locator (
        char                        *rloc_addr,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight)
{
    lispd_locator_elt       *locator                = NULL;

    if ((locator = malloc(sizeof(lispd_locator_elt))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_static_rmt_locator: Unable to allocate memory for lispd_locator_elt: %s", strerror(errno));
        return(NULL);
    }

    if((locator->locator_addr = malloc(sizeof(lisp_addr_t))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_static_rmt_locator: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
        free (locator);
        return (NULL);
    }

    if((locator->state = malloc(sizeof(uint8_t))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_static_rmt_locator: Unable to allocate memory for uint8_t: %s", strerror(errno));
        free (locator->locator_addr);
        free (locator);
        return (NULL);
    }

    if (get_lisp_addr_from_char(rloc_addr,locator->locator_addr) == BAD){
        lispd_log_msg(LISP_LOG_ERR, "new_static_rmt_locator: Error parsing RLOC address ... Ignoring static map cache entry");
        free (locator->locator_addr);
        free (locator->state);
        free (locator);
        return (NULL);
    }

    locator->extended_info = (void *)new_rmt_locator_extended_info();
    if (locator->extended_info == NULL){
        free (locator->locator_addr);
        free (locator->state);
        free (locator);
        return (NULL);
    }

    *(locator->state) = state;
    locator->locator_type = STATIC_LOCATOR;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    locator->data_packets_in = 0;
    locator->data_packets_out = 0;

    return (locator);
}

inline lcl_locator_extended_info *new_lcl_locator_extended_info(int out_socket)
{
    lcl_locator_extended_info *lcl_loc_ext_inf;
    if ((lcl_loc_ext_inf = (lcl_locator_extended_info *)malloc(sizeof(lcl_locator_extended_info))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "lcl_locator_extended_info: Unable to allocate memory for rmt_locator_extended_info: %s", strerror(errno));
        return(NULL);
    }
    lcl_loc_ext_inf->out_socket = out_socket;

    return lcl_loc_ext_inf;
}


inline rmt_locator_extended_info *new_rmt_locator_extended_info()
{
    rmt_locator_extended_info *rmt_loc_ext_inf;
    if ((rmt_loc_ext_inf = (rmt_locator_extended_info *)malloc(sizeof(rmt_locator_extended_info))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_rmt_locator_extended_info: Unable to allocate memory for rmt_locator_extended_info: %s", strerror(errno));
        return(NULL);
    }
    rmt_loc_ext_inf->rloc_probing_nonces = NULL;

    return rmt_loc_ext_inf;
}




/*
 * Free memory of lispd_locator.
 */

void free_locator(lispd_locator_elt   *locator)
{

    if (locator->locator_type == STATIC_LOCATOR || locator->locator_type == DYNAMIC_LOCATOR || locator->locator_type ==PETR_LOCATOR){
        free_rmt_locator_extended_info((rmt_locator_extended_info*)locator->extended_info);
    }
    if (locator->locator_type != LOCAL_LOCATOR){
        free (locator->locator_addr);
        free (locator->state);
    }
    free (locator);
}

inline void free_rmt_locator_extended_info(rmt_locator_extended_info *extenden_info)
{
    if (extenden_info->rloc_probing_nonces != NULL){
        free (extenden_info->rloc_probing_nonces);
    }
    free (extenden_info);
}

void dump_locator (
        lispd_locator_elt   *locator,
        int                 log_level)
{
    char locator_str [2000];
    if (is_loggable(log_level)){
        sprintf(locator_str, "| %39s |", get_char_from_lisp_addr_t(*(locator->locator_addr)));
        sprintf(locator_str + strlen(locator_str), "  %5s ", locator->state ? "Up" : "Down");
        sprintf(locator_str + strlen(locator_str), "|     %3d/%-3d     |", locator->priority, locator->weight);
        lispd_log_msg(log_level,"%s",locator_str);
    }
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
    if (locator->locator_type == LOCAL_LOCATOR &&
            locator->locator_addr->afi != AF_UNSPEC){ /* If it's a local initialized locator, we should store it in order*/
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
    }else{ /* Remote locators and not initialized local locators */
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
 * Extract the locator from a locators list that match with the address.
 * The locator is removed from the list
 */
lispd_locator_elt *extract_locator_from_list(
        lispd_locators_list     **head_locator_list,
        lisp_addr_t             addr)
{
    lispd_locator_elt       *locator                = NULL;
    lispd_locators_list     *locator_list           = NULL;
    lispd_locators_list     *prev_locator_list_elt  = NULL;

    locator_list = *head_locator_list;
    while (locator_list != NULL){
        if (compare_lisp_addr_t(locator_list->locator->locator_addr,&addr)==0){
            locator = locator_list->locator;
            /* Extract the locator from the list */
            if (prev_locator_list_elt != NULL){
                prev_locator_list_elt->next = locator_list->next;
            }else{
                *head_locator_list = locator_list->next;
            }
            free (locator_list);
            break;
        }
        prev_locator_list_elt = locator_list;
        locator_list = locator_list->next;
    }
    return (locator);
}

/*
 * Free memory of lispd_locator_list.
 */

void free_locator_list(lispd_locators_list     *locator_list)
{
    lispd_locators_list  * aux_locator_list     = NULL;
    /*
     * Free the locators
     */
    while (locator_list)
    {
        aux_locator_list = locator_list->next;
        free_locator(locator_list->locator);
        free (locator_list);
        locator_list = aux_locator_list;
    }
}


