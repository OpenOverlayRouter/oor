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
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_locator.h"
#include "lispd_log.h"

/*********************************** FUNCTIONS DECLARATION ************************/

/*
 * Reseve and fill the memory required by a lcl_locator_extended_info
 */
inline lcl_locator_extended_info *new_lcl_locator_extended_info(int *out_socket);

/*
 * Reseve and fill the memory required by a rmt_locator_extended_info
 */
inline rmt_locator_extended_info *new_rmt_locator_extended_info();

/*
 * Generates a clone of local localtor extended info
 */
lcl_locator_extended_info *copy_lcl_locator_extended_info(lcl_locator_extended_info *extended_info);

/*
 * Generates a clone of a rtr localtors list. Timers and nonces not cloned
 */
lispd_rtr_locators_list *copy_rtr_locators_list(lispd_rtr_locators_list *rtr_list);

/*
 * Generates a clone of remote localtor extended info. Timers and nonces not cloned
 */
rmt_locator_extended_info *copy_rmt_locator_extended_info(rmt_locator_extended_info *extended_info);

/*
 * Free memory of a lcl_locator_extended_info structure
 */
inline void free_lcl_locator_extended_info(lcl_locator_extended_info *extended_info);

/*
 * Free memory of a rmt_locator_extended_info structure
 */
inline void free_rmt_locator_extended_info(rmt_locator_extended_info *extended_info);

/**********************************************************************************/

/*
 * Generates the general structure of the locator without extended info
 */
lispd_locator_elt   *new_locator (
        lisp_addr_t                 *locator_addr,
        uint8_t                     *state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight)
{
    lispd_locator_elt       *locator                = NULL;

    if ((locator = calloc(1,sizeof(lispd_locator_elt))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_locator: Unable to allocate memory for lispd_locator_elt: %s", strerror(errno));
        err = ERR_MALLOC;
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
    locator->extended_info = NULL;

    return (locator);
}

/*
 * Generates a local locator element
 */
lispd_locator_elt   *new_local_locator (
        lisp_addr_t                 *locator_addr,
        uint8_t                     *state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight,
        int                         *out_socket)
{
    lispd_locator_elt       *locator                = NULL;

    locator = new_locator (locator_addr, state, priority, weight, mpriority, mweight);

    if (locator == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "new_local_locator: Unable to generate lispd_locator_elt: %s", strerror(errno));
        return(NULL);
    }

    locator->extended_info = (void *)new_lcl_locator_extended_info(out_socket);
    if (locator->extended_info == NULL){
        free_locator (locator);
        return (NULL);
    }

    locator->locator_type = LOCAL_LOCATOR;

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
        err = ERR_MALLOC;
        return(NULL);
    }

    if((locator->locator_addr = malloc(sizeof(lisp_addr_t))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_rmt_locator: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
        free (locator);
        err = ERR_MALLOC;
        return (NULL);
    }

    if((locator->state = malloc(sizeof(uint8_t))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_rmt_locator: Unable to allocate memory for uint8_t: %s", strerror(errno));
        free (locator->locator_addr);
        free (locator);
        err = ERR_MALLOC;
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

/*
 * Generates a static locator element. This is used when creating static mappings
 */
lispd_locator_elt   *new_static_rmt_locator (
        lisp_addr_t                 *locator_addr,
        uint8_t                     state,    /* UP , DOWN */
        uint8_t                     priority,
        uint8_t                     weight,
        uint8_t                     mpriority,
        uint8_t                     mweight)
{
    lispd_locator_elt       *locator                = NULL;
    uint8_t                 *locator_state          = NULL;

    /* Reserve and init the locator state */

    if((locator_state = (uint8_t *)malloc(sizeof(uint8_t))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_static_rmt_locator: Unable to allocate memory for uint8_t: %s", strerror(errno));
        err = ERR_MALLOC;
        return (NULL);
    }

    *locator_state = state;

    /* Generate the general lispd_locator_elt structure */

    locator = new_locator (locator_addr, locator_state, priority, weight, mpriority, mweight);

    if (locator == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "new_static_rmt_locator: Unable to generate lispd_locator_elt: %s", strerror(errno));
        free(locator_state);
        return(NULL);
    }

    locator->locator_type = STATIC_LOCATOR;
    locator->extended_info = (void *)new_rmt_locator_extended_info();
    if (locator->extended_info == NULL){
        // We don't use free_locator function because the locator address is allocated outside this function and it should
        // be released by the caller of this function
        free(locator_state);
        free(locator);
        return (NULL);
    }

    return (locator);
}

/*
 * Generates a clone of a locator element. Parameters like timers or nonces are not cloned
 */
lispd_locator_elt *copy_locator_elt(lispd_locator_elt *loc)
{
    lispd_locator_elt   *locator    = NULL;
    lisp_addr_t         *addr       = NULL;
    uint8_t             *state      = NULL;
    if (loc->locator_type != LOCAL_LOCATOR){
        addr = (lisp_addr_t *)malloc(sizeof(lisp_addr_t));
        if (addr == NULL){
            err = ERR_MALLOC;
            return (NULL);
        }
        state = calloc(sizeof(uint8_t),1);
        if (state == NULL){
            free(addr);
            err = ERR_MALLOC;
            return (NULL);
        }
        copy_lisp_addr(addr,loc->locator_addr);
        *state = *(loc->state);
    }else{// If it is a local locator, address ans state are linked to the interface
        addr = loc->locator_addr;
        state = loc->state;
    }
    locator = new_locator(
            addr,
            state,
            loc->priority,
            loc->weight,
            loc->mpriority,
            loc->mweight);
    if (locator == NULL){
        if (loc->locator_type != LOCAL_LOCATOR){
            free(addr);
            free(state);
        }
        return (NULL);
    }
    locator->locator_type = loc->locator_type;
    if (loc->extended_info != NULL){
        if (locator->locator_type == LOCAL_LOCATOR){
            locator->extended_info = (void *)copy_lcl_locator_extended_info((lcl_locator_extended_info *)loc->extended_info);
        }else{
            locator->extended_info = (void *)copy_rmt_locator_extended_info((rmt_locator_extended_info *)loc->extended_info);
        }
    }

    return (locator);
}



/*
 * Reseve and fill the memory required by a lcl_locator_extended_info
 */
inline lcl_locator_extended_info *new_lcl_locator_extended_info(int *out_socket)
{
    lcl_locator_extended_info *lcl_loc_ext_inf;
    if ((lcl_loc_ext_inf = (lcl_locator_extended_info *)calloc(1,sizeof(lcl_locator_extended_info))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "lcl_locator_extended_info: Unable to allocate memory for rmt_locator_extended_info: %s", strerror(errno));
        err = ERR_MALLOC;
        return(NULL);
    }
    lcl_loc_ext_inf->out_socket = out_socket;
    if (nat_aware == TRUE){
        lcl_loc_ext_inf->nat_info = new_nat_info_str(UNKNOWN, NULL, NULL);

        if (lcl_loc_ext_inf->nat_info == NULL){
            free(lcl_loc_ext_inf);
            err = ERR_MALLOC;
            return(NULL);
        }
    }else{
        lcl_loc_ext_inf->nat_info = NULL;
    }

    return lcl_loc_ext_inf;
}

/*
 * Generates a clone of local localtor extended info
 */
lcl_locator_extended_info *copy_lcl_locator_extended_info(lcl_locator_extended_info *extended_info)
{
    lcl_locator_extended_info *lcl_extended_info = NULL;

    lcl_extended_info = new_lcl_locator_extended_info(extended_info->out_socket);
    if (lcl_extended_info == NULL){
        return (NULL);
    }
    if (extended_info->nat_info != NULL){
        if ((extended_info->nat_info = copy_nat_info_str(extended_info->nat_info)) == NULL){
            free_lcl_locator_extended_info(lcl_extended_info);
            return (NULL);
        }
    }

    return (lcl_extended_info);
}

/*
 * Reseve and fill the memory required by a rmt_locator_extended_info
 */
inline rmt_locator_extended_info *new_rmt_locator_extended_info()
{
    rmt_locator_extended_info *rmt_loc_ext_inf;
    if ((rmt_loc_ext_inf = (rmt_locator_extended_info *)malloc(sizeof(rmt_locator_extended_info))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_rmt_locator_extended_info: Unable to allocate memory for rmt_locator_extended_info: %s", strerror(errno));
        err = ERR_MALLOC;
        return(NULL);
    }
    rmt_loc_ext_inf->rloc_probing_nonces = NULL;
    rmt_loc_ext_inf->probe_timer = NULL;

    return rmt_loc_ext_inf;
}

/*
 * Generates a clone of remote localtor extended info
 */
rmt_locator_extended_info *copy_rmt_locator_extended_info(rmt_locator_extended_info *extended_info)
{
    rmt_locator_extended_info *rmt_extended_info = NULL;

    rmt_extended_info = new_rmt_locator_extended_info();
    if (rmt_extended_info == NULL){
        return (NULL);
    }

    return (rmt_extended_info);
}

/*
 * Generates a lispd_rtr_locator element with the information of a locator of an RTR router.
 */
lispd_rtr_locator *new_rtr_locator(lisp_addr_t address)
{
    lispd_rtr_locator       *rtr_locator            = NULL;

    rtr_locator = (lispd_rtr_locator *)malloc(sizeof(lispd_rtr_locator));
    if (rtr_locator == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "new_rtr_locator: Unable to allocate memory for lispd_rtr_locator: %s", strerror(errno));
        return (NULL);
    }
    rtr_locator->address = address;
    rtr_locator->latency = 0;
    rtr_locator->state = UP;

    return (rtr_locator);
}

/*
 * Generates a new nat status structure
 */

nat_info_str *new_nat_info_str(
        int                         status,
        lisp_addr_t                 *public_address,
        lispd_rtr_locators_list     *rtr_locators_list)
{
    nat_info_str    *nat_info   = NULL;

    if ((nat_info = (nat_info_str *)calloc(1,sizeof(nat_info_str))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "new_nat_info_str: Unable to allocate memory for nat_info_str: %s", strerror(errno));
        err = ERR_MALLOC;
        return(NULL);
    }
    nat_info->status = status;
    nat_info->rtr_locators_list = rtr_locators_list;
    nat_info->public_addr = public_address;

    return (nat_info);
}


/*
 * Leave in the list, rtr with afi equal to the afi passed as a parameter
 */
void remove_rtr_locators_with_afi_different_to(lispd_rtr_locators_list **rtr_list, int afi)
{
    lispd_rtr_locators_list *rtr_list_elt           = *rtr_list;
    lispd_rtr_locators_list *prev_rtr_list_elt      = NULL;
    lispd_rtr_locators_list *aux_rtr_list_elt       = NULL;

    while (rtr_list_elt != NULL){
        if (rtr_list_elt->locator->address.afi == afi){
            if (prev_rtr_list_elt == NULL){
                prev_rtr_list_elt = rtr_list_elt;
                if(rtr_list_elt != *rtr_list){
                    *rtr_list = rtr_list_elt;
                }
            }else{
                prev_rtr_list_elt->next = rtr_list_elt;
                prev_rtr_list_elt = prev_rtr_list_elt->next;
            }
            rtr_list_elt = rtr_list_elt->next;
        }else{
            aux_rtr_list_elt = rtr_list_elt;
            rtr_list_elt = rtr_list_elt->next;
            free (aux_rtr_list_elt->locator);
            free (aux_rtr_list_elt);
        }
    }
    /* Put the next element of the last rtr_locators_list found with afi X to NULL*/
    if (prev_rtr_list_elt != NULL){
        prev_rtr_list_elt->next = NULL;
    }else{
        *rtr_list = NULL;
    }
}


/*
 * Free memory of lispd_locator.
 */
void free_locator(lispd_locator_elt   *locator)
{
    if (locator == NULL){
        return;
    }
    if (locator->locator_type != LOCAL_LOCATOR){
        free_rmt_locator_extended_info((rmt_locator_extended_info*)locator->extended_info);
        free (locator->locator_addr);
        free (locator->state);
    }else{
        free_lcl_locator_extended_info((lcl_locator_extended_info *)locator->extended_info);
    }
    free (locator);
}

/*
 * Free memory of a lcl_locator_extended_info structure
 */
inline void free_lcl_locator_extended_info(lcl_locator_extended_info *extended_info)
{
    if(extended_info == NULL){
        return;
    }
    if(extended_info->nat_info != NULL){
        free_nat_info_str(extended_info->nat_info);
    }
    free (extended_info);
}

/*
 * Free memory of all the elements of a lispd_rtr_locators_list structure
 */
void free_rtr_list(lispd_rtr_locators_list *rtr_list_elt)
{
    lispd_rtr_locators_list *aux_rtr_list_elt   = NULL;

    while (rtr_list_elt != NULL){
        aux_rtr_list_elt = rtr_list_elt->next;
        if (rtr_list_elt->locator != NULL){
            free(rtr_list_elt->locator);
        }
        free(rtr_list_elt);
        rtr_list_elt = aux_rtr_list_elt;
    }
}

/*
 * Free memory of a nat_info_str structure
 */

void free_nat_info_str(nat_info_str *nat_info)
{
    if (nat_info == NULL){
        return;
    }
    if (nat_info->rtr_locators_list != NULL){
        free_rtr_list(nat_info->rtr_locators_list);
    }
    if (nat_info->public_addr != NULL){
        free(nat_info->public_addr);
    }
    if (nat_info->inf_req_nonce != NULL){
        free(nat_info->inf_req_nonce);
    }
    if (nat_info->inf_req_timer != NULL){
        stop_timer(nat_info->inf_req_timer);
    }
    free(nat_info);
}

/*
 * Generates a clone of a nat_ localtors list. Timers and nonces not cloned
 */
nat_info_str *copy_nat_info_str(nat_info_str *nat_info)
{
    nat_info_str                *new_nat_info       = NULL;
    lispd_rtr_locators_list     *new_rtr_list       = NULL;
    lisp_addr_t                 *new_public_addr    = NULL;


    if ((new_rtr_list = copy_rtr_locators_list(nat_info->rtr_locators_list)) == NULL){
        return (NULL);
    }

    if ((new_public_addr = clone_lisp_addr(nat_info->public_addr)) == NULL){
        free_rtr_list(new_rtr_list);
        return (NULL);
    }

    if ((new_nat_info = new_nat_info_str(nat_info->status, new_public_addr, new_rtr_list))==NULL){
        free_rtr_list(new_rtr_list);
        free(new_public_addr);
        return (NULL);
    }

    return (new_nat_info);
}

/*
 * Free memory of a rmt_locator_extended_info structure
 */
inline void free_rmt_locator_extended_info(rmt_locator_extended_info *extended_info)
{
    if (extended_info == NULL){
        return;
    }
    if (extended_info->probe_timer != NULL){
        stop_timer(extended_info->probe_timer);
        extended_info->probe_timer = NULL;
    }
    if (extended_info->rloc_probing_nonces != NULL){
        free (extended_info->rloc_probing_nonces);
    }
    free (extended_info);
}

/*
 * Print the information of a locator element
 */
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
 * Creates a  lispd_locators_list element
 */
lispd_locators_list *new_locators_list_elt(lispd_locator_elt *locator)
{
    lispd_locators_list       *locator_list_elt                = NULL;

    if((locator_list_elt = (lispd_locators_list *)malloc(sizeof(lispd_locators_list))) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_locators_list_elt: Unable to allocate memory for lispd_locators_list: %s", strerror(errno));
        err = ERR_MALLOC;
        return (NULL);
    }
    locator_list_elt->locator   = locator;
    locator_list_elt->next      = NULL;

    return (locator_list_elt);
}

/*
 * Add a locator to a locators list. If it is a local locator, it is added into the list according to the locator address or rtr address
 */
int add_locator_to_list (
        lispd_locators_list         **list,
        lispd_locator_elt           *locator)
{
    lispd_locators_list     *locator_list           = NULL,
                            *aux_locator_list_prev  = NULL,
                            *aux_locator_list_next  = NULL;
    lisp_addr_t             *addr                   = NULL;
    int                     cmp                     = 0;
    uint8_t                 use_rtr                 = FALSE;

    /* Create the locator list element to be introduced in the list */
    locator_list = new_locators_list_elt(locator);

    if (locator_list == NULL) {
        return(ERR_MALLOC);
    }

    /* Add the locator to the list */
    if (locator->locator_type == LOCAL_LOCATOR &&
            locator->locator_addr->afi != AF_UNSPEC){ /* If it's a local initialized locator, we should store it in order*/
        if (*list == NULL){
            *list = locator_list;
        }else{
            if (nat_aware == TRUE && ((lcl_locator_extended_info *)locator->extended_info)->nat_info->rtr_locators_list != NULL){
                addr = &(((lcl_locator_extended_info *)locator->extended_info)->nat_info->rtr_locators_list->locator->address);
                use_rtr = TRUE;
            }else{
                addr = locator->locator_addr;
            }

            aux_locator_list_prev = NULL;
            aux_locator_list_next = *list;
            while (aux_locator_list_next != NULL){
                if (addr->afi == AF_INET){
                    cmp = memcmp(&(addr->address.ip),&(aux_locator_list_next->locator->locator_addr->address.ip),sizeof(struct in_addr));
                } else {
                    cmp = memcmp(&(addr->address.ipv6),&(aux_locator_list_next->locator->locator_addr->address.ipv6),sizeof(struct in6_addr));
                }
                if (cmp < 0){
                    break;
                }
                if (cmp == 0){
                    if (use_rtr == TRUE){ //XXX For the moment we allow to have two locators using the same RTR
                        break;
                    }
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
 * Reinsert a locator to a locators list. It take into account the presence of RTRs to sort locators
 */
int reinsert_locator_to_list (
        lispd_locators_list         **list,
        lispd_locator_elt           *locator)
{
    if (extract_locator_from_list(list, locator->locator_addr) == NULL){
        return (ERR_NO_EXIST);
    }
    if (add_locator_to_list(list,locator) != GOOD){
        return (BAD);
    }
    return (GOOD);
}

/*
 * Generates a clone of a list of locators.
 */
lispd_locators_list *copy_locators_list(lispd_locators_list *locator_list)
{
    lispd_locators_list *locator_list_elt       = NULL;
    lispd_locators_list *first_locator_list_elt = NULL;
    lispd_locators_list *last_locator_list_elt  = NULL;
    lispd_locator_elt   *locator                = NULL;
    uint8_t             error                   = FALSE;

    while (locator_list != NULL){
        locator = copy_locator_elt(locator_list->locator);
        if (locator == NULL){
            lispd_log_msg(LISP_LOG_WARNING, "clone_locators_list: Unable to allocate memory for lispd_locator_elt");
            error = TRUE;
            break;
        }
        locator_list_elt = new_locators_list_elt(locator);
        if (locator_list_elt == NULL){
            lispd_log_msg(LISP_LOG_WARNING, "clone_locators_list: Unable to allocate memory for lispd_locators_list");
            free_locator (locator);
            error = TRUE;
            break;
        }
        if (first_locator_list_elt == NULL){
            first_locator_list_elt = locator_list_elt;
        }else{
            last_locator_list_elt->next = locator_list_elt;
        }
        last_locator_list_elt = locator_list_elt;
        locator_list = locator_list->next;
    }
    /* If an error has occurred during the cloning process, the partial object is removed */
    if (error == TRUE){
        free_locator_list(first_locator_list_elt);
        first_locator_list_elt = NULL;
    }

    return (first_locator_list_elt);
}

/*
 * Add a rtr localtor to a list of rtr locators
 */
int add_rtr_locator_to_list(
        lispd_rtr_locators_list **rtr_list,
        lispd_rtr_locator       *rtr_locator)
{
    lispd_rtr_locators_list *rtr_locator_list_elt   = NULL;
    lispd_rtr_locators_list *rtr_locator_list       = *rtr_list;

    rtr_locator_list_elt = (lispd_rtr_locators_list *)malloc(sizeof(lispd_rtr_locators_list));
    if (rtr_locator_list_elt == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "new_rtr_locator_list_elt: Unable to allocate memory for lispd_rtr_locators_list: %s", strerror(errno));
        return (BAD);
    }
    rtr_locator_list_elt->locator = rtr_locator;
    rtr_locator_list_elt->next = NULL;
    if (rtr_locator_list != NULL){
        while (rtr_locator_list->next != NULL){
            rtr_locator_list = rtr_locator_list->next;
        }
        rtr_locator_list->next = rtr_locator_list_elt;
    }else{
        *rtr_list = rtr_locator_list_elt;
    }

    return (GOOD);
}

int is_rtr_locator_in_the_list(
		lispd_rtr_locators_list *rtr_list,
		lisp_addr_t             *rtr_addr)
{
	lispd_rtr_locator *rtr = NULL;

	while (rtr_list != NULL){
		rtr = rtr_list->locator;
		if (compare_lisp_addr_t(&(rtr->address),rtr_addr) == 0){
			return (TRUE);
		}
		rtr_list = rtr_list->next;
	}
	return (FALSE);
}

/*
 * Generates a clone of a rtr localtors list.
 */
lispd_rtr_locators_list *copy_rtr_locators_list(lispd_rtr_locators_list *rtr_list)
{
    lispd_rtr_locators_list *rtr_locator_list   = NULL;
    lispd_rtr_locator       *rtr_locator        = NULL;

    while (rtr_list != NULL){
        rtr_locator = new_rtr_locator(rtr_list->locator->address);
        add_rtr_locator_to_list(&rtr_locator_list,rtr_locator);
        rtr_list = rtr_list->next;
    }
    return (rtr_locator_list);
}

/*
 * Extract the locator from a locators list that match with the address.
 * The locator is removed from the list
 */
lispd_locator_elt *extract_locator_from_list(
        lispd_locators_list     **head_locator_list,
        lisp_addr_t             *addr)
{
    lispd_locator_elt       *locator                = NULL;
    lispd_locators_list     *locator_list           = NULL;
    lispd_locators_list     *prev_locator_list_elt  = NULL;

    locator_list = *head_locator_list;
    while (locator_list != NULL){
        if (compare_lisp_addr_t(locator_list->locator->locator_addr,addr)==0){
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
 * Return the locator from the list that contains the address passed as a parameter
 */
lispd_locator_elt *get_locator_from_list(
        lispd_locators_list    *locator_list,
        lisp_addr_t            *addr)
{
    lispd_locator_elt       *locator                = NULL;
    int                     cmp                     = 0;

    while (locator_list != NULL){
        cmp = compare_lisp_addr_t(locator_list->locator->locator_addr,addr);
        if (cmp == 0){
            locator = locator_list->locator;
            break;
        }else if (cmp == 1){
            break;
        }
        locator_list = locator_list->next;
    }
    return (locator);
}


lispd_locator_elt *nat_get_locator_with_nonce(
        lispd_locators_list    *locator_list,
        uint64_t                nonce)
{
    lispd_locator_elt           *locator    = NULL;
    lcl_locator_extended_info   *ext_info   = NULL;

    while (locator_list != NULL){
        locator = locator_list->locator;
        ext_info = (lcl_locator_extended_info *)(locator->extended_info);
        if (ext_info->nat_info != NULL && check_nonce(ext_info->nat_info->inf_req_nonce,nonce) == GOOD){
            return (locator);
        }
        locator_list = locator_list->next;
    }

    return (NULL);
}



int remove_locator_from_list(
        lispd_locators_list    **head_locator_list,
        lisp_addr_t            *addr)
{
	lispd_locators_list		*locator_list			= *head_locator_list;
	lispd_locators_list		*prev_locator_list		= NULL;
    lispd_locator_elt       *locator                = NULL;
    int                     cmp                     = 0;
    int 					result					= BAD;

    while (locator_list != NULL){
        cmp = compare_lisp_addr_t(locator_list->locator->locator_addr,addr);
        if (cmp == 0){
            locator = locator_list->locator;
            break;
        }else if (cmp == 1){
            break;
        }
        prev_locator_list = locator_list;
        locator_list = locator_list->next;
    }

    if (locator != NULL){
    	if (prev_locator_list != NULL){
    		prev_locator_list->next = locator_list->next;
    	}else{
    		*head_locator_list = locator_list->next;
    	}
    	free_locator(locator);
    	free (locator_list);
    	result = GOOD;
    }else{
    	result = BAD;
    	lispd_log_msg(LISP_LOG_DEBUG_2,"remove_locator_from_list: The locator %s has not been found.", get_char_from_lisp_addr_t(*addr));
    }

    return (result);
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


