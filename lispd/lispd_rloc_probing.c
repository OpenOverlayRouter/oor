/*
 * lispd_rloc_probing.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
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
 *    Albert López      <alopez@ac.upc.edu>
 *
 */

#include "lispd_external.h"
#include "lispd_local_db.h"
#include "lispd_lib.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_request.h"
#include "lispd_rloc_probing.h"


/*
 * Send a Map-Request probe to check the status of the locator passed through arg
 * If the number of retries without answer is higher than rloc_probe_retries. Change the status of the locator to down
 */

int rloc_probing(
    timer *rloc_prob_timer,
    void *arg)
{
    timer_rloc_probe_argument   *timer_argument     = (timer_rloc_probe_argument *)arg;
    lispd_mapping_elt           *mapping            = NULL;
    lispd_locator_elt           *locator            = NULL;
    rmt_locator_extended_info   *locator_ext_inf    = NULL;
    nonces_list                 *nonces             = NULL;
    uint8_t                     have_control_iface  = FALSE;

    if (rloc_probe_interval == 0){
        lispd_log_msg(LISP_LOG_DEBUG_2,"rloc_probing: No RLOC Probing for %s/%d cache entry. RLOC Probing dissabled",
                get_char_from_lisp_addr_t(mapping->eid_prefix),mapping->eid_prefix_length);
        return (GOOD);
    }

    mapping         = timer_argument->map_cache_entry->mapping;
    locator         = timer_argument->locator;
    locator_ext_inf = (rmt_locator_extended_info *)(locator->extended_info);
    nonces          = locator_ext_inf->rloc_probing_nonces;

    /*
     * If we don't have control iface compatible with the locator to probe, just reprograme the timer for next time
     */

    switch (locator->locator_addr->afi){
    case AF_INET:
        if(default_ctrl_iface_v4 != NULL){
            have_control_iface = TRUE;
        }
        break;
    case AF_INET6:
        if(default_ctrl_iface_v6 != NULL){
            have_control_iface = TRUE;
        }
        break;
    }
    if (have_control_iface == FALSE){
        lispd_log_msg(LISP_LOG_DEBUG_2,"rloc_probing: No control iface compatible with locator %s of the map-cache entry %s/%d. "
                "Reprogramming RLOC Probing",
                get_char_from_lisp_addr_t(*(locator->locator_addr)),
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length);
        start_timer(locator_ext_inf->probe_timer, rloc_probe_interval,(timer_callback)rloc_probing, arg);
        return (BAD);
    }

    /* Generate Nonce structure */

    if (nonces == NULL){
        nonces = new_nonces_list();
        if (nonces==NULL){
            lispd_log_msg(LISP_LOG_WARNING,"rloc_probing: Unable to allocate memory for nonces. Reprogramming RLOC Probing");
            start_timer(locator_ext_inf->probe_timer, rloc_probe_interval,(timer_callback)rloc_probing, arg);
            return (BAD);
        }
        locator_ext_inf->rloc_probing_nonces = nonces;
    }

    /*
     * If the number of retransmits is less than rloc_probe_retries, then try to send the Map Request Probe again
     */

    if (nonces->retransmits - 1 < rloc_probe_retries ){
        if (nonces->retransmits > 0){
            lispd_log_msg(LISP_LOG_DEBUG_1,"Retransmiting Map-Request Probe for locator %s and EID: %s/%d (%d retries)",
                    get_char_from_lisp_addr_t(*(locator->locator_addr)),
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length,
                    nonces->retransmits);
        }

        err = build_and_send_map_request_msg(mapping,NULL,locator->locator_addr, 0, 1, 0, 0,
                &(nonces->nonce[nonces->retransmits]));

        if (err != GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1,"rloc_probing: Couldn't send Map-Request Probe for locator %s and EID: %s/%d",
                    get_char_from_lisp_addr_t(*(locator->locator_addr)),
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length);
        }
        locator_ext_inf->rloc_probing_nonces->retransmits++;

        /* Reprogram time for next retry */
        start_timer(locator_ext_inf->probe_timer, rloc_probe_retries_interval,(timer_callback)rloc_probing, arg);
    }else{ /* If we have reached maximum number of retransmissions, change remote locator status */
        if (*(locator->state) == UP){
            *(locator->state) = DOWN;
            lispd_log_msg(LISP_LOG_DEBUG_1,"rloc_probing: No Map-Reply Probe received for locator %s and EID: %s/%d"
                    "-> Locator state changes to DOWN",
                    get_char_from_lisp_addr_t(*(locator->locator_addr)),
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length);

            /* [re]Calculate balancing locator vectors  if it has been a change of status*/
            calculate_balancing_vectors (
                    mapping,
                    &(((rmt_mapping_extended_info *)mapping->extended_info)->rmt_balancing_locators_vecs));
        }
        free (locator_ext_inf->rloc_probing_nonces);
        locator_ext_inf->rloc_probing_nonces = NULL;

        /* Reprogram time for next probe interval */
        start_timer(locator_ext_inf->probe_timer, rloc_probe_interval,(timer_callback)rloc_probing, arg);
        lispd_log_msg(LISP_LOG_DEBUG_2,"Reprogramed RLOC probing of the locator %s of the EID %s/%d in %d seconds",
                get_char_from_lisp_addr_t(*(locator->locator_addr)),
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length, rloc_probe_interval);
    }

    return (GOOD);
}

/*
 * Program RLOC probing for each locator of the mapping
 */

void programming_rloc_probing(lispd_map_cache_entry *map_cache_entry)
{
    lispd_locators_list         *locators_lists[2]  = {NULL,NULL};
    lispd_locator_elt           *locator            = NULL;
    timer_rloc_probe_argument   *timer_arg          = NULL;
    rmt_locator_extended_info   *locator_ext_inf    = NULL;
    int                         ctr                 = 0;

    locators_lists[0] = map_cache_entry->mapping->head_v4_locators_list;
    locators_lists[1] = map_cache_entry->mapping->head_v6_locators_list;
    /* Start rloc probing for each locator of the mapping */
    for (ctr=0; ctr < 2 ; ctr++){
        while (locators_lists[ctr] != NULL){
            locator = locators_lists[ctr]->locator;
            locator_ext_inf = (rmt_locator_extended_info *)locator->extended_info;
            timer_arg = new_timer_rloc_probe_argument (map_cache_entry, locator);
            /* Create and program the timer */
            if (locator_ext_inf->probe_timer == NULL){
                locator_ext_inf->probe_timer = create_timer (RLOC_PROBING_TIMER);
            }
            start_timer(locator_ext_inf->probe_timer, rloc_probe_interval,(timer_callback)rloc_probing, (void *)timer_arg);
            locators_lists[ctr] = locators_lists[ctr]->next;
        }
    }
}

/*
 * Program RLOC probing for each proxy-ETR
 */

void programming_petr_rloc_probing()
{
    lispd_locators_list         *locators_lists[2]  = {NULL,NULL};
    lispd_locator_elt           *locator            = NULL;
    timer_rloc_probe_argument   *timer_arg          = NULL;
    rmt_locator_extended_info   *locator_ext_inf    = NULL;
    int                         ctr                 = 0;

    if (rloc_probe_interval == 0 || proxy_etrs == NULL){
        return;
    }

    locators_lists[0] = proxy_etrs->mapping->head_v4_locators_list;
    locators_lists[1] = proxy_etrs->mapping->head_v6_locators_list;
    /* Start rloc probing for each locator of the mapping */
    for (ctr=0; ctr < 2 ; ctr++){
        while (locators_lists[ctr] != NULL){
            locator = locators_lists[ctr]->locator;
            locator_ext_inf = (rmt_locator_extended_info *)locator->extended_info;
            timer_arg = new_timer_rloc_probe_argument (proxy_etrs, locator);
            /* Create and program the timer */
            if (locator_ext_inf->probe_timer == NULL){
                locator_ext_inf->probe_timer = create_timer (RLOC_PROBING_TIMER);
            }
            start_timer(locator_ext_inf->probe_timer, rloc_probe_interval,(timer_callback)rloc_probing, (void *)timer_arg);
            locators_lists[ctr] = locators_lists[ctr]->next;
        }
    }
}


timer_rloc_probe_argument *new_timer_rloc_probe_argument(
        lispd_map_cache_entry   *map_cache_entry,
        lispd_locator_elt       *locator)
{
    timer_rloc_probe_argument *timer_argument = NULL;

    if ((timer_argument = (timer_rloc_probe_argument *)malloc(sizeof(timer_rloc_probe_argument)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_timer_rloc_probe_argument: Unable to allocate memory for timer_rloc_probe_argument: %s",
                strerror(errno));
    }else{
        timer_argument->map_cache_entry = map_cache_entry;
        timer_argument->locator = locator;
    }

    return (timer_argument);
}
