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

#include "lispd_local_db.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_request.h"

/*
 *
 */

void rloc_probing(timer *t, void *arg)
{
    lispd_map_cache_entry   *map_cache_entry = (lispd_map_cache_entry *)arg;
    lispd_identifier_elt    *identifier = map_cache_entry->identifier;
    lispd_locators_list 	*locators_lists[2];
    lispd_locators_list     *locators;
    lispd_locator_elt       *locator;
    int loc_ctr = 0;
    int ctr;

    /* First RLOC probing iteration: create timer*/
    if (!t)
        map_cache_entry->probe_timer = create_timer ("RLOC PROBING TIMER");

    if (map_cache_entry->probe_left == 0){
    	locators_lists[0] = identifier->head_v4_locators_list;
    	locators_lists[1] = identifier->head_v6_locators_list;
    	for (ctr = 0 ; ctr < 2 ; ctr++){
    		locators = locators_lists[ctr];
    		/* Send a map request probe for each locator of the identifier */
    		while (locators){
    			locator = locators->locator;
    			if (locator->rloc_probing_nonces != NULL){
    				// XXX alopez: It should never arrive here. Remove once tested
    				syslog (LOG_ERR,"First RLOC Probing -> rloc_probing_nonces not null");
    				exit(1);
    			}
    			locator->rloc_probing_nonces = new_nonces_list();
    			if (!locator->rloc_probing_nonces){
    				// XXX alopez: REPROGRAMAR
    			}
    			if ((err=build_and_send_map_request_msg(&(map_cache_entry->identifier->eid_prefix),
    			        map_cache_entry->identifier->eid_prefix_length,
    					locator->locator_addr, 0, 1, 0, 0,
    					&(locator->rloc_probing_nonces->nonce[0])))!= GOOD){
    				// TODO Actions according to the error
    			}
    			loc_ctr++;
    			locators = locators->next;
    		}
    	}
    	// XXX alopez: Removed once tested
    	if (loc_ctr != identifier->locator_count){
    		syslog(LOG_CRIT, "The number of locators (%d) is different from the number indicated by "
    				"locator_count (%d) ",loc_ctr, identifier->locator_count);
    		exit(1);
    	}
    	map_cache_entry->probe_left = loc_ctr;
    }else {
    	locators_lists[0] = identifier->head_v4_locators_list;
    	locators_lists[1] = identifier->head_v6_locators_list;
    	for (ctr = 0 ; ctr < 2 ; ctr++){
    		locators = locators_lists[ctr];
    		/*
    		 * For each locator check if probe has been received. If not, request new probe.
    		 * If reached the maximum number of retries, locator status set to down
    		 */
    		while (locators){
    			locator = locators->locator;
    			if (locator->rloc_probing_nonces == NULL){ /* Map Reply Probe received */
    				locators = locators->next;
    				continue;
    			}
    			/* No Map Reply Probe received -> Retransmit Map Request Probe */
    			if (locator->rloc_probing_nonces->retransmits -1 < LISPD_MAX_PROBE_RETRANSMIT){
    				if ((err=build_and_send_map_request_msg(&(map_cache_entry->identifier->eid_prefix),
                            map_cache_entry->identifier->eid_prefix_length,
    						locator->locator_addr, 0, 1, 0, 0,
    						&(locator->rloc_probing_nonces->nonce[0])))!= GOOD){
    					// TODO Actions according to the error
    				}
    			}else { /* No Map Reply Probe received for any Map Request Probe */
    				locator->state = DOWN;
    				free (locator->rloc_probing_nonces);
    				locator->rloc_probing_nonces = NULL;
    				map_cache_entry->probe_left --;
    			}
    		}
    	}
    }
    /*
     * Reprogrammin timer:
     *  Until all locators are probed or set down, reprogramming timer with timeout period,
     *  otherwise timer set to probing period time
     */
    if (map_cache_entry->probe_left > 0){
        start_timer(map_cache_entry->probe_timer, LISPD_INITIAL_PROBE_TIMEOUT,
                        rloc_probing, (void *)map_cache_entry);
    }else{
        start_timer(map_cache_entry->probe_timer, RLOC_PROBING_INTERVAL,
                        rloc_probing, (void *)map_cache_entry);
    }


}
