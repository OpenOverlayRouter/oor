/*
 * lispd_smr.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Write a message to /var/log/syslog
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
 *    Albert López       <alopez@ac.upc.edu>
 *
 */
#include "lispd_lib.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_request.h"
#include "lispd_smr.h"
#include "lispd_external.h"

//void smr_pitrs();

/*
 * Send a solicit map request for each proxy itr and rlocs of all eids of the map cahce
 */
void init_smr()
{
    patricia_tree_t     *dbs [2];
    lispd_locators_list *locators_lists[2];
    int                 ctr,ctr1;
    uint64_t			nonce;

    patricia_node_t             *node;
    lispd_map_cache_entry       *map_cache_entry;
    lispd_locators_list         *locator_iterator;
    lispd_locator_elt           *locator;

    dbs[0] = get_map_cache_db(AF_INET);
    dbs[1] = get_map_cache_db(AF_INET6);

    printf("LISP Mapping Cache\n\n");

    for (ctr = 0 ; ctr < 2 ; ctr++){ /*For IPv4 and IPv6 EIDs */
        PATRICIA_WALK(dbs[ctr]->head, node) {
        	map_cache_entry = ((lispd_map_cache_entry *)(node->data));
        	locators_lists[0] = map_cache_entry->identifier->head_v4_locators_list;
        	locators_lists[1] = map_cache_entry->identifier->head_v6_locators_list;
        	for (ctr1 = 0 ; ctr1 < 2 ; ctr1++){ /*For IPv4 and IPv6 RLOCs */
        		if (map_cache_entry->active && locators_lists[ctr1] != NULL){
        			locator_iterator = locators_lists[ctr1];
        			while (locator_iterator){
        				locator = locator_iterator->locator;
        				if (build_and_send_map_request_msg(&(map_cache_entry->identifier->eid_prefix),
                                map_cache_entry->identifier->eid_prefix_length,
        						locator->locator_addr,0,0,1,0,&nonce)==GOOD)
        					syslog(LOG_INFO, "SMR'ing RLOC %s for EID %s/%d",
        							get_char_from_lisp_addr_t(*(locator->locator_addr)),
        							get_char_from_lisp_addr_t(map_cache_entry->identifier->eid_prefix),
        							map_cache_entry->identifier->eid_prefix_length);
        				locator_iterator = locator_iterator->next;

        			}
        		}
        	}
        } PATRICIA_WALK_END;
    }
    /* XXX alopez: Revisar procediment amb pitrs */
    //smr_pitrs();
}

/*
 void smr_pitrs()
{
    patricia_node_t *node;
    lispd_locator_chain_t *locator_chain = NULL;
    lispd_addr_list_t *elt = proxy_itrs;
    uint64_t nonce;

    PATRICIA_WALK(AF4_database->head, node) {
        locator_chain = ((lispd_locator_chain_t *)(node->data));
        if (locator_chain) {
            while (elt) {
                if (build_and_send_map_request_msg(elt->address,
                        &(locator_chain->eid_prefix),
                        (get_addr_len(locator_chain->eid_prefix.afi) * 8),
                        locator_chain->eid_name,
                        0, 0, 1, 0, &nonce))
                    syslog(LOG_DAEMON, "SMR'ing %s", get_char_from_lisp_addr_t(elt->address));
                elt = elt->next;
            }
        }
    } PATRICIA_WALK_END;
}*/

void solicit_map_request_reply(timer *t, void *arg)
{
    lispd_map_cache_entry *map_cache_entry = (lispd_map_cache_entry *)arg;
    nonces_list *nonces = map_cache_entry->nonces;
    if (nonces == NULL){
        nonces = new_nonces_list();
        if (nonces==NULL){
            syslog (LOG_ERR,"Send_map_request_miss: Coudn't allocate memory for nonces");
            return;
        }
        map_cache_entry->nonces = nonces;
    }
    if (nonces->retransmits - 1 < LISPD_MAX_SMR_RETRANSMIT ){

        if((err = build_and_send_map_request_msg(&(map_cache_entry->identifier->eid_prefix),
                map_cache_entry->identifier->eid_prefix_length, map_resolvers->address,1, 0, 0, 1,
                &(map_cache_entry->nonces->nonce[map_cache_entry->nonces->retransmits])))!=GOOD) {
            syslog(LOG_DAEMON, "process_map_request_msg: couldn't build/send SMR triggered Map-Request");
            /* TODO process error */
        }
        nonces->retransmits ++;
        /* Reprograming timer*/
        if (map_cache_entry->smr_timer == NULL)
            map_cache_entry->smr_timer = create_timer ("SMR RETRY");
        start_timer(map_cache_entry->smr_timer, LISPD_INITIAL_SMR_TIMEOUT,
                solicit_map_request_reply, (void *)map_cache_entry);

    }else{
        free(map_cache_entry->nonces);
        map_cache_entry->nonces = NULL;
        free(map_cache_entry->smr_timer);
        map_cache_entry->smr_timer = NULL;
        syslog (LOG_DEBUG,"SMR process: No Map Reply fot EID %s/%d. Ignoring solicit map request ...",
                get_char_from_lisp_addr_t(map_cache_entry->identifier->eid_prefix),
                map_cache_entry->identifier->eid_prefix_length);
    }
}

