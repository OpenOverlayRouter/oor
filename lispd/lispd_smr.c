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
#include "lispd_map_register.h"
#include "lispd_map_request.h"
#include "lispd_smr.h"
#include "lispd_external.h"
#include "lispd_log.h"

//void smr_pitrs();

/*
 * Send a solicit map request for each rloc of all eids in the map cahce database
 */
void init_smr(lispd_mappings_list *affected_mappings)
{
    patricia_tree_t             *dbs [2]            = {NULL,NULL};
    lispd_locators_list         *locators_lists[2]  = {NULL,NULL};
    int                         ctr=0,ctr1=0;
    uint64_t                    nonce               = 0;
    lisp_addr_t                 *src_eid            = NULL;

    patricia_node_t             *node               = NULL;
    lispd_map_cache_entry       *map_cache_entry    = NULL;
    lispd_locators_list         *locator_iterator   = NULL;
    lispd_locator_elt           *locator            = NULL;

    dbs[0] = get_map_cache_db(AF_INET);
    dbs[1] = get_map_cache_db(AF_INET6);

   lispd_log_msg(LISP_LOG_DEBUG_1,"LISP Mapping Cache\n\n");


   while (affected_mappings != NULL){/* For each EID which have a locator modified*/
       src_eid = &(affected_mappings->mapping->eid_prefix);
       /* Send map register to inform map server of the change with the interface */
       err = build_and_send_map_register_msg (affected_mappings->mapping);
       if ( err != GOOD){
           // XXX What should be done if it can't send map register?
       }

       /* Send SMR for each locator of each map-cache entry */

       lispd_log_msg(LISP_LOG_DEBUG_1, "init_smr: Start SMR for the EID:  %s/%d ",
               get_char_from_lisp_addr_t(*src_eid),
               affected_mappings->mapping->eid_prefix_length);
       for (ctr = 0 ; ctr < 2 ; ctr++){ /*For all IPv4 and IPv6 map cache entries */
           PATRICIA_WALK(dbs[ctr]->head, node) {
               map_cache_entry = ((lispd_map_cache_entry *)(node->data));
               locators_lists[0] = map_cache_entry->mapping->head_v4_locators_list;
               locators_lists[1] = map_cache_entry->mapping->head_v6_locators_list;
               for (ctr1 = 0 ; ctr1 < 2 ; ctr1++){ /*For echa IPv4 and IPv6 locator*/
                   if (map_cache_entry->active && locators_lists[ctr1] != NULL){
                       locator_iterator = locators_lists[ctr1];
                       while (locator_iterator){
                           locator = locator_iterator->locator;

                           if (build_and_send_map_request_msg(map_cache_entry->mapping,src_eid,locator->locator_addr,0,0,1,0,&nonce)==GOOD){
                               lispd_log_msg(LISP_LOG_DEBUG_1, "  SMR'ing RLOC %s of EID %s/%d",
                                       get_char_from_lisp_addr_t(*(locator->locator_addr)),
                                       get_char_from_lisp_addr_t(map_cache_entry->mapping->eid_prefix),
                                       map_cache_entry->mapping->eid_prefix_length);
                           }

                           locator_iterator = locator_iterator->next;
                       }
                   }
               }
           } PATRICIA_WALK_END;
       }
       affected_mappings = affected_mappings->next;
   }
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
                    lispd_log_msg(LOG_DAEMON, "SMR'ing %s", get_char_from_lisp_addr_t(elt->address));
                elt = elt->next;
            }
        }
    } PATRICIA_WALK_END;
}*/

int solicit_map_request_reply(
    timer *timer,
    void *arg)
{
    lispd_map_cache_entry *map_cache_entry = (lispd_map_cache_entry *)arg;
    lisp_addr_t *dst_rloc = NULL;

    if (map_cache_entry->nonces == NULL){
        map_cache_entry->nonces = new_nonces_list();
        if (map_cache_entry->nonces==NULL){
            lispd_log_msg(LISP_LOG_ERR,"Send_map_request_miss: Coudn't allocate memory for nonces");
            return (BAD);
        }
    }
    if (map_cache_entry->nonces->retransmits - 1 < LISPD_MAX_SMR_RETRANSMIT ){
        dst_rloc = get_map_resolver();
        if((err = build_and_send_map_request_msg(map_cache_entry->mapping, NULL, dst_rloc, 1, 0, 0, 1,
                &(map_cache_entry->nonces->nonce[map_cache_entry->nonces->retransmits])))!=GOOD) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "solicit_map_request_reply: couldn't build/send SMR triggered Map-Request");
            // TODO process error
        }
        map_cache_entry->nonces->retransmits ++;
        /* Reprograming timer*/
        if (map_cache_entry->smr_inv_timer == NULL){
            map_cache_entry->smr_inv_timer = create_timer (SMR_INV_RETRY_TIMER);
        }
        start_timer(map_cache_entry->smr_inv_timer, LISPD_INITIAL_SMR_TIMEOUT,
                (timer_callback)solicit_map_request_reply, (void *)map_cache_entry);
    }else{
        free(map_cache_entry->nonces);
        map_cache_entry->nonces = NULL;
        free(map_cache_entry->smr_inv_timer);
        map_cache_entry->smr_inv_timer = NULL;
        lispd_log_msg(LISP_LOG_DEBUG_1,"SMR process: No Map Reply fot EID %s/%d. Ignoring solicit map request ...",
                get_char_from_lisp_addr_t(map_cache_entry->mapping->eid_prefix),
                map_cache_entry->mapping->eid_prefix_length);
    }
    return (GOOD);
}


