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

/*
 * smr_timer is used to avoid sending SMRs during transition period.
 */
timer *smr_timer = NULL;

//void smr_pitrs();

/*
 * Send a solicit map request for each rloc of all eids in the map cahce database
 */
void init_smr(
        timer *timer_elt,
        void  *arg)
{
    patricia_tree_t             *local_dbs [2]      = {NULL,NULL};
    patricia_tree_t             *map_cache_dbs [2]  = {NULL,NULL};
    lispd_locators_list         *locators_lists[2]  = {NULL,NULL};
    lispd_mapping_elt           *mapping            = NULL;
    lcl_mapping_extended_info   *lcl_extended_info  = NULL;

    int                         ctr=0,ctr1=0;
    uint64_t                    nonce               = 0;

    patricia_node_t             *lcl_node           = NULL;
    patricia_node_t             *map_cache_node     = NULL;
    lispd_map_cache_entry       *map_cache_entry    = NULL;
    lispd_locators_list         *locator_iterator   = NULL;
    lispd_locator_elt           *locator            = NULL;



    lispd_log_msg(LISP_LOG_DEBUG_2,"*** Init SMR notification ***");

    local_dbs[0] = get_local_db(AF_INET);
    local_dbs[1] = get_local_db(AF_INET6);

    map_cache_dbs[0] = get_map_cache_db(AF_INET);
    map_cache_dbs[1] = get_map_cache_db(AF_INET6);


    for (ctr = 0 ; ctr < 2 ; ctr++){
        PATRICIA_WALK(local_dbs[ctr]->head, lcl_node) {
            mapping = ((lispd_mapping_elt *)(lcl_node->data));
            lcl_extended_info = (lcl_mapping_extended_info *)mapping->extended_info;
            if (lcl_extended_info->requires_smr != NO_SMR){
                /* Send a map register for the affected mapping */
                build_and_send_map_register_msg(mapping);

                lispd_log_msg(LISP_LOG_DEBUG_1, "Start SMR for local EID %s/%d",
                        get_char_from_lisp_addr_t(mapping->eid_prefix),
                        mapping->eid_prefix_length);
                PATRICIA_WALK(map_cache_dbs[ctr]->head, map_cache_node) { /* For each map cache entry with same afi as local EID mapping */
                    map_cache_entry = ((lispd_map_cache_entry *)(map_cache_node->data));
                    locators_lists[0] = map_cache_entry->mapping->head_v4_locators_list;
                    locators_lists[1] = map_cache_entry->mapping->head_v6_locators_list;
                    for (ctr1 = 0 ; ctr1 < 2 ; ctr1++){ /*For echa IPv4 and IPv6 locator*/
                        if (map_cache_entry->active && locators_lists[ctr1] != NULL){
                            locator_iterator = locators_lists[ctr1];
                            while (locator_iterator){
                                locator = locator_iterator->locator;
                                if (build_and_send_map_request_msg(map_cache_entry->mapping,&(mapping->eid_prefix),locator->locator_addr,0,0,1,0,&nonce)==GOOD){
                                    lispd_log_msg(LISP_LOG_DEBUG_1, "  SMR'ing RLOC %s from EID %s/%d",
                                            get_char_from_lisp_addr_t(*(locator->locator_addr)),
                                            get_char_from_lisp_addr_t(map_cache_entry->mapping->eid_prefix),
                                            map_cache_entry->mapping->eid_prefix_length);
                                }

                                locator_iterator = locator_iterator->next;
                            }
                        }
                    }
                }PATRICIA_WALK_END;

                lcl_extended_info->requires_smr = NO_SMR;
            }

        }PATRICIA_WALK_END;
    }

    smr_pitrs();
    lispd_log_msg(LISP_LOG_DEBUG_2,"*** Finish SMR notification ***");
}

/*
 * Send SMR for each local EID prefix to each Proxy-ITR
 */
void smr_pitrs()
{
    patricia_tree_t         *dbs [2]    = {NULL,NULL};
    patricia_node_t         *node       = NULL;
    lispd_mapping_elt       *mapping    = NULL;
    lispd_addr_list_t       *pitr_elt   = NULL;
    uint64_t                nonce       = 0;
    int                     ctr         = 0;

    dbs[0] = get_local_db(AF_INET);
    dbs[1] = get_local_db(AF_INET6);

    for (ctr = 0 ; ctr < 2 ; ctr++){
        pitr_elt  = proxy_itrs;
        PATRICIA_WALK(dbs[ctr]->head, node) {
            mapping = ((lispd_mapping_elt *)(node->data));
            while (pitr_elt) {
                if (build_and_send_map_request_msg(mapping,&(mapping->eid_prefix),pitr_elt->address,0,0,1,0,&nonce)==GOOD){
                    lispd_log_msg(LISP_LOG_DEBUG_1, "  SMR'ing Proxy ITR %s for EID %s/%d",
                            get_char_from_lisp_addr_t(*(pitr_elt->address)),
                            get_char_from_lisp_addr_t(mapping->eid_prefix),
                            mapping->eid_prefix_length);
                }else {
                    lispd_log_msg(LISP_LOG_DEBUG_1, "  Coudn't SMR Proxy ITR %s for EID %s/%d",
                            get_char_from_lisp_addr_t(*(pitr_elt->address)),
                            get_char_from_lisp_addr_t(mapping->eid_prefix),
                            mapping->eid_prefix_length);
                }
                pitr_elt = pitr_elt->next;
            }
        } PATRICIA_WALK_END;
    }
}

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
        if(dst_rloc == NULL ||(build_and_send_map_request_msg(
                map_cache_entry->mapping,
                NULL,
                dst_rloc,
                1,
                0,
                0,
                1,
                &(map_cache_entry->nonces->nonce[map_cache_entry->nonces->retransmits])))!=GOOD) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "solicit_map_request_reply: couldn't build/send SMR triggered Map-Request");
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


