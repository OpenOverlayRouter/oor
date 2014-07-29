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
#include "lispd_timers.h"
#include "lispd_smr.h"
#include "lispd_external.h"
#include "lispd_log.h"

/********************************** Function declaration ********************************/

/*
 * Retry SMR procedure for the list of mappings
 */
int retry_smr(
        timer *timer_elt,
        void  *arg);

/*
 * Creates and initialize a timer_smr_retry_arg
 */
timer_smr_retry_arg * new_timer_smr_retry_arg(lispd_mapping_list *list);


/****************************************************************************************/


/*
 * Send a solicit map request for each rloc of all eids in the map cahce database
 */
void init_smr(
        timer *timer_elt,
        void  *arg)
{
    lispd_iface_list_elt        *iface_list         = NULL;
    lispd_iface_mappings_list   *mappings_list      = NULL;
    lispd_mapping_list          *err_mappings_list  = NULL;
    lispd_mapping_elt           *mapping            = NULL;
    lispd_mapping_list          *smr_mapping_list   = NULL;
    lispd_mapping_list          *aux_mapping_list   = NULL;
    timer_smr_retry_arg         *smr_retry_arg      = NULL;

    lispd_log_msg(LISP_LOG_DEBUG_2,"**** Init SMR notification ****");

    /*
     * Check which mappings should be SMRed and put in a list without duplicate elements
     */

    iface_list = get_head_interface_list();

    while (iface_list != NULL){
        if ( (iface_list->iface->status_changed == TRUE) ||
                (iface_list->iface->ipv4_changed == TRUE) ||
                (iface_list->iface->ipv6_changed == TRUE)){
            mappings_list = iface_list->iface->head_mappings_list;
            while(mappings_list != NULL){
                if (iface_list->iface->status_changed == TRUE ||
                        (iface_list->iface->ipv4_changed == TRUE && mappings_list->use_ipv4_address == TRUE) ||
                        (iface_list->iface->ipv6_changed == TRUE && mappings_list->use_ipv6_address == TRUE)){
                    mapping = mappings_list->mapping;

                    if (is_mapping_in_the_list(mapping,smr_mapping_list) == FALSE){
                        add_mapping_to_list(mapping, &smr_mapping_list);
                    }
                }
                mappings_list = mappings_list->next;
            }
        }
        iface_list->iface->status_changed = FALSE;
        iface_list->iface->ipv4_changed = FALSE;
        iface_list->iface->ipv6_changed = FALSE;
        iface_list = iface_list->next;
    }

    /*
     * Reset smr retry mapping list: Remove mappings to be SMRed in this iteration
     */
    if(smr_retry_timer != NULL){
        smr_retry_arg = (timer_smr_retry_arg *)smr_retry_timer->cb_argument;
        err_mappings_list = smr_retry_arg->mapping_list;
        aux_mapping_list = smr_mapping_list;
        while(aux_mapping_list != NULL){
            remove_mapping_from_list(aux_mapping_list->mapping,&err_mappings_list);
            aux_mapping_list = aux_mapping_list->next;
        }
    }


    /*
     * Send map register and SMR request for each affected mapping
     */

    while(smr_mapping_list != NULL){
    	mapping = smr_mapping_list->mapping;
    	if ((err = smr_send_map_reg(mapping, NULL))!=GOOD){
    	    add_mapping_to_list(mapping, &err_mappings_list);
    	}
        smr_mapping_list = smr_mapping_list->next;
    }

    free_mapping_list(smr_mapping_list, FALSE);

    if(err_mappings_list != NULL){
        if (smr_retry_timer == NULL){
            if ((smr_retry_timer = create_timer (SMR_RETRY_TIMER)) == NULL){
                return;
            }
            if ((smr_retry_arg = new_timer_smr_retry_arg(err_mappings_list))==NULL){
                free(smr_retry_timer);
                return;
            }
        }else{
            smr_retry_arg->retries = 0;
        }

        start_timer(smr_retry_timer, LISPD_MIN_RETRANSMIT_INTERVAL,retry_smr, (void *)smr_retry_arg);
    }else{
        if (smr_retry_timer != NULL){
            stop_timer(smr_retry_timer);
            smr_retry_timer = NULL;
        }
    }


    lispd_log_msg(LISP_LOG_DEBUG_2,"*** Finish SMR notification ***");
}

/*
 * Retry SMR procedure for the list of mappings
 */
int retry_smr(
        timer *timer_elt,
        void  *arg)
{
    timer_smr_retry_arg    *smr_retry_arg       = (timer_smr_retry_arg *)arg;
    lispd_mapping_list     *smr_mapping_list    = smr_retry_arg->mapping_list;
    lispd_mapping_list     *err_mappings_list   = NULL;
    lispd_mapping_elt      *mapping             = NULL;

    if (smr_retry_arg->retries > 3){
        free_timer_smr_retry_arg(smr_retry_arg);
        free(smr_retry_timer);
        smr_retry_timer = NULL;
        return (BAD);
    }
    lispd_log_msg(LISP_LOG_DEBUG_1, "retry_smr: Retrying SMR");
    while(smr_mapping_list != NULL){
        mapping = smr_mapping_list->mapping;
        if (smr_send_map_reg(mapping, NULL)!=GOOD){
            add_mapping_to_list(mapping, &err_mappings_list);
        }
        smr_mapping_list = smr_mapping_list->next;
    }
    if (err_mappings_list != NULL){
        free_mapping_list(smr_mapping_list, FALSE);
        smr_retry_arg->retries = smr_retry_arg->retries +1;
        smr_retry_arg->mapping_list = err_mappings_list;
        start_timer(smr_retry_timer, LISPD_MIN_RETRANSMIT_INTERVAL,retry_smr, (void *)smr_retry_arg);
    }else{
        free_timer_smr_retry_arg(smr_retry_arg);
        free(smr_retry_timer);
        smr_retry_timer = NULL;
    }
    return(GOOD);
}

/**
 * Send initial Map Register associated to the SMR process
 * We notify to the mapping system the change of mapping
 * @param mapping Mapping modified
 * @param src_locator Locator to be used to send the control messages. If NULL, default iface
 * @return GOOD if finish correctly or an error code otherwise
 */
int smr_send_map_reg(lispd_mapping_elt *mapping, lispd_locator_elt *src_locator)
{
    lcl_mapping_extended_info   *map_ext_inf       = NULL;
    timer_map_register_argument *timer_arg         = NULL;
    nat_info_str                *nat_info          = NULL;
    lispd_locators_list         *locator_list      = NULL;
    lispd_locator_elt           *locator           = NULL;

    map_ext_inf = (lcl_mapping_extended_info *)(mapping->extended_info);
    map_ext_inf->to_do_smr = TRUE;

    /* If NAT aware and not src locator provided, we select first IPv4 locator of the mapping */
    if (nat_aware == TRUE){
        if (src_locator == NULL) {
            locator_list = mapping->head_v4_locators_list;
            while (locator_list != NULL){
                locator = locator_list->locator;
                if (*(locator->state) == UP){
                    src_locator = locator;
                    break;
                }
                locator_list = locator_list->next;
            }
            if (src_locator == NULL){
                lispd_log_msg(LISP_LOG_DEBUG_1,"smr_send_map_reg: Couldn't sent Encap Map Register for EID %s/%d. No src locator",
                        get_char_from_lisp_addr_t(mapping->eid_prefix), mapping->eid_prefix_length);
                dump_mapping_entry(mapping, LISP_LOG_DEBUG_2);
                return (BAD);
            }
        }
        nat_info = ((lcl_locator_extended_info*)src_locator->extended_info)->nat_info;
        if(nat_info->emap_reg_timer != NULL){
            timer_arg = (timer_map_register_argument *)nat_info->emap_reg_timer->cb_argument;
        }else{
            timer_arg = new_timer_map_reg_arg(mapping,src_locator);
            if (timer_arg == NULL){
                return  (BAD);
            }
        }
    }else{
        if(map_ext_inf->map_reg_timer != NULL){
            timer_arg = (timer_map_register_argument *)map_ext_inf->map_reg_timer->cb_argument;
        }else{
            timer_arg = new_timer_map_reg_arg(mapping,src_locator);
            if (timer_arg == NULL){
                return  (BAD);
            }
        }
    }

    if (map_register(NULL,(void *)timer_arg) != GOOD){
        return (BAD);
    }

    return (GOOD);
}

/*
 * Send a solicit map request of the mapping for each rloc of all eids in the map cahce database
 */
int smr_send_map_req(lispd_mapping_elt *mapping)
{
    lcl_mapping_extended_info   *map_ext_inf 		= NULL;
    patricia_tree_t             *map_cache_dbs [2]  = {NULL,NULL};
    patricia_node_t             *map_cache_node     = NULL;
    lispd_map_cache_entry       *map_cache_entry    = NULL;
    lispd_locators_list         *locator_iterator   = NULL;
    lispd_locator_elt           *locator            = NULL;
    lispd_addr_list_t           *pitr_elt           = NULL;
    lispd_locators_list         *locators_lists[2]  = {NULL,NULL};
    lispd_rtr_locators_list     *rtr_list           = NULL;

    uint64_t                    nonce               = 0;
    int                         afi_db              = 0;
    int                         ctr					= 0;
    map_request_opts            opts;

    lispd_log_msg(LISP_LOG_DEBUG_1, "Start SMR for local EID %s/%d",
        			get_char_from_lisp_addr_t(mapping->eid_prefix),
        			mapping->eid_prefix_length);

    memset ( &opts, FALSE, sizeof(map_request_opts));
    opts.solicit_map_request = TRUE;

    map_cache_dbs[0] = get_map_cache_db(AF_INET);
    map_cache_dbs[1] = get_map_cache_db(AF_INET6);


	map_ext_inf = (lcl_mapping_extended_info *)(mapping->extended_info);
	map_ext_inf->to_do_smr = FALSE;



	/* For each map cache entry with same afi as local EID mapping */
	if (mapping->eid_prefix.afi ==AF_INET){
		afi_db = 0;
	}else{
		afi_db = 1;
	}
	PATRICIA_WALK(map_cache_dbs[afi_db]->head, map_cache_node) {
		map_cache_entry = ((lispd_map_cache_entry *)(map_cache_node->data));
		locators_lists[0] = map_cache_entry->mapping->head_v4_locators_list;
		locators_lists[1] = map_cache_entry->mapping->head_v6_locators_list;
		for (ctr = 0 ; ctr < 2 ; ctr++){ /*For echa IPv4 and IPv6 locator*/

			if (map_cache_entry->active && locators_lists[ctr] != NULL){
				locator_iterator = locators_lists[ctr];

				while (locator_iterator){
					locator = locator_iterator->locator;
					if (build_and_send_map_request_msg(map_cache_entry->mapping,&(mapping->eid_prefix),locator->locator_addr,opts,&nonce)==GOOD){
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
	/* SMR proxy-itr */
	pitr_elt  = proxy_itrs;

	while (pitr_elt) {
		if (build_and_send_map_request_msg(mapping,&(mapping->eid_prefix),pitr_elt->address,opts,&nonce)==GOOD){
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

	if (nat_aware == TRUE){
	    rtr_list = get_rtr_list_from_mapping(mapping);

	    while (rtr_list!=NULL){
	        if (build_and_send_map_request_msg(mapping,&(mapping->eid_prefix),&(rtr_list->locator->address),opts,&nonce)==GOOD){
	            lispd_log_msg(LISP_LOG_DEBUG_1, "  SMR'ing RTR %s for EID %s/%d",
	                    get_char_from_lisp_addr_t(rtr_list->locator->address),
	                    get_char_from_lisp_addr_t(mapping->eid_prefix),
	                    mapping->eid_prefix_length);
	        }else {
	            lispd_log_msg(LISP_LOG_DEBUG_1, "  Coudn't SMR Proxy ITR %s for EID %s/%d",
	                    get_char_from_lisp_addr_t(rtr_list->locator->address),
	                    get_char_from_lisp_addr_t(mapping->eid_prefix),
	                    mapping->eid_prefix_length);
	        }
	        rtr_list = rtr_list->next;
	    }
	}
	return (GOOD);
	/* We don't have to SMR RTR. They are updated automatically with the encapsulated map register */
}

int solicit_map_request_reply(
        timer *timer,
        void *arg)
{
    lispd_map_cache_entry   *map_cache_entry    = (lispd_map_cache_entry *)arg;
    lisp_addr_t             *dst_rloc           = NULL;
    map_request_opts        opts;

    memset ( &opts, FALSE, sizeof(map_request_opts));

    if (map_cache_entry->nonces == NULL){
        map_cache_entry->nonces = new_nonces_list();
        if (map_cache_entry->nonces==NULL){
            lispd_log_msg(LISP_LOG_ERR,"Send_map_request_miss: Coudn't allocate memory for nonces");
            return (BAD);
        }
    }
    if (map_cache_entry->nonces->retransmits - 1 < LISPD_MAX_SMR_RETRANSMIT ){
        if (map_cache_entry->nonces->retransmits > 0){
            lispd_log_msg(LISP_LOG_DEBUG_1,"Retransmiting Map Request SMR Invoked for EID: %s (%d retries)",
                    get_char_from_lisp_addr_t(map_cache_entry->mapping->eid_prefix),
                    map_cache_entry->nonces->retransmits);
        }
        dst_rloc = get_map_resolver();
        opts.encap = TRUE;
        opts.smr_invoked = TRUE;
        if(dst_rloc == NULL ||(build_and_send_map_request_msg(
                map_cache_entry->mapping,
                NULL,
                dst_rloc,
                opts,
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

/*
 * Creates and initialize a timer_smr_retry_arg
 */
timer_smr_retry_arg * new_timer_smr_retry_arg(lispd_mapping_list *list)
{
    timer_smr_retry_arg *timer_arg = (timer_smr_retry_arg *)malloc(sizeof(timer_smr_retry_arg));
    if (timer_arg == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_timer_smr_retry_arg: Couldn't allocate memory for timer_smr_retry_arg: %s", strerror(errno));
        return (NULL);
    }
    timer_arg->retries = 0;
    timer_arg->mapping_list = list;

    return(timer_arg);
}

/*
 *
 * Free memory of a timer_smr_retry_arg structure
 */
void free_timer_smr_retry_arg(timer_smr_retry_arg *timer_arg)
{
    free_mapping_list(timer_arg->mapping_list, FALSE);
    free(timer_arg);
}
