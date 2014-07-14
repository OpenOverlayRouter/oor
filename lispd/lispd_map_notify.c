/*
 * lispd_map_notify.c
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
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Albert Lopez      <alopez@ac.upc.edu>
 */

#include "lispd_afi.h"
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_notify.h"
#include "lispd_map_register.h"
#include "lispd_smr.h"
#include "hmac/hmac.h"


int process_map_notify(uint8_t *packet)
{

    lispd_pkt_map_notify_t              *map_notify                 = NULL;
    lispd_pkt_mapping_record_t          *record                     = NULL;
    lispd_pkt_mapping_record_locator_t  *locator                    = NULL;
    lisp_addr_t                         eid_prefix;
    uint8_t                             eid_prefix_length           = 0;
    uint8_t                             *eid_ptr                    = NULL;
    lispd_mapping_elt                   *mapping                    = NULL;
    lispd_mapping_list                  *mappings_list              = NULL;
    lcl_mapping_extended_info           *extended_info              = NULL;

    int                                 eid_afi                     = 0;
    int                                 loc_afi                     = 0;
    int                                 record_count                = 0;
    int                                 locator_count               = 0;
    int                                 i                           = 0;
    int                                 j                           = 0;
    int                                 map_notify_length           = 0;
    int                                 partial_map_notify_length1  = 0;
    int                                 partial_map_notify_length2  = 0;
    lispd_site_ID                       *site_ID_msg                = NULL;
    lispd_xTR_ID                        *xTR_ID_msg                 = NULL;
    int                                 result                      = BAD;



    map_notify = (lispd_pkt_map_notify_t *)packet;
    record_count = map_notify->record_count;

    map_notify_length = sizeof(lispd_pkt_map_notify_t);

    record = (lispd_pkt_mapping_record_t *)CO(map_notify, sizeof(lispd_pkt_map_notify_t));
    for (i=0; i < record_count; i++)
    {
        partial_map_notify_length1 = sizeof(lispd_pkt_mapping_record_t);
        eid_afi = lisp2inetafi(ntohs(record->eid_prefix_afi));

        eid_ptr = CO(&(record->eid_prefix_afi),sizeof(uint16_t));
        memset (&eid_prefix,0,sizeof(lisp_addr_t));
        eid_prefix_length = record->eid_prefix_length;
        switch (eid_afi) {
        case AF_INET:
        	memcpy(&(eid_prefix.address.ip),eid_ptr,sizeof(struct in_addr));
        	eid_prefix.afi = AF_INET;
            partial_map_notify_length1 += sizeof(struct in_addr);
            break;
        case AF_INET6:
        	memcpy(&(eid_prefix.address.ip),eid_ptr,sizeof(struct in6_addr));
        	eid_prefix.afi = AF_INET6;
            partial_map_notify_length1 += sizeof(struct in6_addr);
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_notify: Unknown AFI (%d) - EID", record->eid_prefix_afi);
            free_mapping_list(mappings_list, FALSE);
            return(ERR_AFI);
        }
        mapping = lookup_eid_exact_in_db(eid_prefix,eid_prefix_length);
        if (mapping != NULL){
        	if (add_mapping_to_list(mapping,&mappings_list)!=GOOD){
        		free_mapping_list(mappings_list, FALSE);
        		return(BAD);
        	}
        }

        locator_count = record->locator_count;
        locator = (lispd_pkt_mapping_record_locator_t *)CO(record, partial_map_notify_length1);
        for ( j=0 ; j<locator_count ; j++)
        {
            partial_map_notify_length2 = sizeof(lispd_pkt_mapping_record_locator_t);
            loc_afi = lisp2inetafi(ntohs(locator->locator_afi));
            switch (loc_afi) {
            case AF_INET:
                partial_map_notify_length2 = partial_map_notify_length2 + sizeof(struct in_addr);
                break;
            case AF_INET6:
                partial_map_notify_length2 = partial_map_notify_length2 + sizeof(struct in6_addr);
                break;
            default:
                lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_notify: Unknown AFI (%d) - Locator", htons(locator->locator_afi));
                free_mapping_list(mappings_list, FALSE);
                return(ERR_AFI);
            }
            locator = (lispd_pkt_mapping_record_locator_t *)CO(locator, partial_map_notify_length2);
            partial_map_notify_length1 = partial_map_notify_length1 + partial_map_notify_length2;
        }
        map_notify_length = map_notify_length + partial_map_notify_length1;
        record = (lispd_pkt_mapping_record_t *)locator;
    }

    if (map_notify->xtr_id_present == TRUE){
        xTR_ID_msg  = (lispd_xTR_ID *)CO(packet,map_notify_length);
        site_ID_msg = (lispd_site_ID *)CO(packet,map_notify_length + sizeof(lispd_xTR_ID));
        if (memcmp(site_ID_msg, &site_ID, sizeof(lispd_site_ID))!= 0){
            lispd_log_msg(LISP_LOG_DEBUG_1, "process_map_notify: Site ID of the map notify doesn't match");
            free_mapping_list(mappings_list, FALSE);
            return (BAD);
        }
        if (memcmp(xTR_ID_msg, &xTR_ID, sizeof(lispd_xTR_ID))!= 0){
            lispd_log_msg(LISP_LOG_DEBUG_1, "process_map_notify: xTR ID of the map notify doesn't match");
            free_mapping_list(mappings_list, FALSE);
            return (BAD);
        }
        map_notify_length = map_notify_length + sizeof(lispd_site_ID) + sizeof (lispd_xTR_ID);
    }
    if (map_notify->rtr_auth_present == TRUE){
        // Nothing to be done
    }

    err = check_auth_field(map_servers->key_type,
                         map_servers->key,
                         (void *)packet,
                         map_notify_length,
                         (void *)map_notify->auth_data);

    /* Valid message */
    if (err == GOOD){
    	while (mappings_list != NULL){
    		mapping = mappings_list->mapping;
    		extended_info = (lcl_mapping_extended_info *)mapping->extended_info;


    		/* Check the nonce of data Map Notify*/
    		if (map_notify->xtr_id_present == TRUE){
    			if (check_nonce(extended_info->map_reg_nonce,map_notify->nonce) == GOOD){
    				lispd_log_msg(LISP_LOG_DEBUG_2, "Data Map Notify with nonce %s confirms correct registration of the prefix %s/%d",
    				        get_char_from_nonce(map_notify->nonce),
    						get_char_from_lisp_addr_t(mapping->eid_prefix), mapping->eid_prefix_length);
    				free(extended_info->map_reg_nonce);
    				extended_info->map_reg_nonce = NULL;
        			start_timer(extended_info->map_reg_timer, MAP_REGISTER_INTERVAL, map_register, extended_info->map_reg_timer->cb_argument);
        			lispd_log_msg(LISP_LOG_DEBUG_1, "Reprogrammed encapsulated map register for %s/%d in %d seconds",
        			    		get_char_from_lisp_addr_t(mapping->eid_prefix), mapping->eid_prefix_length,MAP_REGISTER_INTERVAL);

        			/* If the Map Notify is received due to a Map Register of a SMR process, continue with the SMR process*/
        			if (extended_info->to_do_smr == TRUE){
        			    smr_send_map_req(mapping);
        			}
    			}else{
    				lispd_log_msg(LISP_LOG_DEBUG_1, "Data Map Notify: Error checking nonce field. No (Encapsulated) Map Register generated with nonce: %s",
    						get_char_from_nonce (map_notify->nonce));
    			}
    		}else{
    		    /* We don't have to check nonce. Map Register is send with nonce 0 */
    		    lispd_log_msg(LISP_LOG_DEBUG_2, "Map Notify confirms correct registration of the prefix %s/%d",
    		            get_char_from_lisp_addr_t(mapping->eid_prefix), mapping->eid_prefix_length);
    		    free(extended_info->map_reg_nonce);
    		    extended_info->map_reg_nonce = NULL;
    		    start_timer(extended_info->map_reg_timer, MAP_REGISTER_INTERVAL, map_register, extended_info->map_reg_timer->cb_argument);
    		    lispd_log_msg(LISP_LOG_DEBUG_1, "Reprogrammed map register for %s/%d in %d seconds",
    		            get_char_from_lisp_addr_t(mapping->eid_prefix), mapping->eid_prefix_length,MAP_REGISTER_INTERVAL);

    		    /* If the Map Notify is received due to a Map Register of a SMR process, continue with the SMR process*/
    		    if (extended_info->to_do_smr == TRUE){
    		        smr_send_map_req(mapping);
    		    }
    		}

    		mappings_list = mappings_list->next;
    	}
    	result = GOOD;

    } else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Notify message with nonce %s is invalid", get_char_from_nonce(map_notify->nonce));
        result = BAD;
    }
    free_mapping_list(mappings_list, FALSE);
    return(result);
}




/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
