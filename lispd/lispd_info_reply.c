/*
 * lispd_info_reply.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Receive and process Info-Reply messages
 *
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
 *    Alberto Rodriguez Natal    <arnatal@ac.upc.edu>
 *
 */


#include "lispd_afi.h"
#include "lispd_external.h"
#include "lispd_info_reply.h"
#include "lispd_info_request.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_register.h"
#include "lispd_nonce.h"
#include "lispd_smr.h"
#include "cksum.h"
#include "hmac/hmac.h"



/*
 *  Process an Info-Reply Message
 *  Receive an Info-Reply message and process based on control bits
 *
 */

int process_info_reply_msg(
        uint8_t         *packet,
        lisp_addr_t     local_rloc)
{

    uint8_t                     *ptr                    = packet;

    uint8_t                     lisp_type               = 0;
    uint8_t                     reply                   = 0;

    uint64_t                    nonce                   = 0;
    uint16_t                    key_id                  = 0;
    uint16_t                    auth_data_len           = 0;
	uint8_t                     *auth_data_pos          = NULL;

    uint32_t                    ttl                     = 0;
    uint8_t                     eid_mask_len            = 0;
    lisp_addr_t                 eid_prefix              = {.afi=AF_UNSPEC};

    uint16_t                    ms_udp_port             = 0;
    uint16_t                    etr_udp_port            = 0;

    uint32_t                    info_reply_hdr_len      = 0;
    uint32_t                    lcaf_addr_len           = 0;
	uint32_t                    pckt_len                = 0;

	uint16_t                    *lcaf_afi               = NULL;

    lisp_addr_t                 global_etr_rloc         = {.afi=AF_UNSPEC};
    lisp_addr_t                 ms_rloc                 = {.afi=AF_UNSPEC};
    lisp_addr_t                 private_etr_rloc        = {.afi=AF_UNSPEC};
    lispd_rtr_locators_list     *rtr_locators_list      = NULL;

    lispd_mapping_elt           *mapping                = NULL;
    lcl_mapping_extended_info   *mapping_ext_inf        = NULL;
    lispd_locator_elt           *src_locator            = NULL;
    nat_info_str                *nat_info               = NULL;


    char                        rtrs_list_str[2000];
    int                         rtrs_list_str_size = 0;
    lispd_rtr_locators_list     *aux_rtr_locators_list  = NULL;

    uint8_t                     is_behind_nat           = FALSE;
    uint8_t                     need_smr                = FALSE;

    timer_map_register_argument *timer_arg              = NULL;

    /*
     * Get source port and address.
     */

    err = extract_info_nat_header(ptr,
            &lisp_type,
            &reply,
            &nonce,
            &key_id,
            &auth_data_len,
            &auth_data_pos,
            &ttl,
            &eid_mask_len,
            &eid_prefix,
            &info_reply_hdr_len);

    if (err != GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_info_reply_msg: Couldn't process Info Reply message");
        return (BAD);
    }
    ptr = CO(ptr,info_reply_hdr_len);

    lcaf_afi = (uint16_t *)ptr;
    if ( ntohs(*lcaf_afi) != LISP_AFI_LCAF){
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_info_reply_msg: Malformed packet");
        return (BAD);
    }

    ptr = CO(ptr,FIELD_AFI_LEN);
	/* Extract Info-Reply body fields */
    err = extract_nat_lcaf_data(ptr,
            &ms_udp_port,
            &etr_udp_port,
            &global_etr_rloc,
            &ms_rloc,
            &private_etr_rloc,
            &rtr_locators_list,
            &lcaf_addr_len);

    if (err != GOOD) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_info_reply_msg: Error extracting packet data");
        return (BAD);
    }

    /* Leave only RTR with same afi as the local rloc where we received the message */
    remove_rtr_locators_with_afi_different_to(&rtr_locators_list, local_rloc.afi);


    lcaf_addr_len = lcaf_addr_len + FIELD_AFI_LEN;



    /* Print the extracted information of the message */
    if (is_loggable(LISP_LOG_DEBUG_2)){
        aux_rtr_locators_list = rtr_locators_list;
        rtrs_list_str[0] = '\0';
        while (aux_rtr_locators_list != NULL){
            sprintf(rtrs_list_str + rtrs_list_str_size, "  %s ", get_char_from_lisp_addr_t(aux_rtr_locators_list->locator->address));
            rtrs_list_str_size = rtrs_list_str_size + strlen(rtrs_list_str);
            aux_rtr_locators_list = aux_rtr_locators_list->next;
        }
        lispd_log_msg(LISP_LOG_DEBUG_2, "Info-Reply message data->"
                "Nonce: %s , KeyID: %hu ,TTL: %u , EID-prefix: %s/%hhu , "
                "MS UDP Port Number: %hu , ETR UDP Port Number: %hu , Global ETR RLOC Address: %s , "
                "MS RLOC Address: %s , Private ETR RLOC Address: %s, RTR RLOC Compatible list: %s",
                get_char_from_nonce(nonce), key_id, ttl, get_char_from_lisp_addr_t(eid_prefix),eid_mask_len,
                ms_udp_port, etr_udp_port, get_char_from_lisp_addr_t(global_etr_rloc),
                get_char_from_lisp_addr_t(ms_rloc),get_char_from_lisp_addr_t(private_etr_rloc),rtrs_list_str);
    }

    mapping = lookup_eid_exact_in_db(eid_prefix, eid_mask_len);
    if (mapping == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_info_reply_msg: Info Reply is not for any local EID");
        free_rtr_list(rtr_locators_list);
        return (BAD);
    }

#ifndef VPNAPI
    src_locator = get_locator_from_mapping(mapping, &local_rloc);
#else
    /*
     * With VPN-API, we only have one listening socket for all interfaces. In order to not modify structures and behaviour of LISPmob,
     * we use nonce to find the interface associated with the received message, even if the message has been receiven in a different interface, we accept it.
     */
    switch(local_rloc.afi){
    case AF_INET:
        src_locator = nat_get_locator_with_nonce(mapping->head_v4_locators_list,nonce);
        break;
    case AF_INET6:
        src_locator = nat_get_locator_with_nonce(mapping->head_v6_locators_list,nonce);
        break;
    }

#endif

    if (src_locator == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_info_reply_msg: Info Reply is not for any locator associated with the EID: %s/%d. "
                "Received into the interface with IP address: %s",
                get_char_from_lisp_addr_t(mapping->eid_prefix), mapping->eid_prefix_length,
                get_char_from_lisp_addr_t(local_rloc));
        free_rtr_list(rtr_locators_list);
        return (BAD);
    }

    nat_info = ((lcl_locator_extended_info *)src_locator->extended_info)->nat_info;
    if (nat_info == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_info_reply_msg: Received a info reply in a not NAT enabled device");
        free_rtr_list(rtr_locators_list);
        return (BAD);
    }

    if(nat_info->inf_req_timer == NULL){
    	/*
    	 * We send two consecutive info request through a not nated interface. The first info reply remove
    	 * mapping_ext_inf->inf_req_timer. The second info reply should be ignored to avoid seg fault
    	 */
    	lispd_log_msg(LISP_LOG_DEBUG_2, "process_info_reply_msg: A previous Info Reply message confirms that we are not behind a NAT interface");
    	free_rtr_list(rtr_locators_list);
    	return (GOOD);
    }

    /* Check authentication data */

    pckt_len = info_reply_hdr_len + lcaf_addr_len;

    if(BAD == check_auth_field(key_id, map_servers->key, (void *) packet, pckt_len, (void *)auth_data_pos)){
        lispd_log_msg(LISP_LOG_DEBUG_2, "Info-Reply: Error checking auth data field");
        return(BAD);
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_2, "Info-Reply: Correct auth data field checking");
    }

    /* Checking the nonce */

     if (check_nonce(nat_info->inf_req_nonce,nonce) == GOOD ){
         lispd_log_msg(LISP_LOG_DEBUG_2, "Info-Reply: Correct nonce field checking ");
         free(nat_info->inf_req_nonce);
         nat_info->inf_req_nonce = NULL;
     }else{
         lispd_log_msg(LISP_LOG_DEBUG_1, "Info-Reply: Error checking nonce field. No Info Request generated with nonce: %s "
                 "and source IP address: %s",
                 get_char_from_nonce (nonce),
                 get_char_from_lisp_addr_t(local_rloc));
         return (BAD);
     }


	// TODO  Select the best RTR from the list retrieved from the Info-Reply


    /* Check if behind NAT */

    switch (compare_lisp_addr_t(&global_etr_rloc, &local_rloc)) {
    case 0:
        is_behind_nat = FALSE;
        lispd_log_msg(LISP_LOG_DEBUG_2, "NAT Traversal: MN is not behind NAT");
        break;
    case 1:
    case 2:
        is_behind_nat = TRUE;
        lispd_log_msg(LISP_LOG_DEBUG_2, "NAT Traversal: MN is behind NAT");
        break;
    case -1:
        is_behind_nat = UNKNOWN;
        lispd_log_msg(LISP_LOG_DEBUG_2, "NAT Traversal: Unknown state");
        break;
    }


    if (is_behind_nat == TRUE){


        nat_info->status= NAT;
    }else{
        nat_info->status= NO_NAT;
    }

    /*
     * We add the list of RTRs even if the locator is not behind NAT
     * In mobile node mode, we use always RTRs
     */

    if (rtr_locators_list == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "process_info_reply_msg: The interface with IP address %s don't have any RTR compatible"
                " with local AFI", get_char_from_lisp_addr_t(local_rloc));
    }

    if (nat_info->rtr_locators_list != NULL){
        free_rtr_list(nat_info->rtr_locators_list);
    }
    nat_info->rtr_locators_list = rtr_locators_list;

    /* Reinsert the locator in the correct position of the list */
    if (reinsert_locator_to_mapping(mapping, src_locator)!=GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_1, "process_info_reply_msg: Error reinserting locator into the correct position of the list of locators");
        return (BAD);
    }

    /* If we are behind NAT, the program timer to send Info Request after TTL minutes */
    // XXX We send always Inf Req, even if we are not behind NAT
    if (nat_info->inf_req_timer == NULL) {
        nat_info->inf_req_timer = create_timer(INFO_REPLY_TTL_TIMER);
    }
    start_timer(nat_info->inf_req_timer, ttl*60, info_request, nat_info->inf_req_timer->cb_argument);
    lispd_log_msg(LISP_LOG_DEBUG_1, "Reprogrammed info request in %d minutes",ttl);



    /* If there is a change of global address -> SMR */
    /* Encap Map Register change RTR cache but need to SMR pXTR. It seems that is not done by the RTR */

    if (nat_info->public_addr != NULL){
    	if (compare_lisp_addr_t(&global_etr_rloc, nat_info->public_addr) != 0){
    		need_smr = TRUE;
    	}
    	free(nat_info->public_addr);
    }else {
    	// First info reply
    	need_smr = TRUE;
    }

    nat_info->public_addr = clone_lisp_addr(&global_etr_rloc);

    if (need_smr){
        smr_send_map_reg(mapping);
    }else{
        /* In SMR process we already send Map Register. It doesn't have to be send again */

        mapping_ext_inf = (lcl_mapping_extended_info *)mapping->extended_info;
        /* Once we know the NAT state we send a Map-Register */
        if (mapping_ext_inf->map_reg_timer == NULL){
            timer_arg = new_timer_map_reg_arg(mapping,src_locator);
            if (timer_arg == NULL){
                return (BAD);
            }
        }else{
            timer_arg = (timer_map_register_argument *)mapping_ext_inf->map_reg_timer->cb_argument;
            timer_arg->src_locator = src_locator;
        }


        map_register(NULL,(void *)timer_arg);
    }

    return (GOOD);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
