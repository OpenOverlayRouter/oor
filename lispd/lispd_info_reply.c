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


#include <sys/timerfd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "lispd_external.h"

#include "lispd_info_reply.h"
#include "lispd_lib.h"

#include "lispd_map_register.h"

int extract_info_reply_body(irp_lcaf,lcaf_afi,flags,lcaf_type,lcaf_length,
                            global_etr_rloc,ms_rloc,private_etr_rloc,rtr_rloc_list)

lispd_pkt_info_reply_lcaf_t *irp_lcaf;
uint16_t * lcaf_afi;
uint8_t * flags;
uint8_t * lcaf_type;
uint16_t * lcaf_length;
lisp_addr_t *global_etr_rloc;
lisp_addr_t *ms_rloc;
lisp_addr_t *private_etr_rloc;
lispd_addr_list_t *rtr_rloc_list;

{
    lispd_addr_list_t *rtr_rloc_itr;

    lisp_addr_t *rtr_rloc_elt;

    void *ptr;

    unsigned int cumulative_add_length;


    *lcaf_afi = ntohs(irp_lcaf->lcaf_afi);


    *flags = irp_lcaf->flags;

    *lcaf_type = irp_lcaf->lcaf_type;

    *lcaf_length = ntohs(irp_lcaf->length);


    cumulative_add_length = FIELD_PORT_LEN * 2; /* 2 UDP ports */


    ptr = (void *) CO(irp_lcaf, sizeof(lispd_pkt_info_reply_lcaf_t));

    /* Extract the Global ETR RLOC */

    *global_etr_rloc = extract_lisp_address(ptr);

    cumulative_add_length +=
        get_addr_len(global_etr_rloc->afi) + FIELD_AFI_LEN;

    ptr = CO(ptr, get_addr_len(global_etr_rloc->afi) + FIELD_AFI_LEN);

    /* Extract the MS RLOC */

    *ms_rloc = extract_lisp_address(ptr);

    cumulative_add_length += get_addr_len(ms_rloc->afi) + FIELD_AFI_LEN;

    ptr = CO(ptr, get_addr_len(ms_rloc->afi) + FIELD_AFI_LEN);

    /* Extract the Private ETR RLOC */

    *private_etr_rloc = extract_lisp_address(ptr);
    /* In this case this function should return afi = 0 */

    cumulative_add_length +=
        get_addr_len(private_etr_rloc->afi) + FIELD_AFI_LEN;

    ptr = CO(ptr, get_addr_len(private_etr_rloc->afi) + FIELD_AFI_LEN);


    /* Extract the list of RTR RLOCs */

    rtr_rloc_itr = rtr_rloc_list;

    while (cumulative_add_length < *lcaf_length) {

        rtr_rloc_elt = (lisp_addr_t *) malloc(sizeof(lisp_addr_t));

        if (rtr_rloc_elt == NULL) {
            lispd_log_msg(LISP_LOG_DEBUG_2, "Info-Reply: Error malloc rtr_rloc_list");
            free_lisp_addr_list(rtr_rloc_list);
            return (BAD);
        }

        *rtr_rloc_elt = extract_lisp_address(ptr);

        rtr_rloc_itr->address = rtr_rloc_elt;

        cumulative_add_length +=
            get_addr_len(rtr_rloc_elt->afi) + FIELD_AFI_LEN;

        /* If still more RTR RLOCs */

        if (cumulative_add_length < *lcaf_length) {

            ptr = CO(ptr, get_addr_len(rtr_rloc_elt->afi) + FIELD_AFI_LEN);

            rtr_rloc_itr->next =
                (lispd_addr_list_t *) malloc(sizeof(lispd_addr_list_t));

            if (rtr_rloc_itr->next == NULL) {
                lispd_log_msg(LISP_LOG_DEBUG_2,"Info-Reply: Error malloc rtr_rloc_list");
                free_lisp_addr_list(rtr_rloc_list);
                return (BAD);
            }

            rtr_rloc_itr = rtr_rloc_itr->next;
        }
    }

    return (GOOD);
}


/*
 *  Process an Info-Reply Message
 *  Receive an Info-Reply message and process based on control bits
 *
 */

int process_info_reply_msg(uint8_t *packet)
{

    lispd_pkt_info_nat_t *irp;
    lispd_pkt_info_reply_lcaf_t *irp_lcaf;

    uint8_t lisp_type;
    uint8_t reply;

    uint64_t nonce;
    uint16_t key_id;
    uint16_t auth_data_len;
	uint8_t *auth_data_pos;

    uint32_t ttl;
    uint8_t eid_mask_len;

    uint16_t lcaf_afi;
    uint8_t flags;
    uint8_t lcaf_type;
    uint16_t lcaf_length;

    lisp_addr_t eid_prefix;

    int hdr_len;

	unsigned int pckt_len;

    lisp_addr_t global_etr_rloc;
    lisp_addr_t ms_rloc;
    lisp_addr_t private_etr_rloc;
    lispd_addr_list_t rtr_rloc_list;


    /*
     * Get source port and address.
     * IPv4 and IPv6 support
     */

    irp = (lispd_pkt_info_nat_t *) packet;


    hdr_len = extract_info_nat_header((lispd_pkt_info_nat_t *) packet,
                                      &lisp_type,
                                      &reply,
                                      &nonce,
                                      &key_id,
                                      &auth_data_len,
                                      &auth_data_pos,
                                      &ttl,
                                      &eid_mask_len,
                                      &eid_prefix);


	

    irp_lcaf =
        (lispd_pkt_info_reply_lcaf_t *) CO(irp,hdr_len + get_addr_len(eid_prefix.afi));

	/* Extract Info-Reply body fields */

    if (BAD == extract_info_reply_body(irp_lcaf,
                                         &lcaf_afi,
                                         &flags,
                                         &lcaf_type,
                                         &lcaf_length,
                                         &global_etr_rloc,
                                         &ms_rloc,
                                         &private_etr_rloc,
                                         &rtr_rloc_list)) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "Info-Reply: Error extracting packet data");
        return (BAD);
    }


    pckt_len = hdr_len+
               sizeof(lispd_pkt_info_reply_lcaf_t)+
               get_addr_len(eid_prefix.afi)+
               lcaf_length - 4; 
               /* These 4 bytes are already in sizeof(lispd_pkt_info_reply_lcaf_t) */

    if(BAD == check_auth_field(key_id,
                                 map_servers->key,
                                 (void *) packet,
                                 pckt_len,
                                 auth_data_pos,
                                 auth_data_len)){
									 
        lispd_log_msg(LISP_LOG_DEBUG_2, "Info-Reply: Error checking auth data field");
        return(BAD);
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_2, "Info-Reply: Correct auth data field checking");
    }

	
	/* Select the best RTR from the list retrieved from the Info-Reply*/

    natt_rtr = *select_best_rtr_from_rtr_list(&rtr_rloc_list);

    /* Check if behind NAT */

    switch (compare_lisp_addresses(&global_etr_rloc, get_current_locator())) {

        case TRUE:

        behind_nat = FALSE;
        lispd_log_msg(LISP_LOG_DEBUG_2, "NAT Traversal: MN is not behind NAT");
        break;

        case FALSE:

        behind_nat = TRUE;
        lispd_log_msg(LISP_LOG_DEBUG_2, "NAT Traversal: MN is behind NAT");

        break;

        case UNKNOWN:

        behind_nat = UNKNOWN;
        lispd_log_msg(LISP_LOG_DEBUG_2, "NAT Traversal: Unknown state");

        break;

    }

    /* Once we know the NAT state we send a Map-Register */

    map_register(NULL,NULL);

    return (GOOD);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
