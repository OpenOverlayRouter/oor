/*
 * lispd_info_request.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Builds and sends Info-Request messages.
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
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 *
 */

#include "lispd_external.h"
#include "lispd_iface_list.h"
#include "lispd_info_request.h"
#include "lispd_lib.h"
#include "lispd_locator.h"
#include "lispd_mapping.h"
#include "lispd_pkt_lib.h"
#include "lispd_sockets.h"
#ifdef VPNAPI
#include "api/ipc.h"
#endif
#include "hmac/hmac.h"


/*
 *  build_info_request_pkt
 *
 *  Build the info-request.
 *
 *  Once done with the packet, it should be free()!
 */



lispd_pkt_info_nat_t *build_info_request_pkt(
        uint8_t         key_type,
        uint32_t        ttl,
        uint8_t         eid_mask_length,
        lisp_addr_t     *eid_prefix,
        uint32_t        *pkt_len,
        uint64_t        *nonce)
{
    lispd_pkt_info_nat_t            *irp         = NULL;
    lispd_pkt_info_request_lcaf_t   *irp_lcaf    = NULL;
    uint32_t                        irp_len      = 0;
    uint32_t                        header_len   = 0;
    uint32_t                        lcaf_hdr_len = 0;

    *nonce = build_nonce((unsigned int) time(NULL));

    irp = create_and_fill_info_nat_header(LISP_INFO_NAT,
                                          NAT_NO_REPLY,
                                          *nonce,
                                          key_type,
                                          ttl,
                                          eid_mask_length,
                                          eid_prefix,
                                          &header_len);

    if (irp == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "Error building info-request header");
        return (NULL);
    }



    lcaf_hdr_len = sizeof(lispd_pkt_info_request_lcaf_t);

    /* Total length of the packet */

    irp_len = header_len + lcaf_hdr_len;

    /*  Expand the amount of memory assigned to the packet */
    irp = realloc(irp, irp_len);

    if (irp == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "realloc (post-header info-nat packet): %s",
               strerror(errno));
        return (NULL);
    }


    /*
     * Skip over the fixed part and build the lcaf
     */

    irp_lcaf = (lispd_pkt_info_request_lcaf_t *) CO(irp, header_len);

    /*
     *  Make sure this is clean
     */

    memset(irp_lcaf, 0, lcaf_hdr_len);

    /* Previous draft implementation */
    /* Fill lcaf info-request fields */
    /*
    irp_lcaf->lcaf_afi = htons(LISP_AFI_LCAF);
    irp_lcaf->flags = 0;
    irp_lcaf->lcaf_type = LISP_LCAF_NULL;
    irp_lcaf->length = htons(0);
    */
 
    /* New draft implementation */
	irp_lcaf->afi = htons(0); /* AFI = 0 */

    /* Return the len of the packet */
    *pkt_len = irp_len;

    return (irp);
}




int build_and_send_info_request(
        lispd_map_server_list_t     *map_server,
        uint32_t                    ttl,
        uint8_t                     eid_mask_length,
        lisp_addr_t                 *eid_prefix,
        lisp_addr_t		            *src_rloc,
        uint64_t                    *nonce)
{
    lispd_pkt_info_nat_t    *info_request_pkt       = NULL;
    uint32_t                info_request_pkt_len    = 0;


    info_request_pkt = build_info_request_pkt(
            map_server->key_type,
            ttl,
            eid_mask_length,
            eid_prefix,
            &info_request_pkt_len,
            nonce);

    if (info_request_pkt == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "build_and_send_info_request: Couldn't build info request packet");
        return (BAD);
    }

    err = complete_auth_fields(map_server->key_type,
            map_server->key,
            (void *)(info_request_pkt),
            info_request_pkt_len,
            (void *)(info_request_pkt->auth_data));

    if (err != GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_2, "build_and_send_info_request: HMAC failed for info-request");
        free(info_request_pkt);
        return (BAD);
    }

    err = send_control_msg((uint8_t *)info_request_pkt,
            info_request_pkt_len,
            src_rloc,
            map_server->address,
            LISP_CONTROL_PORT,
            LISP_CONTROL_PORT);

    free (info_request_pkt);

    if (err == GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_1,"Sent Info Request message to Map Server at %s with EID %s/%d and Nonce %s. Src RLOC: %s",
                        get_char_from_lisp_addr_t(*(map_server->address)),
                        get_char_from_lisp_addr_t(*eid_prefix),
                        eid_mask_length,
                        get_char_from_nonce(*nonce),
                        get_char_from_lisp_addr_t(*src_rloc));
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1,"build_and_send_info_request: Couldn't sent Info Request message to Map Server at %s with EID %s/%d and Nonce %s. Src RLOC: %s",
                        get_char_from_lisp_addr_t(*(map_server->address)),
                        get_char_from_lisp_addr_t(*eid_prefix),
                        eid_mask_length,
                        get_char_from_nonce(*nonce),
                        get_char_from_lisp_addr_t(*src_rloc));
    }

    return (err);
}
int initial_info_request_process()
{
    int                         ctr                 = 0;
    int                         ctr1                = 0;
    lispd_mapping_list          *mapping_list[2]    = {NULL, NULL};
    lispd_mapping_elt           *mapping            = NULL;
    lispd_locators_list         *locators_list[2]   = {NULL, NULL};
    lispd_locator_elt           *locator            = NULL;
    timer_info_request_argument *timer_arg          = NULL;


    mapping_list[0] = get_all_mappings(AF_INET);
    mapping_list[1] = get_all_mappings(AF_INET6);

    for (ctr = 0 ; ctr < 2 ; ctr++) {
        while (mapping_list[ctr]!=NULL){
            mapping = mapping_list[ctr]->mapping;
            locators_list[0] = mapping->head_v4_locators_list;
            locators_list[1] = mapping->head_v6_locators_list;
            for (ctr1 = 0 ; ctr1 < 2 ; ctr1++){
                while(locators_list[ctr1] != NULL){
                    locator = locators_list[ctr1]->locator;
                    if (*(locator->state) == UP){
                        timer_arg = new_timer_inf_req_arg(mapping, locator);
                        if (timer_arg == NULL){
                            locators_list[ctr1] = locators_list[ctr1]->next;
                            continue;
                        }
                        info_request(NULL,timer_arg);
                    }
                    locators_list[ctr1] = locators_list[ctr1]->next;
                }
            }
            mapping_list[ctr] = mapping_list[ctr]->next;
        }
    }
    return(GOOD);
}

void  restart_info_request_process(
		lispd_mapping_list 	*mapping_list,
		lisp_addr_t 		*src_addr)
{
	lispd_mapping_elt           *mapping            = NULL;
	void                        *timer_arg          = NULL;
	lispd_locator_elt           *src_locator        = NULL;
	nat_info_str                *nat_info           = NULL;

	lispd_log_msg(LISP_LOG_DEBUG_1,"restart_info_request_process: Restart info request process for  "
			"mappings associated with address %s", get_char_from_lisp_addr_t(*src_addr));

	if (src_addr == NULL){
		lispd_log_msg(LISP_LOG_DEBUG_1,"restart_info_request_process: No source address specified");
		return;
	}

	while (mapping_list != NULL){
		mapping = mapping_list->mapping;
		src_locator = get_locator_from_mapping(mapping,src_addr);
		if (src_locator == NULL){
		    mapping_list = mapping_list->next;
		    continue;
		}
		nat_info = ((lcl_locator_extended_info *)src_locator->extended_info)->nat_info;

		if (nat_info->inf_req_timer == NULL){
		    nat_info->inf_req_timer = create_timer(INFO_REPLY_TTL_TIMER);
			if (nat_info->inf_req_timer == NULL){
				mapping_list = mapping_list->next;
				continue;
			}

			timer_arg = (void *)new_timer_inf_req_arg(mapping, src_locator);
			if (timer_arg == NULL){
				free(nat_info->inf_req_timer);
				nat_info->inf_req_timer = NULL;
				mapping_list = mapping_list->next;
				continue;
			}
		}else{
			free(nat_info->inf_req_nonce);
			nat_info->inf_req_nonce = NULL;
			timer_arg = nat_info->inf_req_timer->cb_argument;
		}

		start_timer(nat_info->inf_req_timer, LISPD_INF_REQ_HANDOVER_TIMEOUT, info_request, timer_arg);
		mapping_list = mapping_list->next;
	}
}


int info_request(
		timer   *ttl_timer,
		void    *arg)
{
	lispd_mapping_elt           *mapping            = ((timer_info_request_argument *)arg)->mapping;
	lispd_locator_elt           *src_locator        = ((timer_info_request_argument *)arg)->src_locator;
	nat_info_str                *nat_info           = ((lcl_locator_extended_info*)src_locator->extended_info)->nat_info;
	nonces_list                 *nonces             = nat_info->inf_req_nonce;
	int                         next_timer_time     = 0;

	if (nonces == NULL){
		nonces = new_nonces_list();
		if (nonces == NULL){
			lispd_log_msg(LISP_LOG_WARNING,"info_request: Unable to allocate memory for nonces.");
			return (BAD);
		}
		nat_info->inf_req_nonce = nonces;
		nat_info->status = UNKNOWN;
	}

	if (nonces->retransmits <= LISPD_MAX_RETRANSMITS){
		if ((err=build_and_send_info_request(
				map_servers,
				DEFAULT_INFO_REQUEST_TIMEOUT,
				mapping->eid_prefix_length,
				&(mapping->eid_prefix),
				src_locator->locator_addr,
				&(nonces->nonce[nonces->retransmits])))!=GOOD){
			lispd_log_msg(LISP_LOG_DEBUG_1,"info_request: Couldn't send info request message.");
		}
		nonces->retransmits++;
		next_timer_time = LISPD_INITIAL_MR_TIMEOUT;
	} else{
		free (nonces);
		nat_info->inf_req_nonce = NULL;
		lispd_log_msg(LISP_LOG_ERR,"info_request: Communication error between LISPmob and Map Server. Retry after %d seconds",MAP_REGISTER_INTERVAL);
//#ifdef VPNAPI
//        ipc_send_log_msg(INF_REQ_ERR);
//#endif
		next_timer_time = MAP_REGISTER_INTERVAL;
		nat_info->status = NO_INFO_REPLY;
	}

    /*
     * Configure timer to send the next map register.
     */
    if (nat_info->inf_req_timer == NULL) {
        nat_info->inf_req_timer = create_timer(INFO_REPLY_TTL_TIMER);
    }
    start_timer(nat_info->inf_req_timer, next_timer_time, info_request, arg);
    lispd_log_msg(LISP_LOG_DEBUG_1, "Reprogrammed info request in %d seconds",next_timer_time);
    return(GOOD);
}

timer_info_request_argument * new_timer_inf_req_arg(
		lispd_mapping_elt *mapping,
		lispd_locator_elt *src_locator)
{
	timer_info_request_argument * timer_arg = (timer_info_request_argument *)calloc(1,sizeof(timer_info_request_argument));
	if (timer_arg == NULL){
		lispd_log_msg(LISP_LOG_WARNING,"new_timer_inf_req_arg: Unable to allocate memory for a timer_map_register_argument");
		return (NULL);
	}
	timer_arg->mapping = mapping;
	timer_arg->src_locator = src_locator;

	return (timer_arg);
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
