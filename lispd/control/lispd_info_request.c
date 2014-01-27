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

#include "lispd_info_request.h"
#include <lispd_external.h>
#include <lispd_lib.h>
#include <lispd_pkt_lib.h>
#include <lispd_sockets.h>
#include <cksum.h>
#include "lispd_local_db.h"


/*
 *  build_info_request_pkt
 *
 *  Build the info-request.
 *
 *  Once done with the packet, it should be free()!
 */



lispd_pkt_info_nat_t *build_info_request_pkt(
        uint16_t        auth_data_len,
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
                                          auth_data_len,
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
        lispd_iface_elt             *src_iface,
        uint64_t                    *nonce)
{
    uint8_t                 *packet                 = NULL;
    int                     packet_len              = 0;
    lispd_pkt_info_nat_t    *info_request_pkt       = NULL;
    uint32_t                info_request_pkt_len    = 0;
    uint16_t                auth_data_len           = 0;
    lisp_addr_t             *src_addr               = NULL;
    int                     out_socket              = 0;
    int                     result                  = 0;

    auth_data_len = get_auth_data_len(map_server->key_type);


    info_request_pkt = build_info_request_pkt(
            auth_data_len,
            ttl,
            eid_mask_length,
            eid_prefix,
            &info_request_pkt_len,
            nonce);

    if (info_request_pkt == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "build_and_send_info_request: Couldn't build info request packet");
        return (BAD);
    }

    if (BAD == complete_auth_fields(map_server->key_type,
                                      &(info_request_pkt->key_id),
                                      map_server->key,
                                      info_request_pkt,
                                      info_request_pkt_len,
                                      info_request_pkt->auth_data)) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "build_and_send_info_request: HMAC failed for info-request");
        free(info_request_pkt);
        return (BAD);
    }

    /* Get src interface information */

    src_addr    = get_iface_address (src_iface, map_server->address->afi);
    out_socket  = get_iface_socket (src_iface, map_server->address->afi);

    if (src_addr == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2, "build_and_send_info_request: No output interface for afi %d",map_server->address->afi);
        free(info_request_pkt);
        return (BAD);
    }

    /* Add UDP and IP header to the RAW paket */
    packet = build_ip_udp_pcket((uint8_t *)info_request_pkt,
                                info_request_pkt_len,
                                src_addr,
                                map_server->address,
                                LISP_CONTROL_PORT,
                                LISP_CONTROL_PORT,
                                &packet_len);
    free(info_request_pkt);


    if (packet != NULL){
            err = send_packet(out_socket,packet,packet_len);
            free(packet);
    }else {
        err = BAD;
    }

    if (err == GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_1,"Sent Info Request message to Map Server at %s from locator %s with EID %s and Nonce %s",
                        lisp_addr_to_char(map_server->address),
                        lisp_addr_to_char(src_addr),
                        lisp_addr_to_char(eid_prefix),
                        get_char_from_nonce(*nonce));
        result = GOOD;
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1,"build_and_send_info_request: Couldn't sent Info Request message to Map Server at %s from locator %s with EID %s and Nonce %s",
                        lisp_addr_to_char(map_server->address),
                        lisp_addr_to_char(src_addr),
                        lisp_addr_to_char(eid_prefix),
                        get_char_from_nonce(*nonce));
        result = BAD;
    }

    return (result);
}

int initial_info_request_process()
{
    int result = 0;
    lispd_mapping_elt         *mapping          = NULL;
    void                      *it               = NULL;

    local_map_db_foreach_entry(it) {
        mapping = (lispd_mapping_elt *)it;
        if (mapping->locator_count != 0){
            result = info_request(NULL,mapping);
            return (result);
        }
    } local_map_db_foreach_end;
    return(GOOD);
}



int info_request(
        timer   *ttl_timer,
        void    *arg)
{
    lispd_mapping_elt  *mapping         = NULL;
    int                next_timer_time  = 0;

    mapping = (lispd_mapping_elt *)arg;

    if (default_ctrl_iface_v4 != NULL){
        if (nat_ir_nonce == NULL){
            nat_ir_nonce = new_nonces_list();
            if (nat_ir_nonce == NULL){
                lispd_log_msg(LISP_LOG_WARNING,"info_request: Unable to allocate memory for nonces.");
                return (BAD);
            }
        }

        if (nat_ir_nonce->retransmits <= LISPD_MAX_RETRANSMITS){
            if ((err=build_and_send_info_request(
                    map_servers,
                    DEFAULT_INFO_REQUEST_TIMEOUT,
                    mapping->eid_prefix_length,
                    &(mapping->eid_prefix),
                    default_ctrl_iface_v4,
                    &(nat_ir_nonce->nonce[nat_ir_nonce->retransmits])))!=GOOD){
                lispd_log_msg(LISP_LOG_DEBUG_1,"info_request: Couldn't send info request message.");
            }
            nat_ir_nonce->retransmits++;
            next_timer_time = LISPD_INITIAL_EMR_TIMEOUT;
        } else{
            free (nat_ir_nonce);
            nat_ir_nonce = NULL;
            lispd_log_msg(LISP_LOG_ERR,"info_request: Communication error between LISPmob and RTR. Retry after %d seconds",MAP_REGISTER_INTERVAL);
            next_timer_time = MAP_REGISTER_INTERVAL;
        }
    }else {
        return (BAD);
    }

    /*
     * Configure timer to send the next map register.
     */
    if (info_reply_ttl_timer == NULL) {
        info_reply_ttl_timer = create_timer(INFO_REPLY_TTL_TIMER);
    }
    start_timer(info_reply_ttl_timer, next_timer_time, info_request, mapping);
    lispd_log_msg(LISP_LOG_DEBUG_1, "Reprogrammed info request in %d seconds",next_timer_time);
    return(GOOD);
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
