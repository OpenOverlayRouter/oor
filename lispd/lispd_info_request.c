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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

//#define _BSD_SOURCE             // needed?
#include <endian.h>

#include "linux/netlink.h"
#include "lispd_external.h"

#include "lispd_info_request.h"
#include "lispd_sockets.h"


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
        uint16_t        key_type,
        char            *key,
        uint32_t        ttl,
        uint8_t         eid_mask_length,
        lisp_addr_t     *eid_prefix,
        lisp_addr_t     *src_addr,
        uint32_t        src_port,
        lisp_addr_t     *dst_addr,
        uint32_t        dst_port,
        uint64_t        *nonce)
{
    uint32_t             packet_len         = 0;
    uint16_t             auth_data_len      = 0;
    lispd_pkt_info_nat_t *info_request_pkt  = NULL;

    auth_data_len = get_auth_data_len(key_type);


    info_request_pkt = build_info_request_pkt(
            auth_data_len,
            ttl,
            eid_mask_length,
            eid_prefix,
            &packet_len,
            nonce);

    if (info_request_pkt == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "Couldn't build info request packet");
        return (BAD);
    }


    if (BAD == complete_auth_fields(key_type,
                                      &(info_request_pkt->key_id),
                                      key,
                                      info_request_pkt,
                                      packet_len,
                                      info_request_pkt->auth_data)) {
        free(info_request_pkt);
        lispd_log_msg(LISP_LOG_DEBUG_2, "HMAC failed for info-request");
        return (BAD);
    }


    if (BAD == send_udp_ipv4_packet(src_addr,
                             dst_addr,
                             src_port,
                             dst_port,
                             info_request_pkt,
                             packet_len)) {
        lispd_log_msg(LISP_LOG_DEBUG_2,"Couldn't send info-request for",eid_prefix);
        free(info_request_pkt);
        return (BAD);
    }

    free(info_request_pkt);
    return (GOOD);
}

int initial_info_request_process()
{
    int result = 0;
    patricia_tree_t           *dbs[2]           = {NULL,NULL};
    int                       ctr               = 0;
    patricia_tree_t           *tree             = NULL;
    patricia_node_t           *node             = NULL;
    lispd_mapping_elt         *mapping          = NULL;

    dbs[0] = get_local_db(AF_INET);
    dbs[1] = get_local_db(AF_INET6);


    for (ctr = 0 ; ctr < 2 ; ctr++) {
        tree = dbs[ctr];
        if (!tree){
            continue;
        }
        PATRICIA_WALK(tree->head, node) {
            mapping = ((lispd_mapping_elt *)(node->data));
            if (mapping->locator_count != 0){
                result = info_request(NULL,mapping);
                return (result);
            }
        }PATRICIA_WALK_END;
    }
    return(GOOD);
}



int info_request(
        timer   *ttl_timer,
        void    *arg)
{
    lispd_mapping_elt  *mapping         = NULL;
    int                next_timer_time  = 0;

    mapping = (lispd_mapping_elt *)arg;

    if (nat_ir_nonce == NULL){
        nat_ir_nonce = new_nonces_list();
        if (nat_ir_nonce == NULL){
            lispd_log_msg(LISP_LOG_WARNING,"info_request: Unable to allocate memory for nonces.");
            return (BAD);
        }
    }

    if (nat_ir_nonce->retransmits <= LISPD_MAX_RETRANSMITS){
        if ((err=build_and_send_info_request(
                map_servers->key_type,
                map_servers->key,
                DEFAULT_INFO_REQUEST_TIMEOUT,
                mapping->eid_prefix_length,
                &(mapping->eid_prefix),
                default_ctrl_iface_v4->ipv4_address,
                LISP_CONTROL_PORT,
                map_servers->address,
                LISP_CONTROL_PORT,
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
