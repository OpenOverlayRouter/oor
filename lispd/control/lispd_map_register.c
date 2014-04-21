/* 
 * lispd_map_register.c
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
 *
 */

//#include <sys/timerfd.h>
#include "lispd_map_register.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <lispd_external.h>
#include <lispd_lib.h>
#include "lispd_local_db.h"
#include <packets.h>
#include <lispd_sockets.h>
#include "lispd_info_request.h"

int map_register_process_default();
int map_register_process_encap();



/*
 * Build and send a map register for the mapping entry passed as argument.
 *  Return GOOD if at least a map register could be send
 */


int build_and_send_map_register_msg(mapping_t *mapping)
{
    uint8_t                   *packet               = NULL;
    int                       packet_len            = 0;
    uint8_t                   *map_register_pkt     = NULL;
    int                       map_reg_packet_len    = 0;
    map_register_hdr_t  *map_register         = NULL;
    lispd_map_server_list_t   *ms                   = NULL;
    uint32_t                  md_len                = 0;
    int                       sent_map_registers    = 0;
    lisp_addr_t               *src_addr             = NULL;
    int                       out_socket            = 0;

    if ((map_register_pkt = build_map_register_pkt(mapping, &map_reg_packet_len)) == NULL) {
        lmlog(DBG_1, "build_and_send_map_register_msg: Couldn't build map register packet");
        return(BAD);
    }

    map_register = (map_register_hdr_t *)map_register_pkt;

    //  for each map server, send a register, and if verify
    //  send a map-request for our eid prefix

    ms = map_servers;

    while (ms != NULL) {

        /*
         * Fill in proxy_reply and compute the HMAC with SHA-1.
         */

        map_register->proxy_reply = ms->proxy_reply;
        memset(map_register->auth_data,0,LISP_SHA1_AUTH_DATA_LEN);   /* make sure */

        if (!HMAC((const EVP_MD *) EVP_sha1(),
                (const void *) ms->key,
                strlen(ms->key),
                (uchar *) map_register,
                map_reg_packet_len,
                (uchar *) map_register->auth_data,
                &md_len)) {
            lmlog(DBG_1, "build_and_send_map_register_msg: HMAC failed for map-register");
            ms = ms->next;
            continue;
        }


        /*
         * Get src interface
         */

        src_addr    = get_default_ctrl_address(ms->address->afi);
        out_socket  = get_default_ctrl_socket (ms->address->afi);

        if (src_addr == NULL){
            lmlog(DBG_1, "build_and_send_map_register_msg: Couden't send Map Register to %s, no output interface with afi %d.",
                    lisp_addr_to_char(ms->address), ms->address->afi);
            ms = ms->next;
            continue;
        }


        /*
         * Add UDP and IP header to the Map Register message
         */

        packet = build_ip_udp_pcket(map_register_pkt,
                                        map_reg_packet_len,
                                        src_addr,
                                        ms->address,
                                        LISP_CONTROL_PORT,
                                        LISP_CONTROL_PORT,
                                        &packet_len);

        if (packet == NULL){
            lmlog(DBG_1,"build_and_send_map_register_msg: Couldn't send Map-Register. Error adding IP and UDP header to the message");
            ms = ms->next;
            continue;
        }

        /*
         * Send the map register
         */

        if ((err = send_packet(out_socket,packet,packet_len))==GOOD){
            lmlog(DBG_1, "Sent Map-Register message for %s to Map Server at %s",
                    lisp_addr_to_char(mapping_eid(mapping)),
                    lisp_addr_to_char(ms->address));
            sent_map_registers++;
        }else{
            lmlog(LWRN, "Couldn't send Map Register for %s to the Map Server %s",
                    lisp_addr_to_char(mapping_eid(mapping)),
                    lisp_addr_to_char(ms->address));
        }
        free (packet);
        ms = ms->next;
    }

    free(map_register_pkt);
    if (sent_map_registers == 0){
        return (BAD);
    }

    return (GOOD);
}




/*
 *  build_map_register_pkt
 *
 *  Build the map-register
 *
 */

uint8_t *build_map_register_pkt(
        mapping_t       *mapping,
        int                     *mrp_len)
{
    uint8_t                         *packet     = NULL;
    map_register_hdr_t        *mrp        = NULL;
    mapping_record_hdr_t            *mr         = NULL;

    *mrp_len = sizeof(map_register_hdr_t) +
              mapping_get_size_in_record(mapping);

    if ((packet = malloc(*mrp_len)) == NULL) {
        lmlog(LWRN, "build_map_register_pkt: Unable to allocate memory for Map Register packet: %s", strerror(errno));
        return(NULL);
    }

    memset(packet, 0, *mrp_len);

    /*
     *  build the packet
     *
     *  Fill in mrp->proxy_reply and compute the HMAC in 
     *  send_map_register()
     *
     */
    mrp = (map_register_hdr_t *)packet;


    mrp->lisp_type        = LISP_MAP_REGISTER;
    mrp->map_notify       = 1;              /* TODO conf item */
    mrp->nonce            = 0;
    mrp->record_count     = 1;				/* XXX Just supported one record per map register */
    mrp->key_id           = htons(HMAC_SHA_1_96);
    mrp->auth_data_len    = htons(LISP_SHA1_AUTH_DATA_LEN);


    /* skip over the fixed part,  assume one record (mr) */

    mr = (mapping_record_hdr_t *) CO(mrp, sizeof(map_register_hdr_t));

    if (mapping_fill_record_in_pkt(mr, mapping, NULL) != NULL) {
        return(packet);
    } else {
        free(packet);
        return(NULL);
    }
}


int build_and_send_ecm_map_register(
        mapping_t           *mapping,
        lispd_map_server_list_t     *map_server,
        lisp_addr_t                 *nat_rtr_addr,
        lispd_iface_elt             *src_iface,
        lispd_site_ID               *site_ID,
        lispd_xTR_ID                *xTR_ID,
        uint64_t                    *nonce)
{

    uint8_t                     *packet                 = NULL;
    int                         packet_len              = 0;
    map_register_hdr_t    *map_register_pkt       = NULL;
    map_register_hdr_t    *map_register_pkt_tmp   = NULL;
    uint8_t                     *ecm_map_register       = NULL;
    int                         map_register_pkt_len    = 0;
    int                         ecm_map_register_len    = 0;
    lisp_addr_t                 *src_addr               = NULL;
    int                         out_socket              = 0;
    int                         result                  = 0;

    map_register_pkt = (map_register_hdr_t *)build_map_register_pkt(mapping,&map_register_pkt_len);


    /* Map Server proxy reply */
    map_register_pkt->proxy_reply = 1; /* We have to let the Map Server to proxy reply.
                                          If not, we need to keep open a state in NAT via Info-Requests */

    /* R bit always 1 for Map Registers sent to the RTR */
    map_register_pkt->rbit = 1;

    /* xTR-ID must be set if RTR bit is 1 */
    map_register_pkt->ibit = 1;

    /* XXX Quick hack */
    /* Cisco IOS RTR implementation drops Data-Map-Notify if ECM Map Register nonce = 0 */
    map_register_pkt->nonce = nonce_build((unsigned int) time(NULL));
    *nonce = map_register_pkt->nonce;

    /* Add xTR-ID and site-ID fields */

    map_register_pkt_tmp = map_register_pkt;

    map_register_pkt = (map_register_hdr_t *)malloc(map_register_pkt_len +
    													  sizeof(lispd_xTR_ID)+
    													  sizeof(lispd_site_ID));

    memset(map_register_pkt, 0,map_register_pkt_len +
                               sizeof(lispd_xTR_ID) +
                               sizeof(lispd_site_ID));

    memcpy(map_register_pkt,map_register_pkt_tmp,map_register_pkt_len);
    free(map_register_pkt_tmp);


    memcpy(CO(map_register_pkt,map_register_pkt_len),
    	   xTR_ID,
    	   sizeof(lispd_xTR_ID));

    memcpy(CO(map_register_pkt, map_register_pkt_len + sizeof(lispd_xTR_ID)),
       	   site_ID,
       	   sizeof(lispd_site_ID));

    map_register_pkt_len = map_register_pkt_len + sizeof(lispd_site_ID) + sizeof(lispd_xTR_ID);


    complete_auth_fields(map_server->key_type,
                         &(map_register_pkt->key_id),
                         map_server->key,
                         (void *) (map_register_pkt),
                         map_register_pkt_len,
                         &(map_register_pkt->auth_data));


    /* Get Src Iface information */

    if (src_iface == NULL){
        lmlog(DBG_1, "build_and_send_ecm_map_register: Couden't send Encapsulated Map Register to %s, no output interface with afi %d.",
                lisp_addr_to_char(map_server->address),
                ip_addr_afi(lisp_addr_ip(map_server->address)));
        return (BAD);
    }

    switch (nat_rtr_addr->afi){
    case AF_INET:
        src_addr     = src_iface->ipv4_address;
        out_socket   = src_iface->out_socket_v4;
        break;
    case AF_INET6:
        src_addr     = src_iface->ipv6_address;
        out_socket   = src_iface->out_socket_v6;
        break;
    }

    if (src_addr == NULL){
        lmlog(DBG_2, "build_and_send_ecm_map_register: No output interface for afi %d",nat_rtr_addr->afi);
        free (map_register_pkt);
        return (BAD);
    }



    ecm_map_register = build_control_encap_pkt((uint8_t *) map_register_pkt,
                                               map_register_pkt_len,
                                               src_addr,
                                               map_server->address,
                                               LISP_CONTROL_PORT,
                                               LISP_CONTROL_PORT,
                                               &ecm_map_register_len);
    free(map_register_pkt);

    if (ecm_map_register == NULL) {
        return (BAD);
    }


    packet = build_ip_udp_pcket(ecm_map_register,
                                ecm_map_register_len,
                                src_addr,
                                nat_rtr_addr,
                                LISP_DATA_PORT,
                                LISP_CONTROL_PORT,
                                &packet_len);
    free (ecm_map_register);

    if (packet == NULL){
        lmlog(DBG_2, "build_and_send_ecm_map_register: Couldn't send Encapsulated Map Register. Error adding IP and UDP header to the message");
        return (BAD);
    }

    if ((err = send_packet(out_socket,packet,packet_len)) == GOOD){
        lmlog(DBG_1, "Sent Encapsulated Map-Register message for %s/%d to Map Server at %s through RTR %s",
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length,
                get_char_from_lisp_addr_t(*(map_server->address)),
                get_char_from_lisp_addr_t(*nat_rtr_addr));
        result = GOOD;
    }else{
        lmlog(DBG_1, "build_and_send_ecm_map_register: Couldn't sent Encapsulated Map-Register message for %s/%d to Map Server at %s through RTR %s",
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length,
                get_char_from_lisp_addr_t(*(map_server->address)),
                get_char_from_lisp_addr_t(*nat_rtr_addr));
        result = BAD;
    }

    free(packet);

    return (result);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
