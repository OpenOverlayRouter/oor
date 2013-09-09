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
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_register.h"
#include "lispd_map_request.h"
#include "lispd_pkt_lib.h"
#include "lispd_sockets.h"
#include "patricia/patricia.h"
#include "lispd_info_request.h"

int map_register_process();
int encapsulated_map_register_process();


/*
 *  map_server_register (tree)
 *
 */

timer *map_register_timer = NULL;

/*
 * Timer and arg parameters are not used but must be defined to be consistent
 * with timer call back function.
 */
int map_register(
        timer   *t,
        void    *arg)
{
    int result = 0;

    if (!map_servers) {
        lispd_log_msg(LISP_LOG_CRIT, "map_register: No Map Servers conifgured!");
        exit_cleanup();
    }

    if(nat_aware==TRUE){ /* NAT procedure instead of the standard one */

        if(nat_status == UNKNOWN){
            result = initial_info_request_process();
        }

        if(nat_status == FULL_NAT){
            result = encapsulated_map_register_process();
        }
    }

    if((nat_aware == FALSE)||((nat_aware == TRUE)&&(nat_status ==NO_NAT ))){/* Standard Map-Register mechanism */
        result = map_register_process();
    }

    return (result);
}


int map_register_process()
{
    patricia_tree_t           *dbs[2]           = {NULL,NULL};
    patricia_tree_t           *tree             = NULL;
    patricia_node_t           *node             = NULL;
    lispd_mapping_elt         *mapping          = NULL;
    int                       ctr               = 0;

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

                err = build_and_send_map_register_msg(mapping);
                if (err != GOOD){
                    lispd_log_msg(LISP_LOG_ERR, "map_register: Coudn't register %s/%d EID!",
                            get_char_from_lisp_addr_t(mapping->eid_prefix),
                            mapping->eid_prefix_length);
                }
            }
        }PATRICIA_WALK_END;
    }

    /*
     * Configure timer to send the next map register.
     */
    if (map_register_timer == NULL) {
        map_register_timer = create_timer(MAP_REGISTER_TIMER);
    }
    start_timer(map_register_timer, MAP_REGISTER_INTERVAL, map_register, NULL);
    lispd_log_msg(LISP_LOG_DEBUG_1, "Reprogrammed map register in %d seconds",MAP_REGISTER_INTERVAL);
    return(GOOD);
}

int encapsulated_map_register_process()
{
    patricia_tree_t           *dbs[2]           = {NULL,NULL};
    patricia_tree_t           *tree             = NULL;
    patricia_node_t           *node             = NULL;
    lispd_mapping_elt         *mapping          = NULL;
    lispd_locators_list       *locators_list[2] = {NULL, NULL};
    lispd_locator_elt         *locator          = NULL;
    lisp_addr_t               *nat_rtr          = NULL;
    int                       next_timer_time   = 0;
    int                       ctr               = 0;
    int                       ctr1              = 0;

    dbs[0] = get_local_db(AF_INET);
    dbs[1] = get_local_db(AF_INET6);


    if (nat_emr_nonce == NULL){
        nat_emr_nonce = new_nonces_list();
        if (nat_emr_nonce == NULL){
            lispd_log_msg(LISP_LOG_WARNING,"encapsulated_map_register_process: Unable to allocate memory for nonces.");
            return (BAD);
        }
    }
    if (nat_emr_nonce->retransmits <= LISPD_MAX_RETRANSMITS){

        if (nat_emr_nonce->retransmits > 0){
            lispd_log_msg(LISP_LOG_DEBUG_1,"No Map Notify received. Retransmitting encapsulated map register.");
        }

        for (ctr = 0 ; ctr < 2 ; ctr++) {
            tree = dbs[ctr];
            if (!tree){
                continue;
            }
            PATRICIA_WALK(tree->head, node) {
                mapping = ((lispd_mapping_elt *)(node->data));
                if (mapping->locator_count != 0){

                    /* Find the locator behind NAT */
                    locators_list[0] = mapping->head_v4_locators_list;
                    locators_list[1] = mapping->head_v6_locators_list;
                    for (ctr1 = 0 ; ctr1 < 2 ; ctr1++){
                        while (locators_list[ctr1] != NULL){
                            locator = locators_list[ctr1]->locator;
                            if ((((lcl_locator_extended_info *)locator->extended_info)->rtr_locators_list) != NULL){
                                break;
                            }
                            locator = NULL;
                            locators_list[ctr1] = locators_list[ctr1]->next;
                        }
                        if (locator != NULL){
                            break;
                        }
                    }
                    /* If found a locator behind NAT, send Encapsulated Map Register */
                    if (locator != NULL && default_ctrl_iface_v4 != NULL){
                        nat_rtr = &(((lcl_locator_extended_info *)locator->extended_info)->rtr_locators_list->locator->address);
                        /* ECM map register only sent to the first Map Server */
                        err = build_and_send_ecm_map_register(mapping,
                                map_servers,
                                nat_rtr,
                                default_ctrl_iface_v4,
                                &site_ID,
                                &xTR_ID,
                                &(nat_emr_nonce->nonce[nat_emr_nonce->retransmits]));
                        if (err != GOOD){
                            lispd_log_msg(LISP_LOG_ERR,"encapsulated_map_register_process: Couldn't send encapsulated map register.");
                        }
                        nat_emr_nonce->retransmits++;
                    }else{
                        if (locator == NULL){
                            lispd_log_msg(LISP_LOG_ERR,"encapsulated_map_register_process: Couldn't send encapsulated map register. No RTR found");
                        }else{
                            lispd_log_msg(LISP_LOG_ERR,"encapsulated_map_register_process: Couldn't send encapsulated map register. No output interface found");
                        }
                    }
                    next_timer_time = LISPD_INITIAL_EMR_TIMEOUT;
                }
            }PATRICIA_WALK_END;
        }

    }else{
        free (nat_emr_nonce);
        nat_emr_nonce = NULL;
        lispd_log_msg(LISP_LOG_ERR,"encapsulated_map_register_process: Communication error between LISPmob and RTR/MS. Retry after %d seconds",MAP_REGISTER_INTERVAL);
        next_timer_time = MAP_REGISTER_INTERVAL;
    }

    /*
     * Configure timer to send the next map register.
     */
    if (map_register_timer == NULL) {
        map_register_timer = create_timer(MAP_REGISTER_TIMER);
    }
    start_timer(map_register_timer, next_timer_time, map_register, NULL);
    return(GOOD);
}





/*
 * Build and send a map register for the mapping entry passed as argument.
 *  Return GOOD if at least a map register could be send
 */


int build_and_send_map_register_msg(lispd_mapping_elt *mapping)
{
    uint8_t                   *packet               = NULL;
    int                       packet_len            = 0;
    uint8_t                   *map_register_pkt     = NULL;
    int                       map_reg_packet_len    = 0;
    lispd_pkt_map_register_t  *map_register         = NULL;
    lispd_map_server_list_t   *ms                   = NULL;
    uint32_t                  md_len                = 0;
    int                       sent_map_registers    = 0;
    lisp_addr_t               *src_addr             = NULL;
    int                       out_socket            = 0;


    if ((map_register_pkt = build_map_register_pkt(mapping, &map_reg_packet_len)) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_map_register_msg: Couldn't build map register packet");
        return(BAD);
    }

    map_register = (lispd_pkt_map_register_t *)map_register_pkt;

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
            lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_map_register_msg: HMAC failed for map-register");
            ms = ms->next;
            continue;
        }

        /*
         * Get src interface
         */

        src_addr    = get_default_ctrl_address(ms->address->afi);
        out_socket  = get_default_ctrl_socket (ms->address->afi);

        if (src_addr == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_map_register_msg: Couden't send Map Register to %s, no output interface with afi %d.",
                    get_char_from_lisp_addr_t(*(ms->address)),
                    ms->address->afi);
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
            lispd_log_msg(LISP_LOG_DEBUG_1,"build_and_send_map_register_msg: Couldn't send Map-Register. Error adding IP and UDP header to the message");
            ms = ms->next;
            continue;
        }

        /*
         * Send the map register
         */

        if ((err = send_packet(out_socket,packet,packet_len))==GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1, "Sent Map-Register message for %s/%d to Map Server at %s",
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length,
                    get_char_from_lisp_addr_t(*(ms->address)));
            sent_map_registers++;
        }else{
            lispd_log_msg(LISP_LOG_WARNING, "Couldn't send Map Register for %s to the Map Server %s",
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    get_char_from_lisp_addr_t(*(ms->address)));
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
        lispd_mapping_elt       *mapping,
        int                     *mrp_len)
{
    uint8_t                         *packet     = NULL;
    lispd_pkt_map_register_t        *mrp        = NULL;
    lispd_pkt_mapping_record_t      *mr         = NULL;

    *mrp_len = sizeof(lispd_pkt_map_register_t) +
              pkt_get_mapping_record_length(mapping);

    if ((packet = malloc(*mrp_len)) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "build_map_register_pkt: Unable to allocate memory for Map Register packet: %s", strerror(errno));
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
    mrp = (lispd_pkt_map_register_t *)packet;


    mrp->lisp_type        = LISP_MAP_REGISTER;
    mrp->map_notify       = 1;              /* TODO conf item */
    mrp->nonce            = 0;
    mrp->record_count     = 1;				/* XXX Just supported one record per map register */
    mrp->key_id           = htons(HMAC_SHA_1_96);
    mrp->auth_data_len    = htons(LISP_SHA1_AUTH_DATA_LEN);


    /* skip over the fixed part,  assume one record (mr) */

    mr = (lispd_pkt_mapping_record_t *) CO(mrp, sizeof(lispd_pkt_map_register_t));

    if (pkt_fill_mapping_record(mr, mapping, NULL) != NULL) {
        return(packet);
    } else {
        free(packet);
        return(NULL);
    }
}


int build_and_send_ecm_map_register(
        lispd_mapping_elt           *mapping,
        lispd_map_server_list_t     *map_server,
        lisp_addr_t                 *nat_rtr_addr,
        lispd_iface_elt             *src_iface,
        lispd_site_ID               *site_ID,
        lispd_xTR_ID                *xTR_ID,
        uint64_t                    *nonce)
{

    uint8_t                     *packet                 = NULL;
    int                         packet_len              = 0;
    lispd_pkt_map_register_t    *map_register_pkt       = NULL;
    lispd_pkt_map_register_t    *map_register_pkt_tmp   = NULL;
    uint8_t                     *ecm_map_register       = NULL;
    int                         map_register_pkt_len    = 0;
    int                         ecm_map_register_len    = 0;
    lisp_addr_t                 *src_addr               = NULL;
    int                         out_socket              = 0;
    int                         result                  = 0;

    map_register_pkt = (lispd_pkt_map_register_t *)build_map_register_pkt(mapping,&map_register_pkt_len);


    /* Map Server proxy reply */
    map_register_pkt->proxy_reply = 1; /* We have to let the Map Server to proxy reply.
                                          If not, we need to keep open a state in NAT via Info-Requests */

    /* R bit always 1 for Map Registers sent to the RTR */
    map_register_pkt->rbit = 1;

    /* xTR-ID must be set if RTR bit is 1 */
    map_register_pkt->ibit = 1;

    /* XXX Quick hack */
    /* Cisco IOS RTR implementation drops Data-Map-Notify if ECM Map Register nonce = 0 */
    map_register_pkt->nonce = build_nonce((unsigned int) time(NULL));
    *nonce = map_register_pkt->nonce;

    /* Add xTR-ID and site-ID fields */

    map_register_pkt_tmp = map_register_pkt;

    map_register_pkt = (lispd_pkt_map_register_t *)malloc(map_register_pkt_len +
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
        lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_ecm_map_register: Couden't send Encapsulated Map Register to %s, no output interface with afi %d.",
                get_char_from_lisp_addr_t(*(map_server->address)),
                map_server->address->afi);
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
        lispd_log_msg(LISP_LOG_DEBUG_2, "build_and_send_ecm_map_register: No output interface for afi %d",nat_rtr_addr->afi);
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
        lispd_log_msg(LISP_LOG_DEBUG_2, "build_and_send_ecm_map_register: Couldn't send Encapsulated Map Register. Error adding IP and UDP header to the message");
        return (BAD);
    }

    if ((err = send_packet(out_socket,packet,packet_len)) == GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_1, "Sent Encapsulated Map-Register message for %s/%d to Map Server at %s through RTR %s",
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length,
                get_char_from_lisp_addr_t(*(map_server->address)),
                get_char_from_lisp_addr_t(*nat_rtr_addr));
        result = GOOD;
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_ecm_map_register: Couldn't sent Encapsulated Map-Register message for %s/%d to Map Server at %s through RTR %s",
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
