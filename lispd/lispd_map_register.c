/* 
 * lispd_map_register.c
 *
 * This file is part of LISP Implementation.
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
 *    David Meyer               <dmm@cisco.com>
 *    Preethi Natarajan         <prenatar@cisco.com>
 *    Lorand Jakab              <ljakab@ac.upc.edu>
 *    Albert Lopez              <alopez@ac.upc.edu>
 *    Alberto Rodriguez Natal   <arnatal@ac.upc.edu>
 */

#ifdef ANDROID
    #include "../android/jni/android-external-openssl/include/openssl/hmac.h"
    #include "../android/jni/android-external-openssl/include/openssl/evp.h"
#else
    #include <openssl/hmac.h>
    #include <openssl/evp.h>
#endif
#include "lispd_external.h"
#include "lispd_info_request.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_register.h"
#include "lispd_map_request.h"
#include "lispd_pkt_lib.h"
#include "lispd_sockets.h"
#include "api/ipc.h"
#include "patricia/patricia.h"

int map_register_process(timer_map_register_argument *timer_arg);
int encapsulated_map_register_process(timer_map_register_argument *timer_arg);

/*
 * Send a Map Register to all the local mappings of the database
 */
int initial_map_register_process()
{
    int                         ctr                 = 0;
    lispd_mapping_list          *mapping_list[2]    = {NULL, NULL};
    lispd_mapping_elt           *mapping            = NULL;
    timer_map_register_argument *timer_arg          = NULL;

    mapping_list[0] = get_all_mappings(AF_INET);
    mapping_list[1] = get_all_mappings(AF_INET6);

    for (ctr = 0 ; ctr < 2 ; ctr++) {
        while (mapping_list[ctr]!=NULL){
            mapping = mapping_list[ctr]->mapping;
            timer_arg = new_timer_map_reg_arg(mapping,NULL);
            map_register(NULL,timer_arg);
            mapping_list[ctr] = mapping_list[ctr]->next;
        }
    }
    return(GOOD);
}



/*
 * Timer and arg parameters are not used but must be defined to be consistent
 * with timer call back function.
 */
int map_register(
        timer   *t,
        void    *arg)
{

    int result = 0;
    timer_map_register_argument *timer_arg       = (timer_map_register_argument *)arg;
    lispd_mapping_elt           *mapping         = timer_arg->mapping;
    lcl_mapping_extended_info   *map_ext_inf     = (lcl_mapping_extended_info *)(mapping->extended_info);
    lispd_locators_list         *loc_list[2]     = {mapping->head_v4_locators_list, mapping->head_v6_locators_list};
    lispd_locator_elt           *locator         = NULL;
    nat_info_str                *nat_info        = NULL;
    int                         ctr              = 0;

    uint8_t                     all_loc_ready    = TRUE;


    if (!map_servers) {
        lispd_log_msg(LISP_LOG_CRIT, "map_register: No Map Servers conifgured!");
        exit_cleanup();
    }

    if(nat_aware==TRUE){ /* NAT procedure instead of the standard one */

        for (ctr=0; ctr < 2; ctr ++){
            /* Check the NAT status of all locators. We should have information of all of them to proceed */
            while (loc_list[ctr] != NULL){
                locator = loc_list[ctr]->locator;
                nat_info = ((lcl_locator_extended_info *)locator->extended_info)->nat_info;
                /* if status is NO_INFO_REPLY, we procede with the map register */
                if (nat_info->status == UNKNOWN && *(locator->state) == UP){
                    all_loc_ready = FALSE;
                }
                loc_list[ctr] = loc_list[ctr]->next;
            }
        }
        if (all_loc_ready == TRUE){
            result = encapsulated_map_register_process(timer_arg);
        }else{
            // XXX To check the number of retries. If we never receive a Map Reply --> New status in Inf req?
            if (map_ext_inf->map_reg_timer == NULL) {
                map_ext_inf->map_reg_timer = create_timer(MAP_REGISTER_TIMER);
            }
            start_timer(map_ext_inf->map_reg_timer, LISPD_INITIAL_MR_TIMEOUT, map_register, timer_arg);
            lispd_log_msg(LISP_LOG_DEBUG_1, "NAT locators status unknown. Reprogrammed map register for %s/%d in %d seconds",
                    get_char_from_lisp_addr_t(mapping->eid_prefix), mapping->eid_prefix_length,LISPD_INITIAL_MR_TIMEOUT);
            return(BAD);
        }
    }else{
        result = map_register_process(timer_arg);
    }

    return (result);
}


int map_register_process(timer_map_register_argument *timer_arg)
{
    lispd_mapping_elt           *mapping        = timer_arg->mapping;
    lcl_mapping_extended_info   *extended_info  = (lcl_mapping_extended_info *)mapping->extended_info;
    nonces_list                 *nonces         = extended_info->map_reg_nonce;
    int                         next_timer_time = 0;
    // We don't save nonce. Map Register is sent with nonce 0
    if (nonces == NULL){
        nonces = new_nonces_list();
        if (nonces==NULL){
            lispd_log_msg(LISP_LOG_WARNING,"map_register_process: Unable to allocate memory for nonces.");
            return (BAD);
        }
        extended_info->map_reg_nonce = nonces;
    }

    if (nonces->retransmits <= LISPD_MAX_RETRANSMITS){

        if (nonces->retransmits > 0){
            lispd_log_msg(LISP_LOG_DEBUG_1,"No Map Notify received. Retransmitting map register.");
        }

        if (mapping->locator_count != 0){
            err = build_and_send_map_register_msg(mapping);
            if (err != GOOD){
                lispd_log_msg(LISP_LOG_ERR, "map_register: Coudn't register %s/%d EID!",
                        get_char_from_lisp_addr_t(mapping->eid_prefix),
                        mapping->eid_prefix_length);
            }
        }
        nonces->retransmits++;
        next_timer_time = LISPD_INITIAL_MR_TIMEOUT;
    }else{
        free (nonces);
        extended_info->map_reg_nonce = NULL;
        lispd_log_msg(LISP_LOG_ERR,"map_register_process: Communication error between LISPmob and MS. Check MS address and key");
//#ifdef VPNAPI
//        ipc_send_log_msg(MAP_REG_ERR);
//#endif
        next_timer_time = MAP_REGISTER_INTERVAL;
    }

    /*
     * Configure timer to send the next map register.
     */
    if (extended_info->map_reg_timer == NULL) {
        extended_info->map_reg_timer = create_timer(MAP_REGISTER_TIMER);
    }
    start_timer(extended_info->map_reg_timer, next_timer_time, map_register, timer_arg);
    lispd_log_msg(LISP_LOG_DEBUG_1, "Reprogrammed map register for %s/%d in %d seconds",
            get_char_from_lisp_addr_t(mapping->eid_prefix), mapping->eid_prefix_length,next_timer_time);
    return(GOOD);
}

int encapsulated_map_register_process(timer_map_register_argument *timer_arg)
{
    lispd_mapping_elt         *mapping          = timer_arg->mapping;
    lispd_locator_elt         *src_locator      = timer_arg->src_locator;
    lcl_mapping_extended_info *extended_info    = (lcl_mapping_extended_info *)mapping->extended_info;
    nonces_list               *nonces           = extended_info->map_reg_nonce;
    lispd_locators_list       *locators_list[2] = {NULL, NULL};
    lispd_locator_elt         *locator          = NULL;
    lispd_locator_elt         *aux_locator      = NULL;
    lisp_addr_t               *rtr_addr          = NULL;
    int                       next_timer_time   = 0;
    int                       ctr               = 0;

    if (nonces == NULL){
        nonces = new_nonces_list();
        if (nonces == NULL){
            lispd_log_msg(LISP_LOG_WARNING,"encapsulated_map_register_process: Unable to allocate memory for nonces.");
            return (BAD);
        }
        extended_info->map_reg_nonce = nonces;
    }
    if (nonces->retransmits <= LISPD_MAX_RETRANSMITS){

        if (nonces->retransmits > 0){
            lispd_log_msg(LISP_LOG_DEBUG_1,"No Map Notify received. Retransmitting encapsulated map register.");
        }


        if (mapping->locator_count != 0){

            if (src_locator != NULL && ((lcl_locator_extended_info *)src_locator->extended_info)->nat_info->rtr_locators_list != NULL){
                locator = src_locator;
            }else{
                /* Find the locator behind NAT */
                locators_list[0] = mapping->head_v4_locators_list;
                locators_list[1] = mapping->head_v6_locators_list;
                for (ctr = 0 ; ctr < 2 ; ctr++){
                    while (locators_list[ctr] != NULL){
                        aux_locator = locators_list[ctr]->locator;
                        if ((((lcl_locator_extended_info *)aux_locator->extended_info)->nat_info->rtr_locators_list) != NULL){
                            locator = aux_locator;
                            break;
                        }
                        locators_list[ctr] = locators_list[ctr]->next;
                    }
                    if (locator != NULL){
                        timer_arg->src_locator = locator;
                        break;
                    }
                }
            }
            /* If found a locator behind NAT, send Encapsulated Map Register */
            if (locator != NULL){
                rtr_addr = &(((lcl_locator_extended_info *)locator->extended_info)->nat_info->rtr_locators_list->locator->address);
                /* ECM map register only sent to the first Map Server */
                err = build_and_send_ecm_map_register(mapping,
                        map_servers,
                        rtr_addr,
                        locator->locator_addr,
                        &site_ID,
                        &xTR_ID,
                        &(nonces->nonce[nonces->retransmits]));
                if (err != GOOD){
                    lispd_log_msg(LISP_LOG_ERR,"encapsulated_map_register_process: Couldn't send encapsulated map register.");
                }
            }else{
                if (locator == NULL){
                    lispd_log_msg(LISP_LOG_ERR,"encapsulated_map_register_process: Couldn't send encapsulated map register. No RTR found");
                }else{
                    lispd_log_msg(LISP_LOG_ERR,"encapsulated_map_register_process: Couldn't send encapsulated map register. No output interface found");
                }
            }
            nonces->retransmits++;
            next_timer_time = LISPD_INITIAL_MR_TIMEOUT;
        }
    }else{
        free (nonces);
        extended_info->map_reg_nonce = NULL;
        lispd_log_msg(LISP_LOG_ERR,"encapsulated_map_register_process: Communication error between LISPmob and RTR/MS. Retry after %d seconds",MAP_REGISTER_INTERVAL);
//#ifdef VPNAPI
//        ipc_send_log_msg(MAP_REG_ERR);
//#endif
        next_timer_time = MAP_REGISTER_INTERVAL;
    }

    /*
     * Configure timer to send the next map register.
     */
    if (extended_info->map_reg_timer == NULL) {
        extended_info->map_reg_timer = create_timer(MAP_REGISTER_TIMER);
    }
    start_timer(extended_info->map_reg_timer, next_timer_time, map_register, timer_arg);
    return(GOOD);
}





/*
 * Build and send a map register for the mapping entry passed as argument.
 *  Return GOOD if at least a map register could be send
 */


int build_and_send_map_register_msg(lispd_mapping_elt *mapping)
{
    uint8_t                   *map_register_pkt     = NULL;
    int                       map_reg_packet_len    = 0;
    lispd_pkt_map_register_t  *map_register         = NULL;
    lispd_map_server_list_t   *ms                   = NULL;
    uint32_t                  md_len                = 0;
    int                       sent_map_registers    = 0;


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
         * Send the map register
         */

        err = send_control_msg(map_register_pkt,
                map_reg_packet_len,
                NULL,
                ms->address,
                LISP_CONTROL_PORT,
                LISP_CONTROL_PORT);

        if (err == GOOD){
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
    mrp->record_count     = 1;                /* XXX Just supported one record per map register */
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
        lisp_addr_t                 *src_addr,
        lispd_site_ID               *site_ID,
        lispd_xTR_ID                *xTR_ID,
        uint64_t                    *nonce)
{
    lispd_pkt_map_register_t    *map_register_pkt       = NULL;
    lispd_pkt_map_register_t    *map_register_pkt_tmp   = NULL;
    uint8_t                     *ecm_map_register       = NULL;
    int                         map_register_pkt_len    = 0;
    int                         ecm_map_register_len    = 0;
    int                         result                  = 0;
    encap_control_opts          opts;

    memset(&opts, FALSE, sizeof(encap_control_opts));

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
                                               opts,
                                               &ecm_map_register_len);
    free(map_register_pkt);

    if (ecm_map_register == NULL) {
        return (BAD);
    }

    /*
     * Send the map register
     */

    err = send_control_msg(ecm_map_register,
                                ecm_map_register_len,
                                src_addr,
                                nat_rtr_addr,
                                LISP_DATA_PORT,
                                LISP_CONTROL_PORT);
    free (ecm_map_register);

    if (err == GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_1, "Sent Encapsulated Map-Register message with nonce %s for %s/%d to Map Server at %s through RTR %s using src rloc %s. xTR-ID: 0x%s",
                get_char_from_nonce(*nonce),
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length,
                get_char_from_lisp_addr_t(*(map_server->address)),
                get_char_from_lisp_addr_t(*nat_rtr_addr),
                get_char_from_lisp_addr_t(*src_addr),
                get_char_from_xTR_ID(xTR_ID));
        result = GOOD;
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_ecm_map_register: Couldn't sent Encapsulated Map-Register message for %s/%d to Map Server at %s through RTR %s using src rloc %s",
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length,
                get_char_from_lisp_addr_t(*(map_server->address)),
                get_char_from_lisp_addr_t(*nat_rtr_addr),
                get_char_from_lisp_addr_t(*src_addr));
        result = BAD;
    }

    return (result);
}

timer_map_register_argument * new_timer_map_reg_arg(
        lispd_mapping_elt *mapping,
        lispd_locator_elt *src_locator)
{
    timer_map_register_argument * timer_arg = (timer_map_register_argument *)calloc(1,sizeof(timer_map_register_argument));
    if (timer_arg == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"new_timer_map_reg_arg: Unable to allocate memory for a timer_map_register_argument");
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
