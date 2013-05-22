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




uint8_t *build_map_register_pkt(
        lispd_mapping_elt       *mapping,
        int                     *mrp_len);


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
    patricia_tree_t           *dbs[2];
    patricia_tree_t           *tree = NULL;
    patricia_node_t           *node;
    lispd_mapping_elt         *mapping;
    int                       ctr = 0;

    dbs[0] = get_local_db(AF_INET);
    dbs[1] = get_local_db(AF_INET6);

    if (!map_servers) {
        lispd_log_msg(LISP_LOG_CRIT, "map_register: No Map Servers conifgured!");
        exit(EXIT_FAILURE);
    }

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
    if (!map_register_timer) {
        map_register_timer = create_timer(MAP_REGISTER_TIMER);
    }
    start_timer(map_register_timer, MAP_REGISTER_INTERVAL, map_register, NULL);
    lispd_log_msg(LISP_LOG_DEBUG_1, "Reprogrammed map register in %d seconds",MAP_REGISTER_INTERVAL);
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
    lispd_pkt_map_register_t  *map_register_pkt     = NULL;
    lispd_map_server_list_t   *ms                   = NULL;
    uint32_t                  md_len                = 0;
    int                       sent_map_registers    = 0;


    if ((packet = build_map_register_pkt(mapping, &packet_len)) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_map_register_msg: Couldn't build map register packet");
        return(BAD);
    }

    map_register_pkt = (lispd_pkt_map_register_t *)packet;

    //  for each map server, send a register, and if verify
    //  send a map-request for our eid prefix

    ms = map_servers;

    while (ms) {

        /*
         * Fill in proxy_reply and compute the HMAC with SHA-1.
         */

        map_register_pkt->proxy_reply = ms->proxy_reply;
        memset(map_register_pkt->auth_data,0,LISP_SHA1_AUTH_DATA_LEN);   /* make sure */

        if (!HMAC((const EVP_MD *) EVP_sha1(),
                (const void *) ms->key,
                strlen(ms->key),
                (uchar *) map_register_pkt,
                packet_len,
                (uchar *) map_register_pkt->auth_data,
                &md_len)) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_map_register_msg: HMAC failed for map-register");
            ms = ms->next;
            continue;
        }

        /* Send the map register */
        err = send_udp_ctrl_packet(ms->address,LISP_CONTROL_PORT,LISP_CONTROL_PORT,(void *)map_register_pkt,packet_len);

        if (err == GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1, "Sent Map-Register message for %s/%d to Map Server %s",
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length,
                    get_char_from_lisp_addr_t(*(ms->address)));
            sent_map_registers++;
        }else{
            lispd_log_msg(LISP_LOG_WARNING, "Couldn't send map-register for %s",get_char_from_lisp_addr_t(mapping->eid_prefix));
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


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
