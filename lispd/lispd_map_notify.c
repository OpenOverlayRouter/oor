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

#if ANDROID

//#include "timerfd.h"
#else
//#include <sys/timerfd.h>
#endif
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "lispd_afi.h"
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_map_notify.h"
#include "lispd_map_register.h"


int process_map_notify(uint8_t *packet)
{

    lispd_pkt_map_notify_t              *map_notify                         = NULL;
    lispd_pkt_mapping_record_t          *record                     = NULL;
    lispd_pkt_mapping_record_locator_t  *locator                    = NULL;


    int                                 eid_afi                     = 0;
    int                                 loc_afi                     = 0;
    int                                 record_count                = 0;
    int                                 locator_count               = 0;
    int                                 i                           = 0;
    int                                 j                           = 0;
    uint8_t                             auth_data[LISP_SHA1_AUTH_DATA_LEN];
    int                                 map_notify_length           = 0;
    int                                 partial_map_notify_length1  = 0;
    int                                 partial_map_notify_length2  = 0;
    uint32_t                            md_len                      = 0;
    lispd_site_ID                       *site_ID_msg                = NULL;
    lispd_xTR_ID                        *xTR_ID_msg                 = NULL;
    int                                 next_timer_time             = 0;
    int                                 result                      = BAD;



    map_notify = (lispd_pkt_map_notify_t *)packet;
    record_count = map_notify->record_count;

    /* Check the nonce of data Map Notify*/
    if (map_notify->xtr_id_present == TRUE){
        if (check_nonce(nat_emr_nonce,map_notify->nonce) == GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_2, "Data Map Notify: Correct nonce field checking ");
            /* Free nonce if authentication is ok */
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1, "Data Map Notify: Error checking nonce field. No (Encapsulated) Map Register generated with nonce: %s",
                    get_char_from_nonce (map_notify->nonce));
            return (BAD);
        }
    }

    map_notify_length = sizeof(lispd_pkt_map_notify_t);

    record = (lispd_pkt_mapping_record_t *)CO(map_notify, sizeof(lispd_pkt_map_notify_t));
    for (i=0; i < record_count; i++)
    {
        partial_map_notify_length1 = sizeof(lispd_pkt_mapping_record_t);
        eid_afi = lisp2inetafi(ntohs(record->eid_prefix_afi));

        switch (eid_afi) {
        case AF_INET:
            partial_map_notify_length1 += sizeof(struct in_addr);
            break;
        case AF_INET6:
            partial_map_notify_length1 += sizeof(struct in6_addr);
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_notify: Unknown AFI (%d) - EID", record->eid_prefix_afi);
            return(ERR_AFI);
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
                return(ERR_AFI);
            }
            locator = (lispd_pkt_mapping_record_locator_t *)CO(locator, partial_map_notify_length2);
            partial_map_notify_length1 = partial_map_notify_length1 + partial_map_notify_length2;
        }
        map_notify_length = map_notify_length + partial_map_notify_length1;
        record = (lispd_pkt_mapping_record_t *)locator;
    }

    for (i=0 ; i < LISP_SHA1_AUTH_DATA_LEN; i++)
    {
        auth_data[i] = map_notify->auth_data[i];
        map_notify->auth_data[i] = 0;
    }

    if (map_notify->xtr_id_present == TRUE){
        xTR_ID_msg  = (lispd_xTR_ID *)CO(packet,map_notify_length);
        site_ID_msg = (lispd_site_ID *)CO(packet,map_notify_length + sizeof(lispd_xTR_ID));
        if (memcmp(site_ID_msg, &site_ID, sizeof(lispd_site_ID))!= 0){
            lispd_log_msg(LISP_LOG_DEBUG_1, "process_map_notify: Site ID of the map notify doesn't match");
            return (BAD);
        }
        if (memcmp(xTR_ID_msg, &xTR_ID, sizeof(lispd_xTR_ID))!= 0){
            lispd_log_msg(LISP_LOG_DEBUG_1, "process_map_notify: xTR ID of the map notify doesn't match");
            return (BAD);
        }
        map_notify_length = map_notify_length + sizeof(lispd_site_ID) + sizeof (lispd_xTR_ID);
    }
    if (map_notify->rtr_auth_present == TRUE){
        // Nothing to be done
    }

    if (!HMAC((const EVP_MD *) EVP_sha1(),
            (const void *) map_servers->key,
            strlen(map_servers->key),
            (uchar *) packet,
            map_notify_length,
            (uchar *) map_notify->auth_data,
            &md_len)) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_notify: HMAC failed for Map-Notify");
        return(BAD);
    }
    if ((strncmp((char *)map_notify->auth_data, (char *)auth_data, (size_t)LISP_SHA1_AUTH_DATA_LEN)) == 0){
        lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Notify message confirms correct registration");
        next_timer_time = MAP_REGISTER_INTERVAL;
        free (nat_emr_nonce);
        nat_emr_nonce = NULL;
        result = GOOD;

    } else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Notify message is invalid");
        next_timer_time = LISPD_INITIAL_EMR_TIMEOUT;
        result = BAD;
    }

    if (map_register_timer == NULL) {
        map_register_timer = create_timer(MAP_REGISTER_TIMER);
    }
    start_timer(map_register_timer, next_timer_time, map_register, NULL);

    return(result);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
