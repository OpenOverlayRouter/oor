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


#include <sys/timerfd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_map_notify.h"


int process_map_notify(packet)
    uint8_t *packet;
{

    lispd_pkt_map_notify_t              *mn;
    lispd_pkt_mapping_record_t          *record;
    lispd_pkt_mapping_record_locator_t  *locator;
    lispd_pkt_lcaf_iid_t                *lcaf_iid;

    int                                 eid_afi;
    int                                 loc_afi;
    int                                 record_count;
    int                                 locator_count;
    int                                 i,j;
    uint8_t                             auth_data[LISP_SHA1_AUTH_DATA_LEN];
    int                                 map_notify_length;
    int                                 partial_map_notify_length1;
    int                                 partial_map_notify_length2;
    uint32_t                            md_len;


    mn = (lispd_pkt_map_notify_t *)packet;
    record_count = mn->record_count;

    map_notify_length = sizeof(lispd_pkt_map_notify_t);

    record = (lispd_pkt_mapping_record_t *)CO(mn, sizeof(lispd_pkt_map_notify_t));
    for (i=0; i < record_count; i++)
    {
        partial_map_notify_length1 = sizeof(lispd_pkt_mapping_record_t);
        eid_afi = lisp2inetafi(ntohs(record->eid_prefix_afi));

        /* XXX:  If we have LCAF, just assume it's Instance ID, jump over
         *       and get the EID
         * TODO: Proper LCAF handling on receipt
         */
        if (eid_afi < 0) {
            partial_map_notify_length1 += sizeof(lispd_pkt_lcaf_t);
            lcaf_iid = (lispd_pkt_lcaf_iid_t *)
                       CO(record, partial_map_notify_length1);
            eid_afi  = lisp2inetafi(ntohs(lcaf_iid->afi));
            partial_map_notify_length1 += sizeof(lispd_pkt_lcaf_iid_t);
        }

        switch (eid_afi) {
        case AF_INET:
            partial_map_notify_length1 += sizeof(struct in_addr);
            break;
        case AF_INET6:
            partial_map_notify_length1 += sizeof(struct in6_addr);
            break;
        default:
            syslog(LOG_DAEMON, "get_lisp_afi: unknown AFI (%d) - EID", record->eid_prefix_afi);
            return(0);
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
                syslog(LOG_DAEMON, "get_lisp_afi: unknown AFI (%d) - Locator", htons(locator->locator_afi));
                return(0);
            }
            locator = (lispd_pkt_mapping_record_locator_t *)CO(locator, partial_map_notify_length2);
            partial_map_notify_length1 = partial_map_notify_length1 + partial_map_notify_length2;
        }
        map_notify_length = map_notify_length + partial_map_notify_length1;
        record = (lispd_pkt_mapping_record_t *)locator;
    }

    for (i=0 ; i < LISP_SHA1_AUTH_DATA_LEN; i++)
    {
        auth_data[i] = mn->auth_data[i];
        mn->auth_data[i] = 0;
    }

    if (!HMAC((const EVP_MD *) EVP_sha1(),
            (const void *) map_servers->key,
            strlen(map_servers->key),
            (uchar *) mn,
            map_notify_length,
            (uchar *) mn->auth_data,
            &md_len)) {
        syslog(LOG_DAEMON, "HMAC failed for Map-Notify");
        return(0);
    }
    if ((strncmp((char *)mn->auth_data, (char *)auth_data, (size_t)LISP_SHA1_AUTH_DATA_LEN)) == 0)
        syslog(LOG_DAEMON, "Map-Notify message confirms correct registration");
    else
        syslog(LOG_DAEMON, "Map-Notify message is invalid");
    return(1);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
