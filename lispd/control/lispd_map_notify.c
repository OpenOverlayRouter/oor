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


//#include <sys/timerfd.h>

#include "lispd_afi.h"
#include "lispd_external.h"
#include "lispd_lib.h"
#include "lispd_map_notify.h"
#include "lispd_map_register.h"
#include <lisp_messages.h>


int process_map_notify(map_notify_msg *msg)
{

    lisp_addr_t                         *eid                        = NULL;
    mapping_record                      *record                     = NULL;
    int                                 next_timer_time             = 0;
    int                                 result                      = BAD;
    auth_field                          *afield                     = NULL;

    /* FC XXX: what is this? */
    if (mnotify_msg_hdr(msg)->xtr_id_present == TRUE) {
        if (check_nonce(nat_emr_nonce, mnotify_msg_hdr(msg)->nonce) == GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_3, "Data Map Notify: Correct nonce");
            /* Free nonce if authentication is ok */
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1, "Data Map Notify: Error checking nonce field. No (Encapsulated) Map Register generated with nonce: %s",
                    nonce_to_char (mnotify_msg_hdr(msg)->nonce));
            return (BAD);
        }
    }

    afield = mnotify_msg_auth_data(msg);
//    if (mnotify_msg_check_auth(msg, map_servers->key)) {
    if (auth_field_check(mnotify_msg_data(msg), mnotify_msg_get_len(msg), afield, map_servers->key)) {
        record = glist_first_data(mnotify_msg_records(msg));
        eid = lisp_addr_init_from_field(mapping_record_eid(record));
        if (lisp_addr_get_afi(eid) == LM_AFI_IP)
            lisp_addr_set_plen(eid, mapping_record_hdr(record)->eid_prefix_length);
        lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Notify message confirms correct registration of %s", lisp_addr_to_char(eid));

        next_timer_time = MAP_REGISTER_INTERVAL;
        free (nat_emr_nonce);
        nat_emr_nonce = NULL;
        result = GOOD;
        lisp_addr_del(eid);
    } else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Notify message is invalid");
        next_timer_time = LISPD_INITIAL_EMR_TIMEOUT;
        result = BAD;
    }

    if (map_register_timer == NULL) {
        map_register_timer = create_timer(MAP_REGISTER_TIMER);
    }
    start_timer(map_register_timer, next_timer_time, map_register_cb, NULL);

    return(result);

}




/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
