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
    mapping_t                           *mapping                    = NULL;
    mapping_t                           *local_mapping              = NULL;
    mapping_t                           *mcache_mapping             = NULL;
    lispd_map_cache_entry               *mce                        = NULL;

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
    if (auth_field_check(mnotify_msg_data(msg), mnotify_msg_get_len(msg), afield, map_servers->key)) {
        record = glist_first_data(mnotify_msg_records(msg));

        mapping = mapping_init_from_record(record);
        eid = mapping_eid(mapping);

        local_mapping = local_map_db_lookup_eid_exact(eid);
        if (!local_mapping) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Notify confirms registration of UNKNOWN EID %s. Dropping!",
                    lisp_addr_to_char(mapping_eid(mapping)));
        }

        lispd_log_msg(LISP_LOG_DEBUG_1, "Map-Notify message confirms correct registration of %s", lisp_addr_to_char(eid));

        /* === merge semantics on === */
        if (mapping_cmp(local_mapping, mapping) != 0 || lisp_addr_is_mc(eid)) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "Merge-Semantics on, moving returned mapping to map-cache");

            /* Save the mapping returned by the map-notify in the mapping cache */
            mcache_mapping = mcache_lookup_mapping(eid);
            if (mcache_mapping && mapping_cmp(mcache_mapping, mapping) != 0) {
                /* UPDATED rlocs */
                lispd_log_msg(LISP_LOG_DEBUG_3, "Prefix %s already registered, updating locators", lisp_addr_to_char(eid));
                mapping_update_locators(mcache_mapping, mapping->head_v4_locators_list, mapping->head_v6_locators_list, mapping->locator_count);

                mapping_compute_balancing_vectors(mcache_mapping);
                programming_rloc_probing(mcache_mapping);

                /* cheap hack to avoid cloning */
                mapping->head_v4_locators_list = NULL;
                mapping->head_v6_locators_list = NULL;
                mapping_del(mapping);
            } else if (!mcache_mapping) {
                /* FIRST registration */
                if (mcache_add_mapping(mapping) != GOOD) {
                    mapping_del(mapping);
                    return(BAD);
                }

                /* ACTIVATE the mapping */
                /* XXX: still works with the old method of looking up the mcache entry */
                mce = map_cache_lookup_exact(eid);
                mce->active = 1;
                programming_rloc_probing(mcache_entry_get_mapping(mce));
                map_cache_entry_start_expiration_timer(mce);
                mapping_compute_balancing_vectors(mcache_entry_get_mapping(mce));

                /* for MC initialize the JIB */
                if (lisp_addr_is_mc(eid) && !mapping_get_re_data(mcache_entry_get_mapping(mce)))
                    mapping_init_re_data(mcache_entry_get_mapping(mce));

            }

        }

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
    start_timer(map_register_timer, next_timer_time, map_register_cb, NULL);

    return(result);

}




/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
