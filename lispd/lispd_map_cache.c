/*
 * lispd_map_cache.c
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
 *    Albert Lopez      <alopez@ac.upc.edu>
 */

#include "lispd.h"
#include "lispd_lib.h"
#include "lispd_log.h"
#include "lispd_map_cache.h"
#include "lispd_map_cache_db.h"




lispd_map_cache_entry *new_map_cache_entry_no_db (
        lisp_addr_t     eid_prefix,
        int             eid_prefix_length,
        int             how_learned,
        uint16_t        ttl)
{
    lispd_map_cache_entry *map_cache_entry;
    /* Create map cache entry */
    if ((map_cache_entry = malloc(sizeof(lispd_map_cache_entry))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING,"new_map_cache_entry: Unable to allocate memory for lispd_map_cache_entry: %s", strerror(errno));
        return(NULL);
    }
    memset(map_cache_entry,0,sizeof(lispd_map_cache_entry));

    /* Create themapping for this map-cache */
    map_cache_entry->mapping = new_map_cache_mapping (eid_prefix, eid_prefix_length, -1);
    if (map_cache_entry->mapping == NULL){
        return(NULL);
    }

    map_cache_entry->active_witin_period = FALSE;
    map_cache_entry->probe_left = 0;
    map_cache_entry->how_learned = how_learned;
    map_cache_entry->ttl = ttl;
    if (how_learned == DYNAMIC_MAP_CACHE_ENTRY){
        map_cache_entry->active = NO_ACTIVE;
    }
    else{
        map_cache_entry->active = ACTIVE;
    }
    map_cache_entry->expiry_cache_timer = NULL;
    map_cache_entry->probe_timer = NULL;
    map_cache_entry->smr_inv_timer = NULL;
    map_cache_entry->request_retry_timer = NULL;
    map_cache_entry->nonces = NULL;

    map_cache_entry->timestamp = time(NULL);
    map_cache_entry->actions = ACT_NO_ACTION;

    return (map_cache_entry);
}

lispd_map_cache_entry *new_map_cache_entry (
        lisp_addr_t     eid_prefix,
        int             eid_prefix_length,
        int             how_learned,
        uint16_t        ttl)
{
    lispd_map_cache_entry *map_cache_entry;

    map_cache_entry = new_map_cache_entry_no_db (eid_prefix, eid_prefix_length, how_learned, ttl);

    if (map_cache_entry == NULL){
        return (NULL);
    }

    /* Add entry to the data base */
    if (add_map_cache_entry_to_db (map_cache_entry)==BAD){
        free(map_cache_entry);
        return (NULL);
    }


    return (map_cache_entry);
}



void free_map_cache_entry(lispd_map_cache_entry *entry)
{
    free_mapping_elt(entry->mapping, FALSE);
    /*
     * Free the entry
     */
    if (entry->how_learned == DYNAMIC_MAP_CACHE_ENTRY) {
        if (entry->expiry_cache_timer){
            stop_timer(entry->expiry_cache_timer);
        }
        if (entry->request_retry_timer){
            stop_timer(entry->request_retry_timer);
        }
        if (entry->smr_inv_timer){
            stop_timer(entry->smr_inv_timer);
        }
    }

    if (entry->probe_timer){
        stop_timer(entry->probe_timer);
    }
    if (entry->nonces){
        free(entry->nonces);
    }
    free(entry);
}

void dump_map_cache_entry (lispd_map_cache_entry *entry, int log_level)
{
    char                buf[256], buf2[256];
    time_t              expiretime;
    time_t              uptime;
    int                 ctr = 0;
    char                str[400];
    lispd_locators_list         *locator_iterator_array[2]  = {NULL,NULL};
    lispd_locators_list         *locator_iterator           = NULL;
    lispd_locator_elt           *locator                    = NULL;

    if (is_loggable(log_level) == FALSE){
        return;
    }


    sprintf(str,"IDENTIFIER (EID): %s/%d (IID = %d), ", get_char_from_lisp_addr_t(entry->mapping->eid_prefix),
            entry->mapping->eid_prefix_length, entry->mapping->iid);
    uptime = time(NULL);
    uptime = uptime - entry->timestamp;
    strftime(buf, 20, "%H:%M:%S", localtime(&uptime));
    expiretime = (entry->ttl * 60) - uptime;
    if (expiretime > 0)
        strftime(buf2, 20, "%H:%M:%S", localtime(&expiretime));

    sprintf(str + strlen(str),"  UPTIME: %s, EXPIRES: %s   ", buf, buf2);

    if (entry->how_learned == STATIC_LOCATOR)
        sprintf(str + strlen(str),"   TYPE: Static ");
    else
        sprintf(str + strlen(str),"   TYPE: Dynamic ");
    sprintf(str + strlen(str),"   ACTIVE: %s\n", entry->active == TRUE ? "Yes" : "No");
    lispd_log_msg(log_level,"%s",str);

    if (entry->mapping->locator_count > 0){

        locator_iterator_array[0] = entry->mapping->head_v4_locators_list;
        locator_iterator_array[1] = entry->mapping->head_v6_locators_list;
        lispd_log_msg(log_level, "|               Locator (RLOC)            | Status | Priority/Weight |");
        // Loop through the locators and print each
        for (ctr = 0 ; ctr < 2 ; ctr++){
            locator_iterator = locator_iterator_array[ctr];
            while (locator_iterator != NULL) {
                locator = locator_iterator->locator;
                dump_locator(locator, log_level);
                locator_iterator = locator_iterator->next;
            }
        }
        lispd_log_msg(log_level,"\n");
    }
}
