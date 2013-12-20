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


/*
 * Creates a map cache entry structure without adding it to the data base
 */
lispd_map_cache_entry *new_map_cache_entry_no_db (
        lisp_addr_t     eid_prefix,
        int             eid_prefix_length,
        int             how_learned,
        uint16_t        ttl)
{
    lispd_map_cache_entry *map_cache_entry;
    /* Create map cache entry */
    if ((map_cache_entry = calloc(1,sizeof(lispd_map_cache_entry))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING,"new_map_cache_entry: Unable to allocate memory for lispd_map_cache_entry: %s", strerror(errno));
        err = ERR_MALLOC;
        return(NULL);
    }

    /* Create themapping for this map-cache */
    map_cache_entry->mapping = new_map_cache_mapping (eid_prefix, eid_prefix_length, 0);
    if (map_cache_entry->mapping == NULL){
        return(NULL);
    }

    map_cache_entry->active_witin_period = FALSE;
    map_cache_entry->how_learned = how_learned;
    map_cache_entry->ttl = ttl;
    if (how_learned == DYNAMIC_MAP_CACHE_ENTRY){
        map_cache_entry->active = NO_ACTIVE;
    }
    else{
        map_cache_entry->active = ACTIVE;
    }
    map_cache_entry->expiry_cache_timer = NULL;
    map_cache_entry->smr_inv_timer = NULL;
    map_cache_entry->request_retry_timer = NULL;
    map_cache_entry->nonces = NULL;

    map_cache_entry->timestamp = time(NULL);
    map_cache_entry->actions = MAPPING_ACT_NO_ACTION;

    return (map_cache_entry);
}

/*
 * Create a map cache entry and save it in the database
 */
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
    if (add_map_cache_entry_to_db (map_cache_entry) != GOOD){
        free_map_cache_entry(map_cache_entry);
        return (NULL);
    }

    return (map_cache_entry);
}


/*
 * Generates a copy of a map cache entry without initializing timers and nonces. The entry is not
 * added to the database.
 */
lispd_map_cache_entry *copy_map_cache_entry (lispd_map_cache_entry *map_cache_entry_src)
{
    lispd_map_cache_entry   *map_cache_entry_dst = NULL;

    map_cache_entry_dst = (lispd_map_cache_entry *)calloc(1,sizeof(lispd_map_cache_entry));
    if (map_cache_entry_dst == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"copy_map_cache_entry: Couldn't allocate memory for lispd_map_cache_entry: %s", strerror(errno));
        err = ERR_MALLOC;
        return (NULL);
    }

    map_cache_entry_dst->mapping = copy_mapping_elt(map_cache_entry_src->mapping);
    if (map_cache_entry_dst->mapping == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_1,"copy_map_cache_entry: Couldn't copy map cache entry");
        free_map_cache_entry(map_cache_entry_dst);
        return (NULL);
    }

    map_cache_entry_dst->how_learned            = map_cache_entry_src->how_learned;
    map_cache_entry_dst->actions                = map_cache_entry_src->actions;
    map_cache_entry_dst->active                 = map_cache_entry_src->active;
    map_cache_entry_dst->active_witin_period    = map_cache_entry_src->active_witin_period;
    map_cache_entry_dst->ttl                    = map_cache_entry_src->ttl;
    map_cache_entry_dst->timestamp              = map_cache_entry_src->timestamp;

    return (map_cache_entry_dst);
}

/*
 * Free memory of a lispd_map_cache_entry structure
 */
void free_map_cache_entry(lispd_map_cache_entry *entry)
{
    if (entry == NULL){
        return;
    }

    free_mapping_elt(entry->mapping);
    /*
     * Free the entry
     */
    if (entry->how_learned == DYNAMIC_MAP_CACHE_ENTRY) {
        if (entry->expiry_cache_timer != NULL){
            stop_timer(entry->expiry_cache_timer);
            entry->expiry_cache_timer = NULL;
        }
        if (entry->request_retry_timer != NULL){
            stop_timer(entry->request_retry_timer);
            entry->request_retry_timer = NULL;
        }
        if (entry->smr_inv_timer != NULL){
            stop_timer(entry->smr_inv_timer);
            entry->smr_inv_timer = NULL;
        }
    }

    if (entry->nonces != NULL){
        free(entry->nonces);
    }
    free(entry);
}

/*
 * Activate a map cache entry generated by a miss as a negative entry.
 * Typically used when working as a ddt client
 */
int activate_negative_map_cache (
        lispd_map_cache_entry   *cache_entry,
        lisp_addr_t             new_eid_prefix,
        int                     new_eid_prefix_length,
        int                     ttl,
        uint8_t                 action)
{
    /* Change map cache prefix if it is not the same*/
    if (cache_entry->mapping->eid_prefix_length != new_eid_prefix_length){
        if (change_map_cache_prefix_in_db(new_eid_prefix, new_eid_prefix_length, cache_entry) != GOOD){
            lispd_log_msg(LISP_LOG_DEBUG_1,"activate_negative_map_cache: Couldn't activate negative map cache entry: %s/%d"
                    , get_char_from_lisp_addr_t(new_eid_prefix), new_eid_prefix_length);
            return (BAD);
        }
    }

    cache_entry->active = TRUE;
    cache_entry->ttl = ttl;
    cache_entry->actions = action;
    cache_entry->active_witin_period = 1;
    cache_entry->timestamp = time(NULL);
    /* Stop Map Request Timer */
    if (cache_entry->request_retry_timer != NULL){
        stop_timer(cache_entry->request_retry_timer);
        cache_entry->request_retry_timer = NULL;
    }
    /* Remove Nonces */
    if (cache_entry->nonces != NULL){
        free (cache_entry->nonces);
        cache_entry->nonces = NULL;
    }

    /* Expiration cache timer */
    if (cache_entry->expiry_cache_timer == NULL){
        cache_entry->expiry_cache_timer = create_timer (EXPIRE_MAP_CACHE_TIMER);
    }
    start_timer(cache_entry->expiry_cache_timer, cache_entry->ttl*60, (timer_callback)map_cache_entry_expiration,
            (void *)cache_entry);
    lispd_log_msg(LISP_LOG_DEBUG_1,"Activated negative map cache with prefix %s/%d. The entry will expire in %d minutes.",
            get_char_from_lisp_addr_t(cache_entry->mapping->eid_prefix),
            cache_entry->mapping->eid_prefix_length, cache_entry->ttl);
    return (GOOD);
}

/*
 * Print the information of a lispd_map_cache_entry element
 */
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
