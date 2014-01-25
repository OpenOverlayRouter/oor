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


inline lispd_map_cache_entry *mcache_entry_new() {
    lispd_map_cache_entry *mce;
    if ((mce = calloc(1, sizeof(lispd_map_cache_entry))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING,"new_map_cache_entry: Unable to allocate memory for lispd_map_cache_entry: %s", strerror(errno));
        return(NULL);
    }

    mce->active = NO_ACTIVE;
    mce->expiry_cache_timer = NULL;
    mce->smr_inv_timer = NULL;
    mce->request_retry_timer = NULL;
    mce->nonces = NULL;

    mce->timestamp = time(NULL);
    mce->actions = ACT_NO_ACTION;

    return(mce);
}

lispd_map_cache_entry *mcache_entry_init(lispd_mapping_elt *mapping) {
    lispd_map_cache_entry *mce;
    mce = mcache_entry_new();

    if (!mce)
        return (NULL);

    mce->mapping = mapping;
    mce->how_learned = DYNAMIC_MAP_CACHE_ENTRY;
    mce->ttl = DEFAULT_DATA_CACHE_TTL;

    return(mce);
}

lispd_map_cache_entry *mcache_entry_init_static(lispd_mapping_elt *mapping) {
    lispd_map_cache_entry *mce;
    mce = mcache_entry_new();

    if (!mce)
        return (NULL);

    mce->active = ACTIVE;
    mce->mapping = mapping;
    mce->how_learned = STATIC_MAP_CACHE_ENTRY;
    mce->ttl = 255;

    return(mce);
}




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

    if (map_cache_entry == NULL)
        return (NULL);


    /* Add entry to the data base */
    if (map_cache_add_entry (map_cache_entry)==BAD){
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

void dump_map_cache_entry (lispd_map_cache_entry *entry, int log_level)
{
    char                buf[256], buf2[256];
    time_t              expiretime;
    time_t              uptime;
    int                 ctr = 0;
    char                str[400];
//    char                fmt[200];
    lispd_locators_list         *locator_iterator_array[2]  = {NULL,NULL};
    lispd_locators_list         *locator_iterator           = NULL;
    lispd_locator_elt           *locator                    = NULL;
    lispd_mapping_elt           *mapping                    = NULL;

    if (is_loggable(log_level) == FALSE){
        return;
    }

    mapping = mcache_entry_get_mapping(entry);

    sprintf(str,"IDENTIFIER (EID): %s (IID = %d), ",
            lisp_addr_to_char(mapping_get_eid_addr(mapping)), mapping->iid );
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


/*
 * lispd_map_cache_entry set/get functions
 */

inline void mcache_entry_set_eid_addr(lispd_map_cache_entry *mce, lisp_addr_t *addr) {
    mapping_set_eid_addr(mcache_entry_get_mapping(mce), addr);
}


inline lispd_mapping_elt *mcache_entry_get_mapping(lispd_map_cache_entry* mce) {
    assert(mce);
    return(mce->mapping);
}

inline lisp_addr_t *mcache_entry_get_eid_addr(lispd_map_cache_entry *mce) {
    return(mapping_get_eid_addr(mcache_entry_get_mapping(mce)));
}

inline nonces_list *mcache_entry_get_nonces_list(lispd_map_cache_entry *mce) {
    assert(mce);
    return(mce->nonces);
}

inline uint8_t  mcache_entry_get_active(lispd_map_cache_entry *mce) {
    assert(mce);
    return(mce->active);
}
