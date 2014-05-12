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

//#include "lispd.h"
//#include "lispd_log.h"
#include "map_cache_entry.h"
#include "defs.h"
//#include "lisp_map_cache.h"
//#include "lispd_lib.h"



inline mcache_entry_t *
mcache_entry_new()
{
    mcache_entry_t *mce;
    mce = xzalloc(sizeof(mcache_entry_t));

    mce->active = NOT_ACTIVE;
    mce->timestamp = time(NULL);

    mce->nonces = NULL;

    mce->expiry_cache_timer = NULL;
    mce->smr_inv_timer = NULL;
    mce->request_retry_timer = NULL;

    return(mce);
}

void
mcache_entry_init(mcache_entry_t **mce, mapping_t *mapping)
{
    if (!*mce) {
        *mce = mcache_entry_new();
    }

    (*mce)->mapping = mapping;
    (*mce)->how_learned = DYNAMIC_MAP_CACHE_ENTRY;
    (*mce)->ttl = DEFAULT_DATA_CACHE_TTL;

}

void
mcache_entry_init_static(mcache_entry_t **mce_, mapping_t *mapping)
{
    mcache_entry_t *mce = *mce_;
    if (!mce) {
        mce = mcache_entry_new();
    }

    mce->active = ACTIVE;
    mce->mapping = mapping;
    mce->how_learned = STATIC_MAP_CACHE_ENTRY;
    mce->ttl = 255; /* XXX: why 255? */
}


/*
 * Creates a map cache entry structure without adding it to the data base
 */
mcache_entry_t *
new_map_cache_entry_no_db(lisp_addr_t eid_prefix, int eid_prefix_length,
        int how_learned, uint16_t ttl)
{
    mcache_entry_t *map_cache_entry;
    /* Create map cache entry */
    if ((map_cache_entry = calloc(1, sizeof(map_cache_entry))) == NULL) {
        lmlog(LWRN,"new_map_cache_entry: Unable to allocate memory for lispd_map_cache_entry: %s", strerror(errno));
        return(NULL);
    }
//    memset(map_cache_entry,0,sizeof(lispd_map_cache_entry));

    /* Create themapping for this map-cache */
    if (lisp_addr_afi(&eid_prefix) == LM_AFI_IP)
        lisp_addr_set_plen(&eid_prefix, eid_prefix_length);
    //    map_cache_entry->mapping = new_map_cache_mapping (eid_prefix, eid_prefix_length, -1);
    map_cache_entry->mapping = mapping_init_remote(&eid_prefix);
    if (!map_cache_entry->mapping)
        return(NULL);

    map_cache_entry->active_witin_period = FALSE;
    map_cache_entry->how_learned = how_learned;
    map_cache_entry->ttl = ttl;
    if (how_learned == DYNAMIC_MAP_CACHE_ENTRY){
        map_cache_entry->active = NOT_ACTIVE;
    }
    else{
        map_cache_entry->active = ACTIVE;
    }
    map_cache_entry->expiry_cache_timer = NULL;
    map_cache_entry->smr_inv_timer = NULL;
    map_cache_entry->request_retry_timer = NULL;
    map_cache_entry->nonces = NULL;

    map_cache_entry->timestamp = time(NULL);

    return (map_cache_entry);
}

void
mcache_entry_del(mcache_entry_t *entry)
{
    mapping_del(mcache_entry_mapping(entry));

    if (entry->how_learned == DYNAMIC_MAP_CACHE_ENTRY) {
        if (entry->expiry_cache_timer){
            stop_timer(entry->expiry_cache_timer);
            entry->expiry_cache_timer = NULL;
        }
        if (entry->request_retry_timer){
            mcache_entry_stop_req_retry_timer(entry);
        }
        if (entry->smr_inv_timer){
            mcache_entry_stop_smr_inv_timer(entry);
        }
    }

    if (entry->nonces != NULL){
        free(entry->nonces);
    }
    free(entry);
}

void
map_cache_entry_to_char (mcache_entry_t *entry, int log_level)
{
    char                buf[256], buf2[256];
    time_t              expiretime;
    time_t              uptime;
    int                 ctr = 0;
    char                str[400];
//    char                fmt[200];
    locators_list_t         *locator_iterator_array[2]  = {NULL,NULL};
    locators_list_t         *locator_iterator           = NULL;
    locator_t           *locator                    = NULL;
    mapping_t           *mapping                    = NULL;

    if (is_loggable(log_level) == FALSE){
        return;
    }

    mapping = mcache_entry_mapping(entry);

    sprintf(str,"IDENTIFIER (EID): %s (IID = %d), ",
            lisp_addr_to_char(mapping_eid(mapping)), mapping->iid );
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
    lmlog(log_level,"%s",str);

    if (entry->mapping->locator_count > 0){
        locator_iterator_array[0] = entry->mapping->head_v4_locators_list;
        locator_iterator_array[1] = entry->mapping->head_v6_locators_list;
        lmlog(log_level, "|               Locator (RLOC)            | Status | Priority/Weight |");
        // Loop through the locators and print each
        for (ctr = 0 ; ctr < 2 ; ctr++){
            locator_iterator = locator_iterator_array[ctr];
            while (locator_iterator != NULL) {
                locator = locator_iterator->locator;
                locator_to_char(locator);
                locator_iterator = locator_iterator->next;
            }
        }
        lmlog(log_level,"\n");
    }
}



