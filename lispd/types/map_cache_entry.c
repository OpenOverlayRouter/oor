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
mcache_entry_init(mcache_entry_t *mce, mapping_t *mapping)
{

    mce->mapping = mapping;
    mce->how_learned = MCE_DYNAMIC;
    mce->ttl = DEFAULT_DATA_CACHE_TTL;

}

void
mcache_entry_init_static(mcache_entry_t *mce, mapping_t *mapping)
{

    mce->active = ACTIVE;
    mce->mapping = mapping;
    mce->how_learned = MCE_STATIC;
    mce->ttl = 255; /* XXX: why 255? */
}


void
mcache_entry_del(mcache_entry_t *entry)
{
    mapping_del(mcache_entry_mapping(entry));

    if (entry->how_learned == MCE_DYNAMIC) {
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

    if (entry->nonces != NULL) {
        free(entry->nonces);
    }
    free(entry);
}

void
map_cache_entry_to_char (mcache_entry_t *entry, int log_level)
{
    char buf[256], buf2[256];
    time_t expiretime;
    time_t uptime;
    char str[400];
    mapping_t *mapping = NULL;

    if (is_loggable(log_level) == FALSE){
        return;
    }

    mapping = mcache_entry_mapping(entry);

    uptime = time(NULL);
    uptime = uptime - entry->timestamp;
    strftime(buf, 20, "%H:%M:%S", localtime(&uptime));
    expiretime = (entry->ttl * 60) - uptime;
    if (expiretime > 0) {
        strftime(buf2, 20, "%H:%M:%S", localtime(&expiretime));
    }

    sprintf(str, "ENTRY UPTIME: %s, EXPIRES: %s, ", buf, buf2);

    if (entry->how_learned == MCE_STATIC) {
        sprintf(str + strlen(str),"TYPE: Static, ");
    } else {
        sprintf(str + strlen(str),"TYPE: Dynamic, ");
    }
    sprintf(str + strlen(str),"ACTIVE: %s",
            entry->active == TRUE ? "Yes" : "No");

    lmlog(log_level, "%s\n%s\n", str, mapping_to_char(mapping));
}



