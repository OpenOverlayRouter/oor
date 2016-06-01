/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <time.h>

#include "map_cache_entry.h"
#include "oor_log.h"
#include "timers_utils.h"
#include "../defs.h"



inline mcache_entry_t *
mcache_entry_new()
{
    mcache_entry_t *mce;
    mce = xzalloc(sizeof(mcache_entry_t));

    mce->active = NOT_ACTIVE;
    mce->timestamp = time(NULL);

    return(mce);
}

void
mcache_entry_init(mcache_entry_t *mce, mapping_t *mapping)
{

    mce->mapping = mapping;
    mce->how_learned = MCE_DYNAMIC;
}

void
mcache_entry_init_static(mcache_entry_t *mce, mapping_t *mapping)
{

    mce->active = ACTIVE;
    mce->mapping = mapping;
    mce->how_learned = MCE_STATIC;
}


void
mcache_entry_del(mcache_entry_t *entry)
{
    locator_t *loct;

    assert(entry);
    /* Stop timers associated to the locators */
    mapping_foreach_locator(mcache_entry_mapping(entry),loct){
        stop_timers_from_obj(loct,ptrs_to_timers_ht, nonces_ht);
    }mapping_foreach_locator_end;
    stop_timers_from_obj(entry,ptrs_to_timers_ht, nonces_ht);

    mapping_del(mcache_entry_mapping(entry));

    if (entry->routing_info != NULL){
        entry->routing_inf_del(entry->routing_info);
    }

    free(entry);
}

inline uint8_t
mcache_has_locators(mcache_entry_t *m)
{
    if (mapping_locator_count(m->mapping) > 0){
        return (TRUE);
    }else{
        return (FALSE);
    }
}


void
map_cache_entry_dump (mcache_entry_t *entry, int log_level)
{
    if (is_loggable(log_level) == FALSE){
        return;
    }

    char buf[256], buf2[64];
    time_t expiretime;
    time_t uptime;
    char str[400];
    mapping_t *mapping = NULL;

    *buf = '\0';
    *buf2 = '\0';
    *str = '\0';
    mapping = mcache_entry_mapping(entry);

    uptime = time(NULL);
    uptime = uptime - entry->timestamp;
    strftime(buf, 20, "%H:%M:%S", localtime(&uptime));
    expiretime = (mapping_ttl(mcache_entry_mapping(entry)) * 60) - uptime;
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

    OOR_LOG(log_level, "%s\n%s\n", str, mapping_to_char(mapping));
}




