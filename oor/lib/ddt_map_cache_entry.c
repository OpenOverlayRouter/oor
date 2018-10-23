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

#include "ddt_map_cache_entry.h"
#include "oor_log.h"
#include "timers_utils.h"
#include "../defs.h"



inline ddt_mcache_entry_t *
ddt_mcache_entry_new()
{
    ddt_mcache_entry_t *mce;
    mce = xzalloc(sizeof(ddt_mcache_entry_t));

    mce->timestamp = time(NULL);

    return(mce);
}

void
ddt_mcache_entry_init(ddt_mcache_entry_t *mce, mref_mapping_t *mapping)
{

    mce->mapping = mapping;
    mce->how_learned = DDT_MCE_DYNAMIC;
}

void
ddt_mcache_entry_init_static(ddt_mcache_entry_t *mce, mref_mapping_t *mapping)
{

    mce->mapping = mapping;
    mce->how_learned = DDT_MCE_STATIC;
}


void
ddt_mcache_entry_del(ddt_mcache_entry_t *entry)
{
    locator_t *loct;
    if (!entry){
    	return;
    }
    /* Stop timers associated to the locators */
    mref_mapping_foreach_referral(ddt_mcache_entry_mapping(entry),loct){
        stop_timers_from_obj(loct,ptrs_to_timers_ht, nonces_ht);
    }mref_mapping_foreach_referral_end;
    stop_timers_from_obj(entry,ptrs_to_timers_ht, nonces_ht);

    mref_mapping_del(ddt_mcache_entry_mapping(entry));

    free(entry);
}


inline lisp_addr_t *
ddt_mcache_entry_eid(ddt_mcache_entry_t *mce)
{
    return(mref_mapping_eid(mce->mapping));
}

inline uint8_t
ddt_mcache_has_referrals(ddt_mcache_entry_t *m)
{
    if (mref_mapping_referral_count(m->mapping) > 0){
        return (TRUE);
    }else{
        return (FALSE);
    }
}

void
ddt_map_cache_entry_dump (ddt_mcache_entry_t *entry, int log_level)
{
    if (is_loggable(log_level) == FALSE){
        return;
    }

    char buf[256], buf2[64];
    time_t expiretime;
    time_t uptime;
    char str[400];
    mref_mapping_t *mapping = NULL;

    *buf = '\0';
    *buf2 = '\0';
    *str = '\0';
    mapping = ddt_mcache_entry_mapping(entry);

    uptime = time(NULL);
    uptime = uptime - entry->timestamp;
    strftime(buf, 20, "%H:%M:%S", localtime(&uptime));
    expiretime = (mref_mapping_ttl(ddt_mcache_entry_mapping(entry)) * 60) - uptime;
    if (expiretime > 0) {
        strftime(buf2, 20, "%H:%M:%S", localtime(&expiretime));
    }

    snprintf(str,sizeof(str), "ENTRY UPTIME: %s, EXPIRES: %s, ", buf, buf2);

    if (entry->how_learned == DDT_MCE_STATIC) {
        snprintf(str + strlen(str),sizeof(str) - strlen(str),"TYPE: Static, ");
    } else {
        snprintf(str + strlen(str),sizeof(str) - strlen(str),"TYPE: Dynamic, ");
    }

    OOR_LOG(log_level, "%s\n%s\n", str, mref_mapping_to_char(mapping));
}

ddt_mcache_entry_t *
ddt_map_cache_entry_clone(ddt_mcache_entry_t *entry)
{
	ddt_mcache_entry_t *ddt_mc = ddt_mcache_entry_new();
	ddt_mc->how_learned = entry->how_learned;
	ddt_mc->mapping = mref_mapping_clone(entry->mapping);
	ddt_mc->timestamp = entry->timestamp;

	return (ddt_mc);
}



