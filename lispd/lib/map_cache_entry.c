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
#include "lmlog.h"
#include "../defs.h"



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
    if (entry == NULL){
        return;
    }

    mapping_del(mcache_entry_mapping(entry));

    if (entry->how_learned == MCE_DYNAMIC) {
        if (entry->expiry_cache_timer) {
            lmtimer_stop(entry->expiry_cache_timer);
            entry->expiry_cache_timer = NULL;
        }
        if (entry->request_retry_timer) {
            mcache_entry_stop_req_retry_timer(entry);
            entry->request_retry_timer = NULL;
        }
        if (entry->smr_inv_timer) {
            mcache_entry_stop_smr_inv_timer(entry);
            entry->smr_inv_timer = NULL;
        }
    }

    if (entry->routing_info != NULL){
        entry->routing_inf_del(entry->routing_info);
    }

    if (entry->nonces != NULL) {
        free(entry->nonces);
    }
    lisp_addr_del(entry->requester);
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

    char buf[256], buf2[256];
    time_t expiretime;
    time_t uptime;
    char str[400];
    mapping_t *mapping = NULL;

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

    LMLOG(log_level, "%s\n%s\n", str, mapping_to_char(mapping));
}

inline void
mcache_entry_stop_req_retry_timer(mcache_entry_t *m)
{
    lmtimer_stop(m->request_retry_timer);
    m->request_retry_timer = NULL;
}

inline lmtimer_t *
mcache_entry_init_req_retry_timer(mcache_entry_t *m)
{
    if (m->request_retry_timer) {
        mcache_entry_stop_req_retry_timer(m);
    }
    m->request_retry_timer = lmtimer_create(MAP_REQUEST_RETRY_TIMER);
    return(m->request_retry_timer);
}

inline void
mcache_entry_stop_smr_inv_timer(mcache_entry_t *m)
{
    free(m->smr_inv_timer->cb_argument);
    lmtimer_stop(m->smr_inv_timer);
    m->smr_inv_timer = NULL;
}

inline lmtimer_t *
mcache_entry_init_smr_inv_timer(mcache_entry_t *m)
{
    if (m->smr_inv_timer) {
        mcache_entry_stop_smr_inv_timer(m);
    }
    m->smr_inv_timer = lmtimer_create(SMR_INV_RETRY_TIMER);
    return(m->smr_inv_timer);
}

