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

#include "oor_log.h"
#include "map_local_entry.h"
#include "timers_utils.h"
#include "../defs.h"

inline mapping_t *
map_local_entry_mapping(map_local_entry_t *mle)
{
    return (mle->mapping);
}

inline void
map_local_entry_set_mapping(
        map_local_entry_t *mle,
        mapping_t *map)
{
    mle->mapping = map;
}

inline void *
map_local_entry_fwd_info(map_local_entry_t *mle)
{
    return (mle->fwd_info);
}

inline void
map_local_entry_set_fwd_info(
        map_local_entry_t *mle,
        void *fwd_info,
        fwd_info_del_fct fwd_del_fct)
{
    mle->fwd_info = fwd_info;
    if (fwd_del_fct == NULL){
        OOR_LOG(LDBG_1, "map_local_entry_set_fwd_info: No specified function to delete fwd info.");
    }
    mle->fwd_inf_del = fwd_del_fct;
}

inline lisp_addr_t *
map_local_entry_eid(map_local_entry_t *mle){
    return (mapping_eid(map_local_entry_mapping(mle)));
}

map_local_entry_t *
map_local_entry_new()
{
	map_local_entry_t *mle;
	mle = xzalloc(sizeof(map_local_entry_t));

	return (mle);
}

map_local_entry_t *
map_local_entry_new_init(mapping_t *map)
{
    map_local_entry_t *mle;
    mle = xzalloc(sizeof(map_local_entry_t));
    if (mle == NULL){
        OOR_LOG(LDBG_1, "map_local_entry_new_init: Can't create local database mapping with EID prefix %s.",
            lisp_addr_to_char(mapping_eid(map)));
        return (NULL);
    }
    mle->mapping = map;

    return (mle);
}

void
map_local_entry_init(map_local_entry_t *mle, mapping_t *map)
{
	mle->mapping = map;
}

void
map_local_entry_del(map_local_entry_t *mle)
{
    if (mle == NULL){
        return;
    }
    stop_timers_from_obj(mle,ptrs_to_timers_ht, nonces_ht);
	mapping_del(mle->mapping);
	if (mle->fwd_info != NULL){
	    mle->fwd_inf_del(mle->fwd_info);
	}
	free(mle);
}

void
map_local_entry_dump(map_local_entry_t *mle, int log_level)
{
	// TODO
    OOR_LOG(log_level,mapping_to_char(mle->mapping));
}

char *
map_local_entry_to_char(map_local_entry_t *mle)
{
    // TODO
    return (mapping_to_char(mle->mapping));
}
