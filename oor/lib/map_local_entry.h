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

#ifndef MAP_LOCAL_ENTRY_H_
#define MAP_LOCAL_ENTRY_H_

#include "../liblisp/lisp_mapping.h"
#include "shash.h"

typedef void (*fwd_info_del_fct)(void *);

typedef struct nat_info_ {
    shash_t *loct_addr_to_rtrs;
    shash_t *rtr_addr_to_locts;
}nat_info_t;

typedef struct map_local_entry_ {
    mapping_t *         mapping;
    void *              fwd_info;
    fwd_info_del_fct    fwd_inf_del;
    nat_info_t *        nat_info;
} map_local_entry_t;

map_local_entry_t *map_local_entry_new();
map_local_entry_t *map_local_entry_new_init(mapping_t *map);
void map_local_entry_init(map_local_entry_t *mle, mapping_t *map);

void map_local_entry_del(map_local_entry_t *mle);
void map_local_entry_dump(map_local_entry_t *mle, int log_level);
char * map_local_entry_to_char(map_local_entry_t *mle);

inline mapping_t *map_local_entry_mapping(map_local_entry_t *mle);
inline void map_local_entry_set_mapping(map_local_entry_t *mle, mapping_t *map);
inline void *map_local_entry_fwd_info(map_local_entry_t *mle);
inline void map_local_entry_set_fwd_info(map_local_entry_t *mle, void *fwd_info,
		fwd_info_del_fct fwd_del_fct);
inline lisp_addr_t *map_local_entry_eid(map_local_entry_t *mle);

void mle_nat_info_update(map_local_entry_t *mle, locator_t *loct, glist_t *new_rtr_list);
glist_t * mle_rtr_addr_list(map_local_entry_t *mle);

#endif /* MAP_LOCAL_ENTRY_H_ */
