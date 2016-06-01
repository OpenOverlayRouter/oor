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


#ifndef POINTERS_TABLE_H_
#define POINTERS_TABLE_H_

#include "../defs.h"
#include "../elibs/khash/khash.h"
#include "generic_list.h"
#include "timers.h"

#if UINTPTR_MAX == 0xffffffff
  KHASH_INIT(ptrs, void *, void *, 1, kh_int_hash_func, kh_int_hash_equal)
#elif UINTPTR_MAX == 0xffffffffffffffff
  KHASH_INIT(ptrs, void *, void *, 1, kh_int64_hash_func, kh_int64_hash_equal)
#endif



typedef struct htable_ptrs{
    khash_t(ptrs) *ht;
}htable_ptrs_t;

htable_ptrs_t *htable_ptrs_new();

void htable_ptrs_insert(htable_ptrs_t *ptr_ht, void *key, void *val);
/* Remove entry of hash table and return the value */
void* htable_ptrs_remove(htable_ptrs_t *ptr_ht, void *key);
void *htable_ptrs_lookup(htable_ptrs_t *ptr_ht, void *key);
void htable_ptrs_destroy(htable_ptrs_t *ptr_ht);

/* Add the timer to the list of timers associated to the object. Creats the entry into the
 * hash table if it doesn't exist. User is responsible to check if exists duplicate timers before
 * inserting the new one */
int htable_ptrs_timers_add(htable_ptrs_t *ptr_ht, void *key, oor_timer_t *timer);
/* Return the list of timers associated with the object */
glist_t *htable_ptrs_timers_get_timers(htable_ptrs_t *ptr_ht, void *key);
/* Return the list the timers of the requested type associated with the object */
glist_t *htable_ptrs_timers_get_timers_of_type_from_obj(htable_ptrs_t *ptr_ht, void *key,
        timer_type type);
/* Remove the entry from hash table and returns the list of timers associated with the object */
glist_t *htable_ptrs_timers_rm(htable_ptrs_t *ptr_ht, void *key);
/* Remove from the list the timers of the requested type associated with the object
 * The removed timers are returned in a list */
glist_t *htable_ptrs_timers_rm_timers_of_type(htable_ptrs_t *ptr_ht, void *key, timer_type type);
/* Remove the timer from the list. It doesn't stop the timer */
int htable_ptrs_timers_rm_timer(htable_ptrs_t *ptr_ht, void *key, oor_timer_t *timer);

#endif /* POINTERS_TABLE_H_ */
