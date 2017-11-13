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

#ifndef OOR_HTABLE_PTRS_H_
#define OOR_HTABLE_PTRS_H_

#include "../elibs/khash/khash.h"
#include "generic_list.h"

#if UINTPTR_MAX == 0xffffffff
  KHASH_INIT(ptrs, void *, void *, 1, kh_int_hash_func, kh_int_hash_equal)
#elif UINTPTR_MAX == 0xffffffffffffffff
  KHASH_INIT(ptrs, void *, void *, 1, kh_int64_hash_func, kh_int64_hash_equal)
#endif

/* Prototype for a pointer to a free key function. */
typedef void (*free_value_fn_t)(const void *key);


typedef struct htable_ptrs{
    khash_t(ptrs) *htable;
    free_value_fn_t free_value_fn;
} htable_ptrs_t;




htable_ptrs_t *htable_ptrs_new();
htable_ptrs_t *htable_ptrs_new_managed(free_value_fn_t df);
void htable_ptrs_insert(htable_ptrs_t *ht, void *key, void *val);
void *htable_ptrs_remove(htable_ptrs_t *, void *);
void *htable_ptrs_lookup(htable_ptrs_t *, void *);
void htable_ptrs_destroy(htable_ptrs_t *sh);
glist_t *htable_ptrs_keys(htable_ptrs_t *sh);
glist_t *htable_ptrs_values(htable_ptrs_t *ht);


#endif /* OOR_HTABLE_PTRS_H_ */
