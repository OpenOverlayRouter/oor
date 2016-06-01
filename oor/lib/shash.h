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

#ifndef SHASH_H_
#define SHASH_H_

#include "../elibs/khash/khash.h"
#include "generic_list.h"

//KHASH_MAP_INIT_STR(str, void *)
KHASH_INIT(str, char *, void *, 1, kh_str_hash_func, kh_str_hash_equal)

/* Prototype for a pointer to a free key function. */
typedef void (*free_value_fn_t)(const void *key);


typedef struct shash {
    khash_t(str) *htable;
    free_value_fn_t free_value_fn;
} shash_t;




shash_t *shash_new();
shash_t *shash_new_managed(free_value_fn_t df);
void shash_del(shash_t *);
void shash_insert(shash_t *, char *,  void *);
void shash_remove(shash_t *, char *);
void *shash_lookup(shash_t *, char *);
void shash_destroy(shash_t *sh);
glist_t *shash_keys(shash_t *sh);
glist_t *shash_values(shash_t *sh);



#endif /* SHASH_H_ */
