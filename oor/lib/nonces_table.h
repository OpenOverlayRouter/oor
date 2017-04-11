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

#ifndef NONCES_TABLE_H_
#define NONCES_TABLE_H_

#include "../defs.h"
#include "../elibs/khash/khash.h"
#include "timers.h"

typedef struct {
    glist_t *nonces_list; //<uint64_t>
    oor_timer_t *timer;
} nonces_list_t;

KHASH_INIT(nonces, uint64_t, nonces_list_t *, 1, kh_int64_hash_func, kh_int64_hash_equal)
//KHASH_MAP_INIT_INT64(nonces, nonces_list_t *)

typedef struct htable_nonces_{
    khash_t(nonces) *ht;
}htable_nonces_t;

htable_nonces_t *htable_nonces_new();
void htable_nonces_insert(htable_nonces_t *nonces_ht, uint64_t nonce,
        nonces_list_t *nonces_lst);
nonces_list_t *htable_nonces_remove(htable_nonces_t *nonces_ht, uint64_t nonce);
nonces_list_t *htable_nonces_lookup(htable_nonces_t *nonce_ht, uint64_t nonce);
void htable_nonces_destroy(htable_nonces_t *nonces_ht);
void htable_nonces_reset_nonces_lst(htable_nonces_t *nonces_ht, nonces_list_t *nonces_lst);

uint64_t nonce_build(int seed);
uint64_t nonce_new();
glist_t *nonces_list_list(nonces_list_t * nonces_lst);
oor_timer_t *nonces_list_timer(nonces_list_t * nonces_lst);
nonces_list_t *nonces_list_new_init(oor_timer_t *timer);
void nonces_list_free(nonces_list_t *nonces_lst);
int nonces_list_size(nonces_list_t *nonces_lst);


#endif /* NONCES_TABLE_H_ */
