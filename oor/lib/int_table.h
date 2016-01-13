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

#ifndef INT_TABLE_H_
#define INT_TABLE_H_

#include "generic_list.h"
#include "../elibs/khash/khash.h"

KHASH_INIT(int, int, void *, 1, kh_int_hash_func, kh_int_hash_equal)

/* Prototype for a pointer to a free key function. */
typedef void (*free_value_fn_t)(const void *key);

typedef struct int_htable_{
    khash_t(int) *htable;
    free_value_fn_t free_value_fn;
}int_htable;

int_htable *int_htable_new();
int_htable *int_htable_new_managed(free_value_fn_t df);
void int_htable_del(int_htable *);
void int_htable_insert(int_htable *,int,void *);
void int_htable_remove(int_htable *, int);
void *int_htable_lookup(int_htable *, int);
void int_htable_destroy(int_htable *ht);
glist_t *int_htable_values(int_htable *ht);



#define int_htable_foreach_key(_ht, _it)                                            \
        do {                                                                        \
            khiter_t _k_;                                                           \
            for (_k_ = kh_begin(_ht->htable); _k_ != kh_end(_ht->htable); ++_k_){   \
                if (kh_exist(_ht->htable, _k_)){                                    \
                    _it = kh_key(_ht->htable,_k_);

#define int_htable_foreach_key_end       \
                }                        \
            }                            \
        } while (0)

#define int_htable_foreach_value(_ht, _it)                                          \
        do {                                                                        \
            khiter_t _k_;                                                           \
            for (_k_ = kh_begin(_ht->htable); _k_ != kh_end(_ht->htable); ++_k_){   \
                if (kh_exist(_ht->htable, _k_)){                                    \
                    _it = kh_value(_ht->htable,_k_);

#define int_htable_foreach_value_end      \
                }                         \
            }                             \
        } while (0)





#endif /* INT_TABLE_H_ */
