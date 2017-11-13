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
 * diptrsibuted under the License is diptrsibuted on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "htable_ptrs.h"
#include "mem_util.h"

htable_ptrs_t *
htable_ptrs_new()
{
    htable_ptrs_t * ht;
    ht = (htable_ptrs_t *)xzalloc(sizeof(htable_ptrs_t));
    ht->htable = kh_init(ptrs);
    return(ht);
}

htable_ptrs_t *
htable_ptrs_new_managed(free_value_fn_t df)
{
    htable_ptrs_t *ht;

    ht = (htable_ptrs_t *)xzalloc(sizeof(htable_ptrs_t));
    ht->htable = kh_init(ptrs);
    ht->free_value_fn = df;
    return(ht);
}

void
htable_ptrs_insert(htable_ptrs_t *ht, void *key, void *val)
{
    khiter_t k;
    int ret;

    k = kh_put(ptrs,ht->htable,key,&ret);
    kh_value(ht->htable, k) = val;
}

void *
htable_ptrs_remove(htable_ptrs_t *ht, void *key)
{
    void *val;
    khiter_t k;

    k = kh_get(ptrs,ht->htable, key);
    if (k == kh_end(ht->htable)){
        return (NULL);
    }
    val =  kh_value(ht->htable, k);
    kh_del(ptrs,ht->htable,k);

    return (val);
}

void *
htable_ptrs_lookup(htable_ptrs_t *ht, void *key)
{
    khiter_t k;

    k = kh_get(ptrs,ht->htable, key);
    if (k == kh_end(ht->htable)){
        return (NULL);
    }
    return (kh_value(ht->htable,k));
}

void
htable_ptrs_destroy(htable_ptrs_t *ht)
{
    khiter_t k;

    if (!ht) {
        return;
    }

    for (k = kh_begin(ht->htable); k != kh_end(ht->htable); ++k){
        if (kh_exist(ht->htable, k)){
            //free(kh_key(ht->htable,k));
            if (ht->free_value_fn){
                ht->free_value_fn(kh_value(ht->htable,k));
            }
        }
    }
    kh_destroy(ptrs, ht->htable);
    free(ht);
}

glist_t *
htable_ptrs_keys(htable_ptrs_t *ht)
{
    glist_t *list;
    khiter_t k;

    list = glist_new();
    for (k = kh_begin(ht->htable); k != kh_end(ht->htable); ++k){
        if (kh_exist(ht->htable, k)){
            glist_add(kh_key(ht->htable,k), list);
        }
    }

    return (list);
}

glist_t *
htable_ptrs_values(htable_ptrs_t *ht)
{
    glist_t *list;
    khiter_t k;

    list = glist_new();
    for (k = kh_begin(ht->htable); k != kh_end(ht->htable); ++k){
        if (kh_exist(ht->htable, k)){
            glist_add(kh_value(ht->htable,k), list);
        }
    }

    return (list);
}
