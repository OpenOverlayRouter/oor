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



#include "int_table.h"
#include "mem_util.h"

int_htable *
int_htable_new()
{
    int_htable *ht;

    ht =xcalloc(1,sizeof(int_htable));
    ht->htable = kh_init(int);
    return(ht);
}

int_htable *
int_htable_new_managed(free_value_fn_t df)
{
    int_htable *ht;

    ht =xcalloc(1,sizeof(int_htable));
    ht->htable = kh_init(int);
    ht->free_value_fn = df;
    return(ht);
}


void
int_htable_insert(int_htable *ht, int key, void *val)
{
    khiter_t k;
    int ret;

    k = kh_put(int,ht->htable,key,&ret);
    kh_value(ht->htable, k) = val;
}

void
int_htable_remove(int_htable *ht, int key)
{
    khiter_t k;

    k = kh_get(int,ht->htable, key);
    if (k == kh_end(ht->htable)){
        return;
    }
    if (ht->free_value_fn){
        ht->free_value_fn(kh_value(ht->htable,k));
    }
    kh_del(int,ht->htable,k);
}

void *
int_htable_lookup(int_htable *ht, int key)
{
    khiter_t k;

    k = kh_get(int,ht->htable, key);
    if (k == kh_end(ht->htable)){
        return (NULL);
    }
    return (kh_value(ht->htable,k));
}

void
int_htable_destroy(int_htable *ht)
{
    khiter_t k;

    if (!ht) {
        return;
    }

    for (k = kh_begin(sh->htable); k != kh_end(ht->htable); ++k){
        if (kh_exist(ht->htable, k)){
            if (ht->free_value_fn){
                ht->free_value_fn(kh_value(ht->htable,k));
            }
        }
    }
    kh_destroy(int, ht->htable);
    free(ht);
}


glist_t *int_htable_values(int_htable *ht)
{
    glist_t *list;
    khiter_t k;

    list = glist_new();
    for (k = kh_begin(sh->htable); k != kh_end(ht->htable); ++k){
        if (kh_exist(ht->htable, k)){
            glist_add(kh_value(ht->htable,k), list);
        }
    }

    return (list);
}
