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

#include "shash.h"
#include "mem_util.h"

shash_t *
shash_new()
{
    shash_t *sh;

    sh =xcalloc(1,sizeof(shash_t));
    sh->htable = kh_init(str);
    return(sh);
}

shash_t *
shash_new_managed(free_value_fn_t df)
{
    shash_t *sh;

    sh =xcalloc(1,sizeof(shash_t));
    sh->htable = kh_init(str);
    sh->free_value_fn = df;
    return(sh);
}

void
shash_insert(shash_t *sh, char *key, void *val)
{
    khiter_t k;
    int ret;
    k = kh_get(str,sh->htable, key);
    if (k == kh_end(sh->htable)){
        k = kh_put(str,sh->htable,key,&ret);
    }else{
        free(key);
    }
    k = kh_put(str,sh->htable,key,&ret);
    kh_value(sh->htable, k) = val;
}

void
shash_remove(shash_t *sh, char *key)
{
    khiter_t k;

    k = kh_get(str,sh->htable, key);
    if (k == kh_end(sh->htable)){
        return;
    }
    free(kh_key(sh->htable,k));
    if (sh->free_value_fn){
        sh->free_value_fn(kh_value(sh->htable,k));
    }
    kh_del(str,sh->htable,k);
}

void *
shash_lookup(shash_t *sh, char *key)
{
    khiter_t k;

    k = kh_get(str,sh->htable, key);
    if (k == kh_end(sh->htable)){
        return (NULL);
    }
    return (kh_value(sh->htable,k));
}

void
shash_destroy(shash_t *sh)
{
    khiter_t k;

    if (!sh) {
        return;
    }

    for (k = kh_begin(sh->htable); k != kh_end(sh->htable); ++k){
        if (kh_exist(sh->htable, k)){
            free(kh_key(sh->htable,k));
            if (sh->free_value_fn){
                sh->free_value_fn(kh_value(sh->htable,k));
            }
        }
    }
    kh_destroy(str, sh->htable);
    free(sh);
}

glist_t *
shash_keys(shash_t *sh)
{
    glist_t *list;
    khiter_t k;

    list = glist_new();
    for (k = kh_begin(sh->htable); k != kh_end(sh->htable); ++k){
        if (kh_exist(sh->htable, k)){
            glist_add(kh_key(sh->htable,k), list);
        }
    }

    return (list);
}

glist_t *shash_values(shash_t *sh)
{
    glist_t *list;
    khiter_t k;

    list = glist_new();
    for (k = kh_begin(sh->htable); k != kh_end(sh->htable); ++k){
        if (kh_exist(sh->htable, k)){
            glist_add(kh_value(sh->htable,k), list);
        }
    }

    return (list);
}
