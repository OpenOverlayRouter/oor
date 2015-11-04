/*
 * shash.c
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#include "shash.h"
#include "util.h"

shash_t *
shash_new()
{
    shash_t *sh;

    sh =xcalloc(1,sizeof(shash_t));
    sh->htable = kh_init(str);
    return(sh);
}

shash_t *
shash_new_managed(free_key_fn_t df)
{
    shash_t *sh;

    sh =xcalloc(1,sizeof(shash_t));
    sh->htable = kh_init(str);
    sh->free_key_fn = df;
    return(sh);
}

void
shash_insert(shash_t *sh, char *key, void *val)
{
    khiter_t k;
    int ret;

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
    if (sh->free_key_fn){
        sh->free_key_fn(kh_value(sh->htable,k));
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
            if (sh->free_key_fn){
                sh->free_key_fn(kh_value(sh->htable,k));
            }
        }
    }
    kh_destroy(str, sh->htable);
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
