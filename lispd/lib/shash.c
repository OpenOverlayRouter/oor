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
    sh = hash_new(NULL, NULL, (hash_free_key_fn_t)free, NULL, NULL, 0);
    return(sh);
}

shash_t *
shash_new_managed(hash_free_fn_t df)
{
    shash_t *sh;
    sh = hash_new(NULL, NULL, (hash_free_key_fn_t)free, df, NULL, 0);
    return(sh);
}

void
shash_insert(shash_t *sh, const char *key, const void *val)
{
    hash_put(sh, key, CONST_CAST(void *, val));
}

void
shash_remove(shash_t *sh, const char *key)
{
    hash_delete(sh, key);
}

void *
shash_lookup(shash_t *sh, const char *key)
{
    return hash_get(sh, key);
}

void
shash_destroy(shash_t *sh)
{
    if (sh) {
        hash_destroy(sh);
    }
}

glist_t *shash_keys(shash_t *sh)
{
    return (hash_keys(sh,1));
}

glist_t *shash_values(shash_t *sh)
{
    return (hash_values(sh));
}
