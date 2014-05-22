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
    sh = htable_new(g_str_hash, g_str_equal, free, NULL);
    return(sh);
}

shash_t *
shash_new_managed(h_del_fct df)
{
    shash_t *sh;
    sh = htable_new(g_str_hash, g_str_equal, free, df);
    return(sh);
}

void
shash_del(shash_t *sh) {
    htable_destroy(sh);
    free(sh);
}

void
shash_insert(shash_t *sh, const char *key, const void *val)
{
    htable_insert(sh, strdup(key), CONST_CAST(void *, val));
}

void
shash_remove(shash_t *sh, const char *key)
{
    htable_remove(sh, key);
}

void *
shash_lookup(shash_t *sh, const char *key)
{
    return htable_lookup(sh, key);
}

void
shash_destroy(shash_t *sh)
{
    if (sh) {
        htable_destroy(sh);
    }
}
