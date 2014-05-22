/*
 * ttable.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
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


#ifndef TTABLE_H_
#define TTABLE_H_

#include <time.h>
#include "hash_table.h"
#include "packets.h"

typedef struct fwd_entry fwd_entry_t;

typedef struct ttable {
    htable_t *htable;
} ttable_t;

typedef struct ttable_node {
    fwd_entry_t *fe;
    struct timespec ts;
} ttable_node_t;

void ttable_init(ttable_t *tt);
void ttable_uninit(ttable_t *tt);
ttable_t *ttable_create();
void ttable_destroy(ttable_t *tt);
void ttable_insert(ttable_t *, packet_tuple_t *tpl, fwd_entry_t *fe);
void ttable_remove(ttable_t *tt, packet_tuple_t *tpl);
fwd_entry_t *ttable_lookup(ttable_t *tt, packet_tuple_t *tpl);


#endif /* TTABLE_H_ */
