/*
 * ttable.c
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

#include "ttable.h"
#include "util.h"
#include "packets.h"
#include "lmlog.h"


#include "liblisp.h"

/* Time after which an entry is considered to have timed out and
 * is removed from the table */
#define TIMEOUT 3

/* Time after which a negative entry is considered to have timed
 * out and is removed from the table */
#define NEGATIVE_TIMEOUT 0.1

/* Maximum size of the tuple table */
#define MAX_SIZE 10000

static double
time_diff(struct timespec *x , struct timespec *y)
{
    double x_s, y_s, diff;

    x_s = (double)x->tv_sec + 1.0e-9*x->tv_nsec;
    y_s = (double)y->tv_sec + 1.0e-9*y->tv_nsec;

    diff = (double)y_s - (double)x_s;

    return diff;
}

static double
time_elapsed(struct timespec *time_node)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return(time_diff(time_node, &now));
}

static void
ttable_node_del(ttable_node_t *tn)
{
    free(tn->fe);
    free(tn);
}

void
ttable_init(ttable_t *tt)
{
    tt->htable = htable_new((h_key_fct)pkt_tuple_hash, (h_key_eq_fct)pkt_tuple_cmp,
            (h_key_del_fct)pkt_tuple_del, (h_val_del_fct)ttable_node_del);
}

void
ttable_uninit(ttable_t *tt)
{
    htable_destroy(tt->htable);
}

ttable_t *
ttable_create()
{
   ttable_t *tt = xzalloc(sizeof(ttable_t));
   ttable_init(tt);
   return(tt);
}

void
ttable_destroy(ttable_t *tt)
{
    ttable_uninit(tt);
    free(tt);
}

static int
tnode_expired(packet_tuple_t *tpl, ttable_node_t *tn, void *ud)
{
    return(time_elapsed(&tn->ts) > TIMEOUT);
}

void
ttable_insert(ttable_t *tt, packet_tuple_t *tpl, fwd_entry_t *fe)
{
    ttable_node_t *node = xzalloc(sizeof(ttable_node_t));
    node->fe = fe;
    clock_gettime(CLOCK_MONOTONIC, &node->ts);

    htable_insert(tt->htable, tpl, node);

    /* If table is full, lookup and remove expired entries */
    if (htable_size(tt->htable) >= MAX_SIZE) {
        htable_foreach_remove(tt->htable, (h_usr_del_fct)tnode_expired, NULL);
    }
}

void
ttable_remove(ttable_t *tt, packet_tuple_t *tpl)
{
    htable_remove(tt->htable, tpl);
}

fwd_entry_t *
ttable_lookup(ttable_t *tt, packet_tuple_t *tpl)
{
    ttable_node_t *tn = htable_lookup(tt->htable, tpl);
    double elapsed;
    if (!tn) {
        return(NULL);
    }

    elapsed = time_elapsed(&tn->ts);
    if (elapsed > TIMEOUT
        || ((!tn->fe->srloc || !tn->fe->drloc)
                && elapsed > NEGATIVE_TIMEOUT)) {
        htable_remove(tt->htable, tpl);
        return(NULL);
    } else {
        return(tn->fe);
    }
}

