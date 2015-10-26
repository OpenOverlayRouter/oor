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

#include "ttable.h"
#include "util.h"
#include "packets.h"
#include "lmlog.h"
#include "sockets.h"


#include "../liblisp/liblisp.h"

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
    fwd_entry_del(tn->fe);
    free(tn);
}

void
ttable_init(ttable_t *tt)
{
    tt->htable = hash_new((hash_function_t)pkt_tuple_hash, (hash_cmp_key_fn_t) pkt_tuple_cmp,
            (hash_free_key_fn_t)pkt_tuple_del, (hash_free_fn_t) ttable_node_del,
            (hash_clone_key_fn_t) pkt_tuple_clone, 0);
}

void
ttable_uninit(ttable_t *tt)
{
    hash_destroy(tt->htable);
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

    hash_put(tt->htable, tpl, node);

    /* If table is full, lookup and remove expired entries */
    if (hash_num_entries(tt->htable) >= MAX_SIZE) {
        hash_foreach_remove(tt->htable, (hash_remove_fn_t)tnode_expired, NULL);
    }
}

void
ttable_remove(ttable_t *tt, packet_tuple_t *tpl)
{
    hash_delete(tt->htable, tpl);
}

fwd_entry_t *
ttable_lookup(ttable_t *tt, packet_tuple_t *tpl)
{
    ttable_node_t *tn = hash_get(tt->htable, tpl);
    double elapsed;
    if (!tn) {
        return(NULL);
    }

    elapsed = time_elapsed(&tn->ts);
    if (elapsed > TIMEOUT
        || ((!tn->fe || !tn->fe->srloc || !tn->fe->drloc)
                && elapsed > NEGATIVE_TIMEOUT)) {
        hash_delete(tt->htable, tpl);
        return(NULL);
    } else {
        return(tn->fe);
    }
}

