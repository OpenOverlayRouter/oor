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
#include "mem_util.h"
#include "packets.h"
#include "oor_log.h"
#include "sockets.h"
#include "../fwd_policies/fwd_policy.h"
#include "../liblisp/liblisp.h"

/* Time after which an entry is considered to have timed out and
 * is removed from the table */
#define TIMEOUT 3

/* Time after which a negative entry is considered to have timed
 * out and is removed from the table */
#define NEGATIVE_TIMEOUT 0.1

/* Maximum size of the tuple table */
#define MAX_SIZE 10000
#define OLD_ENTRIES 1000

static void ttable_remove_with_khiter(ttable_t *tt, khiter_t k);

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
    pkt_tuple_del(tn->tpl);
    fwd_info_del(tn->fi,(fwd_info_data_del)fwd_entry_del);
    free(tn);
}

void
ttable_init(ttable_t *tt)
{
    tt->htable =  kh_init(ttable);
    list_init(&tt->head_list);
}

void
ttable_uninit(ttable_t *tt)
{
    khiter_t k;

    for (k = kh_begin(tt->htable); k != kh_end(tt->htable); ++k){
        if (kh_exist(tt->htable, k)){
            ttable_node_del(kh_value(tt->htable,k));
        }
    }
    kh_destroy(ttable, tt->htable);
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
tnode_expired(ttable_node_t *tn)
{
    return(time_elapsed(&tn->ts) > TIMEOUT);
}

void
ttable_insert(ttable_t *tt, packet_tuple_t *tpl, fwd_info_t *fi)
{
    khiter_t k;
    int ret,i,removed,to_remove;
    ttable_node_t *node;
    struct ovs_list *list_elt;

    /* If table is full, lookup and remove expired entries. If it is still
     * full, remove old entries */
    if (kh_size(tt->htable) >= MAX_SIZE) {
        OOR_LOG(LDBG_1,"ttable_insert: Max size of forwarding table reached. Removing expired entries");
        removed = 0;
        for (k = kh_begin(tt->htable); k != kh_end(tt->htable); ++k){
            if (!kh_exist(tt->htable, k)){
                continue;
            }
            if (tnode_expired(kh_value(tt->htable,k))){
                ttable_remove_with_khiter(tt,k);
                removed++;
            }
        }
        if (removed <  OLD_ENTRIES){
            OOR_LOG(LDBG_1,"ttable_insert: Max size of forwarding table reached. Removing older entries");
            to_remove = OLD_ENTRIES - removed;
            for (i = 0 ; i < to_remove ; i++){
                list_elt = list_back(&tt->head_list);
                node = CONTAINER_OF(list_elt, ttable_node_t, list_elt);
                ttable_remove(tt, node->tpl);
            }
        }
    }

    node = xzalloc(sizeof(ttable_node_t));
    node->fi = fi;
    node->tpl = tpl;
    clock_gettime(CLOCK_MONOTONIC, &node->ts);

    list_init(&node->list_elt);
    list_push_front(&tt->head_list, &node->list_elt);

    k = kh_put(ttable,tt->htable,tpl,&ret);
    kh_value(tt->htable, k) = node;
    OOR_LOG(LDBG_3,"ttable_insert: Inserted tupla: %s ", pkt_tuple_to_char(tpl));
}

void
ttable_remove(ttable_t *tt, packet_tuple_t *tpl)
{
    khiter_t k;
    ttable_node_t *tn;

    k = kh_get(ttable,tt->htable, tpl);
    if (k == kh_end(tt->htable)){
        return;
    }
    tn = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove: Remove tupla: %s ", pkt_tuple_to_char(tn->tpl));
    list_remove(&tn->list_elt);
    ttable_node_del(tn);
    kh_del(ttable,tt->htable,k);
}

static void
ttable_remove_with_khiter(ttable_t *tt, khiter_t k)
{
    ttable_node_t *node;

    node = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove_with_khiter: Remove tupla: %s ", pkt_tuple_to_char(node->tpl));
    list_remove(&node->list_elt);
    ttable_node_del(node);
    kh_del(ttable,tt->htable,k);
}

fwd_info_t *
ttable_lookup(ttable_t *tt, packet_tuple_t *tpl)
{
    ttable_node_t *tn;
    khiter_t k;
    double elapsed;

    k = kh_get(ttable,tt->htable, tpl);
    if (k == kh_end(tt->htable)){
        return (NULL);
    }
    tn = kh_value(tt->htable,k);

    elapsed = time_elapsed(&tn->ts);
    if (!tn->fi->temporal){
        if (elapsed > TIMEOUT){
            goto expired;
        }
    }else{
        if (elapsed > NEGATIVE_TIMEOUT){
            goto expired;
        }
    }

    list_remove(&tn->list_elt);
    list_push_front(&tt->head_list, &tn->list_elt);

    return (tn->fi);

expired:
    ttable_remove_with_khiter(tt, k);
    return(NULL);
}

