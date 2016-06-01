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

#include "pointers_table.h"
#include "../defs.h"


htable_ptrs_t *
htable_ptrs_new()
{
    htable_ptrs_t * ht;
    ht = (htable_ptrs_t *)xzalloc(sizeof(htable_ptrs_t));
    ht->ht = kh_init(ptrs);
    return(ht);
}

void
htable_ptrs_insert(htable_ptrs_t *ptr_ht, void *key, void *val)
{
    khiter_t k;
    int ret;

    k = kh_put(ptrs,ptr_ht->ht,key,&ret);
    kh_value(ptr_ht->ht, k) = val;
}

void *
htable_ptrs_remove(htable_ptrs_t *ptr_ht, void *key)
{
    void *val;
    khiter_t k;

    k = kh_get(ptrs,ptr_ht->ht, key);
    if (k == kh_end(ptr_ht->ht)){
        return (NULL);
    }
    val =  kh_value(ptr_ht->ht, k);
    kh_del(ptrs,ptr_ht->ht,k);

    return (val);
}

void *
htable_ptrs_lookup(htable_ptrs_t *ptr_ht, void *key)
{
    khiter_t k;

    k = kh_get(ptrs,ptr_ht->ht, key);
    if (k == kh_end(ptr_ht->ht)){
        return (NULL);
    }
    return (kh_value(ptr_ht->ht,k));
}


void
htable_ptrs_destroy(htable_ptrs_t *ptr_ht)
{

    if (!ptr_ht) {
        return;
    }
    kh_destroy(ptrs, ptr_ht->ht);
    free(ptr_ht);
}

int
htable_ptrs_timers_add(htable_ptrs_t *ptr_ht, void *key, oor_timer_t *timer)
{
    glist_t *timer_lst;

    timer_lst = htable_ptrs_lookup(ptr_ht, key);
    if (!timer_lst){
        timer_lst = glist_new();
        if (!timer_lst){
            return (BAD);
        }
        htable_ptrs_insert(ptr_ht, key, timer_lst);
    }
    return (glist_add(timer, timer_lst));
}

/* Return the list of timers associated with the object */
glist_t *
htable_ptrs_timers_get_timers(htable_ptrs_t *ptr_ht, void *key)
{
    return(htable_ptrs_lookup(ptr_ht, key));
}

/* Return the list the timers of the requested type associated with the object */
glist_t *
htable_ptrs_timers_get_timers_of_type_from_obj(htable_ptrs_t *ptr_ht, void *key,
        timer_type type)
{
    oor_timer_t *timer;
    glist_t *set_timers_lst;
    glist_t *timer_lst;
    glist_entry_t *timer_it, *timer_it_aux;

    set_timers_lst = glist_new();

    timer_lst = htable_ptrs_lookup(ptr_ht, key);
    if (!timer_lst){
        return (set_timers_lst);
    }

    glist_for_each_entry_safe(timer_it,timer_it_aux,timer_lst){
        timer = (oor_timer_t*)glist_entry_data(timer_it);
        if (type == oor_timer_type(timer)){
            glist_add(timer, set_timers_lst);
        }
    }
    return set_timers_lst;
}



/* Remove the entry from hash table and returns the list of timers associated
 * with the object */
glist_t *
htable_ptrs_timers_rm(htable_ptrs_t *ptr_ht, void *key)
{
    return ((glist_t *)htable_ptrs_remove(ptr_ht, key));
}

/* Remove from the list the timers of the requested type associated with the object
 * The removed timers are returned in a list */
glist_t *
htable_ptrs_timers_rm_timers_of_type(htable_ptrs_t *ptr_ht, void *key,
        timer_type type)
{
    glist_t *rm_timers_lst = glist_new();
    glist_t *timer_lst;
    glist_entry_t *timer_it, *timer_it_aux;
    oor_timer_t *timer;

    timer_lst = htable_ptrs_lookup(ptr_ht, key);
    if (!timer_lst){
        return (rm_timers_lst);
    }

    glist_for_each_entry_safe(timer_it,timer_it_aux,timer_lst){
        timer = (oor_timer_t*)glist_entry_data(timer_it);
        if (type == oor_timer_type(timer)){
            glist_add(timer, rm_timers_lst);
            glist_remove(timer_it, timer_lst);
        }
    }
    return rm_timers_lst;
}

/* Remove the timer from the list. It doesn't stop the timer */
int
htable_ptrs_timers_rm_timer(htable_ptrs_t *ptr_ht, void *key, oor_timer_t *timer)
{
    glist_t *timer_lst;

    timer_lst = htable_ptrs_lookup(ptr_ht, key);
    if (!timer_lst){
        return(ERR_NO_EXIST);
    }
    glist_remove_obj(timer, timer_lst);
    return (GOOD);
}
