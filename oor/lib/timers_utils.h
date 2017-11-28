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


#ifndef TIMERS_UTILS_H_
#define TIMERS_UTILS_H_

#include "htable_ptrs.h"
#include "nonces_table.h"

oor_timer_t *
oor_timer_without_nonce_new(timer_type type, void *owner, oor_timer_callback_t cb_fn,
        void *timer_arg,oor_timer_del_cb_arg_fn free_arg_fn);

oor_timer_t * oor_timer_with_nonce_new(timer_type type, void *owner,
        oor_timer_callback_t cb_fn, void *timer_arg,
        oor_timer_del_cb_arg_fn free_arg_fn);


int stop_timer_from_obj(void *obj,oor_timer_t *timer,htable_ptrs_t *ptrs_ht,
        htable_nonces_t *nonce_ht);
int stop_timers_from_obj(void *obj,htable_ptrs_t *ptrs_ht, htable_nonces_t *nonce_ht);
int stop_timers_of_type_from_obj(void *obj, timer_type type,
        htable_ptrs_t *ptrs_ht, htable_nonces_t *nonce_ht);


/* Add the timer to the list of timers associated to the object. Creats the entry into the
 * hash table if it doesn't exist. User is responsible to check if exists duplicate timers before
 * inserting the new one */
int htable_ptrs_timers_add(htable_ptrs_t *ptr_ht, void *key, oor_timer_t *timer);
/* Return the list of timers associated with the object */
glist_t *htable_ptrs_timers_get_timers(htable_ptrs_t *ptr_ht, void *key);
/* Return the list the timers of the requested type associated with the object */
glist_t *htable_ptrs_timers_get_timers_of_type_from_obj(htable_ptrs_t *ptr_ht, void *key,
        timer_type type);
/* Remove the entry from hash table and returns the list of timers associated with the object */
glist_t *htable_ptrs_timers_rm(htable_ptrs_t *ptr_ht, void *key);
/* Remove from the list the timers of the requested type associated with the object
 * The removed timers are returned in a list */
glist_t *htable_ptrs_timers_rm_timers_of_type(htable_ptrs_t *ptr_ht, void *key, timer_type type);
/* Remove the timer from the list. It doesn't stop the timer */
int htable_ptrs_timers_rm_timer(htable_ptrs_t *ptr_ht, void *key, oor_timer_t *timer);

#endif /* TIMERS_UTILS_H_ */
