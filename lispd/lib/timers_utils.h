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

#include "nonces_table.h"
#include "pointers_table.h"

lmtimer_t * lmtimer_with_nonce_new(timer_type type, void *owner,
        lmtimer_callback_t cb_fn, void *timer_arg,
        lmtimer_del_cb_arg_fn free_arg_fn);


int stop_timer_from_obj(void *obj,lmtimer_t *timer,htable_ptrs_t *ptrs_ht,
        htable_nonces_t *nonce_ht);
int stop_timers_from_obj(void *obj,htable_ptrs_t *ptrs_ht, htable_nonces_t *nonce_ht);
int stop_timers_of_type_from_obj(void *obj, timer_type type,
        htable_ptrs_t *ptrs_ht, htable_nonces_t *nonce_ht);

#endif /* TIMERS_UTILS_H_ */
