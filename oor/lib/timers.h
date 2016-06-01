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

#ifndef TIMERS_H_
#define TIMERS_H_

#include "sockets.h"

typedef enum {
    EXPIRE_MAP_CACHE_TIMER,
    MAP_REGISTER_TIMER,
    ENCAP_MAP_REGISTER_TIMER,
    MAP_REQUEST_RETRY_TIMER,
    RLOC_PROBING_TIMER,
    SMR_TIMER,
    SMR_INV_RETRY_TIMER,
    INFO_REQUEST_TIMER,
    RE_UPSTREAM_JOIN_TIMER,
    RE_ITR_RESOLUTION_TIMER,
    REG_SITE_EXPRY_TIMER
} timer_type;

#define TIMER_NAME_LEN          64

typedef struct oor_timer_links {
    struct oor_timer_links *prev;
    struct oor_timer_links *next;
} oor_timer_links_t;

struct oor_timer;
typedef int (*oor_timer_callback_t)(struct oor_timer *t);
typedef void (*oor_timer_del_cb_arg_fn)(void *arg);

typedef struct oor_timer {
    oor_timer_links_t links;
    int duration;
    int rotation_count;
    oor_timer_callback_t cb;
    oor_timer_del_cb_arg_fn del_arg_fn;
    void *cb_argument;
    void *owner;
    void *nonces_lst;
    timer_type type;
} oor_timer_t;



int oor_timers_init();
void oor_timers_destroy();

oor_timer_t *oor_timer_create(timer_type type);
void oor_timer_init(oor_timer_t *new_timer, void *owner, oor_timer_callback_t cb_fn,
        void *arg, oor_timer_del_cb_arg_fn del_arg_fn, void *nonces_lst);

void oor_timer_start(oor_timer_t *, int);

void oor_timer_stop(oor_timer_t *);

inline void *oor_timer_owner(oor_timer_t *);
inline void *oor_timer_cb_argument(oor_timer_t *);
inline timer_type oor_timer_type(oor_timer_t *);
inline void *oor_timer_nonces(oor_timer_t *);


#endif /*TIMERS_H_*/
