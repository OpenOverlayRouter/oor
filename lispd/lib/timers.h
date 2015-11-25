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
    MAP_REQUEST_RETRY_TIMER,
    RLOC_PROBING_TIMER,
    SMR_TIMER,
    SMR_INV_RETRY_TIMER,
    INFO_REPLY_TTL_TIMER,
    RE_UPSTREAM_JOIN_TIMER,
    RE_ITR_RESOLUTION_TIMER,
    REG_SITE_EXPRY_TIMER
} timer_type;

#define TIMER_NAME_LEN          64

typedef struct lmtimer_links {
    struct lmtimer_links *prev;
    struct lmtimer_links *next;
} lmtimer_links_t;

struct lmtimer;
typedef int (*lmtimer_callback_t)(struct lmtimer *t);
typedef void (*lmtimer_del_cb_arg_fn)(void *arg);

typedef struct lmtimer {
    lmtimer_links_t links;
    int duration;
    int rotation_count;
    lmtimer_callback_t cb;
    lmtimer_del_cb_arg_fn del_arg_fn;
    void *cb_argument;
    void *owner;
    void *nonces_lst;
    timer_type type;
} lmtimer_t;



int lmtimers_init();
void lmtimers_destroy();

lmtimer_t *lmtimer_create(timer_type type);
void lmtimer_init(lmtimer_t *new_timer, void *owner, lmtimer_callback_t cb_fn,
        void *arg, lmtimer_del_cb_arg_fn del_arg_fn, void *nonces_lst);

void lmtimer_start(lmtimer_t *, int);

void lmtimer_stop(lmtimer_t *);

inline void *lmtimer_owner(lmtimer_t *);
inline void *lmtimer_cb_argument(lmtimer_t *);
inline timer_type lmtimer_type(lmtimer_t *);
inline void *lmtimer_nonces(lmtimer_t *);


#endif /*TIMERS_H_*/
