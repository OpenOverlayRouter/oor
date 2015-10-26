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

#define RLOC_PROBE_CHECK_INTERVAL 1 /* 1 second */

#define EXPIRE_MAP_CACHE_TIMER  "EXPIRE_MAP_CACHE_TIMER"
#define MAP_REGISTER_TIMER      "MAP_REGISTER_TIMER"
#define MAP_REQUEST_RETRY_TIMER "MAP_REQUEST_RETRY_TIMER"
#define RLOC_PROBING_TIMER      "RLOC_PROBING_TIMER"
#define SMR_TIMER               "SMR_TIMER"
#define SMR_INV_RETRY_TIMER     "SMR_INV_RETRY_TIMER"
#define INFO_REPLY_TTL_TIMER    "INFO_REPLY_TTL_TIMER"
#define RE_UPSTREAM_JOIN_TIMER  "RE_UPSTREAM_JOIN_TIMER"
#define RE_ITR_RESOLUTION_TIMER "RE_ITR_RESOLUTION_TIMER"
#define REG_SITE_EXPRY_TIMER    "REG_SITE_EXPIRY_TIMER"

#define TIMER_NAME_LEN          64

typedef struct lmtimer_links {
    struct lmtimer_links *prev;
    struct lmtimer_links *next;
} lmtimer_links_t;

struct lmtimer;
typedef int (*lmtimer_callback_t)(struct lmtimer *t, void *arg);

typedef struct lmtimer {
    lmtimer_links_t links;
    int duration;
    int rotation_count;
    lmtimer_callback_t cb;
    void *cb_argument;
    void *owner;
    char name[TIMER_NAME_LEN];
} lmtimer_t;



int lmtimers_init();
void lmtimers_destroy();

lmtimer_t *lmtimer_create(char *);

void lmtimer_start(lmtimer_t *, int, lmtimer_callback_t, void *, void *);

void lmtimer_stop(lmtimer_t *);


#endif /*TIMERS_H_*/
