/*
 * timers.h
 *
 * Timer maintenance routines. Simple to start with (single
 * master timer triggers check of timestamps for map-registers/
 * map-reply retries).
 *
 * Author: Chris White
 * Copyright 2010 Cisco Systems, Inc.
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



int timers_init();
void timers_destroy();

lmtimer_t *create_timer(char *);

void start_timer(lmtimer_t *tptr, int, lmtimer_callback_t, void *);
void start_timer_new(lmtimer_t *, int, lmtimer_callback_t, void *, void *);

void stop_timer(lmtimer_t *);


#endif /*TIMERS_H_*/
