/*
 * lispd_timers.h
 *
 * Timer maintenance routines. Simple to start with (single
 * master timer triggers check of timestamps for map-registers/
 * map-reply retries).
 *
 * Author: Chris White
 * Copyright 2010 Cisco Systems, Inc.
 */
#ifndef LISPD_TIMERS_H_
#define LISPD_TIMERS_H_

#include <signal.h>
#include <time.h>

#define RLOC_PROBE_CHECK_INTERVAL 1 // 1 second

#define EXPIRE_MAP_CACHE "Expire map cache"

typedef struct _timer_links {
    struct _timer_links *prev;
    struct _timer_links *next;
} timer_links;

struct _timer;
typedef int (*timer_callback)(struct _timer *t, void *arg);

typedef struct _timer {
    timer_links     links;
    int             duration;
    int             rotation_count;
    timer_callback  cb;
    void           *cb_argument;
    char            name[64];
} timer;

int      init_timers();
timer   *create_timer(char *);
void     start_timer(timer *, int, timer_callback,
                   void *);
void     stop_timer(timer *);
void     handle_timers(void);

#endif /*LISPD_TIMERS_H_*/
