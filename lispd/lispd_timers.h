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

#define EXPIRE_MAP_CACHE_TIMER  "EXPIRE_MAP_CACHE_TIMER"
#define MAP_REGISTER_TIMER      "MAP_REGISTER_TIMER"
#define MAP_REQUEST_RETRY_TIMER "MAP_REQUEST_RETRY_TIMER"
#define RLOC_PROBING_TIMER      "RLOC_PROBING_TIMER"
#define SMR_TIMER               "SMR_TIMER"
#define SMR_INV_RETRY_TIMER     "SMR_INV_RETRY_TIMER"

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



int init_timers();

timer *create_timer(char *);

void start_timer(
    timer               *tptr,
    int                 seconds_to_expiry,
    timer_callback      cb,
    void                *cb_arg);

void stop_timer(timer *);

int process_timer_signal();

/*
 * build_timer_event_socket
 *
 * Set up the event handler socket. This is
 * used to serialize events like timer expirations that
 * we would rather deal with synchronously. This avoids
 * having to deal with all sorts of locking and multithreading
 * nonsense.
 */
int build_timers_event_socket(int *timers_fd);

#endif /*LISPD_TIMERS_H_*/
