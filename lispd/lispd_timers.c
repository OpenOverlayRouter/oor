/*
 * lispd_timers.c
 *
 * Timer maintenance routines. A simple, fixed granularity (1 second)
 * timer wheel implementation for scalable timers.
 *
 * Author: Chris White
 * Copyright 2012 Cisco Systems, Inc.
 */
#include <signal.h>

#include "lispd.h"
#include "lispd_timers.h"

const int TimerTickInterval = 1;  // Seconds
const int WheelSize = 4096;       // Good for a little over an hour

struct {
    int      num_spokes;
    int      current_spoke;
    timer_links   *spokes;
    timer_t  tick_timer_id;
    int      running_timers;
    int      expirations;
} timer_wheel;

/*
 * create_timer_wheel()
 *
 * Creates the timer wheel structure and starts
 * the rotation timer.
 */
timer_t create_wheel_timer(void)
{
    timer_t tid;
    struct sigevent sev;
    struct itimerspec timerspec;

    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    sev.sigev_value.sival_ptr = &tid;
    if (timer_create(CLOCK_REALTIME, &sev, &tid) == -1)
    {
        syslog(LOG_INFO, "timer_create(): %s", strerror(errno));
        return (timer_t)0;
    }

    timerspec.it_value.tv_nsec = 0;
    timerspec.it_value.tv_sec = TimerTickInterval;
    timerspec.it_interval.tv_nsec = 0;
    timerspec.it_interval.tv_sec = TimerTickInterval;
    syslog(LOG_ERR, "Master wheel tick timer %d set for %d seconds",
           tid, timerspec.it_value.tv_sec);

    if (timer_settime(tid, 0, &timerspec, NULL) == -1) {
        syslog(LOG_INFO, "timer start failed for %d %s",
               tid, strerror(errno));
        return (timer_t)0;
    }
    return(tid);
}

/*
 * init_timers()
 *
 */
int init_timers()
{
    int i = 0;
    timer_links *spoke;

    syslog(LOG_INFO, "Initializing lispd timers...");

    if (create_wheel_timer() == 0) {
        syslog(LOG_INFO, "Failed to set up lispd timers.");
        return(0);
    }

    timer_wheel.num_spokes = WheelSize;
    timer_wheel.spokes = (timer_links *)malloc(sizeof(timer_links) * WheelSize);
    timer_wheel.current_spoke = 0;
    timer_wheel.running_timers = 0;
    timer_wheel.expirations = 0;

    spoke = &timer_wheel.spokes[0];
    for (i = 0; i < WheelSize; i++) {
        spoke->next = spoke;
        spoke->prev = spoke;
        spoke++;
    }
    return(1);
}

/*
 * create_timer()
 *
 * Convenience function to allocate and zero a new timer.
 */
timer *create_timer(char *name)
{
    timer *new_timer = (timer *)malloc(sizeof(timer));
    memset(new_timer, 0, sizeof(timer));
    strncpy(new_timer->name, name, 64);
    return(new_timer);
}

/*
 * insert_timer()
 *
 * Insert a timer in the wheel at the appropriate location.
 */
void insert_timer(timer *tptr)
{
    timer_links *prev, *spoke;
    uint32_t pos;
    uint32_t ticks;
    uint32_t td;

    // Number of ticks for this timer.
    ticks = tptr->duration;

     /*
      * tick posisiton, referenced from the
      * current index.
      */
     td = (ticks % timer_wheel.num_spokes);

     /*
      * Full rotations required before this timer expires
      */
     tptr->rotation_count = (ticks / timer_wheel.num_spokes);

     /*
      * Find the right spoke
      */
     pos = ((timer_wheel.current_spoke + td) % timer_wheel.num_spokes);
     spoke = &timer_wheel.spokes[pos];

     /*
      * Link the timer into the list at this position
      */

     prev = spoke->prev;
     tptr->links.next = spoke;      /* append to end of spoke  */
     tptr->links.prev = prev;
     prev->next   = (timer_links *)tptr;
     spoke->prev = (timer_links *)tptr;
     return;
}

/*
 * start_timer()
 *
 * Starts a new timer with given expiration time, callback function,
 * and arguments. Returns a pointer to the new timer, which must be kept
 * to stop the timer later if desired.
 */
void start_timer(timer *tptr, int seconds_to_expiry, timer_callback cb,
                 void *cb_arg)
{
    timer_links *next, *prev;

    /*
     * See if this timer is also running.
     */
    next = tptr->links.next;

    if (next) {
        prev = tptr->links.prev;
        next->prev = prev;
        prev->next = next;

        /*
         * Update stats
         */
        timer_wheel.running_timers--;
    }

    /*
     * Hook up the callback
     */
    tptr->cb      = cb;
    tptr->cb_argument     = cb_arg;
    tptr->duration = seconds_to_expiry;
    insert_timer(tptr);

    timer_wheel.running_timers++;
    return;
}

/*
 * stop_timer()
 *
 * Mark one of the global timers as stopped.
 */
void stop_timer(timer *tptr)
{
    timer_links *next, *prev;

    if (tptr == NULL) {
        return;
    }

    next = tptr->links.next;
    prev = tptr->links.prev;
    if (next)
        next->prev = prev;
    if (prev)
        prev->next = next;
    tptr->links.next = NULL;
    tptr->links.prev = NULL;

    /*
     * Update stats
     */
    if (next || prev)
        timer_wheel.running_timers--;
}

/*
 * handle_timers()
 *
 * Update the wheel index, and expire any timers there, calling
 * the appropriate function to deal with it.
 */
void handle_timers(void)
{
    struct timeval  nowtime;
    timer_links    *current_spoke, *next, *prev;
    timer          *tptr;
    timer_callback  callback;
    gettimeofday(&nowtime, NULL);
    timer_wheel.current_spoke = (timer_wheel.current_spoke + 1) % timer_wheel.num_spokes;
    current_spoke = &timer_wheel.spokes[timer_wheel.current_spoke];

    tptr = (timer *)current_spoke->next;
    while ( (timer_links *)tptr != current_spoke) {
        next = tptr->links.next;
        prev = tptr->links.prev;

        if (tptr->rotation_count > 0) {
            tptr->rotation_count--;
        } else {

            prev->next = next;
            next->prev = prev;
            tptr->links.next = NULL;
            tptr->links.prev = NULL;

            // Update stats
            timer_wheel.running_timers--;
            timer_wheel.expirations++;

            callback = tptr->cb;
            (*callback)(tptr, tptr->cb_argument);
        }
        tptr = next;
    }
}
