/*
 * lispd_timers.c
 *
 * Timer maintenance routines. A simple, fixed granularity (1 second)
 * timer wheel implementation for scalable timers.
 *
 * Author: Chris White
 * Copyright 2012 Cisco Systems, Inc.
 */
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>

#include "lispd.h"
#include "lispd_iface_mgmt.h"
#include "lispd_log.h"
#include "lispd_map_request.h"
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

void     handle_timers(void);

static int signal_pipe[2]; // We don't have signalfd in bionic, fake it.


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
        lispd_log_msg(LISP_LOG_DEBUG_1, "timer_create(): %s", strerror(errno));
        return (timer_t)0;
    }

    timerspec.it_value.tv_nsec = 0;
    timerspec.it_value.tv_sec = TimerTickInterval;
    timerspec.it_interval.tv_nsec = 0;
    timerspec.it_interval.tv_sec = TimerTickInterval;


    if (timer_settime(tid, 0, &timerspec, NULL) == -1) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "create_wheel_timer: timer start failed for %d %s",
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

    lispd_log_msg(LISP_LOG_DEBUG_1, "Initializing lispd timers...");

    if (create_wheel_timer() == 0) {
        lispd_log_msg(LISP_LOG_INFO, "Failed to set up lispd timers.");
        return(BAD);
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
    return(GOOD);
}

/*
 * create_timer()
 *
 * Convenience function to allocate and zero a new timer.
 */
timer *create_timer(char *name)
{
    timer *new_timer = malloc(sizeof(timer));
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
void start_timer(
    timer               *tptr,
    int                 seconds_to_expiry,
    timer_callback      cb,
    void                *cb_arg)
{
    timer_links *next, *prev;

    /*
     * See if this timer is also running.
     */
    next = tptr->links.next;

    if (next != NULL) {
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
 * Mark one of the global timers as stopped and remove it.
 */
void stop_timer(timer *tptr)
{
    timer_links *next, *prev;

    if (tptr == NULL) {
        return;
    }

    if (strcmp(tptr->name,MAP_REQUEST_RETRY_TIMER)==0){
        free ((timer_map_request_argument *)tptr->cb_argument);
    }

    next = tptr->links.next;
    prev = tptr->links.prev;
    if (next != NULL){
        next->prev = prev;
    }
    if (prev != NULL){
        prev->next = next;
    }
    tptr->links.next = NULL;
    tptr->links.prev = NULL;

    /*
     * Update stats
     */
    if (next != NULL || prev != NULL){
        timer_wheel.running_timers--;
    }
    free (tptr);
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
        tptr = (timer *)next;
    }
}



int process_timer_signal(int timers_fd)
{
    int sig;
    int bytes;

    bytes = read(timers_fd, &sig, sizeof(sig));

    if (bytes != sizeof(sig)) {
        lispd_log_msg(LISP_LOG_WARNING, "process_event_signal(): nothing to read");
        return(-1);
    }

    if (sig == SIGRTMIN) {
        handle_timers();
    }
    return(0);
}



/*
 * event_sig_handler
 *
 * Forward signal to the fd for handling in the event loop
 */
static void event_sig_handler(int sig)
{
    if (write(signal_pipe[1], &sig, sizeof(sig)) != sizeof(sig)) {
        lispd_log_msg(LISP_LOG_WARNING, "write signal %d: %s", sig, strerror(errno));
    }
}


/*
 * build_timer_event_socket
 *
 * Set up the event handler socket. This is
 * used to serialize events like timer expirations that
 * we would rather deal with synchronously. This avoids
 * having to deal with all sorts of locking and multithreading
 * nonsense.
 */
int build_timers_event_socket(int *timers_fd)
{
    int flags;
    struct sigaction sa;

    if (pipe(signal_pipe) == -1) {
        lispd_log_msg(LISP_LOG_ERR, "build_timers_event_socket: signal pipe setup failed %s", strerror(errno));
        return (BAD);
    }
    *timers_fd = signal_pipe[0];

    if ((flags = fcntl(*timers_fd, F_GETFL, 0)) == -1) {
        lispd_log_msg(LISP_LOG_ERR, "build_timers_event_socket: fcntl() F_GETFL failed %s", strerror(errno));
        return (BAD);
    }
    if (fcntl(*timers_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        lispd_log_msg(LISP_LOG_ERR, "build_timers_event_socket: fcntl() set O_NONBLOCK failed %s", strerror(errno));
        return (BAD);
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = event_sig_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGRTMIN, &sa, NULL) == -1) {
        lispd_log_msg(LISP_LOG_ERR, "build_timers_event_socket: sigaction() failed %s", strerror(errno));
    }
    return(GOOD);
}
