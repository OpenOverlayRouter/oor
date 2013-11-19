int timerfd_create(int clockid, int flags);
int timerfd_settime(int fd, int flags,
                           const struct itimerspec *new_value,
                           struct itimerspec *old_value);
int timerfd_gettime(int fd, struct itimerspec *curr_value);
