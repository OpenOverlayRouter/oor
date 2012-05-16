/*
 * lispd.c 
 *
 * This file is part of LISP Mobile Node Implementation.
 * lispd Implementation
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Albert Cabellos   <acabello@ac.upc.edu>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <net/if.h>
#include "lispd.h"

void event_loop(void);
void signal_handler(int);
void callback_elt(datacache_elt_t *);

/*
 *      global (more or less) vars
 *
 */

/*
 *      database and map cache
 */

lispd_database_t  *lispd_database       = NULL;
lispd_map_cache_t *lispd_map_cache      = NULL;

/*
 *      next gen database
 */

patricia_tree_t *AF4_database           = NULL;
patricia_tree_t *AF6_database           = NULL;

/*
 *      data cache
 */

datacache_t     *datacache;

/*
 *      config paramaters
 */

lispd_addr_list_t       *map_resolvers  = 0;
lispd_addr_list_t       *proxy_etrs     = 0;
lispd_addr_list_t       *proxy_itrs     = 0;
lispd_map_server_list_t *map_servers    = 0;
char    *config_file                    = "lispd.conf";
char    *map_resolver                   = NULL;
char    *map_server                     = NULL;
char    *proxy_etr                      = NULL;
char    *proxy_itr                      = NULL;
int      debug                          = 0;
int      daemonize                      = 0;
int      map_request_retries            = DEFAULT_MAP_REQUEST_RETRIES;
int      control_port                   = LISP_CONTROL_PORT;
uint32_t iseed  = 0;            /* initial random number generator */
/*
 *      various globals
 */

char   msg[128];                                /* syslog msg buffer */
pid_t  pid                              = 0;    /* child pid */
pid_t  sid                              = 0;
/*
 *      sockets (fds)
 */
int     v6_receive_fd                   = 0;
int     v4_receive_fd                   = 0;
int     netlink_fd                      = 0;
fd_set  readfds;
struct  sockaddr_nl dst_addr;
struct  sockaddr_nl src_addr;
nlsock_handle nlh;
/*
 *      timers (fds)
 */
int     map_register_timer_fd           = 0;
#ifdef LISPMOBMH
/* timer to rate control smr's in multihoming scenarios */
int 	smr_timer_fd					= 0;
#endif

/* 
 * Interface on which control messages
 * are sent
 */
iface_list_elt *ctrl_iface              = NULL;
lisp_addr_t source_rloc;

int main(int argc, char **argv) 
{

    /*
     *  Check for superuser privileges
     */

    if (geteuid()) {
        printf("Running %s requires superuser privileges! Exiting...\n", LISPD);
        exit(EXIT_FAILURE);
    }

    /*
     *  Initialize the random number generator
     */
     
    iseed = (unsigned int) time (NULL);
    srandom(iseed);

    /*
     * Set up signal handlers
     */

    signal(SIGHUP,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGQUIT, signal_handler);

    /*
     *  set up syslog now, checking to see if we're daemonizing...
     */

    set_up_syslog();

    /*
     *  Unload/load LISP kernel modules
     */

    system("/sbin/modprobe -r lisp lisp_int");

    if (system("/sbin/modprobe lisp")) {
        syslog(LOG_DAEMON, "Loading the 'lisp' kernel module failed! Exiting...");
        exit(EXIT_FAILURE);
    }
    syslog(LOG_DAEMON, "Loaded the 'lisp' kernel module");
    sleep(1);

    if (system("/sbin/modprobe lisp_int")) {
        syslog(LOG_DAEMON, "Loading the 'lisp_int' kernel module failed! Exiting...");
        exit(EXIT_FAILURE);
    }
    syslog(LOG_DAEMON, "Loaded the 'lisp_int' kernel module");
    sleep(1);

    /*
     *  Setup LISP and routing netlink sockets
     */

    if (!setup_netlink()) {
        syslog(LOG_DAEMON, "Can't set up netlink socket for lisp_mod communication");
        exit(EXIT_FAILURE);
    }

    if (!setup_netlink_iface()) {
        syslog(LOG_DAEMON, "Can't set up netlink socket for interface events");
        exit(EXIT_FAILURE);
    }

    syslog(LOG_DAEMON, "Netlink sockets created");

    /*
     *  set up databases
     */

    AF4_database  = New_Patricia(sizeof(struct in_addr)  * 8);
    AF6_database  = New_Patricia(sizeof(struct in6_addr) * 8);

    /*
     *  Parse command line options
     */

    handle_lispd_command_line(argc, argv);

    // Modified by acabello
    // init_datacache has the following parameters:
    // void (*cbk)(datacache_elt_t*); -> callback function (see example in lispd_lib.c)
    if (!init_datacache(callback_elt)) {
        syslog(LOG_DAEMON, "malloc (datacache): %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    /*
     *  Now do the config file
     */

    handle_lispd_config_file();

    /*
     * now build the v4/v6 receive sockets
     */

    if (build_receive_sockets() == 0) 
        exit(EXIT_FAILURE);

    /*
     *  create timers
     */

    if ((map_register_timer_fd = timerfd_create(CLOCK_REALTIME, 0)) == -1)
        syslog(LOG_INFO, "Could not create periodic map register timer");

#ifdef LISPMOBMH
    if ((smr_timer_fd = timerfd_create(CLOCK_REALTIME, 0)) == -1)
        syslog(LOG_INFO, "Could not create the SMR timer controller");
    /*Make sure the timer starts with coherent values*/
    stop_smr_timeout();
#endif


    /*
     *  see if we need to daemonize, and if so, do it
     */

    if (daemonize) {
        syslog(LOG_INFO, "Starting the daemonizing process");
        if ((pid = fork()) < 0) {
            exit(EXIT_FAILURE);
        } 
        umask(0);
        if (pid > 0)
            exit(EXIT_SUCCESS);
        if ((sid = setsid()) < 0)
            exit(EXIT_FAILURE);
        if ((chdir("/")) < 0)
            exit(EXIT_FAILURE);
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    /* PN XXX
     * comment out test definition to avoid any
     * interactions with the data plane
     */



#define test
#ifdef test

    int ret = register_lispd_process();
    if (ret < 0) {
        syslog(LOG_INFO, "Couldn't register lispd process, err: %d", ret);
        exit(EXIT_FAILURE);
    }
    syslog(LOG_DAEMON, "Registered lispd with kernel module");

    ret = install_database_mappings();
    if (ret < 0) {
        syslog(LOG_INFO, "Could not install database mappings, err: %d", ret);
        exit(EXIT_FAILURE);
    }
    syslog(LOG_DAEMON, "Installed database mappings");

    ret = install_map_cache_entries();
    if (ret < 0) {
        syslog(LOG_INFO, "Could not install static map-cache entries, err: %d", ret);
    }

#endif

    /*
     *  Dump routing table so we can get the gateway address for source routing
     */

    if (!dump_routing_table(AF_INET, RT_TABLE_MAIN))
        syslog(LOG_INFO, "Dumping main routing table failed");

    /*
     *  Register to the Map-Server(s)
     */

    if (!map_register(AF6_database))
        syslog(LOG_INFO, "Could not map register AF_INET6 with Map Servers");

    if (!map_register(AF4_database))
        syslog(LOG_INFO, "Could not map register AF_INET with Map Servers");

    event_loop();
    syslog(LOG_INFO, "Exiting...");         /* event_loop returned bad */
    closelog();
    return(0);
}

/*
 *      main event loop
 *
 *      should never return (in theory)
 */

void event_loop(void)
{
    int    max_fd;
    fd_set readfds;
    time_t curr,prev; //Modified by acabello

    /*
     *  calculate the max_fd for select. Is there a better way
     *  to do this?
     */

    max_fd = (v4_receive_fd > v6_receive_fd) ? v4_receive_fd : v6_receive_fd;
    max_fd = (max_fd > netlink_fd)           ? max_fd : netlink_fd;
    max_fd = (max_fd > nlh.fd)               ? max_fd : nlh.fd;
    max_fd = (max_fd > map_register_timer_fd)? max_fd : map_register_timer_fd;
#ifdef LISPMOBMH
    max_fd = (max_fd > smr_timer_fd)		 ? max_fd : smr_timer_fd;
#endif

    // Modified by acabello
    prev=time(NULL);

    for (EVER) {
        FD_ZERO(&readfds);
        FD_SET(v4_receive_fd,&readfds);
        FD_SET(v6_receive_fd,&readfds);
        FD_SET(netlink_fd,&readfds);
        FD_SET(nlh.fd, &readfds);
        FD_SET(map_register_timer_fd, &readfds);
#ifdef LISPMOBMH
        FD_SET(smr_timer_fd,&readfds);
#endif
        if (have_input(max_fd,&readfds) == -1)
            break;                              /* news is bad */
        if (FD_ISSET(v4_receive_fd,&readfds))
            process_lisp_msg(v4_receive_fd, AF_INET);
        if (FD_ISSET(v6_receive_fd,&readfds))
            process_lisp_msg(v6_receive_fd, AF_INET6);
        if (FD_ISSET(netlink_fd,&readfds))
            process_netlink_msg();
        if (FD_ISSET(nlh.fd,&readfds)) 
                process_netlink_iface();
        if (FD_ISSET(map_register_timer_fd,&readfds))
                periodic_map_register();
#ifdef LISPMOBMH
        if (FD_ISSET(smr_timer_fd,&readfds))
                smr_on_timeout();
#endif
        // Modified by acabello
        // Each second expire_datacache
        // This can be improved by using threading and timer_create()
        curr=time(NULL);
        if ((curr-prev)>LISPD_EXPIRE_TIMEOUT) {
                expire_datacache();
                prev=time(NULL);
            }
    }
}

/*
 *      signal_handler --
 *
 */

void signal_handler(int sig) {
    switch (sig) {
    case SIGHUP:
        /* TODO: SIGHUP should trigger reloading the configuration file */
        syslog(LOG_WARNING, "Received SIGHUP signal.");
        break;
    case SIGTERM:
        /* SIGTERM is the default signal sent by 'kill'. Exit cleanly */
        syslog(LOG_WARNING, "Received SIGTERM signal. Cleaning up...");
        exit_cleanup();
        break;
    case SIGINT:
        /* SIGINT is sent by pressing Ctrl-C. Exit cleanly */
        syslog(LOG_WARNING, "Terminal interrupt. Cleaning up...");
        exit_cleanup();
        break;
    default:
        syslog(LOG_WARNING,"Unhandled signal (%d)", sig);
        exit(EXIT_FAILURE);
    }
}


// Modified by acabello
// Callback function triggered each time an elt record expires
void callback_elt(elt)
        datacache_elt_t *elt;
{
    char eid_name[128];
    char mreq_type[32];
    uint16_t timeout;

    memset(mreq_type, 0, 32);

    /*
     * TODO: AC: Gather some statistics, pass to lisp virtual interface?
     */

    elt->retries++;
    if (elt->smr_invoked) {
        if (elt->retries>LISPD_MAX_SMR_RETRANSMIT) {
#ifdef  DEBUG
            syslog(LOG_INFO, "Expired MRq SMR, we didn't receive corresponding MRp\n");
#endif
            delete_datacache_entry(elt);
            return;
        }
        timeout = min_timeout(((elt->retries+1)*(elt->timeout)),LISPD_MAX_MRQ_TIMEOUT);
        strcat(mreq_type, "SMR-invoked MRq");
    }
    else if (elt->probe) {
        if (elt->retries>LISPD_MAX_PROBE_RETRANSMIT) {
#ifdef  DEBUG
            syslog(LOG_INFO, "Expired RLOC probe, setting locator status DOWN");
#endif
            update_map_cache_entry_rloc_status(&elt->eid_prefix,
                    elt->eid_prefix_length, &elt->dest, 0);
            delete_datacache_entry(elt);
            return;
        }
        /* TODO: Review */
        timeout = 1;
        strcat(mreq_type, "RLOC probe");
    }
    else {
        if (elt->retries>map_request_retries) {
#ifdef  DEBUG
            syslog(LOG_INFO, "Expired MRq, we didn't receive corresponding MRp\n");
#endif
            delete_datacache_entry(elt);
            return;
        }
        timeout = min_timeout(((elt->retries+1)*(elt->timeout)),LISPD_MAX_MRQ_TIMEOUT);
        strcat(mreq_type, "MRq");
    }

    inet_ntop(elt->eid_prefix.afi, &(elt->eid_prefix).address,eid_name,128);

#ifdef DEBUG
    syslog(LOG_INFO, "Retransmitting %s for %s/%d, retries: %d, timeout: %d",
            mreq_type, eid_name, elt->eid_prefix_length, elt->retries, timeout);
#endif

    build_and_send_map_request_msg(&elt->dest,
                                    &elt->eid_prefix,
                                    elt->eid_prefix_length,
                                    eid_name,
                                    elt->encap,
                                    elt->probe,
                                    0,
                                    elt->smr_invoked,
                                    elt->local,
                                    elt->retries,
                                    timeout,
                                    0);
    delete_datacache_entry(elt);
    return;
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
