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
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
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
#include <sys/stat.h>
#include <sys/capability.h>
#include <sys/prctl.h>
//#include <sys/timerfd.h>
#include <netinet/in.h>
#include <net/if.h>
#include "lispd.h"
#include "lispd_config.h"
#include "lispd_iface_list.h"
#include "lispd_iface_mgmt.h"
#include "lispd_input.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_log.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_register.h"
#include "lispd_map_request.h"
#include "lispd_output.h"
#include "lispd_rloc_probing.h"
#include "lispd_routing_tables_lib.h"
#include "lispd_smr.h"
#include "lispd_sockets.h"
#include "lispd_timers.h"
#include "lispd_tun.h"


void event_loop();
void signal_handler(int);




/*
 *      config paramaters
 */

lispd_addr_list_t          *map_resolvers   = NULL;
lispd_addr_list_t          *proxy_itrs      = NULL;
lispd_map_cache_entry      *proxy_etrs      = NULL;
lispd_map_server_list_t    *map_servers     = NULL;
char    *config_file                        = NULL;
int      debug_level                        = 0;
int      default_rloc_afi                   = -1;
int      daemonize                          = FALSE;
int      map_request_retries                = DEFAULT_MAP_REQUEST_RETRIES;
/* RLOC probing parameters */
int      rloc_probe_interval                = RLOC_PROBING_INTERVAL;
int      rloc_probe_retries                 = DEFAULT_RLOC_PROBING_RETRIES;
int      rloc_probe_retries_interval        = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;

int      control_port                       = LISP_CONTROL_PORT;
uint32_t iseed                              = 0;  /* initial random number generator */
int      total_mappings                     = 0;
/*
 *      various globals
 */

char   msg[128];                                /* syslog msg buffer */
pid_t  pid                                  = 0;    /* child pid */
pid_t  sid                                  = 0;
/*
 *      sockets (fds)
 */
int     ipv4_data_input_fd                  = 0;
int     ipv6_data_input_fd                  = 0;
int     ipv4_control_input_fd               = 0;
int     ipv6_control_input_fd               = 0;
int     netlink_fd                          = 0;
fd_set  readfds;
struct  sockaddr_nl dst_addr;
struct  sockaddr_nl src_addr;
nlsock_handle nlh;

/* NAT */

int             nat_aware   = FALSE;
int             nat_status  = UNKNOWN;
lispd_site_ID   site_ID     = {.byte = {0}}; //XXX Check if this works
lispd_xTR_ID    xTR_ID      = {.byte = {0}};
// Global variables used to store nonces of encapsulated map register and info request.
// To be removed when NAT with multihoming supported.
nonces_list     *nat_emr_nonce  = NULL;
nonces_list     *nat_ir_nonce   = NULL;


/*
 *      timers (fds)
 */

int     timers_fd                       = 0;


int check_capabilities()
{

    /*
     *  Check for superuser privileges
     */
 	struct __user_cap_header_struct cap_header;
	struct __user_cap_data_struct cap_data;

	cap_header.pid = getpid();
	cap_header.version = _LINUX_CAPABILITY_VERSION;
	if (capget(&cap_header, &cap_data) < 0)
	{
        lispd_log_msg(LISP_LOG_ERR, "Could not retrieve capabilities");
        return BAD;
	}

    lispd_log_msg(LISP_LOG_INFO, "Rights: Effective [%u] Permitted  [%u]", cap_data.effective, cap_data.permitted);

    /* check for capabilities */
    if(  (cap_data.effective & CAP_TO_MASK(CAP_NET_ADMIN)) && (cap_data.effective & CAP_TO_MASK(CAP_NET_RAW))  )  {
    }
    else {
        lispd_log_msg(LISP_LOG_CRIT, "Insufficiant rights, you need CAP_NET_ADMIN and CAP_NET_RAW. See readme");
        return BAD;
    }

    /* Clear all but the capability to bind to low ports */
    cap_data.effective = CAP_TO_MASK(CAP_NET_ADMIN) | CAP_TO_MASK(CAP_NET_RAW);
    cap_data.permitted = cap_data.effective ;
    cap_data.inheritable = 0;
    if (capset(&cap_header, &cap_data) < 0) {
        lispd_log_msg(LISP_LOG_WARNING, "Could not drop privileges");
        return BAD;
    }

    /* Tell kernel not clear permitted capabilities when dropping root */
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
        lispd_log_msg(LISP_LOG_WARNING, "Sprctl(PR_SET_KEEPCAPS) failed");
        return GOOD;
    }

    /* Now we can drop privilege, drop effective rights even with KEEPCAPS */
    if (setuid(getuid()) < 0) {
        lispd_log_msg(LISP_LOG_WARNING, "Could not drop privileges");
    }

    /* that's why we need to set effective rights equal to permitted rights */
	if (capset(&cap_header, &cap_data) < 0)
	{
        lispd_log_msg(LISP_LOG_CRIT, "Could not set effective rights to permitted ones");
        return (BAD);
	}

    lispd_log_msg(LISP_LOG_INFO, "Rights: Effective [%u] Permitted  [%u]", cap_data.effective, cap_data.permitted);

    return GOOD;
}


int main(int argc, char **argv)
{
    lisp_addr_t *tun_v4_addr;
    lisp_addr_t *tun_v6_addr;
    char *tun_dev_name = TUN_IFACE_NAME;

#ifdef ROUTER
#ifdef OPENWRT
    lispd_log_msg(LISP_LOG_INFO,"LISPmob compiled for openWRT xTR\n");
#else
    lispd_log_msg(LISP_LOG_INFO,"LISPmob compiled for linux xTR\n");
#endif
#else
    lispd_log_msg(LISP_LOG_INFO,"LISPmob compiled for mobile node\n");
#endif

    /*
     *  Check for required capabilities and drop unnecssary privileges
     */
    if(check_capabilities() != GOOD) {
        exit_cleanup();
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
     *  set up databases
     */

    db_init();
    map_cache_init();


    /*
     *  Parse command line options
     */

    handle_lispd_command_line(argc, argv);



    /*
     *  see if we need to daemonize, and if so, do it
     */

    if (daemonize) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "Starting the daemonizing process");
        if ((pid = fork()) < 0) {
            exit_cleanup();
        }
        umask(0);
        if (pid > 0)
            exit_cleanup();
        if ((sid = setsid()) < 0)
            exit_cleanup();
        if ((chdir("/")) < 0)
            exit_cleanup();
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }


    /*
     *  create timers
     */

    if (build_timers_event_socket(&timers_fd) == 0)
    {
        lispd_log_msg(LISP_LOG_CRIT, " Error programing the timer signal. Exiting...");
        exit_cleanup();
    }
    init_timers();




    /*
     *  Parse config file. Format of the file depends on the node: Linux Box or OpenWRT router
     */

#ifdef OPENWRT
    if (config_file == NULL){
        config_file = "/etc/config/lispd";
    }
    handle_uci_lispd_config_file(config_file);
#else
    if (config_file == NULL){
        config_file = "/etc/lispd.conf";
    }
    handle_lispd_config_file(config_file);
#endif

    if (map_servers == NULL){
        lispd_log_msg(LISP_LOG_CRIT, "No Map Server configured. Exiting...");
        exit_cleanup();
    }

    if (map_resolvers == NULL){
        lispd_log_msg(LISP_LOG_CRIT, "No Map Resolver configured. Exiting...");
        exit_cleanup();
    }

    if (proxy_etrs == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "No Proxy-ETR defined. Packets to non-LISP destinations will be "
                "forwarded natively (no LISP encapsulation). This may prevent mobility in some scenarios.");
        sleep(3);
    }else{
        calculate_balancing_vectors (
                proxy_etrs->mapping,
                &(((rmt_mapping_extended_info *)(proxy_etrs->mapping->extended_info))->rmt_balancing_locators_vecs));
    }


    /*
     * Select the default rlocs for output data packets and output control packets
     */

    set_default_output_ifaces();

    set_default_ctrl_ifaces();


    /*
     * Create tun interface
     */

    create_tun(tun_dev_name,
            TUN_RECEIVE_SIZE,
            TUN_MTU,
            &tun_receive_fd,
            &tun_ifindex,
            &tun_receive_buf);


    /*
     * Assign address to the tun interface
     * Assign route to 0.0.0.0/1 and 128.0.0.0/1 via tun interface
     *                 ::/1      and 8000::/1
     */

#ifdef ROUTER
    tun_v4_addr = get_main_eid(AF_INET);
    if (tun_v4_addr != NULL){
        tun_v4_addr = (lisp_addr_t *)malloc(sizeof(lisp_addr_t));
        get_lisp_addr_from_char(TUN_LOCAL_V4_ADDR,tun_v4_addr);
    }
    tun_v6_addr = get_main_eid(AF_INET6);
    if (tun_v6_addr != NULL){
        tun_v6_addr = (lisp_addr_t *)malloc(sizeof(lisp_addr_t));
        get_lisp_addr_from_char(TUN_LOCAL_V6_ADDR,tun_v6_addr);
    }
#else
    tun_v4_addr = get_main_eid(AF_INET);
    tun_v6_addr = get_main_eid(AF_INET6);
#endif

    tun_bring_up_iface(tun_dev_name);
    if (tun_v4_addr != NULL){
        tun_add_eid_to_iface(*tun_v4_addr,tun_dev_name);
        set_tun_default_route_v4();
    }
    if (tun_v6_addr != NULL){
        tun_add_eid_to_iface(*tun_v6_addr,tun_dev_name);
        set_tun_default_route_v6();
    }
#ifdef ROUTER
    if (tun_v4_addr != NULL){
        free(tun_v4_addr);
    }
    if (tun_v6_addr != NULL){
        free(tun_v6_addr);
    }
#endif
    /*
     * Generate receive sockets for control (4342) and data port (4341)
     */

    if (default_rloc_afi == -1 || default_rloc_afi == AF_INET){
        ipv4_control_input_fd = open_control_input_socket(AF_INET);
        ipv4_data_input_fd = open_data_input_socket(AF_INET);
    }

    if (default_rloc_afi == -1 || default_rloc_afi == AF_INET6){
        ipv6_control_input_fd = open_control_input_socket(AF_INET6);
        ipv6_data_input_fd = open_data_input_socket(AF_INET6);
    }

    /*
     * Create net_link socket to receive notifications of changes of RLOC status.
     */
    netlink_fd = opent_netlink_socket();

    lispd_log_msg(LISP_LOG_INFO,"LISPmob (0.3.3): 'lispd' started...");

    /*
     * Request to dump the routing tables to obtain the gatways when processing the netlink messages
     */

    request_route_table(RT_TABLE_MAIN, AF_INET);
    process_netlink_msg(netlink_fd);
    request_route_table(RT_TABLE_MAIN, AF_INET6);
    process_netlink_msg(netlink_fd);

    /*
     *  Register to the Map-Server(s)
     */

    map_register (NULL,NULL);

    /*
     * SMR proxy-ITRs list to be updated with new mappings
     */

    init_smr(NULL,NULL);

    /*
     * RLOC Probing proxy ETRs
     */
    programming_petr_rloc_probing();


    event_loop();

    lispd_log_msg(LISP_LOG_INFO, "Exiting...");         /* event_loop returned bad */
    closelog();
    return(0);
}

/*
 *      main event loop
 *
 *      should never return (in theory)
 */

void event_loop()
{
    int    max_fd;
    fd_set readfds;
    int    retval;

    /*
     *  calculate the max_fd for select.
     */

    max_fd = ipv4_data_input_fd;
    max_fd = (max_fd > ipv6_data_input_fd)      ? max_fd : ipv6_data_input_fd;
    max_fd = (max_fd > ipv4_control_input_fd)   ? max_fd : ipv4_control_input_fd;
    max_fd = (max_fd > ipv6_control_input_fd)   ? max_fd : ipv6_control_input_fd;
    max_fd = (max_fd > tun_receive_fd)          ? max_fd : tun_receive_fd;
    max_fd = (max_fd > timers_fd)               ? max_fd : timers_fd;
    max_fd = (max_fd > netlink_fd)              ? max_fd : netlink_fd;

    for (;;) {
        FD_ZERO(&readfds);
        FD_SET(tun_receive_fd, &readfds);
        FD_SET(ipv4_data_input_fd, &readfds);
        FD_SET(ipv6_data_input_fd, &readfds);
        FD_SET(ipv4_control_input_fd, &readfds);
        FD_SET(ipv6_control_input_fd, &readfds);
        FD_SET(timers_fd, &readfds);
        FD_SET(netlink_fd, &readfds);

        retval = have_input(max_fd, &readfds);
        if (retval == -1) {
            break;           /* doom */
        }
        if (retval == BAD) {
            continue;        /* interrupted */
        }

        if (FD_ISSET(ipv4_data_input_fd, &readfds)) {
            //lispd_log_msg(LISP_LOG_DEBUG_3,"Received input IPv4 packet");
            process_input_packet(ipv4_data_input_fd, AF_INET, tun_receive_fd);
        }
        if (FD_ISSET(ipv6_data_input_fd, &readfds)) {
            //lispd_log_msg(LISP_LOG_DEBUG_3,"Received input IPv6 packet");
            process_input_packet(ipv6_data_input_fd, AF_INET6, tun_receive_fd);
        }
        if (FD_ISSET(ipv4_control_input_fd, &readfds)) {
            lispd_log_msg(LISP_LOG_DEBUG_3,"Received IPv4 packet in the control input buffer (4342)");
            process_lisp_ctr_msg(ipv4_control_input_fd, AF_INET);
        }
        if (FD_ISSET(ipv6_control_input_fd, &readfds)) {
            lispd_log_msg(LISP_LOG_DEBUG_3,"Received IPv6 packet in the control input buffer (4342)");
            process_lisp_ctr_msg(ipv6_control_input_fd, AF_INET6);
        }
        if (FD_ISSET(tun_receive_fd, &readfds)) {
            lispd_log_msg(LISP_LOG_DEBUG_3,"Received packet in the tun buffer");
            process_output_packet(tun_receive_fd, tun_receive_buf, TUN_RECEIVE_SIZE);
        }
        if (FD_ISSET(timers_fd,&readfds)){
            //lispd_log_msg(LISP_LOG_DEBUG_3,"Received something in the timer fd");
            process_timer_signal(timers_fd);
        }
        if (FD_ISSET(netlink_fd,&readfds)){
            lispd_log_msg(LISP_LOG_DEBUG_3,"Received notification from net link");
            process_netlink_msg(netlink_fd);
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
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received SIGHUP signal.");
        break;
    case SIGTERM:
        /* SIGTERM is the default signal sent by 'kill'. Exit cleanly */
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received SIGTERM signal. Cleaning up...");
        exit_cleanup();
        break;
    case SIGINT:
        /* SIGINT is sent by pressing Ctrl-C. Exit cleanly */
        lispd_log_msg(LISP_LOG_DEBUG_1, "Terminal interrupt. Cleaning up...");
        exit_cleanup();
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_1,"Unhandled signal (%d)", sig);
        exit(EXIT_FAILURE);
    }
}

/*
 *  exit_cleanup()
 *
 *  Close opened sockets and file descriptors
 */

void exit_cleanup(void) {
    /* Remove source routing tables */
    remove_created_rules();
    /* Close timer file descriptors */
    close(timers_fd);
    /* Close receive sockets */
    close(tun_receive_fd);
    close(ipv4_data_input_fd);
    close(ipv4_control_input_fd);
    close(ipv6_data_input_fd);
    close(ipv6_control_input_fd);
    /* Close send sockets */
    close_output_sockets();
    /* Close netlink socket */
    close(netlink_fd);
    lispd_log_msg(LISP_LOG_INFO,"Exiting ...");

    exit(EXIT_SUCCESS);
}




/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
