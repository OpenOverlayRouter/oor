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
#ifdef ANDROID
 #include <fcntl.h>
#endif
#include <linux/capability.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include "lispd.h"
#include "lispd_config.h"
#include "lispd_iface_list.h"
#include "lispd_iface_mgmt.h"
#include "lispd_input.h"
#ifdef VPNAPI
 #include "lispd_jni.h"
#endif
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_log.h"
#include "lispd_map_cache_db.h"
#include "lispd_map_register.h"
#include "lispd_map_request.h"
#include "lispd_output.h"
#include "lispd_referral_cache_db.h"
#include "lispd_rloc_probing.h"
#include "lispd_routing_tables_lib.h"
#include "lispd_smr.h"
#include "lispd_sockets.h"
#include "lispd_timers.h"
#include "lispd_tun.h"
#include "api/ipc.h"



void event_loop();
void signal_handler(int);
int check_capabilities();
/* system calls - look to libc for function to system call mapping */
extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);
#ifdef ANDROID
#define CAP_TO_MASK(x)      (1 << ((x) & 31))
#endif


/*
 *      config paramaters
 */
uint8_t                      router_mode;

lispd_addr_list_t            *map_resolvers;
int                          ddt_client;
lispd_addr_list_t            *proxy_itrs;
lispd_map_cache_entry        *proxy_etrs;
lispd_map_server_list_t      *map_servers;
char                         *config_file;
int                          debug_level;
int                          ctrl_supported_afi;
int                          default_rloc_afi;
int                          daemonize;
int                          map_request_retries;
/* RLOC probing parameters */
int                          rloc_probe_interval;
int                          rloc_probe_retries;
int                          rloc_probe_retries_interval;

int                          control_port;

/*
 *      various globals
 */

char                           msg[128];   /* syslog msg buffer */

/*
 *      sockets (fds)
 */
int                         ipv4_data_input_fd;
int                         ipv6_data_input_fd;
int                         ipv4_control_input_fd;
int                         ipv6_control_input_fd;

/* FD used in VPN-API */
int							ipc_data_fd;
int							ipc_control_fd;

int                         netlink_fd;
fd_set                      readfds;
struct                      sockaddr_nl dst_addr;
struct                      sockaddr_nl src_addr;
nlsock_handle               nlh;

/* NAT */

int                         nat_aware;
lispd_site_ID               site_ID;
lispd_xTR_ID                xTR_ID;


/*
 * smr_timer is used to avoid sending SMRs during transition period.
 */
timer                         *smr_timer;

/*
 *      timers (fds)
 */
int                         timers_fd;

uint8_t						lispd_running;

#ifndef VPNAPI
int main(int argc, char **argv)
{
    uint32_t 			iseed         = 0;  /* initial random number generator */
    pid_t  				pid           = 0;    /* child pid */
    pid_t  				sid           = 0;


#ifdef OPENWRT
    lispd_log_msg(LISP_LOG_INFO,"LISPmob %s compiled for openWRT\n", LISPD_VERSION);
#else
#ifdef ANDROID
    open_log_file();
    lispd_log_msg(LISP_LOG_INFO,"LISPmob %s compiled for Android\n", LISPD_VERSION);
#else
    lispd_log_msg(LISP_LOG_INFO,"LISPmob %s compiled for Linux\n", LISPD_VERSION);
#endif
#endif

    init_globales();


#ifndef ANDROID
    /*
     *  Check for required capabilities and drop unnecssary privileges
     */

    if(check_capabilities() != GOOD) {
        exit_cleanup();
    }
#else

    /*
     * Check for superuser privileges
     */
    if (geteuid() != 0) {
        lispd_log_msg(LISP_LOG_INFO,"Running %s requires superuser privileges! Exiting...\n", LISPD);
        exit_cleanup();
    }
#endif

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
    init_referral_cache();

    /*
     *  Parse command line options
     */

    handle_lispd_command_line(argc, argv);


    /*
     *  see if we need to daemonize, and if so, do it
     */

    if (daemonize) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "Starting the daemonizing process1");
        if ((pid = fork()) < 0) {
            exit_cleanup();
        }
        umask(0);
        if (pid > 0){
        	exit(EXIT_SUCCESS);
        }
        if ((sid = setsid()) < 0){
            exit_cleanup();
        }
        if ((chdir("/")) < 0){
            exit_cleanup();
        }
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
     * Create net_link socket to receive notifications of changes of RLOC status.
     */
    netlink_fd = opent_netlink_socket();

    /*
     *  Parse config file. Format of the file depends on the node: Linux Box or OpenWRT router
     */

#ifdef OPENWRT
    if (config_file == NULL){
        config_file = strdup("/etc/config/lispd");
    }
    err = handle_uci_lispd_config_file(config_file);
#else
    if (config_file == NULL){
        config_file = strdup("/etc/lispd.conf");
    }
    err = handle_lispd_config_file(config_file);
#endif

    if (err != GOOD){
        lispd_log_msg(LISP_LOG_CRIT,"Wrong configuration.");
        exit_cleanup();
    }

    if (ddt_client == FALSE){
        drop_referral_cache();
    }

    if (nat_aware == TRUE){
    	nat_set_xTR_ID();
    }

    /*
     * Select the default rlocs for output data packets and output control packets
     */
    set_default_output_ifaces();

    set_default_ctrl_ifaces();

    /*
     * Create tun interface
     */

    if (create_tun(TUN_IFACE_NAME,
            TUN_RECEIVE_SIZE,
            TUN_MTU) != GOOD){
        exit_cleanup();
    }

    /*
     * Assign address to the tun interface and add routing to this interface
     */
    if (configure_routing_to_tun() != GOOD){
        exit_cleanup();
    }

    /*
     * Generate receive sockets for control (4342) and data port (4341)
     */

    if (default_rloc_afi == AF_UNSPEC || default_rloc_afi == AF_INET){
        ipv4_control_input_fd = open_control_input_socket(AF_INET);
        ipv4_data_input_fd = open_data_input_socket(AF_INET);
    }

    if (default_rloc_afi == AF_UNSPEC || default_rloc_afi == AF_INET6){
        ipv6_control_input_fd = open_control_input_socket(AF_INET6);
        ipv6_data_input_fd = open_data_input_socket(AF_INET6);
    }



    /*
     * Request to dump the routing tables to obtain the gatways when processing the netlink messages
     */

    request_route_table(RT_TABLE_MAIN, AF_INET);
    process_netlink_msg(netlink_fd);
    request_route_table(RT_TABLE_MAIN, AF_INET6);
    process_netlink_msg(netlink_fd);

    lispd_log_msg(LISP_LOG_INFO,"LISPmob (%s): 'lispd' started...", LISPD_VERSION);
    if (router_mode == TRUE){
        lispd_log_msg(LISP_LOG_INFO,"Running as an xTR router");
    }else{
        lispd_log_msg(LISP_LOG_INFO,"Running as a LISP mobile node");
    }



    /*
     *  Register to the Map-Server(s)
     */
    initial_map_register_process();

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

#else

JNIEXPORT jintArray JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_startLispd
  (JNIEnv *env, jclass cl, jint vpn_tun_fd, jstring storage_path)
{
	jintArray 			fd_list;
	jint				sockets_fds[4];
	uint32_t 			iseed         = 0;  /* initial random number generator */
	pid_t  				pid           = 0;    /* child pid */
	pid_t  				sid           = 0;
	char 				log_file[1024];
	const char 			*path 		  = NULL;

	memset (log_file,0,sizeof(char)*1024);
	init_globales();

	path = (*env)->GetStringUTFChars(env, storage_path, 0);
	config_file = calloc(1024, sizeof(char));
	strcat(config_file,path);
	strcat(config_file,CONF_FILE_NAME);
	strcat(log_file,path);
	strcat(log_file,LOG_FILE_NAME);
	(*env)->ReleaseStringUTFChars(env, storage_path, path);

	open_log_file(log_file);


	lispd_log_msg(LISP_LOG_INFO,"LISPmob %s compiled for Android", LISPD_VERSION);



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
	init_referral_cache();

	/*
	 *  create timers
	 */

	if (build_timers_event_socket(&timers_fd) == 0)
	{
		lispd_log_msg(LISP_LOG_CRIT, " Error programing the timer signal. Exiting...");
		exit_cleanup();
		return (NULL);
	}
	init_timers();

    /*
     * Create net_link socket to receive notifications of changes of RLOC status.
     */
	netlink_fd 		  = opent_netlink_socket();

    ipc_control_fd    = open_ipc_socket(IPC_CONTROL_RX_PORT);

	err = handle_lispd_config_file(config_file);


	if (err != GOOD){
		lispd_log_msg(LISP_LOG_CRIT,"Wrong configurationn.");
        ipc_send_log_msg("Configuration file error. Check logs for more details",1);
		exit_cleanup();
		return (NULL);
	}

    if (nat_aware == TRUE){
    	nat_set_xTR_ID();
    }

	/*
	 * Select the default rlocs for output data packets and output control packets
	 */
	set_default_output_ifaces();

	set_default_ctrl_ifaces();


    /*
     * Generate receive sockets for control (4342) and data port (4341)
     */

    if (default_rloc_afi == AF_UNSPEC || default_rloc_afi == AF_INET){
        ipv4_control_input_fd = open_control_input_socket(AF_INET);
        ipv4_data_input_fd = open_data_input_socket(AF_INET);
    }

    if (default_rloc_afi == AF_UNSPEC || default_rloc_afi == AF_INET6){
        ipv6_control_input_fd = open_control_input_socket(AF_INET6);
        ipv6_data_input_fd = open_data_input_socket(AF_INET6);
    }

    tun_fd = vpn_tun_fd;





	lispd_log_msg(LISP_LOG_INFO,"LISPmob (%s): 'lispd' started...", LISPD_VERSION);
	if (router_mode == TRUE){
		lispd_log_msg(LISP_LOG_INFO,"Running as an xTR router");
	}else{
		lispd_log_msg(LISP_LOG_INFO,"Running as a LISP mobile node");
	}


	fd_list = (*env)->NewIntArray(env, 4);
	if (fd_list == NULL) {
		return NULL; /* out of memory error thrown */
	}

	sockets_fds[0] = ipv4_control_input_fd;
	sockets_fds[1] = ipv4_data_input_fd;
	sockets_fds[2] = ipv6_control_input_fd;
	sockets_fds[3] = ipv6_data_input_fd;

	(*env)->SetIntArrayRegion(env, fd_list, 0, 4, sockets_fds);
	return fd_list;
}
#endif //VPNAPI


/*
 *      main event loop
 *
 *      should never return (in theory)
 */


#ifndef VPNAPI

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
    max_fd = (max_fd > tun_fd)          		? max_fd : tun_fd;
    max_fd = (max_fd > timers_fd)               ? max_fd : timers_fd;
    max_fd = (max_fd > netlink_fd)              ? max_fd : netlink_fd;

    lispd_running = TRUE;

    while (lispd_running) {
        FD_ZERO(&readfds);
        FD_SET(tun_fd, &readfds);
        FD_SET(ipv4_data_input_fd, &readfds);
        FD_SET(ipv6_data_input_fd, &readfds);
        FD_SET(ipv4_control_input_fd, &readfds);
        FD_SET(ipv6_control_input_fd, &readfds);
        FD_SET(timers_fd, &readfds);
        FD_SET(netlink_fd, &readfds);

        retval = have_input(max_fd, &readfds);

        if (retval != GOOD) {
            continue;        /* interrupted */
        }

        if (FD_ISSET(ipv4_data_input_fd, &readfds)) {
            //lispd_log_msg(LISP_LOG_DEBUG_3,"Received input IPv4 packet");
            process_input_packet(ipv4_data_input_fd, AF_INET);
        }
        if (FD_ISSET(ipv6_data_input_fd, &readfds)) {
            //lispd_log_msg(LISP_LOG_DEBUG_3,"Received input IPv6 packet");
            process_input_packet(ipv6_data_input_fd, AF_INET6);
        }
        if (FD_ISSET(ipv4_control_input_fd, &readfds)) {
            lispd_log_msg(LISP_LOG_DEBUG_3,"Received IPv4 packet in the control input buffer (4342)");
            process_ctr_msg(ipv4_control_input_fd, AF_INET);
        }
        if (FD_ISSET(ipv6_control_input_fd, &readfds)) {
            lispd_log_msg(LISP_LOG_DEBUG_3,"Received IPv6 packet in the control input buffer (4342)");
            process_ctr_msg(ipv6_control_input_fd, AF_INET6);
        }
        if (FD_ISSET(tun_fd, &readfds)) {
            lispd_log_msg(LISP_LOG_DEBUG_3,"Received packet in the tun buffer");
            process_output_packet(tun_fd);
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

#else

void event_loop (){}

JNIEXPORT void JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_lispd_1loop(JNIEnv * env, jclass cl)
{
	int    max_fd;
	fd_set readfds;
	int    retval;

	initial_map_register_process ();

	/*
	 * SMR proxy-ITRs list to be updated with new mappings
	 */

	init_smr(NULL,NULL);

	/*
	 * RLOC Probing proxy ETRs
	 */
	programming_petr_rloc_probing();

	/*
	 *  calculate the max_fd for select.
	 */

	 max_fd = tun_fd;
	 max_fd = (max_fd > ipv4_data_input_fd)      ? max_fd : ipv4_data_input_fd;
	 max_fd = (max_fd > ipv6_data_input_fd)      ? max_fd : ipv6_data_input_fd;
	 max_fd = (max_fd > ipv4_control_input_fd)   ? max_fd : ipv4_control_input_fd;
	 max_fd = (max_fd > ipv6_control_input_fd)   ? max_fd : ipv6_control_input_fd;
	 max_fd = (max_fd > timers_fd)               ? max_fd : timers_fd;
	 max_fd = (max_fd > netlink_fd)              ? max_fd : netlink_fd;


	 lispd_running = TRUE;

	 while (lispd_running){
	         FD_ZERO(&readfds);
	         FD_SET(tun_fd, &readfds);
	         FD_SET(ipv4_data_input_fd, &readfds);
	         FD_SET(ipv6_data_input_fd, &readfds);
	         FD_SET(ipv4_control_input_fd, &readfds);
	         FD_SET(ipv6_control_input_fd, &readfds);
	         FD_SET(timers_fd, &readfds);
	         FD_SET(netlink_fd, &readfds);


	         retval = have_input(max_fd, &readfds);
//
//	         if (retval != GOOD) {
//	        	 continue;        /* interrupted */
//	         }

	         if (FD_ISSET(tun_fd, &readfds)) {
	        	 lispd_log_msg(LISP_LOG_DEBUG_3,"Received packet in the tun buffer");
	        	 process_output_packet();
	         }

	         if (FD_ISSET(ipv4_data_input_fd, &readfds)) {
	        	 //lispd_log_msg(LISP_LOG_DEBUG_3,"Received input IPv4 packet");
	        	 process_input_packet(ipv4_data_input_fd, AF_INET);
	         }

	         if (FD_ISSET(ipv6_data_input_fd, &readfds)) {
	        	 //lispd_log_msg(LISP_LOG_DEBUG_3,"Received input IPv6 packet");
	        	 process_input_packet(ipv6_data_input_fd, AF_INET6);
	         }

	         if (FD_ISSET(ipv4_control_input_fd, &readfds)) {
	        	 lispd_log_msg(LISP_LOG_DEBUG_3,"Received IPv4 packet in the control input buffer (4342)");
	        	 process_ctr_msg(ipv4_control_input_fd, AF_INET);
	         }

	         if (FD_ISSET(ipv6_control_input_fd, &readfds)) {
	        	 lispd_log_msg(LISP_LOG_DEBUG_3,"Received IPv6 packet in the control input buffer (4342)");
	        	 process_ctr_msg(ipv6_control_input_fd, AF_INET6);
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
	 lispd_log_msg(LISP_LOG_DEBUG_2,"event_loop: Exiting from event loop");
}

JNIEXPORT void JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_lispd_1exit
   (JNIEnv * env, jclass cl){
	exit_cleanup();
}


#endif

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
        exit_cleanup();
    }
}


/*
 *  Check for superuser privileges
 */
int check_capabilities()
{
    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data;

    cap_header.pid = getpid();
    cap_header.version = _LINUX_CAPABILITY_VERSION;
    if (capget(&cap_header, &cap_data) < 0)
    {
        lispd_log_msg(LISP_LOG_ERR, "Could not retrieve capabilities");
        return BAD;
    }

    lispd_log_msg(LISP_LOG_DEBUG_1, "Rights: Effective [%u] Permitted  [%u]", cap_data.effective, cap_data.permitted);

    /* check for capabilities */
    if(  (cap_data.effective & CAP_TO_MASK(CAP_NET_ADMIN)) && (cap_data.effective & CAP_TO_MASK(CAP_NET_RAW))  )  {
    }
    else {
        lispd_log_msg(LISP_LOG_CRIT, "Insufficient rights, you need CAP_NET_ADMIN and CAP_NET_RAW. See README");
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

    lispd_log_msg(LISP_LOG_DEBUG_1, "Rights: Effective [%u] Permitted  [%u]", cap_data.effective, cap_data.permitted);

    return GOOD;
}


/*
 *  exit_cleanup()
 *
 *  Close opened sockets and file descriptors
 */

#ifndef VPNAPI
void exit_cleanup(void) {
	lispd_running = FALSE;
    /* Remove source routing tables */
    remove_created_rules();
    /* Close timer file descriptors */
    if (timers_fd != 0){
    	remove_sig_timer();
    }
    /* Close receive sockets */
    close(tun_fd);
    close(ipv4_data_input_fd);
    close(ipv4_control_input_fd);
    close(ipv6_data_input_fd);
    close(ipv6_control_input_fd);
    /* Close send sockets */
    close_output_sockets();
    /* Close netlink socket */
    close(netlink_fd);

    free_map_cache_entry(proxy_etrs);
    free_lisp_addr_list(proxy_itrs, TRUE);
    free_map_server_list(map_servers);
    free_ifaces_list();
    drop_map_cache();
    drop_local_mappings();
    drop_referral_cache();
    free(config_file);

#ifdef ANDROID
    close_log_file();
#endif
    exit(EXIT_SUCCESS);
}
#else
void exit_cleanup(void) {
	lispd_running = FALSE;
	/* Close timer file descriptors */
	if (timers_fd != 0){
		remove_sig_timer();
	}
	/* Close receive sockets */
	close(tun_fd);
	close(ipv4_data_input_fd);
	close(ipv4_control_input_fd);
	close(ipv6_data_input_fd);
	close(ipv6_control_input_fd);
	/* Close netlink socket */
	close(netlink_fd);

	free_ifaces_list();
	drop_map_cache();
	drop_local_mappings();
	drop_referral_cache();
	free_map_cache_entry(proxy_etrs);
	free_lisp_addr_list(proxy_itrs, TRUE);
	free_map_server_list(map_servers);
	free(config_file);


    close_log_file();
}
#endif




/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
