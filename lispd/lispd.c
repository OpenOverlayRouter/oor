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

#include <signal.h>
#include <linux/capability.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/prctl.h>
#include <time.h>

#include "lispd.h"
#ifdef OPENWRT
#include "lispd_config_uci.h"
#else
#include "lispd_config_confuse.h"
#endif
#include "cmdline.h"
#include "iface_list.h"
#include "iface_mgmt.h"
#include "data-tun/lispd_input.h"
#include "lib/lmlog.h"
#include "lib/sockets.h"
#include "lib/timers.h"
#include "data-tun/lispd_tun.h"
#include "data-tun/lispd_output.h"
#include "lib/routing_tables_lib.h"
#include "lispd_api_internals.h"
#include "liblisp/liblisp.h"
#include "control/lisp_control.h"
#include "control/lisp_xtr.h"
#include "control/lisp_ms.h"
#include "lib/shash.h"
#include "lib/generic_list.h"
#ifdef VPNAPI
 #include "lispd_jni.h"
#endif


/* system calls - look to libc for function to system call mapping */
extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);
#ifdef ANDROID
#define CAP_TO_MASK(x)      (1 << ((x) & 31))
#endif

/* config paramaters */
char    *config_file                        = NULL;
int      debug_level                        = 0;
int      default_rloc_afi                   = AF_UNSPEC;
int      daemonize                          = FALSE;

uint32_t iseed                              = 0;  /* initial random number generator */

/* various globals */
pid_t  pid                                  = 0;    /* child pid */
pid_t  sid                                  = 0;

/* sockets (fds)  */
int     ipv4_data_input_fd                  = -1;
int     ipv6_data_input_fd                  = -1;
int     netlink_fd                          = -1;

/* NAT */
int nat_aware = FALSE;
int nat_status = UNKNOWN;
nonces_list_t *nat_ir_nonce = NULL;

sockmstr_t *smaster = NULL;
lisp_ctrl_dev_t *ctrl_dev;
lisp_ctrl_t *lctrl;

/* LISPmob's API connection structure */
lmapi_connection_t lmapi_connection;

/**************************** FUNCTION DECLARATION ***************************/
/* Check if lispmob is already running: /var/run/lispd.pid */
int pid_file_check_not_exist();

/* Creates the PID file of the process */
int pid_file_create();

/* Remove the PID file of the process */
void pid_file_remove();
/*****************************************************************************/

int
init_tr_data_plane(lisp_dev_type_e mode)
{
    int (*cb_func)(sock_t *) = NULL;
    uint8_t router_mode = FALSE;

    LMLOG(LINF, "\nIntializing data plane\n");

    /* Select the default rlocs for output data packets and output control
     * packets */
    set_default_output_ifaces();

    if (mode == xTR_MODE || mode == MN_MODE) {
        lisp_xtr_t  *xtr         = NULL;
        lisp_addr_t *tun_v4_addr = NULL;
        lisp_addr_t *tun_v6_addr = NULL;
        xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

        tun_v4_addr = local_map_db_get_main_eid(xtr->local_mdb, AF_INET);
        tun_v6_addr = local_map_db_get_main_eid(xtr->local_mdb, AF_INET6);

        if (mode == xTR_MODE){
            router_mode = TRUE;
        }

        if (tun_configure_data_plane(router_mode, tun_v4_addr, tun_v6_addr)!=GOOD){
            return(BAD);
        }
        sockmstr_register_read_listener(smaster, lisp_output_recv, NULL,
                    tun_receive_fd);

        cb_func = process_input_packet;
    } else if (mode == RTR_MODE) {
        cb_func = rtr_process_input_packet;
    }

    /* Generate receive sockets for data port (4341) */
    if (default_rloc_afi != AF_INET6) {
        ipv4_data_input_fd = open_data_input_socket(AF_INET);
        sockmstr_register_read_listener(smaster, cb_func, NULL,
                ipv4_data_input_fd);
    }

    if (default_rloc_afi != AF_INET) {
        ipv6_data_input_fd = open_data_input_socket(AF_INET6);
        sockmstr_register_read_listener(smaster, cb_func, NULL,
                ipv6_data_input_fd);
    }

    lisp_output_init();

    return(GOOD);
}

/* Check if lispmob is already running: /var/run/lispd.pid */
int pid_file_check_not_exist()
{
    FILE *pid_file = NULL;

    pid_file = fopen("/var/run/lispd.pid", "r");
    if (pid_file != NULL)
    {
        LMLOG(LCRIT, "Check no other instance of lispd is running. If no instance is running, remove /var/run/lispd.pid");
        fclose(pid_file);
        return (BAD);
    }

    return (GOOD);
}

/* Creates the PID file of the process */
int pid_file_create()
{
    FILE *pid_file = NULL;
    int pid = getpid();

    pid_file = fopen("/var/run/lispd.pid", "w");
    if (pid_file == NULL){
        LMLOG(LCRIT, "pid_file_create: Error creating PID file: %s",strerror(errno));
        return (BAD);
    }
    fprintf(pid_file, "%d\n",pid);
    fclose(pid_file);

    LMLOG(LDBG_1, "PID file created: /var/run/lispd.pid -> %d",pid);

    return (GOOD);
}

/* Remove the PID file of the process */
void pid_file_remove()
{
    FILE *pid_file = NULL;
    char line[80];
    long int pid;

    pid_file = fopen("/var/run/lispd.pid", "r");
    if (pid_file == NULL){
        return;
    }

    if (fgets(line, 80, pid_file) == NULL){
        LMLOG(LWRN, "pid_file_remove: Couldn't read PID number from file");
        fclose(pid_file);
        return;
    }
    sscanf (line, "%ld", &pid);

    fclose(pid_file);

    if (pid != getpid()){
        return;
    }

    if (remove("/var/run/lispd.pid") != 0){
        LMLOG(LWRN,"pid_file_remove: PID file couldn't be removed: /var/run/lispd.pid");
    }else{
        LMLOG(LDBG_1,"PID file removed");
    }
}

/*
 *  Check for superuser privileges
 */
#ifndef ANDROID
int check_capabilities()
{
    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data;

    cap_header.pid = getpid();
    cap_header.version = _LINUX_CAPABILITY_VERSION;

    /* Check if lispmob is already running: /var/run/lispd.pid */

    if (capget(&cap_header, &cap_data) < 0)
    {
        LMLOG(LCRIT, "Could not retrieve capabilities");
        return BAD;
    }

    LMLOG(LWRN, "Rights: Effective [%u] Permitted  [%u]", cap_data.effective, cap_data.permitted);

    /* check for capabilities */
    if(  (cap_data.effective & CAP_TO_MASK(CAP_NET_ADMIN)) && (cap_data.effective & CAP_TO_MASK(CAP_NET_RAW))  )  {
    }
    else {
        LMLOG(LCRIT, "Insufficient rights, you need CAP_NET_ADMIN and CAP_NET_RAW. See README");
        return BAD;
    }

    /* Clear all but the capability to bind to low ports */
    cap_data.effective = CAP_TO_MASK(CAP_NET_ADMIN) | CAP_TO_MASK(CAP_NET_RAW);
    cap_data.permitted = cap_data.effective ;
    cap_data.inheritable = 0;
    if (capset(&cap_header, &cap_data) < 0) {
        LMLOG(LWRN, "Could not drop privileges");
        return BAD;
    }

    /* Tell kernel not clear permitted capabilities when dropping root */
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
        LMLOG(LWRN, "Sprctl(PR_SET_KEEPCAPS) failed");
        return GOOD;
    }

    /* Now we can drop privilege, drop effective rights even with KEEPCAPS */
    if (setuid(getuid()) < 0) {
        LMLOG(LWRN, "Could not drop privileges");
    }

    /* that's why we need to set effective rights equal to permitted rights */
    if (capset(&cap_header, &cap_data) < 0)
    {
        LMLOG(LCRIT,"Could not set effective rights to permitted ones");
        return (BAD);
    }

    LMLOG(LDBG_1, "Rights: Effective [%u] Permitted  [%u]", cap_data.effective, cap_data.permitted);

    return GOOD;
}
#else
int check_capabilities()
{
    if (geteuid() != 0) {
        LMLOG(LCRIT,"Running %s requires superuser privileges! Exiting...\n", LISPD);
        return (BAD);
    }

    return (GOOD);
}
#endif



void signal_handler(int sig) {
    switch (sig) {
    case SIGHUP:
        /* TODO: SIGHUP should trigger reloading the configuration file */
        LMLOG(LDBG_1, "Received SIGHUP signal.");
        break;
    case SIGTERM:
        /* SIGTERM is the default signal sent by 'kill'. Exit cleanly */
        LMLOG(LDBG_1, "Received SIGTERM signal. Cleaning up...");
        exit_cleanup();
        break;
    case SIGINT:
        /* SIGINT is sent by pressing Ctrl-C. Exit cleanly */
        LMLOG(LDBG_1, "Terminal interrupt. Cleaning up...");
        exit_cleanup();
        break;
    default:
        LMLOG(LDBG_1,"Unhandled signal (%d)", sig);
        exit(EXIT_FAILURE);
    }
}

/*
 *  exit_cleanup()
 *
 *  Close opened sockets and file descriptors
 */

void
exit_cleanup(void) {
    LMLOG(LDBG_2,"Exit Cleanup");

    //lmapi_end(&lmapi_connection);
#ifndef ANDROID
    pid_file_remove();
#endif

    ctrl_destroy(lctrl);

    ifaces_destroy();

    lisp_output_uninit();
    sockmstr_destroy(smaster);

    lmtimers_destroy();

    LMLOG(LINF,"Exiting ...");
    exit(EXIT_SUCCESS);
}

/*
 *  handle_lispd_command_line --
 *
 *  Get command line args and set up whatever is needed
 *
 *  David Meyer
 *  dmm@1-4-5.net
 *  Wed Apr 21 13:31:00 2010
 *
 *  $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */

static void
handle_lispd_command_line(int argc, char **argv)
{
    struct gengetopt_args_info args_info;

    if (cmdline_parser(argc, argv, &args_info) != 0) {
        exit_cleanup();
    }

    if (args_info.daemonize_given) {
        daemonize = TRUE;
    }
    if (args_info.config_file_given) {
        config_file = strdup(args_info.config_file_arg);
    }
    if (args_info.debug_given) {
        debug_level = args_info.debug_arg;
    } else {
        debug_level = -1;
    }
    if (args_info.afi_given) {
        switch (args_info.afi_arg) {
        case 0: /* afi given = 4 */
            default_rloc_afi = AF_INET;
            break;
        case 1: /* afi given = 6 */
            default_rloc_afi = AF_INET6;
            break;
        default:
            LMLOG(LINF, "AFI must be IPv4 (-a 4) or IPv6 (-a 6)\n");
            break;
        }
    } else {
        default_rloc_afi = AF_UNSPEC;
    }

    cmdline_parser_free(&args_info);
}

static void
demonize_start()
{
    if (daemonize) {
        LMLOG(LDBG_1, "Starting the daemonizing process");
        if ((pid = fork()) < 0) {
            exit_cleanup();
        }
        umask(0);
        if (pid > 0)
            exit(EXIT_SUCCESS);
        if ((sid = setsid()) < 0)
            exit_cleanup();
        if ((chdir("/")) < 0)
            exit_cleanup();
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }
}

static void
setup_signal_handlers()
{
    signal(SIGHUP,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGQUIT, signal_handler);
}

static void
init_netlink()
{
    struct sock *nl_sl;

    /* Create net_link socket to receive notifications of changes of RLOC
     * status. */
    netlink_fd = opent_netlink_socket();

    /* Request to dump the routing tables to obtain the gatways when
     * processing the netlink messages  */
    nl_sl = sockmstr_register_read_listener(smaster, process_netlink_msg, NULL,
            netlink_fd);

    request_route_table(RT_TABLE_MAIN, AF_INET);
    process_netlink_msg(nl_sl);
    request_route_table(RT_TABLE_MAIN, AF_INET6);
    process_netlink_msg(nl_sl);
}

static void
parse_config_file()
{
    int err;
    err = handle_config_file(config_file);;
    if (err != GOOD){
        exit_cleanup();
    }
    if (ctrl_dev->mode == xTR_MODE || ctrl_dev->mode == RTR_MODE || ctrl_dev->mode == MN_MODE) {
        if (init_tr_data_plane(ctrl_dev->mode)!=GOOD){
            exit_cleanup();
        }
    }
}

static void
initial_setup()
{
#ifndef ANDROID
#ifdef OPENWRT
    LMLOG(LINF,"LISPmob compiled for openWRT xTR\n");
#else
    LMLOG(LINF,"LISPmob compiled for linux xTR\n");
#endif
    if(pid_file_check_not_exist() == BAD){
        exit_cleanup();
    }
    pid_file_create();
#endif

#ifndef VPNAPI
    if (check_capabilities() != GOOD){
        exit_cleanup();
    }
#endif

    /* Initialize the random number generator  */
    iseed = (unsigned int) time(NULL);
    srandom(iseed);

    setup_signal_handlers();
}

int
main(int argc, char **argv)
{

    initial_setup();

    handle_lispd_command_line(argc, argv);

    /* see if we need to daemonize, and if so, do it */
    demonize_start();

    /* create socket master, timer wheel, initialize interfaces */
    smaster = sockmstr_create();
    lmtimers_init();
    ifaces_init();

    /* create control. Only one instance for now */
    lctrl = ctrl_create();

    /* parse config and create ctrl_dev */
    parse_config_file();

    LMLOG(LINF,"\n\n LISPmob (0.5): 'lispd' started... \n\n");

    ctrl_init(lctrl);
    init_netlink();

    /* run lisp control device xtr/ms */
    if (!ctrl_dev) {
        LMLOG(LDBG_1, "device NULL");
        exit(0);
    }
    ctrl_dev_run(ctrl_dev);

    /* Initialize API for external access */

    lmapi_init_server(&lmapi_connection);

    /* EVENT LOOP */
    for (;;) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
        lmapi_loop(&lmapi_connection);
    }

    /* event_loop returned: bad! */
    LMLOG(LINF, "Exiting...");
    exit_cleanup();
    return(0);
}

#ifdef VPNAPI
JNIEXPORT jintArray JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_startLispd
  (JNIEnv *env, jclass cl, jint vpn_tun_fd, jstring storage_path)
{
    jintArray           fd_list;
    jint                sockets_fds[4];
    uint32_t            iseed         = 0;  /* initial random number generator */
    pid_t               pid           = 0;    /* child pid */
    pid_t               sid           = 0;
    char                log_file[1024];
    const char          *path         = NULL;

    memset (log_file,0,sizeof(char)*1024);
    init_globales();

    path = (*env)->GetStringUTFChars(env, storage_path, 0);
    config_file = calloc(1024, sizeof(char));
    strcat(config_file,path);
    strcat(config_file,CONF_FILE_NAME);
    strcat(log_file,path);
    strcat(log_file,LOG_FILE_NAME);
    (*env)->ReleaseStringUTFChars(env, storage_path, path);

    LMLOG(LINF,"LISPmob %s compiled for not rooted Android", LISPD_VERSION);

    initial_setup();

    /* create socket master, timer wheel, initialize interfaces */
    smaster = sockmstr_create();
    lmtimers_init();
    ifaces_init();

    /* create control. Only one instance for now */
    lctrl = ctrl_create();




















}
#endif


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
