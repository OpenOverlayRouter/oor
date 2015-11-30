/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <signal.h>
#include <linux/capability.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/prctl.h>
#include <sys/stat.h>
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
#include "data-plane/data-plane.h"
#include "lib/lmlog.h"
#include "lib/nonces_table.h"
#include "lib/pointers_table.h"
#include "lib/sockets.h"
#include "lib/timers.h"
#include "lib/routing_tables_lib.h"
#ifndef ANDROID
 #include "lispd_api_internals.h"
#endif
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
int      debug_level                        = -1;
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
#ifdef VPNAPI
int lispd_running;
#endif
#ifndef ANDROID
/* LISPmob's API connection structure */
lmapi_connection_t lmapi_connection;
#endif

htable_nonces_t *nonces_ht;
htable_ptrs_t *ptrs_to_timers_ht;

/**************************** FUNCTION DECLARATION ***************************/
/* Check if lispmob is already running: /var/run/lispd.pid */
int pid_file_check_not_exist();

/* Creates the PID file of the process */
int pid_file_create();

/* Remove the PID file of the process */
void pid_file_remove();
/*****************************************************************************/


/* Check if lispmob is already running: /var/run/lispd.pid */
int
pid_file_check_not_exist()
{
    FILE *pid_file;

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
int
pid_file_create()
{
    FILE *pid_file;
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
void
pid_file_remove()
{
    FILE *pid_file;
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
int
check_capabilities()
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

    return GOOD;
}
#else
int
check_capabilities()
{
    if (geteuid() != 0) {
        LMLOG(LCRIT,"Running %s requires superuser privileges! Exiting...\n", LISPD);
        return (BAD);
    }

    return (GOOD);
}
#endif



void
signal_handler(int sig) {
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

    if (!data_plane){
        data_plane->datap_uninit();
    }

    sockmstr_destroy(smaster);

    lmtimers_destroy();

    htable_ptrs_destroy(ptrs_to_timers_ht);
    htable_nonces_destroy(nonces_ht);

    close_log_file();
#ifndef VPNAPI
    LMLOG(LINF,"Exiting ...");
    exit(EXIT_SUCCESS);
#else
    jni_uninit();
#endif

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
        if (pid > 0){
            exit(EXIT_SUCCESS);
        }
        if ((sid = setsid()) < 0){
            exit_cleanup();
        }
        if ((chdir("/")) < 0){
            exit_cleanup();
        }
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

    nl_sl = sockmstr_register_read_listener(smaster, process_netlink_msg, NULL,
            netlink_fd);

    /* Request to dump the routing tables to obtain the gatways when
     * processing the netlink messages  */
    request_route_table(RT_TABLE_MAIN, AF_INET);
    process_netlink_msg(nl_sl);
    request_route_table(RT_TABLE_MAIN, AF_INET6);
    process_netlink_msg(nl_sl);
}

static int
parse_config_file()
{
    int err;
    err = handle_config_file(&config_file);
    if (config_file != NULL){
        free(config_file);
    }

    return (err);
}

static void
initial_setup()
{
#ifdef OPENWRT
    LMLOG(LINF,"LISPmob %s compiled for openWRT\n", LISPD_VERSION);
#else
#ifdef ANDROID
#ifdef VPNAPI
    LMLOG(LINF,"LISPmob %s compiled for not rooted Android\n", LISPD_VERSION);
#else
    LMLOG(LINF,"LISPmob %s compiled for rooted Android\n", LISPD_VERSION);

#endif
#else
    LMLOG(LINF,"LISPmob %s compiled for Linux\n", LISPD_VERSION);
#endif
#endif

#if UINTPTR_MAX == 0xffffffff
    LMLOG(LDBG_1,"x32 system");
#elif UINTPTR_MAX == 0xffffffffffffffff
    LMLOG(LDBG_1,"x64 system");
#else
    LMLOG(LERR,"Unknow system. Please contact the LISPmob team providing your hardware");
#endif

#ifndef VPNAPI
    if (check_capabilities() != GOOD){
        exit(EXIT_SUCCESS);
    }
    if(pid_file_check_not_exist() == BAD){
        exit(EXIT_SUCCESS);
    }
    pid_file_create();
#endif

    /* Initialize the random number generator  */
    iseed = (unsigned int) time(NULL);
    srandom(iseed);
    setup_signal_handlers();

    /* Initialize hash table that control timers */
    nonces_ht = htable_nonces_new();
    ptrs_to_timers_ht = htable_ptrs_new();
}

#ifndef VPNAPI
int
main(int argc, char **argv)
{
    lisp_dev_type_e dev_type;

    initial_setup();

    handle_lispd_command_line(argc, argv);

    /* see if we need to daemonize, and if so, do it */
    demonize_start();

    /* create socket master, timer wheel, initialize interfaces */
    smaster = sockmstr_create();
    lmtimers_init();
    ifaces_init();

    /* create control. Only one instance for now */
    if ((lctrl = ctrl_create())==NULL){
        exit_cleanup();
    }

    /* Detect the data plane type */
    data_plane_select();

    /* parse config and create ctrl_dev */
    if (parse_config_file() != GOOD){
        exit_cleanup();
    }


    dev_type = ctrl_dev_mode(ctrl_dev);
    if (dev_type == xTR_MODE || dev_type == RTR_MODE || dev_type == MN_MODE) {
        data_plane->datap_init(dev_type);
    }

    ctrl_init(lctrl);
    init_netlink();

    /* run lisp control device xtr/ms */
    if (!ctrl_dev) {
        LMLOG(LDBG_1, "device NULL");
        exit(0);
    }
    ctrl_dev_run(ctrl_dev);

    LMLOG(LINF,"\n\n LISPmob (%s): 'lispd' started... \n\n",LISPD_VERSION);

#ifndef ANDROID
    /* Initialize API for external access */
    lmapi_init_server(&lmapi_connection);

    for (;;) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
        lmapi_loop(&lmapi_connection);
    }
#else
    for (;;) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
    }
#endif



    /* EVENT LOOP */
    for (;;) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
#ifndef ANDROID
        lmapi_loop(&lmapi_connection);
#endif
    }

    /* event_loop returned: bad! */
    LMLOG(LINF, "Exiting...");
    exit_cleanup();
    return(0);
}

#else
JNIEXPORT jint JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_startLispd
  (JNIEnv *env, jobject thisObj, jint vpn_tun_fd, jstring storage_path)
{
    lisp_dev_type_e dev_type;
    jintArray fd_list;
    uint32_t iseed = 0;  /* initial random number generator */
    pid_t pid = 0;    /* child pid */
    pid_t sid = 0;
    char log_file[1024];
    const char *path = NULL;

    memset (log_file,0,sizeof(char)*1024);


    initial_setup();
    jni_init(env,thisObj);

    /* create socket master, timer wheel, initialize interfaces */
    smaster = sockmstr_create();
    lmtimers_init();
    ifaces_init();

    /* create control. Only one instance for now */
    lctrl = ctrl_create();

    /* Detect the data plane type */
    data_plane_select();

    /** parse config and create ctrl_dev **/

    /* obtain the configuration file */
    path = (*env)->GetStringUTFChars(env, storage_path, 0);
    config_file = calloc(1024, sizeof(char));
    strcat(config_file,path);
    strcat(config_file,"lispd.conf");
    strcat(log_file,path);
    strcat(log_file,"lispd.log");
    (*env)->ReleaseStringUTFChars(env, storage_path, path);
    open_log_file(log_file);

    if (parse_config_file()!=GOOD){
        exit_cleanup();
        return (BAD);
    }

    dev_type = ctrl_dev_mode(ctrl_dev);
    if (dev_type == xTR_MODE || dev_type == RTR_MODE || dev_type == MN_MODE) {
        data_plane->datap_init(dev_type, vpn_tun_fd);
    }

    ctrl_init(lctrl);
    init_netlink();

    /* run lisp control device xtr/ms */
     if (!ctrl_dev) {
         LMLOG(LDBG_1, "device NULL");
         return (BAD);
     }

     return (GOOD);
}


JNIEXPORT void JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_lispd_1loop(JNIEnv * env, jclass cl)
{
    lispd_running = TRUE;
    ctrl_dev_run(ctrl_dev);

    /* EVENT LOOP */
    while (lispd_running) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
    }

    /* event_loop returned: bad! */
    LMLOG(LINF, "Exiting...");
    exit_cleanup();
}

JNIEXPORT void JNICALL Java_org_lispmob_noroot_LISPmob_1JNI_lispd_1exit
   (JNIEnv * env, jclass cl){
    lispd_running = false;
}

#endif

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
