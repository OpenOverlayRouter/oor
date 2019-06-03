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
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


#include "oor.h"
#include "cmdline.h"
#include "iface_list.h"
#include "control/oor_control.h"
#include "control/lisp_xtr.h"
#include "control/lisp_ms.h"
#include "data-plane/data-plane.h"
#include "net_mgr/net_mgr.h"
#include "lib/htable_ptrs.h"
#include "lib/oor_log.h"
#include "lib/nonces_table.h"
#include "lib/sockets.h"
#include "lib/timers.h"
#include "lib/routing_tables_lib.h"
#include "liblisp/liblisp.h"
#include "lib/shash.h"
#include "lib/generic_list.h"

#ifdef VPP
#include "lib/vpp_api/vpp_api.h"
#endif

#ifdef VPNAPI
#include "oor_jni.h"
#endif

#ifdef __APPLE__
#include <syslog.h>
#include "lib/interfaces_lib.h"
#else
#include <linux/capability.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/prctl.h>
#endif

#if !defined(ANDROID) && !defined(OPENWRT)
#include "config/oor_api_internals.h"
#endif
#ifdef OPENWRT
#include "config/oor_config_uci.h"
#else
#include "config/oor_config_confuse.h"
#endif

#ifdef ANDROID
#define CAP_TO_MASK(x)      (1 << ((x) & 31))
#endif

// system calls - look to libc for function to system call mapping
#ifndef __APPLE__
extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, const cap_user_data_t data);
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

sockmstr_t *smaster = NULL;
oor_ctrl_dev_t *ctrl_dev;
oor_ctrl_t *lctrl;

#ifdef VPNAPI
int oor_running;
#endif

#if !defined(ANDROID) && !defined(OPENWRT)
/* OOR's API connection structure */
oor_api_connection_t oor_api_connection;
#endif

htable_nonces_t *nonces_ht; //<uint64_t, oor_timer_t>
htable_ptrs_t *ptrs_to_timers_ht; //<pointer, glist_t of timers>


/*
 *  Check for superuser privileges
 */
#if !defined(ANDROID) && !defined(__APPLE__)
int
check_capabilities()
{
    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data;
    
    cap_header.pid = getpid();
    cap_header.version = _LINUX_CAPABILITY_VERSION;
    
    /* Check if oor is already running: /var/run/oor.pid */
    
    if (capget(&cap_header, &cap_data) < 0)
    {
        OOR_LOG(LCRIT, "Could not retrieve capabilities");
        return BAD;
    }
    
    OOR_LOG(LDBG_1, "Rights: Effective [%u] Permitted  [%u]", cap_data.effective, cap_data.permitted);
    
    /* check for capabilities */
    if(  (cap_data.effective & CAP_TO_MASK(CAP_NET_ADMIN)) && (cap_data.effective & CAP_TO_MASK(CAP_NET_RAW))  )  {
    }
    else {
        OOR_LOG(LCRIT, "Insufficient rights, you need CAP_NET_ADMIN and CAP_NET_RAW. See README");
        return BAD;
    }
    
    return GOOD;
}
#else
int
check_capabilities()
{
    if (geteuid() != 0) {
        OOR_LOG(LCRIT,"Running Open Overlay Router requires superuser privileges! Exiting...\n");
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
            OOR_LOG(LDBG_1, "Received SIGHUP signal.");
            break;
        case SIGTERM:
            /* SIGTERM is the default signal sent by 'kill'. Exit cleanly */
            OOR_LOG(LDBG_1, "Received SIGTERM signal. Cleaning up...");
            exit_cleanup();
            break;
        case SIGINT:
            /* SIGINT is sent by pressing Ctrl-C. Exit cleanly */
            OOR_LOG(LDBG_1, "Terminal interrupt. Cleaning up...");
            exit_cleanup();
            break;
        default:
            OOR_LOG(LDBG_1,"Unhandled signal (%d)", sig);
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
    OOR_LOG(LDBG_2,"Exit Cleanup");
    
    // Order is important
    ctrl_destroy(lctrl);
    
    if (data_plane){
        data_plane->datap_uninit();
    }
    
    if (net_mgr){
        net_mgr->netm_uninit();
    }
    
    ifaces_destroy();
    
    sockmstr_destroy(smaster);
    
    oor_timers_destroy();
    
    htable_ptrs_destroy(ptrs_to_timers_ht);
    htable_nonces_destroy(nonces_ht);
    
    close_log_file();
#ifndef VPNAPI
    OOR_LOG(LINF,"Exiting ...");
    exit(EXIT_SUCCESS);
#else
    jni_uninit();
#endif
#ifdef VPP
    vpp_uninit_api();
#endif
}

/*
 *  handle_oor_command_line --
 */
static void
handle_oor_command_line(int argc, char **argv)
{
    struct gengetopt_args_info args_info;
    
    if (cmdline_parser(argc, argv, &args_info) != 0) {
        exit_cleanup();
    }
    
    if (args_info.config_file_given) {
        config_file = strdup(args_info.config_file_arg);
    }else{
#ifdef OPENWRT
        config_file = strdup("/etc/config/oor");
#else
        config_file = strdup("/etc/oor.conf");
#endif
    }
    
    if (args_info.daemonize_given) {
        if (config_file[0] != '/'){
            OOR_LOG(LCRIT, "Couldn't find config file %s. If you are useing OOR in daemon mode, please indicate a full path file.", config_file);
        }
        daemonize = TRUE;
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
                OOR_LOG(LINF, "AFI must be IPv4 (-a 4) or IPv6 (-a 6)\n");
                break;
        }
    } else {
        default_rloc_afi = AF_UNSPEC;
    }
#ifdef VPP
    default_rloc_afi = AF_INET;
    OOR_LOG(LINF, "VPP: Disabling IPv6 RLOCs\n");
#endif
    
    cmdline_parser_free(&args_info);
}

static void
demonize_start()
{
    if (daemonize) {
        OOR_LOG(LDBG_1, "Starting the daemonizing process");
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

static int
parse_config_file()
{
    int err;
    err = handle_config_file();
    
    return (err);
}

static int
initial_setup()
{
    
    int selected = 0;
    
#ifdef OPENWRT
    OOR_LOG(LINF,"Open Overlay Router %s compiled for openWRT\n", OOR_VERSION);
    selected ++;
#endif
    
#ifdef VPP
    OOR_LOG(LINF,"Open Overlay Router %s compiled for linux with VPP data plane\n", OOR_VERSION);
    selected ++;
#endif
    
#ifdef ANDROID
#ifdef VPNAPI
    OOR_LOG(LINF,"Open Overlay Router %s compiled for not rooted Android\n", OOR_VERSION);
    selected ++;
#else
    OOR_LOG(LINF,"Open Overlay Router %s compiled for rooted Android\n", OOR_VERSION);
    selected ++;
#endif
#endif
    
#ifdef __APPLE__
    OOR_LOG(LINF,"Open Overlay Router %s compiled for iOS\n", OOR_VERSION);
    selected ++;
#endif
    
    if (selected > 1){
        OOR_LOG(LERR,"Wrong platform selection");
        return (BAD);
    }else if (selected == 0){
        OOR_LOG(LINF,"Open Overlay Router %s compiled for linux\n", OOR_VERSION);
    }
    
#if UINTPTR_MAX == 0xffffffff
    OOR_LOG(LDBG_1,"x32 system");
#elif UINTPTR_MAX == 0xffffffffffffffff
    OOR_LOG(LDBG_1,"x64 system");
#else
    OOR_LOG(LERR,"Unknow system. Please contact the Open Overlay Router team providing your hardware");
#endif
    
#if !defined(VPNAPI) && !defined(__APPLE__)
    if (check_capabilities() != GOOD){
        return (BAD);
    }
#endif
    
    /* Initialize the random number generator  */
    iseed = (unsigned int) time(NULL);
    srandom(iseed);
    setup_signal_handlers();
    
    /* Initialize hash table that control timers */
    nonces_ht = htable_nonces_new();
    ptrs_to_timers_ht = htable_ptrs_new();
    
#ifdef VPP
    if (vpp_is_enabled() == FALSE || vpp_init_api() != GOOD){
        return (BAD);
    }
#endif
    return(GOOD);
}

#if !defined(VPNAPI) && !defined(__APPLE__)
int
main(int argc, char **argv)
{
    oor_dev_type_e dev_type;
    tr_abstract_device *tunnel_router;
    
    if (initial_setup() != GOOD){
        exit(EXIT_SUCCESS);
    }

    handle_oor_command_line(argc, argv);
    
    /* Check config file exists */
    if (access( config_file, F_OK ) == -1 ) {
        OOR_LOG(LCRIT, "Couldn't find config file %s.", config_file);
        exit(EXIT_SUCCESS);
    }

    /* see if we need to daemonize, and if so, do it */
    demonize_start();
    
    /* Detect the data plane type */
    data_plane_select();
    net_mgr_select();
    
    /* create socket master, timer wheel, initialize interfaces */
    smaster = sockmstr_create();
    oor_timers_init();
    if (ifaces_init() != GOOD){
        exit_cleanup();
    }
    /* create control. Only one instance for now */
    if ((lctrl = ctrl_create())==NULL){
        exit_cleanup();
    }
    /* parse config and create ctrl_dev */
    if (parse_config_file() != GOOD){
        exit_cleanup();
    }
    dev_type = ctrl_dev_mode(ctrl_dev);
#ifdef VPP
    if (dev_type != xTR_MODE){
        OOR_LOG(LERR, "VPP is only supported in xTR mode");
        exit_cleanup();
    }
#endif
    if (dev_type == xTR_MODE || dev_type == RTR_MODE || dev_type == MN_MODE) {
        OOR_LOG(LDBG_2, "Configuring data plane");
        tunnel_router = lisp_tr_abstract_cast(ctrl_dev);
        if (data_plane->datap_init(dev_type,tr_encap_type(&tunnel_router->tr),tr_allowed_dst_eids(&tunnel_router->tr))!=GOOD){
            data_plane = NULL;
            exit_cleanup();
        }
        OOR_LOG(LDBG_1, "Data plane initialized");
    }
    
    /* The control should be initialized after data plane */
    if (ctrl_init(lctrl) != GOOD){
        exit_cleanup();
    }
    if (net_mgr->netm_init() != GOOD){
        exit_cleanup();
    }
    /* run lisp control device xtr/ms */
    ctrl_dev_run(ctrl_dev);
    
    OOR_LOG(LINF,"\n\n Open Overlay Router (%s): started... \n\n",OOR_VERSION);
    
#if !defined(ANDROID) && !defined(OPENWRT)
    /* Initialize API for external access */
    oor_api_init_server(&oor_api_connection);
    
    for (;;) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
        oor_api_loop(&oor_api_connection);
    }
#else
    for (;;) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
    }
#endif
    
    /* event_loop returned: bad! */
    OOR_LOG(LINF, "Exiting...");
    exit_cleanup();
    return(0);
}
#endif

#ifdef VPNAPI
JNIEXPORT jint JNICALL Java_org_openoverlayrouter_noroot_OOR_1JNI_oor_1start
(JNIEnv *env, jobject thisObj, jint vpn_tun_fd, jstring storage_path)
{
    oor_dev_type_e dev_type;
    jintArray fd_list;
    uint32_t iseed = 0;  /* initial random number generator */
    pid_t pid = 0;    /* child pid */
    pid_t sid = 0;
    char log_file[1024];
    const char *path = NULL;
    tr_abstract_device *tunnel_router;
    memset (log_file,0,sizeof(char)*1024);
    initial_setup();
    jni_init(env,thisObj);
    /* create socket master, timer wheel, initialize interfaces */
    smaster = sockmstr_create();
    oor_timers_init();
    /* create control. Only one instance for now */
    lctrl = ctrl_create();
    
    /* Detect the data plane type */
    data_plane_select();
    net_mgr_select();
    if (ifaces_init()!=GOOD){
        exit_cleanup();
        close(vpn_tun_fd);
        return (BAD);
    }
    
    /** parse config and create ctrl_dev **/
    /* obtain the configuration file */
    path = (*env)->GetStringUTFChars(env, storage_path, 0);
    config_file = calloc(1024, sizeof(char));
    strcat(config_file,path);
    strcat(config_file,"oor.conf");
    strcat(log_file,path);
    strcat(log_file,"oor.log");
    (*env)->ReleaseStringUTFChars(env, storage_path, path);
    open_log_file(log_file);
    OOR_LOG(LDBG_2, "Default selected afi: %d",default_rloc_afi);
    if (parse_config_file()!=GOOD){
        exit_cleanup();
        close(vpn_tun_fd);
        return (BAD);
    }
    dev_type = ctrl_dev_mode(ctrl_dev);
    if (dev_type == xTR_MODE || dev_type == RTR_MODE || dev_type == MN_MODE) {
        OOR_LOG(LDBG_2, "Configuring data plane");
        tunnel_router = lisp_tr_abstract_cast(ctrl_dev);
        if (data_plane->datap_init(dev_type, tr_encap_type(&tunnel_router->tr), vpn_tun_fd) != GOOD){
            data_plane = NULL;
            return (BAD);
        }
        OOR_LOG(LDBG_1, "Data plane initialized");
        
    }
    ctrl_init(lctrl);
    if (net_mgr->netm_init() != GOOD){
        exit_cleanup();
    }
    return (GOOD);
}

JNIEXPORT void JNICALL Java_org_openoverlayrouter_noroot_OOR_1JNI_oor_1loop(JNIEnv * env, jclass cl)
{
    oor_running = TRUE;
    ctrl_dev_run(ctrl_dev);
    
    /* EVENT LOOP */
    while (oor_running) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
    }
    /* event_loop returned: bad! */
    exit_cleanup();
}

JNIEXPORT void JNICALL Java_org_openoverlayrouter_noroot_OOR_1JNI_oor_1exit(JNIEnv * env,
                                                                            jclass cl)
{
    oor_running = false;
}

#endif

#ifdef __APPLE__

int oor_running;

char *logPath;
char *confPath;

void setLogPath(const char *path) {
    logPath = (char *)path;
}

void setConfPath(const char *path) {
    confPath = (char *)path;
}

int oor_start() {
    
    oor_dev_type_e dev_type;
    char log_file[1024];
    tr_abstract_device *tunnel_router;
    memset (log_file,0,sizeof(char)*1024);
    initial_setup();
    /* create socket master, timer wheel, initialize interfaces */
    /* Can not use IPv6 RLOCs */
    default_rloc_afi = AF_INET;
    smaster = sockmstr_create();
    oor_timers_init();
    
    // create control. Only one instance for now
    lctrl = ctrl_create();
    
    // Detect the data plane type
    data_plane_select();
    net_mgr_select();
    if (ifaces_init()!=GOOD){
        exit_cleanup();
        return (BAD);
    }
    
    // parse config and create ctrl_dev
    // obtain the configuration file
    config_file = calloc(1024, sizeof(char));
    strcat(config_file,confPath);
    strcat(log_file,logPath);
    open_log_file(log_file);
    OOR_LOG(LINF, "==> Default selected afi: %d",default_rloc_afi);
    if (parse_config_file()!=GOOD){
        exit_cleanup();
        return (BAD);
    }
    
    dev_type = ctrl_dev_mode(ctrl_dev);
    if (dev_type == xTR_MODE || dev_type == RTR_MODE || dev_type == MN_MODE) {
        OOR_LOG(LDBG_2, "Configuring data plane");
        tunnel_router = lisp_tr_abstract_cast(ctrl_dev);
        if (data_plane->datap_init(dev_type, tr_encap_type(&tunnel_router->tr)) != GOOD){
            data_plane = NULL;
            return (BAD);
        }
        OOR_LOG(LDBG_1, "Data plane initialized");
        
    }
    
    ctrl_init(lctrl);
    
    if (net_mgr->netm_init() != GOOD){
        exit_cleanup();
    }
    return (GOOD);
}

void trigtimer() {
    
}

void oor_loop() {
    oor_running = TRUE;
    ctrl_dev_run(ctrl_dev);
    // EVENT LOOP
    while (oor_running) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
    }
    // event_loop returned: bad!
    exit_cleanup();
    
}

void oor_stop() {
    oor_running = false;
    close_log_file();
}

#endif

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
