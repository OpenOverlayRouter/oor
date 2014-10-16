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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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
#include "lispd_input.h"
#include "lmlog.h"
#include "sockets.h"
#include "timers.h"
#include "lispd_tun.h"
#include "lispd_output.h"
#include "routing_tables_lib.h"
#include <liblisp.h>
#include <lisp_control.h>
#include <lisp_xtr.h>
#include <lisp_ms.h>
#include <shash.h>
#include <generic_list.h>

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
int     ipv4_data_input_fd                  = 0;
int     ipv6_data_input_fd                  = 0;
int     netlink_fd                          = 0;

/* NAT */
int nat_aware = FALSE;
int nat_status = UNKNOWN;
nonces_list_t *nat_ir_nonce = NULL;

sockmstr_t *smaster = NULL;
lisp_ctrl_dev_t *ctrl_dev;
lisp_ctrl_t *lctrl;

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

    /* Generate receive sockets for control (4342) and data port (4341) */
    if (default_rloc_afi != AF_INET6) {
        ipv4_data_input_fd = open_data_input_socket(AF_INET);
        sockmstr_register_read_listener(smaster, cb_func, NULL,
                ipv4_data_input_fd);
    }

    if (default_rloc_afi == AF_INET) {
        ipv6_data_input_fd = open_data_input_socket(AF_INET6);
        sockmstr_register_read_listener(smaster, cb_func, NULL,
                ipv6_data_input_fd);
    }

    lisp_output_init();

    return(GOOD);
}


void test_elp()
{
    lisp_xtr_t *xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
    lisp_addr_t *laddr = lisp_addr_new_afi(LM_AFI_LCAF);
    lcaf_addr_t *lcaf = lisp_addr_get_lcaf(laddr);
    packet_tuple_t tuple;
    lcaf_addr_set_type(lcaf, LCAF_EXPL_LOC_PATH);

    elp_t *elp = elp_type_new();

    elp_node_t *en1 = xzalloc(sizeof(elp_node_t));
    en1->L = 0; en1->P = 0; en1->S = 1;
    en1->addr = lisp_addr_new(); lisp_addr_ip_from_char("1.1.1.1", en1->addr);

    elp_node_t *en2 = xzalloc(sizeof(elp_node_t));
    en2->L = 0; en2->P = 0; en2->S = 1;
    en2->addr = lisp_addr_new(); lisp_addr_ip_from_char("2.2.2.2", en2->addr);

    elp_node_t *en3 = xzalloc(sizeof(elp_node_t));
    en3->L = 0; en1->P = 0; en3->S = 1;
    en3->addr = lisp_addr_new(); lisp_addr_ip_from_char("3.3.3.3", en3->addr);

    glist_add_tail(en1, elp->nodes);
    glist_add_tail(en2, elp->nodes);
    glist_add_tail(en3, elp->nodes);
    lcaf->addr = elp;

    LMLOG(LWRN, "the generated lcaf: %s", lisp_addr_to_char(laddr));
    LMLOG(LWRN, "let's see now!");

    lisp_addr_t *eid = lisp_addr_new(); lisp_addr_ip_from_char("4.5.6.7", eid);
    uint8_t status = 1;
    locator_t *locator = locator_init_remote_full(laddr, status, 1, 100, 1, 100);
    mapping_t *mapping = mapping_init_local(eid);
    LMLOG(LWRN, "mapping created!");

    mapping_add_locator(mapping, locator);
    LMLOG(LWRN, "locator added!");
    local_map_db_add_mapping(xtr->local_mdb, mapping);
    local_map_db_dump(xtr->local_mdb, LWRN);

//    program_map_register(xtr, 0);

    LMLOG(LWRN, "removing mapping!");
    local_map_db_del_mapping(xtr->local_mdb, eid);

    lisp_addr_copy(&tuple.dst_addr, eid);
    lisp_addr_set_afi(&tuple.src_addr, LM_AFI_NO_ADDR);

    LMLOG(LWRN, "done. Sending map-request!");
    ctrl_get_forwarding_entry(&tuple);

    LMLOG(LWRN, "finished!");
//    lisp_addr_del(laddr);
//    free_mapping_elt(mapping, 1);
//    for(;;) {
//        sleep(1);
//    }
}



void signal_handler(int sig) {
    switch (sig) {
    case SIGHUP:
        /* TODO: SIGHUP should trigger reloading the configuration file */
        LMLOG(DBG_1, "Received SIGHUP signal.");
        break;
    case SIGTERM:
        /* SIGTERM is the default signal sent by 'kill'. Exit cleanly */
        LMLOG(DBG_1, "Received SIGTERM signal. Cleaning up...");
        exit_cleanup();
        break;
    case SIGINT:
        /* SIGINT is sent by pressing Ctrl-C. Exit cleanly */
        LMLOG(DBG_1, "Terminal interrupt. Cleaning up...");
        exit_cleanup();
        break;
    default:
        LMLOG(DBG_1,"Unhandled signal (%d)", sig);
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
    LMLOG(DBG_2,"Exist Clenup");

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
        LMLOG(DBG_1, "Starting the daemonizing process");
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
    err = handle_config_file(config_file);

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
#ifdef OPENWRT
    LMLOG(LINF,"LISPmob compiled for openWRT xTR\n");
#else
    LMLOG(LINF,"LISPmob compiled for linux xTR\n");
#endif


    /* Check for superuser privileges */
    if (geteuid()) {
        LMLOG(LINF,"Running %s requires superuser privileges! Exiting...\n",
                LISPD);
        exit_cleanup();
    }

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

    ctrl_dev_set_ctrl(ctrl_dev, lctrl);

    ctrl_init(lctrl);
    init_netlink();

    /* run lisp control device xtr/ms */
    if (!ctrl_dev) {
        LMLOG(DBG_1, "device NULL");
        exit(0);
    }
    ctrl_dev_run(ctrl_dev);

    /* EVENT LOOP */
    for (;;) {
        sockmstr_wait_on_all_read(smaster);
        sockmstr_process_all(smaster);
    }

    /* event_loop returned: bad! */
    LMLOG(LINF, "Exiting...");
    exit_cleanup();
    return(0);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
