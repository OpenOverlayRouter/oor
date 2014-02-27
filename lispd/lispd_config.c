/*
 * lispd_config.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
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
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 *
 */

#include "cmdline.h"
#include "confuse.h"
#include "lispd_afi.h"
#include "lispd_config.h"
#include "lispd_external.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_cache_entry.h"
#include "lispd_map_cache_db.h"
#include "lispd_mapping.h"
#include "lispd_rloc_probing.h"
#include "lispd_lcaf.h"
#include "lispd_control.h"
#include "elibs/htable/hash_table.h"




#ifdef OPENWRT
#include <uci.h>
#include <libgen.h>
#include <string.h>
#endif


int add_database_mapping(
        char   *eid,
        int    iid,
        char   *iface_name,
        int    priority_v4,
        int    weight_v4,
        int    priority_v6,
        int    weight_v6);

int add_local_db_mapping(cfg_t *map, HashTable *lcaf_ht);

int add_map_server(
        char       *map_server,
        int        key_type,
        char       *key,
        uint8_t    proxy_reply);

int add_proxy_etr_entry(
        char   *addr,
        int    priority,
        int    weight);

int add_server(
        char *server,
        lispd_addr_list_t  **list);

int add_static_map_cache_entry(
        char   *eid,
        int    iid,
        char   *rloc,
        int    priority,
        int    weight,
        HashTable *elp_hash);

void validate_rloc_probing_parameters (
        int probe_int,
        int probe_retries,
        int probe_retries_interval);


lisp_site_prefix *build_lisp_site_prefix(char *eidstr, uint32_t iid, int key_type, char *key,
        uint8_t more_specifics, uint8_t proxy_reply);

mapping_t *build_mapping_from_config(cfg_t *map, HashTable *lcaf_ht, int local);

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

void handle_lispd_command_line(
        int     argc,
        char    **argv)
{
    struct gengetopt_args_info args_info;

    if (cmdline_parser(argc, argv, &args_info) != 0){
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
    }else{
        debug_level = -1;
    }
    if (args_info.afi_given) {
        switch (args_info.afi_arg){
        case 0: /* afi given = 4 */
            default_rloc_afi = AF_INET;
            break;
        case 1: /* afi given = 6 */
            default_rloc_afi = AF_INET6;
            break;
        default:
            lispd_log_msg(LISP_LOG_INFO,"AFI must be IPv4 (-a 4) or IPv6 (-a 6)\n");
            break;
        }
    }else{
        default_rloc_afi = -1;
    }
}


#ifdef OPENWRT
/* Compiling for OpenWRT */

/* UCI parsing function (for OpenWRT) */

int handle_uci_lispd_config_file(char *uci_conf_file_path) {


    struct uci_context  *ctx                            = NULL;
    struct uci_package  *pck                            = NULL;
    struct uci_section  *s                              = NULL;
    struct uci_element  *e                              = NULL;
    int                 uci_debug                       = 0;
    int                 uci_retries                     = 0;
    int                 uci_rloc_probe_int              = 0;
    int                 uci_rloc_probe_retries          = 0;
    int                 uci_rloc_probe_retries_interval = 0;
    const char*         uci_site_id                     = NULL;
    const char*         uci_xtr_id                      = NULL;
    const char*         uci_address                     = NULL;
    int                 uci_key_type                    = 0;
    const char*         uci_key                         = NULL;
    int                 uci_proxy_reply                 = 0;
    int                 uci_priority_v4                 = 0;
    int                 uci_weigth_v4                   = 0;
    int                 uci_priority_v6                 = 0;
    int                 uci_weigth_v6                   = 0;
    int                 uci_priority                    = 0;
    int                 uci_weigth                      = 0;
    const char*         uci_interface                   = NULL;
    int                 uci_iid                         = -1;
    const char*         uci_rloc                        = NULL;
    const char*         uci_eid_prefix                  = NULL;

    char                *uci_conf_dir                   = NULL;
    char                *uci_conf_file                  = NULL;

    //arnatal TODO XXX: check errors for the whole function



    ctx = uci_alloc_context();

    if (ctx == NULL) {
        lispd_log_msg(LISP_LOG_CRIT, "Could not create UCI context. Exiting ...");
        exit_cleanup();
    }

    uci_conf_dir = dirname(strdup(uci_conf_file_path));
    uci_conf_file = basename(strdup(uci_conf_file_path));


    uci_set_confdir(ctx, uci_conf_dir);

    lispd_log_msg(LISP_LOG_DEBUG_1,"Conf dir: %s\n",ctx->confdir);

    uci_load(ctx,uci_conf_file,&pck);

    if (pck == NULL) {
        lispd_log_msg(LISP_LOG_CRIT, "Could not load conf file: %s. Exiting ...",uci_conf_file);
        uci_perror(ctx,"Error while loading packet ");
        uci_free_context(ctx);
        exit_cleanup();
    }


    lispd_log_msg(LISP_LOG_DEBUG_3,"package uci: %s\n",pck->ctx->confdir);


    uci_foreach_element(&pck->sections, e) {
        uci_debug = 0;
        uci_retries = 0;

        uci_address = NULL;
        uci_key_type = 0;
        uci_key = NULL;
        uci_proxy_reply = 0;
        uci_priority_v4 = 0;
        uci_weigth_v4 = 0;
        uci_priority_v6 = 0;
        uci_weigth_v6 = 0;
        uci_priority = 0;
        uci_weigth = 0;
        uci_iid = -1;
        uci_interface = NULL;
        uci_rloc = NULL;
        uci_eid_prefix = NULL;

        s = uci_to_section(e);

        if (strcmp(s->type, "daemon") == 0){

            uci_debug = strtol(uci_lookup_option_string(ctx, s, "debug"),NULL,10);


            if (debug_level == -1){//Used to not overwrite debug level passed by console
                if (uci_debug > 0)
                    debug_level = uci_debug;
                else
                    debug_level = 0;
                if (debug_level > 3)
                    debug_level = 3;
            }

            uci_retries = strtol(uci_lookup_option_string(ctx, s, "map_request_retries"),NULL,10);

            if (uci_retries >= 0 && uci_retries <= LISPD_MAX_RETRANSMITS){
                map_request_retries = uci_retries;
            }else if (uci_retries > LISPD_MAX_RETRANSMITS){
                map_request_retries = LISPD_MAX_RETRANSMITS;
                lispd_log_msg(LISP_LOG_WARNING, "Map-Request retries should be between 0 and %d. Using default value: %d",
                        LISPD_MAX_RETRANSMITS, LISPD_MAX_RETRANSMITS);
            }



            continue;
        }

        if (strcmp(s->type, "rloc-probing") == 0){
            uci_rloc_probe_int = strtol(uci_lookup_option_string(ctx, s, "rloc_probe_interval"),NULL,10);
            uci_rloc_probe_retries = strtol(uci_lookup_option_string(ctx, s, "rloc_probe_retries"),NULL,10);
            uci_rloc_probe_retries_interval = strtol(uci_lookup_option_string(ctx, s, "rloc_probe_retries_interval"),NULL,10);
            continue;
        }

        if (strcmp(s->type, "nat-traversal") == 0){
            if (strcmp(uci_lookup_option_string(ctx, s, "nat_aware"), "on") == 0){
                nat_aware = TRUE;
            }else{
                nat_aware = FALSE;
            }
            uci_site_id = uci_lookup_option_string(ctx, s, "site_ID");
            uci_xtr_id = uci_lookup_option_string(ctx, s, "xTR_ID");

            if (nat_aware == TRUE){
                if ((convert_hex_string_to_bytes(uci_site_id,site_ID.byte,8)) != GOOD){
                    lispd_log_msg(LISP_LOG_CRIT, "Configuration file: Wrong Site-ID format");
                    exit_cleanup();
                }
                if ((convert_hex_string_to_bytes(uci_xtr_id,xTR_ID.byte,16)) != GOOD){
                    lispd_log_msg(LISP_LOG_CRIT, "Configuration file: Wrong xTR-ID format");
                    exit_cleanup();
                }
            }

            continue;
        }



        if (strcmp(s->type, "map-resolver") == 0){
            uci_address = uci_lookup_option_string(ctx, s, "address");

            if (add_server((char *)uci_address, &map_resolvers) != GOOD){
                lispd_log_msg(LISP_LOG_CRIT,"Can't add %s Map Resolver.",uci_address);
            }else{
                lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to map-resolver list", uci_address);
            }
            continue;
        }


        if (strcmp(s->type, "map-server") == 0){

            uci_address = uci_lookup_option_string(ctx, s, "address");
            uci_key_type = strtol(uci_lookup_option_string(ctx, s, "key_type"),NULL,10);
            uci_key = uci_lookup_option_string(ctx, s, "key");

            if (strcmp(uci_lookup_option_string(ctx, s, "proxy_reply"), "on") == 0){
                uci_proxy_reply = TRUE;
            }else{
                uci_proxy_reply = FALSE;
            }

            if (add_map_server((char *)uci_address,
                    uci_key_type,
                    (char *)uci_key,
                    uci_proxy_reply) != GOOD ){
                lispd_log_msg(LISP_LOG_CRIT, "Can't add %s Map Server.", uci_address);
            }else{
                lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to map-server list", uci_address);
            }
            continue;
        }


        if (strcmp(s->type, "proxy-etr") == 0){
            uci_address = uci_lookup_option_string(ctx, s, "address");
            uci_priority = strtol(uci_lookup_option_string(ctx, s, "priority"),NULL,10);
            uci_weigth = strtol(uci_lookup_option_string(ctx, s, "weight"),NULL,10);

            if (add_proxy_etr_entry((char *)uci_address,
                    uci_priority,
                    uci_weigth) != GOOD ){
                lispd_log_msg(LISP_LOG_ERR, "Can't add proxy-etr %s", uci_address);
            }else{
                lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to proxy-etr list", uci_address);
            }
            continue;
        }


        if (strcmp(s->type, "database-mapping") == 0){
            uci_eid_prefix = uci_lookup_option_string(ctx, s, "eid_prefix");
            uci_interface = uci_lookup_option_string(ctx, s, "interface");
            uci_priority_v4 = strtol(uci_lookup_option_string(ctx, s, "priority_v4"),NULL,10);
            uci_weigth_v4 = strtol(uci_lookup_option_string(ctx, s, "weight_v4"),NULL,10);
            uci_priority_v6 = strtol(uci_lookup_option_string(ctx, s, "priority_v6"),NULL,10);
            uci_weigth_v6 = strtol(uci_lookup_option_string(ctx, s, "weight_v6"),NULL,10);

            if (add_database_mapping((char *)uci_eid_prefix,
                    uci_iid,
                    (char *)uci_interface,
                    uci_priority_v4,
                    uci_weigth_v4,
                    uci_priority_v6,
                    uci_weigth_v6) != GOOD ){
                lispd_log_msg(LISP_LOG_ERR, "Can't add EID prefix %s. Discarded ...",
                        uci_eid_prefix);
            }else{
                lispd_log_msg(LISP_LOG_DEBUG_1, "Added EID prefix %s in the database.",
                        uci_eid_prefix);
            }
            continue;
        }


        if (strcmp(s->type, "static-map-cache") == 0){
            uci_eid_prefix = uci_lookup_option_string(ctx, s, "eid_prefix");
            uci_rloc = uci_lookup_option_string(ctx, s, "rloc");
            uci_priority = strtol(uci_lookup_option_string(ctx, s, "priority"),NULL,10);
            uci_weigth = strtol(uci_lookup_option_string(ctx, s, "weight"),NULL,10);

            if (add_static_map_cache_entry((char *)uci_eid_prefix,
                    uci_iid,
                    (char *)uci_rloc,
                    uci_priority,
                    uci_weigth) != GOOD ){
                lispd_log_msg(LISP_LOG_WARNING,"Can't add static-map-cache (EID:%s -> RLOC:%s). Discarded ...",
                        uci_eid_prefix,
                        uci_rloc);

            }else{
                lispd_log_msg(LISP_LOG_DEBUG_1,"Added static-map-cache (EID:%s -> RLOC:%s)",
                        uci_eid_prefix,
                        uci_rloc);
            }
            continue;
        }


        if (strcmp(s->type, "proxy-itr") == 0){
            uci_address = uci_lookup_option_string(ctx, s, "address");

            if (add_server((char *)uci_address, &proxy_itrs) != GOOD){
                lispd_log_msg(LISP_LOG_ERR, "Can't add %s to proxy-itr list. Discarded ...", uci_address);
            }else{
                lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to proxy-itr list", uci_address);
            }
            continue;
        }

    }

    validate_rloc_probing_parameters (uci_rloc_probe_int, uci_rloc_probe_retries, uci_rloc_probe_retries_interval);

    if (!proxy_etrs){
        lispd_log_msg(LISP_LOG_WARNING, "No Proxy-ETR defined. Packets to non-LISP destinations will be "
                "forwarded natively (no LISP encapsulation). This may prevent mobility in some scenarios.");
        sleep(3);
    }

    if (debug_level == 1){
        lispd_log_msg (LISP_LOG_INFO, "Log levet: Low debug");
    }else if (debug_level == 2){
        lispd_log_msg (LISP_LOG_INFO, "Log levet: Medium debug");
    }else if (debug_level == 3){
        lispd_log_msg (LISP_LOG_INFO, "Log levet: High Debug ");
    }

    lispd_log_msg (LISP_LOG_DEBUG_1, "****** Summary of the configuration ******");
    local_map_db_dump(LISP_LOG_DEBUG_1);
    if (is_loggable(LISP_LOG_DEBUG_1)){
        map_cache_dump_db(LISP_LOG_DEBUG_1);
    }
    dump_map_servers(LISP_LOG_DEBUG_1);
    dump_servers(map_resolvers, "Map-Resolvers", LISP_LOG_DEBUG_1);
    dump_proxy_etrs(LISP_LOG_DEBUG_1);
    dump_servers(proxy_itrs, "Proxy-ITRs", LISP_LOG_DEBUG_1);

    uci_free_context(ctx);

    return(GOOD);
}

#else
/* OPENWRT is not defined */


/*
 *  handle_lispd_config_file --
 *
 *  Parse config file and set up whatever is needed
 *
 *  David Meyer
 *  dmm@1-4-5.net
 *  Wed Apr 21 13:31:00 2010
 *
 *  $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */


static void parse_elp_list(cfg_t *cfg, HashTable *ht) {
//    HashTable   *ht     = NULL;
    elp_node_t  *enode  = NULL;
    elp_t       *elp    = NULL;
    lisp_addr_t *laddr  = NULL;
    char        *name   = NULL;
    int i, j;

    for(i = 0; i < cfg_size(cfg, "explicit-locator-path"); i++) {
        cfg_t *selp = cfg_getnsec(cfg, "explicit-locator-path", i);
        name = cfg_getstr(selp, "elp-name");

        laddr = lisp_addr_new_afi(LM_AFI_LCAF);
        lisp_addr_lcaf_set_type(laddr, LCAF_EXPL_LOC_PATH);

        elp = elp_type_new();

        for (j = 0; j < cfg_size(selp, "elp-node");j++) {
            cfg_t *senode = cfg_getnsec(selp, "elp-node", j);
            enode = calloc(1, sizeof(elp_node_t));
            enode->addr = lisp_addr_new();
            if (get_lisp_addr_from_char(cfg_getstr(senode, "address"), enode->addr) != GOOD) {
                elp_node_del(enode);
                lispd_log_msg(LISP_LOG_DEBUG_1, "parse_elp_list: Couldn't parse ELP node %s",
                        cfg_getstr(senode, "address"));
                continue;
            }
            enode->L = cfg_getbool(senode, "lookup") ? 1 : 0;
            enode->P = cfg_getbool(senode, "probe") ? 1 : 0;
            enode->S = cfg_getbool(senode, "strict") ? 1: 0;

            glist_add_tail(enode, elp->nodes);
        }

        lisp_addr_lcaf_set_addr(laddr, (void *)elp);
        lispd_log_msg(LISP_LOG_DEBUG_1, "Configuration file: parsed explicit-locator-path: %s", lisp_addr_to_char(laddr));

        hash_table_insert(ht, strdup(name), laddr);
    }

}

static void parse_rle_list(cfg_t *cfg, HashTable *ht) {
    rle_node_t  *rnode  = NULL;
    rle_t       *rle    = NULL;
    lisp_addr_t *laddr  = NULL;
    char        *name   = NULL;
    int i, j;

    for (i = 0; i < cfg_size(cfg, "replication-list"); i++) {
        cfg_t *selp = cfg_getnsec(cfg, "replication-list", i);
        name = cfg_getstr(selp, "rle-name");

        laddr = lisp_addr_new_afi(LM_AFI_LCAF);
        lisp_addr_lcaf_set_type(laddr, LCAF_RLE);

        rle = rle_type_new();

        for (j = 0; j < cfg_size(selp, "rle-node"); j++) {
            cfg_t *rlenode = cfg_getnsec(selp, "rle-node", j);
            rnode = rle_node_new();
            if (get_lisp_addr_from_char(cfg_getstr(rlenode, "address"), rnode->addr) != GOOD) {
                rle_node_del(rnode);
                lispd_log_msg(LISP_LOG_DEBUG_1, "parse_rle_list: Couldn't parse RLE node %s",
                        cfg_getstr(rlenode, "address"));
            }
            rnode->level = cfg_getint(rlenode, "level");

            glist_add_tail(rnode, rle->nodes);
        }
        lisp_addr_lcaf_set_addr(laddr, (void *)rle);
        lispd_log_msg(LISP_LOG_DEBUG_1, "Configuration file: parsed replication-list: %s", lisp_addr_to_char(laddr));

        hash_table_insert(ht, strdup(name), laddr);
    }

}

static void parse_mcinfo_list(cfg_t *cfg, HashTable *ht) {
    mc_t        *mc     = NULL;
    lisp_addr_t *laddr  = NULL;
    char        *name   = NULL;
    int i;

    for (i = 0; i < cfg_size(cfg, "multicast-info"); i++) {
        cfg_t *mcnode = cfg_getnsec(cfg, "multicast-info", i);
        name = cfg_getstr(mcnode, "mc-info-name");

        laddr = lisp_addr_new_afi(LM_AFI_LCAF);
        lisp_addr_lcaf_set_type(laddr, LCAF_MCAST_INFO);

        mc = mc_type_new();
        get_lisp_addr_from_char(cfg_getstr(mcnode, "source"), mc->src);
        mc->src_plen = cfg_getint(mcnode, "source-mask-length");
        get_lisp_addr_from_char(cfg_getstr(mcnode, "group"), mc->grp);
        mc->src_plen = cfg_getint(mcnode, "group-mask-length");
        mc->iid = cfg_getint(mcnode, "iid");

        lisp_addr_lcaf_set_addr(laddr, mc);
        lispd_log_msg(LISP_LOG_DEBUG_1, "Configuration file: parsed multicast-info: %s", lisp_addr_to_char(laddr));

        hash_table_insert(ht, strdup(name), laddr);
    }

    lispd_log_msg(LISP_LOG_INFO, "Parsed configured multicast addresses");

}

static HashTable *parse_lcafs(cfg_t *cfg) {
    HashTable               *lcaf_ht                = NULL;

    /* create lcaf hash table */
    lcaf_ht = hash_table_new(g_str_hash, g_str_equal, free, (DestroyFunc)lisp_addr_del);
    parse_elp_list(cfg, lcaf_ht);
    parse_rle_list(cfg, lcaf_ht);
    parse_mcinfo_list(cfg, lcaf_ht);

    return(lcaf_ht);
}

int configure_rtr(cfg_t *cfg) {
    int                     i                       = 0;
    int                     n                       = 0;
    int                     ret                     = 0;
    int                     probe_int               = 0;
    int                     probe_retries           = 0;
    int                     probe_retries_interval  = 0;
    char                    *map_resolver           = NULL;
    HashTable               *lcaf_ht                = NULL;
    char                    *iface                  = NULL;


    /* initialize rtr - as a control device, it is only an xtr */
    ctrl_dev = rtr_ctrl_init();

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of static map cache entries  */
    lcaf_ht = parse_lcafs(cfg);


    ret = cfg_getint(cfg, "map-request-retries");
    if (ret != 0)
        map_request_retries = ret;


    /*
     *  RLOC Probing options
     */

    cfg_t *dm = cfg_getnsec(cfg, "rloc-probing", 0);
    if (dm != NULL){
        probe_int = cfg_getint(dm, "rloc-probe-interval");
        probe_retries = cfg_getint(dm, "rloc-probe-retries");
        probe_retries_interval = cfg_getint(dm, "rloc-probe-retries-interval");

        validate_rloc_probing_parameters (probe_int, probe_retries, probe_retries_interval);
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "Configuration file: RLOC probing not defined. "
                "Setting default values: RLOC Probing Interval: %d sec.",RLOC_PROBING_INTERVAL);
    }

    /*
     *  handle map-resolver config
     */
    n = cfg_size(cfg, "map-resolver");
    for(i = 0; i < n; i++) {
        if ((map_resolver = cfg_getnstr(cfg, "map-resolver", i)) != NULL) {
            if (add_server(map_resolver, &map_resolvers) == GOOD){
                lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to map-resolver list", map_resolver);
            }else{
                lispd_log_msg(LISP_LOG_CRIT,"Can't add %s Map Resolver.",map_resolver);
            }
        }
    }

    /* TODO: should work with all interfaces in the future */
    iface = cfg_getstr(cfg, "rtr-data-iface");
    if (iface) {
        if (!add_interface(iface))
            return(BAD);
    }

    /*
     *  handle static-map-cache config
     */

    n = cfg_size(cfg, "static-map-cache");
    for(i = 0; i < n; i++) {
        cfg_t *smc = cfg_getnsec(cfg, "static-map-cache", i);

        if (!add_static_map_cache_entry(cfg_getstr(smc, "eid-prefix"),
                cfg_getint(smc, "iid"),
                cfg_getstr(smc, "rloc"),
                cfg_getint(smc, "priority"),
                cfg_getint(smc, "weight"),
                lcaf_ht)

        ) {
            lispd_log_msg(LISP_LOG_WARNING,"Can't add static-map-cache (EID:%s -> RLOC:%s). Discarded ...",
                    cfg_getstr(smc, "eid-prefix"),
                    cfg_getstr(smc, "rloc"));
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1,"Added static-map-cache (EID:%s -> RLOC:%s)",
                    cfg_getstr(smc, "eid-prefix"),
                    cfg_getstr(smc, "rloc"));
        }
    }


    /*
     * RTR database mappings (like for instance replication lists (
     */

    n = cfg_size(cfg, "rtr-database-mapping");
    for (i = 0; i < n; i++) {
        add_local_db_mapping(cfg_getnsec(cfg, "rtr-database-mapping", i), lcaf_ht);
    }


    /*
     *  handle map-server config
     */

    n = cfg_size(cfg, "map-server");
    for(i = 0; i < n; i++) {
        cfg_t *ms = cfg_getnsec(cfg, "map-server", i);
        if (add_map_server(cfg_getstr(ms, "address"),
                cfg_getint(ms, "key-type"),
                cfg_getstr(ms, "key"),
                (cfg_getbool(ms, "proxy-reply") ? 1:0))== GOOD
        ){
            lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to map-server list",cfg_getstr(ms, "address"));
        }else {
            lispd_log_msg(LISP_LOG_WARNING, "Can't add %s Map Server.",cfg_getstr(ms, "address"));
        }
    }



    hash_table_destroy(lcaf_ht);

    return(GOOD);
}

int configure_xtr(cfg_t *cfg) {

    int                     i                       = 0;
    int                     n                       = 0;
    int                     ret                     = 0;
    char                    *map_resolver           = NULL;
    char                    *proxy_itr              = NULL;
    char                    *nat_site_ID            = NULL;
    char                    *nat_xTR_ID             = NULL;
    int                     probe_int               = 0;
    int                     probe_retries           = 0;
    int                     probe_retries_interval  = 0;
    int                     ctr                     = 0;
    HashTable               *lcaf_ht                = NULL;

    /* initialize xtr */
    ctrl_dev = (lisp_ctrl_device *)xtr_ctrl_init();

    /* create lcaf hash table */
    lcaf_ht = hash_table_new(g_str_hash, g_str_equal, free, (DestroyFunc)lisp_addr_del);

    ret = cfg_getint(cfg, "map-request-retries");
    if (ret != 0)
        map_request_retries = ret;

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of database mappings
     * or static map cache entries  */
    lcaf_ht = parse_lcafs(cfg);


    /*
     *  RLOC Probing options
     */

    cfg_t *dm = cfg_getnsec(cfg, "rloc-probing", 0);
    if (dm != NULL){
        probe_int = cfg_getint(dm, "rloc-probe-interval");
        probe_retries = cfg_getint(dm, "rloc-probe-retries");
        probe_retries_interval = cfg_getint(dm, "rloc-probe-retries-interval");

        validate_rloc_probing_parameters (probe_int, probe_retries, probe_retries_interval);
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "Configuration file: RLOC probing not defined. "
                "Setting default values: RLOC Probing Interval: %d sec.",RLOC_PROBING_INTERVAL);
    }


    /*
     * Nat Traversal options
     */
    cfg_t *nt = cfg_getnsec(cfg, "nat-traversal", 0);
    if (nt != NULL){
        nat_aware   = cfg_getbool(nt, "nat_aware") ? TRUE:FALSE;
        nat_site_ID = cfg_getstr(nt, "site_ID");
        nat_xTR_ID  = cfg_getstr(nt, "xTR_ID");
        if (nat_aware == TRUE){
            if ((convert_hex_string_to_bytes(nat_site_ID,site_ID.byte,8)) != GOOD){
                lispd_log_msg(LISP_LOG_CRIT, "Configuration file: Wrong Site-ID format");
                exit_cleanup();
            }
            if ((convert_hex_string_to_bytes(nat_xTR_ID,xTR_ID.byte,16)) != GOOD){
                lispd_log_msg(LISP_LOG_CRIT, "Configuration file: Wrong xTR-ID format");
                exit_cleanup();
            }
        }
    }else {
        nat_aware = FALSE;
    }

    /*
     *  LISP config options
     */

    /*
     *  handle map-resolver config
     */
    n = cfg_size(cfg, "map-resolver");
    for(i = 0; i < n; i++) {
        if ((map_resolver = cfg_getnstr(cfg, "map-resolver", i)) != NULL) {
            if (add_server(map_resolver, &map_resolvers) == GOOD){
                lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to map-resolver list", map_resolver);
            }else{
                lispd_log_msg(LISP_LOG_CRIT,"Can't add %s Map Resolver.",map_resolver);
            }
        }
    }


    /*
     *  handle proxy-etr config
     */


    n = cfg_size(cfg, "proxy-etr");
    for(i = 0; i < n; i++) {
        cfg_t *petr = cfg_getnsec(cfg, "proxy-etr", i);
        if (add_proxy_etr_entry(cfg_getstr(petr, "address"),
                cfg_getint(petr, "priority"),
                cfg_getint(petr, "weight")) == GOOD) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to proxy-etr list", cfg_getstr(petr, "address"));
        } else{
            lispd_log_msg(LISP_LOG_ERR, "Can't add proxy-etr %s", cfg_getstr(petr, "address"));
        }
    }


    /*
     *  handle proxy-itr config
     */

    n = cfg_size(cfg, "proxy-itrs");
    for(i = 0; i < n; i++) {
        if ((proxy_itr = cfg_getnstr(cfg, "proxy-itrs", i)) != NULL) {
            if (add_server(proxy_itr, &proxy_itrs)==GOOD){
                lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to proxy-itr list", proxy_itr);
            }else {
                lispd_log_msg(LISP_LOG_ERR, "Can't add %s to proxy-itr list. Discarded ...", proxy_itr);
            }
        }
    }

    /*
     *  handle database-mapping config
     */

    n = cfg_size(cfg, "database-mapping");
    for(i = 0; i < n; i++) {
        ctr ++;
        cfg_t *dm = cfg_getnsec(cfg, "database-mapping", i);
        if (add_database_mapping(cfg_getstr(dm, "eid-prefix"),
                cfg_getint(dm, "iid"),
                cfg_getstr(dm, "interface"),
                cfg_getint(dm, "priority_v4"),
                cfg_getint(dm, "weight_v4"),
                cfg_getint(dm, "priority_v6"),
                cfg_getint(dm, "weight_v6")) == GOOD) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "Added EID %s in the database.",
                    cfg_getstr(dm, "eid-prefix"));
        }else{
            lispd_log_msg(LISP_LOG_ERR, "Can't add database-mapping %s. Discarded ...",
                    cfg_getstr(dm, "eid-prefix"));
        }
    }



    n = cfg_size(cfg, "database-mapping-new");
    for (i = 0; i < n; i++) {
        add_local_db_mapping(cfg_getnsec(cfg, "database-mapping-new", i), lcaf_ht);
    }




    /*
     *  handle map-server config
     */

    n = cfg_size(cfg, "map-server");
    for(i = 0; i < n; i++) {
        cfg_t *ms = cfg_getnsec(cfg, "map-server", i);
        if (add_map_server(cfg_getstr(ms, "address"),
                cfg_getint(ms, "key-type"),
                cfg_getstr(ms, "key"),
                (cfg_getbool(ms, "proxy-reply") ? 1:0))== GOOD
        ){
            lispd_log_msg(LISP_LOG_DEBUG_1, "Added %s to map-server list",cfg_getstr(ms, "address"));
        }else {
            lispd_log_msg(LISP_LOG_WARNING, "Can't add %s Map Server.",cfg_getstr(ms, "address"));
        }
    }

    /*
     *  handle static-map-cache config
     */


    n = cfg_size(cfg, "static-map-cache");
    for(i = 0; i < n; i++) {
        cfg_t *smc = cfg_getnsec(cfg, "static-map-cache", i);

        if (!add_static_map_cache_entry(cfg_getstr(smc, "eid-prefix"),
                cfg_getint(smc, "iid"),
                cfg_getstr(smc, "rloc"),
                cfg_getint(smc, "priority"),
                cfg_getint(smc, "weight"),
                lcaf_ht)

        ) {
            lispd_log_msg(LISP_LOG_WARNING,"Can't add static-map-cache (EID:%s -> RLOC:%s). Discarded ...",
                    cfg_getstr(smc, "eid-prefix"),
                    cfg_getstr(smc, "rloc"));
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1,"Added static-map-cache (EID:%s -> RLOC:%s)",
                    cfg_getstr(smc, "eid-prefix"),
                    cfg_getstr(smc, "rloc"));
        }
    }


    /* Check configured parameters when NAT-T activated. These limitations will be removed in future release */
    if (nat_aware == TRUE){
        if (ctr > 1){
            lispd_log_msg(LISP_LOG_CRIT,"NAT aware on -> This version of LISPmob is limited to one EID prefix "
                    "and one interface when NAT-T is enabled");
            exit_cleanup();
        }

        if (map_servers->next != NULL || map_servers->address->afi != AF_INET){
            lispd_log_msg(LISP_LOG_INFO,"NAT aware on -> This version of LISPmob is limited to one IPv4 Map Server.");
            exit_cleanup();
        }

        if (map_resolvers->next != NULL || map_resolvers->address->afi != AF_INET){
            lispd_log_msg(LISP_LOG_INFO,"NAT aware on -> This version of LISPmob is limited to one IPv4 Map Resolver.");
            exit_cleanup();
        }

        if (rloc_probe_interval > 0){
            rloc_probe_interval = 0;
            lispd_log_msg(LISP_LOG_INFO,"NAT aware on -> disabling RLOC Probing");
        }
    }

    /* destroy the hash table */
    hash_table_destroy(lcaf_ht);


    /* Check number of EID prefixes */
#ifndef ROUTER
    if (local_map_db_num_ip_eids(AF_INET) > 1){
        lispd_log_msg (LISP_LOG_ERR, "LISPmob in mobile node mode only supports one IPv4 EID prefix and one IPv6 EID prefix");
        exit_cleanup();
    }
    if (local_map_db_num_ip_eids(AF_INET6) > 1){
        lispd_log_msg (LISP_LOG_ERR, "LISPmob in mobile node mode only supports one IPv4 EID prefix and one IPv6 EID prefix");
        exit_cleanup();
    }
#endif


    lispd_log_msg (LISP_LOG_DEBUG_1, "****** Summary of the configuration ******");
    local_map_db_dump(LISP_LOG_DEBUG_1);
    if (is_loggable(LISP_LOG_DEBUG_1)){
        map_cache_dump_db(LISP_LOG_DEBUG_1);
    }

    dump_map_servers(LISP_LOG_DEBUG_1);
    dump_servers(map_resolvers, "Map-Resolvers", LISP_LOG_DEBUG_1);
    dump_proxy_etrs(LISP_LOG_DEBUG_1);
    dump_servers(proxy_itrs, "Proxy-ITRs", LISP_LOG_DEBUG_1);

    return(GOOD);

}

int configure_ms(cfg_t *cfg) {
    char                *iface  = NULL;
    lisp_site_prefix    *site   = NULL;
    HashTable           *lcaf_ht    = NULL;
    int i;

    ctrl_dev = (lisp_ctrl_device *)ms_ctrl_init();


    /* create lcaf hash table */
    lcaf_ht = parse_lcafs(cfg);

    /*
     * handle control interface
     */

    /* TODO: should work with all interfaces in the future */
    iface = cfg_getstr(cfg, "control-iface");
    if (iface) {
        if (!add_interface(iface))
            return(BAD);
    }

    /*
     *  handle lisp-site config
     */

    for (i = 0; i < cfg_size(cfg, "lisp-site"); i++) {
        cfg_t *ls = cfg_getnsec(cfg, "lisp-site", i);
        site = build_lisp_site_prefix(cfg_getstr(ls, "eid-prefix"),
                cfg_getint(ls, "iid"),
                cfg_getint(ls, "key-type"),
                cfg_getstr(ls, "key"),
                cfg_getbool(ls, "accept-more-specifics") ? 1:0,
                cfg_getbool(ls, "proxy-reply") ? 1:0);
        if (site) {
            ms_add_lisp_site_prefix(ctrl_dev, site);
            lispd_log_msg(LISP_LOG_DEBUG_1, "Added lisp site prefix %s to the lisp-sites database.",
                    cfg_getstr(ls, "eid-prefix"));
        }else{
            lispd_log_msg(LISP_LOG_ERR, "Can't add lisp-site prefix %s. Discarded ...",
                    cfg_getstr(ls, "eid-prefix"));
        }
    }

    for (i = 0; i< cfg_size(cfg, "ms-static-registered-site"); i++ ) {
        cfg_t *mss = cfg_getnsec(cfg, "ms-static-registered-site", i);
        mapping_t *mapping = build_mapping_from_config(mss, lcaf_ht, 0);
        if (ms_add_registered_site_prefix(ctrl_dev, mapping) != GOOD)
            lispd_log_msg(LISP_LOG_DEBUG_1, "Failed to add static registered site for %s to the registered sites list!",
                    lisp_addr_to_char(mapping_eid(mapping)));
        else
            lispd_log_msg(LISP_LOG_DEBUG_1, "Added static registered site for %s to the registered sites list!",
                    lisp_addr_to_char(mapping_eid(mapping)));
    }

    /* destroy the hash table */
    hash_table_destroy(lcaf_ht);

    return(GOOD);
}

int handle_lispd_config_file(char * lispdconf_conf_file)
{
    int                     ret                     = 0;
    cfg_t                   *cfg                    = 0;
    char                    *mode                   = NULL;


    /* xTR specific */
    static cfg_opt_t map_server_opts[] = {
            CFG_STR("address",              0, CFGF_NONE),
            CFG_INT("key-type",             0, CFGF_NONE),
            CFG_STR("key",                  0, CFGF_NONE),
            CFG_BOOL("proxy-reply", cfg_false, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t db_mapping_opts[] = {
            CFG_STR("eid-prefix",           0, CFGF_NONE),
            CFG_INT("iid",                 -1, CFGF_NONE),
            CFG_STR("interface",            0, CFGF_NONE),
            CFG_INT("priority_v4",          0, CFGF_NONE),
            CFG_INT("weight_v4",            0, CFGF_NONE),
            CFG_INT("priority_v6",          0, CFGF_NONE),
            CFG_INT("weight_v6",            0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rloc_opts[] = {
            CFG_STR("address",       0, CFGF_NONE),
            CFG_INT("priority",      0, CFGF_NONE),
            CFG_INT("weight",        0, CFGF_NONE),
            CFG_END()
    };
    static cfg_opt_t db_mapping_opts_new[] = {
            CFG_STR("eid-prefix",           0, CFGF_NONE),
            CFG_INT("iid",                  0, CFGF_NONE),
            CFG_SEC("rloc",                 rloc_opts, CFGF_MULTI),
            CFG_END()
    };

    static cfg_opt_t mc_mapping_opts[] = {
            CFG_STR("eid-prefix",           0, CFGF_NONE),
            CFG_INT("iid",                 -1, CFGF_NONE),
            CFG_STR("rloc",                 0, CFGF_NONE),
            CFG_INT("priority",             0, CFGF_NONE),
            CFG_INT("weight",               0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t petr_mapping_opts[] = {
            CFG_STR("address",              0, CFGF_NONE),
            CFG_INT("priority",           255, CFGF_NONE),
            CFG_INT("weight",               0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t nat_traversal_opts[] = {
            CFG_BOOL("nat_aware",   cfg_false, CFGF_NONE),
            CFG_STR("site_ID",              0, CFGF_NONE),
            CFG_STR("xTR_ID",               0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rloc_probing_opts[] = {
            CFG_INT("rloc-probe-interval",           0, CFGF_NONE),
            CFG_INT("rloc-probe-retries",            0, CFGF_NONE),
            CFG_INT("rloc-probe-retries-interval",   0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t elp_node_opts[] = {
            CFG_STR("address",      0,          CFGF_NONE),
            CFG_BOOL("strict",      cfg_false,  CFGF_NONE),
            CFG_BOOL("probe",       cfg_false,  CFGF_NONE),
            CFG_BOOL("lookup",      cfg_false,  CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t elp_opts[] = {
            CFG_STR("elp-name",     0,              CFGF_NONE),
            CFG_SEC("elp-node",     elp_node_opts,  CFGF_MULTI),
            CFG_END()
    };

    static cfg_opt_t rle_node_opts[] = {
            CFG_STR("address",      0,          CFGF_NONE),
            CFG_INT("level",        0,          CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rle_opts[] = {
            CFG_STR("rle-name",     0,              CFGF_NONE),
            CFG_SEC("rle-node",     rle_node_opts,  CFGF_MULTI),
            CFG_END()
    };

    static cfg_opt_t mc_info_opts[] = {
            CFG_STR("mc-info-name",     0,              CFGF_NONE),
            CFG_STR("source",           0,              CFGF_NONE),
            CFG_INT("source-mask-length", 0,            CFGF_NONE),
            CFG_STR("group",            0,              CFGF_NONE),
            CFG_INT("group-mask-length", 0,             CFGF_NONE),
            CFG_INT("iid",              0,              CFGF_NONE),
            CFG_END()
    };

    /* Map-Server specific */
    static cfg_opt_t lisp_site_opts[] = {
            CFG_STR("eid-prefix",               0, CFGF_NONE),
            CFG_INT("iid",                      0, CFGF_NONE),
            CFG_INT("key-type",                 0, CFGF_NONE),
            CFG_STR("key",                      0, CFGF_NONE),
            CFG_BOOL("accept-more-specifics",   cfg_false, CFGF_NONE),
            CFG_BOOL("proxy-reply",             cfg_false, CFGF_NONE),
            CFG_END()
    };

    cfg_opt_t opts[] = {
            CFG_SEC("database-mapping",     db_mapping_opts,        CFGF_MULTI),
            CFG_SEC("database-mapping-new", db_mapping_opts_new,    CFGF_MULTI),
            CFG_SEC("ms-static-registered-site", db_mapping_opts_new, CFGF_MULTI),
            CFG_SEC("rtr-database-mapping", db_mapping_opts_new,    CFGF_MULTI),
            CFG_SEC("static-map-cache",     mc_mapping_opts,        CFGF_MULTI),
            CFG_SEC("map-server",           map_server_opts,        CFGF_MULTI),
            CFG_SEC("proxy-etr",            petr_mapping_opts,      CFGF_MULTI),
            CFG_SEC("nat-traversal",        nat_traversal_opts,     CFGF_MULTI),
            CFG_SEC("rloc-probing",         rloc_probing_opts,      CFGF_MULTI),
            CFG_INT("map-request-retries",  0, CFGF_NONE),
            CFG_INT("control-port",         0, CFGF_NONE),
            CFG_INT("debug",                0, CFGF_NONE),
            CFG_INT("rloc-probing-interval",0, CFGF_NONE),
            CFG_STR_LIST("map-resolver",    0, CFGF_NONE),
            CFG_STR_LIST("proxy-itrs",      0, CFGF_NONE),
            CFG_STR("operating-mode",       0, CFGF_NONE),
            CFG_STR("control-iface",        0, CFGF_NONE),
            CFG_STR("rtr-data-iface",        0, CFGF_NONE),
            CFG_SEC("lisp-site",            lisp_site_opts,         CFGF_MULTI),
            CFG_SEC("explicit-locator-path", elp_opts,              CFGF_MULTI),
            CFG_SEC("replication-list",     rle_opts,               CFGF_MULTI),
            CFG_SEC("multicast-info",       mc_info_opts,           CFGF_MULTI),
            CFG_END()
    };

    /*
     *  parse config_file
     */

    cfg = cfg_init(opts, CFGF_NOCASE);
    ret = cfg_parse(cfg, lispdconf_conf_file);

    if (ret == CFG_FILE_ERROR) {
        lispd_log_msg(LISP_LOG_CRIT, "Couldn't find config file %s, exiting...", config_file);
        exit_cleanup();
    } else if(ret == CFG_PARSE_ERROR) {
        lispd_log_msg(LISP_LOG_CRIT, "Parse error in file %s, exiting. Check conf file (see lispd.conf.example)", config_file);
        exit_cleanup();
    }


    /*
     *  lispd config options
     */


    /*
     * Debug level
     */

    if (debug_level == -1){
        ret = cfg_getint(cfg, "debug");
        if (ret > 0)
            debug_level = ret;
        else
            debug_level = 0;
        if (debug_level > 3)
            debug_level = 3;
    }

    if (debug_level == 1){
        lispd_log_msg (LISP_LOG_INFO, "Log level: Low debug");
    }else if (debug_level == 2){
        lispd_log_msg (LISP_LOG_INFO, "Log level: Medium debug");
    }else if (debug_level == 3){
        lispd_log_msg (LISP_LOG_INFO, "Log level: High Debug");
    }


    mode = cfg_getstr(cfg, "operating-mode");
    if (mode) {
        if (strcmp(mode, "xTR") == 0) {
            ret=configure_xtr(cfg);
        }
        if (strcmp(mode, "MS") == 0) {
            ret=configure_ms(cfg);
        }
        if (strcmp(mode, "RTR") == 0) {
            ret=configure_rtr(cfg);
        }
    }

    cfg_free(cfg);
    return(GOOD);
}



#endif
/* ifdef OPENWRT*/


/*
 *  add_database_mapping
 *
 *  Get a single database mapping 
 *
 *  David Meyer <dmm@1-4-5.net>
 *  Preethi Natarajan <prenatar@cisco.com>
 *
 */

int add_database_mapping(
        char   *eid,
        int    iid,
        char   *iface_name,
        int    priority_v4,
        int    weight_v4,
        int    priority_v6,
        int    weight_v6)

{
    mapping_t           *mapping            = NULL;
    locator_t           *locator            = NULL;
    lispd_iface_elt             *interface          = NULL;
    lisp_addr_t                 eid_prefix;           /* save the eid_prefix here */
    int                         eid_prefix_length   = 0;
    uint8_t                     is_new_mapping      = FALSE;


    if (iface_name == NULL){
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: No interface specificated for database mapping. Ignoring mapping");
        return (BAD);
    }

    if (iid > MAX_IID || iid < -1) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Instance ID %d out of range [0..%d], disabling...", iid, MAX_IID);
        iid = -1;
    }

    if (priority_v4 < (MAX_PRIORITY - 1) || priority_v4 > UNUSED_RLOC_PRIORITY) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Priority %d out of range [%d..%d], set minimum priority...",
                priority_v4, MAX_PRIORITY, UNUSED_RLOC_PRIORITY);
        priority_v4 = MIN_PRIORITY;
    }

    if (priority_v6 < (MAX_PRIORITY - 1)|| priority_v6 > UNUSED_RLOC_PRIORITY) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Priority %d out of range [%d..%d], set minimum priority...",
                priority_v6, MAX_PRIORITY, UNUSED_RLOC_PRIORITY);
        priority_v6 = MIN_PRIORITY;
    }

    if (weight_v4 < (MIN_WEIGHT) || weight_v4 > MAX_WEIGHT) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Weight %d out of range [%d..%d], set weight to 100...",
                weight_v4, MIN_WEIGHT, MAX_WEIGHT);
        weight_v4 = 100;
    }

    if (weight_v6 < (MIN_WEIGHT) || weight_v6 > MAX_WEIGHT) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Weight %d out of range [%d..%d], set weight to 100...",
                weight_v6, MIN_WEIGHT, MAX_WEIGHT);
        weight_v6 = 100;
    }


    if (get_lisp_addr_and_mask_from_char(eid,&eid_prefix,&eid_prefix_length)!=GOOD){
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Error parsing EID address");
        return (BAD);
    }

    if (if_nametoindex(iface_name) == 0) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: INVALID INTERFACE or not initialized virtual interface"
                ": %s ", iface_name);
    }

    /*
     * Lookup if the mapping exists. If not, a new mapping is created.
     */
    mapping = local_map_db_lookup_eid_exact(&eid_prefix);

    if (mapping == NULL) {
        mapping = new_local_mapping(eid_prefix,eid_prefix_length,iid);
        if (mapping == NULL) {
            lispd_log_msg(LISP_LOG_ERR,"Configuration file: mapping %s could not be added",eid);
            return (BAD);
        }
        /* Add the mapping to the local database */
        if (local_map_db_add_mapping(mapping)!=GOOD) {
            mapping_del(mapping);
            return (BAD);
        }
        is_new_mapping = TRUE;
    }else{
        if (mapping->iid != iid){
            lispd_log_msg(LISP_LOG_ERR,"Same EID prefix with different iid. This configuration is not supported..."
                    "Ignoring EID prefix.");
            return (BAD);
        }
        is_new_mapping = FALSE;
    }



    /*
     * Add the interface.
     */
    /* Check if the interface already exists. If not, add it*/
    if ((interface=get_interface(iface_name))==NULL)
        interface = add_interface(iface_name);

    /* If we couldn't add the interface and the mapping is new, we remove it. */
    if (interface == NULL && is_new_mapping == TRUE){
        if (is_new_mapping){
            local_map_db_del_mapping(mapping_eid(mapping));
            lispd_log_msg(LISP_LOG_WARNING,"add_database_mapping: Couldn't add mapping -> Could't create interface");
        }else{
            lispd_log_msg(LISP_LOG_WARNING,"add_database_mapping: Couldn't add locator to the mapping -> Cudn't create interface");
        }
        return (BAD);
    }

    /* Assign the mapping to the v4 mappings of the interface. Create IPv4 locator and assign to the mapping  */
    if (priority_v4 >= 0){
        if ((err = add_mapping_to_interface (interface, mapping, AF_INET)) == GOOD){
            locator = new_local_locator (interface->ipv4_address,&(interface->status),priority_v4,weight_v4,255,0,&(interface->out_socket_v4));
            if (locator != NULL){
                if ((err=add_locator_to_mapping (mapping,locator))!=GOOD){
                    return (BAD);
                }
            }else{
                return (BAD);
            }
        }else {
            return (BAD);
        }
    }
    /* Assign the mapping to the v6 mappings of the interface. Create IPv6 locator and assign to the mapping  */
    if (priority_v6 >= 0){
        if ((err = add_mapping_to_interface (interface, mapping, AF_INET6)) == GOOD){
            locator = new_local_locator (interface->ipv6_address,&(interface->status),priority_v6,weight_v6,255,0,&(interface->out_socket_v6));
            if (locator != NULL){
                if ((err=add_locator_to_mapping (mapping,locator))!=GOOD){
                    return (BAD);
                }
            }else{
                return (BAD);
            }
        }else{
            return (BAD);
        }
    }

    /* Recalculate the outgoing rloc vectors */
    if (calculate_balancing_vectors (mapping,&((lcl_mapping_extended_info *)mapping->extended_info)->outgoing_balancing_locators_vecs) != GOOD){
        lispd_log_msg(LISP_LOG_WARNING,"add_database_mapping: Couldn't calculate outgoing rloc prefenernce");
    }

    return(GOOD);
}


char *get_interface_name_from_address(lisp_addr_t *addr) {
    char *iface  = NULL;

    if (lisp_addr_get_afi(addr) != LM_AFI_IP) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "get_interface_name_from_address: failed for %s. Function only "
                "supports IP syntax addresses!", lisp_addr_to_char(addr));
        return(NULL);
    }

    iface = hash_table_lookup(iface_addr_ht, lisp_addr_to_char(addr));
//    lispd_log_msg(LISP_LOG_DEBUG_1, "iface %s and strlen addr %d", iface, strlen(lisp_addr_to_char(addr)));
    if (iface)
        return((char *)iface);
    else
        return(NULL);

}

locator_t *parse_locator(char *address, int priority, int weight,
        HashTable *lcaf_ht, int local)
{

    char                *iface_name         = NULL;
    locator_t           *locator            = NULL;
    lisp_addr_t         *lcaf_rloc          = NULL;
    lispd_iface_elt     *interface          = NULL;
    lisp_addr_t         *rloc               = NULL;
    lisp_addr_t         *aux_rloc           = NULL;


    if (priority < (MAX_PRIORITY - 1) || priority > UNUSED_RLOC_PRIORITY) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Priority %d out of range [%d..%d], set minimum priority...",
                priority, MAX_PRIORITY, UNUSED_RLOC_PRIORITY);
        priority = MIN_PRIORITY;
    }


    if (weight < (MIN_WEIGHT) || weight > MAX_WEIGHT) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Weight %d out of range [%d..%d], set weight to 100...",
                weight, MIN_WEIGHT, MAX_WEIGHT);
        weight = 100;
    }

    rloc = lisp_addr_new();
    if (get_lisp_addr_from_char(address, rloc)!=GOOD) {
        lisp_addr_del(rloc);
        lcaf_rloc = hash_table_lookup(lcaf_ht, address);
        if(!lcaf_rloc){
            lispd_log_msg(LISP_LOG_ERR, "Configuration file: Error parsing RLOC address %s", address);
            return (NULL);
        }
    }


    if (local) {
        /* LOCAL locator */

        /* decide rloc to be used to lookup the interface */
        if (lcaf_rloc) {
            aux_rloc = lcaf_rloc_get_ip_addr(lcaf_rloc);
            if (!aux_rloc) {
                lispd_log_msg(LISP_LOG_ERR, "Configuration file: Can't determine RLOC address %s", lisp_addr_to_char(lcaf_rloc));
                lisp_addr_del(lcaf_rloc);
                return(NULL);
            }
        } else {
            aux_rloc = rloc;
        }

        if (!(iface_name = get_interface_name_from_address(aux_rloc))) {
            lispd_log_msg(LISP_LOG_ERR, "Configuration file: Can't find interface for RLOC %s", lisp_addr_to_char(aux_rloc));
            lisp_addr_del(aux_rloc);
            return(NULL);
        }

        if (!(interface = get_interface(iface_name))) {
            if (!(interface = add_interface(iface_name))) {
                lisp_addr_del(aux_rloc);
            }
        }

        if (!lcaf_rloc) {
            locator = new_local_locator(rloc,&(interface->status), priority, weight, 255, 0, &(interface->out_socket_v4));
        }else {
            locator = new_local_locator(lisp_addr_clone(lcaf_rloc),&(interface->status), priority, weight, 255, 0, &(interface->out_socket_v4));
            if (!locator) {
                lispd_log_msg(LISP_LOG_DEBUG_1, "Configuration file: failed to create locator with addr %s",
                        lisp_addr_to_char(lcaf_rloc));
                return(NULL);
            }
        }
    } else {
        /* REMOTE locator */
        if (!lcaf_rloc)
            locator = locator_init_remote_full(rloc, 1, priority, weight, 255, 0);
        else
            locator = locator_init_remote_full(lisp_addr_clone(lcaf_rloc), 1, priority, weight, 255, 0);

        if (!locator) {
            lispd_log_msg(LISP_LOG_DEBUG_1, "Configuration file: failed to create locator with addr %s",
                    lisp_addr_to_char(rloc));
            return(NULL);
        }
    }

    return(locator);
}

mapping_t *build_mapping_from_config(cfg_t *map, HashTable *lcaf_ht, int local) {
    int i;
    mapping_t           *mapping            = NULL;
    locator_t           *locator            = NULL;
    lisp_addr_t         *eid_prefix;           /* save the eid_prefix here */
    lisp_addr_t         *new_eid            = NULL;
    int                 eid_prefix_length   = 0;
    int                 iid                 = 0;
    char                *address            = NULL;

    address = cfg_getstr(map, "eid-prefix");
    eid_prefix = lisp_addr_new();
    if (get_lisp_addr_and_mask_from_char(address, eid_prefix, &eid_prefix_length)!=GOOD){
        lisp_addr_del(eid_prefix);
        /* if not found, try in the hash table */
        eid_prefix = hash_table_lookup(lcaf_ht, address);
        if(!eid_prefix){
            lispd_log_msg(LISP_LOG_ERR, "Configuration file: Error parsing RLOC address %s", address);
            return (NULL);
        }
    }

    /* add iid to eid-prefix if different from 0 */
    iid = cfg_getint(map, "iid");

    if (iid > MAX_IID || iid < -1) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Instance ID %d out of range [0..%d], disabling...", iid, MAX_IID);
        iid = 0;
    }

    if (iid != 0) {
        new_eid = lisp_addr_new_afi(LM_AFI_LCAF);
        lisp_addr_lcaf_set_type(new_eid, LCAF_IID);
        /* XXX: mask not defined. Just filling in a value for now */
        lisp_addr_lcaf_set_addr(new_eid, (void *)iid_type_init(iid, eid_prefix, 32));
        eid_prefix = new_eid;
    }

    mapping = (local) ? mapping_init_local(eid_prefix) : mapping_init_remote(eid_prefix);

    for (i = 0; i < cfg_size(map, "rloc"); i++) {
        cfg_t *rl = cfg_getnsec(map, "rloc", i);
        if (local)
            locator = parse_locator(cfg_getstr(rl, "address"),
                    cfg_getint(rl, "priority"),
                    cfg_getint(rl, "weight"),
                    lcaf_ht, 1);
        else
            locator = parse_locator(cfg_getstr(rl, "address"),
                    cfg_getint(rl, "priority"),
                    cfg_getint(rl, "weight"),
                    lcaf_ht, 0);

        if (!locator) {
            lispd_log_msg(LISP_LOG_WARNING, "Configuration file: couldn't parse locator %s", cfg_getstr(rl, "address"));
            continue;
        }

        add_locator_to_mapping(mapping, locator);
    }

    /* Recalculate the outgoing rloc vectors */
    if (calculate_balancing_vectors (mapping,&((lcl_mapping_extended_info *)mapping->extended_info)->outgoing_balancing_locators_vecs) != GOOD){
        lispd_log_msg(LISP_LOG_WARNING,"add_database_mapping: Couldn't calculate outgoing rloc preference");
    }

    return(mapping);
}

int add_local_db_mapping(cfg_t *map, HashTable *lcaf_ht) {
    int i;
    mapping_t           *mapping            = NULL;
    locator_t           *locator            = NULL;
    lisp_addr_t         *eid_prefix;           /* save the eid_prefix here */
    lisp_addr_t         *new_eid            = NULL;
    int                 eid_prefix_length   = 0;
    int                 iid                 = 0;
    char                *address            = NULL;


    address = cfg_getstr(map, "eid-prefix");
    eid_prefix = lisp_addr_new();
    if (get_lisp_addr_and_mask_from_char(address, eid_prefix, &eid_prefix_length)!=GOOD){
        lisp_addr_del(eid_prefix);
        /* if not found, try in the hash table */
        eid_prefix = hash_table_lookup(lcaf_ht, address);
        if(!eid_prefix){
            lispd_log_msg(LISP_LOG_ERR, "Configuration file: Error parsing RLOC address %s", address);
            return(BAD);
        }
    }

    /* add iid to eid-prefix if different from 0 */
    iid = cfg_getint(map, "iid");

    if (iid > MAX_IID || iid < -1) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Instance ID %d out of range [0..%d], disabling...", iid, MAX_IID);
        iid = 0;
    }

    if (iid != 0) {
        new_eid = lisp_addr_new_afi(LM_AFI_LCAF);
        /* XXX: mask not defined. Just filling in a value for now */
        lisp_addr_lcaf_set_addr(new_eid, (void *)iid_type_init(iid, eid_prefix, 32));
        eid_prefix = new_eid;
    }

    mapping = local_map_db_lookup_eid_exact(eid_prefix);
    if (!mapping) {
        mapping = mapping_init_local(eid_prefix);
        local_map_db_add_mapping(mapping);
    } else {
        /* no need for the prefix */
        lisp_addr_del(eid_prefix);
    }

    for (i = 0; i < cfg_size(map, "rloc"); i++) {
        cfg_t *rl = cfg_getnsec(map, "rloc", i);
        locator = parse_locator(cfg_getstr(rl, "address"),
                cfg_getint(rl, "priority"),
                cfg_getint(rl, "weight"),
                lcaf_ht, 1);

        if (!locator) {
            lispd_log_msg(LISP_LOG_WARNING, "Configuration file: couldn't parse %s", cfg_getstr(rl, "address"));
            continue;
        }

        add_locator_to_mapping(mapping, locator);
    }

    /* Recalculate the outgoing rloc vectors */
    if (calculate_balancing_vectors (mapping,&((lcl_mapping_extended_info *)mapping->extended_info)->outgoing_balancing_locators_vecs) != GOOD){
        lispd_log_msg(LISP_LOG_WARNING,"add_database_mapping: Couldn't calculate outgoing rloc preference");
    }

    return(GOOD);
}


/*
 *  add_static_map_cache_entry --
 *
 *  Get a single static mapping
 *
 *  David Meyer
 *  dmm@1-4-5.net
 *  Wed Apr 21 13:31:00 2010
 *
 *  $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */

int add_static_map_cache_entry(
        char   *eid,
        int    iid,
        char   *rloc_addr,
        int    priority,
        int    weight,
        HashTable *elp_hash)
{
    mapping_t        *mapping;
    locator_t        *locator;
    lisp_addr_t      rloc;
    lisp_addr_t      *lcaf_rloc;
    lisp_addr_t              eid_prefix;
    int                      eid_prefix_length;


    if (iid > MAX_IID) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Instance ID %d out of range [0..%d], disabling...", iid, MAX_IID);
        iid = -1;
    }

    if (iid < 0)
        iid = -1;

    if (priority < MAX_PRIORITY || priority > UNUSED_RLOC_PRIORITY) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Priority %d out of range [%d..%d], set minimum priority...",
                priority, MAX_PRIORITY, UNUSED_RLOC_PRIORITY);
        priority = MIN_PRIORITY;
    }

    if (get_lisp_addr_and_mask_from_char(eid,&eid_prefix,&eid_prefix_length)!=GOOD){
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Error parsing EID address ...Ignoring static map cache entry");
        return (BAD);
    }

    /* HACK: change afi from IP to IPPREF and set mask */
    lisp_addr_set_afi(&eid_prefix, LM_AFI_IPPREF);
    ip_prefix_set_plen(lisp_addr_get_ippref(&eid_prefix), (uint8_t)eid_prefix_length);


    mapping = mapping_init_static(&eid_prefix);
    if (!mapping)
        return(BAD);

    /* TODO convert eid_prefix into lcaf */
    mapping->iid = iid;

//    map_cache_entry = new_map_cache_entry(eid_prefix, eid_prefix_length, STATIC_MAP_CACHE_ENTRY,255);
//    if (map_cache_entry == NULL)
//        return (BAD);
//
//    map_cache_entry->mapping->iid = iid;

    if (get_lisp_addr_from_char(rloc_addr, &rloc) == BAD){
        lcaf_rloc = hash_table_lookup(elp_hash, rloc_addr);
        if (!lcaf_rloc) {
            lispd_log_msg(LISP_LOG_ERR, "new_static_rmt_locator: Error parsing RLOC address ... Ignoring static map cache entry");
            return(BAD);
        }
        locator = new_static_rmt_locator(lcaf_rloc,UP,priority,weight,255,0);

    } else {
        locator = new_static_rmt_locator(&rloc,UP,priority,weight,255,0);
    }

    if (locator != NULL){
        if ((err=add_locator_to_mapping(mapping, locator)) != GOOD){
            return (BAD);
        }
    }else{
        return (BAD);
    }

    mcache_add_static_mapping(mapping);

    return (GOOD);
}

/*
 *  add a map-resolver to the list
 */

int add_server(
        char                *server,
        lispd_addr_list_t   **list)
{

    uint                afi;
    lisp_addr_t         *addr;
    lispd_addr_list_t   *list_elt;

//    if ((addr = malloc(sizeof(lisp_addr_t))) == NULL) {
//        lispd_log_msg(LISP_LOG_WARNING, "add_server: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
//        return(ERR_MALLOC);
//    }
//    memset(addr,0,sizeof(lisp_addr_t));


    afi = get_afi(server);
//    addr->afi = afi;
    addr = lisp_addr_new_afi(LM_AFI_IP);
    lisp_addr_ip_set_afi(addr, afi);

//    if (inet_pton(afi, server, &(addr->address)) != 1) {
    if (inet_pton(afi, server,  ip_addr_get_addr(lisp_addr_get_ip(addr))) != 1) {
        lispd_log_msg(LISP_LOG_ERR, "add_server: Wrong address format: %s", strerror(errno));
        lisp_addr_del(addr);
        return(BAD);
    }

    /*
     * Check that the afi of the map server matches with the default rloc afi (if it's defined).
     */
    if (default_rloc_afi != -1 && default_rloc_afi != lisp_addr_ip_get_afi(addr)){
        lispd_log_msg(LISP_LOG_WARNING, "The server %s will not be added due to the selected default rloc afi",server);
        lisp_addr_del(addr);
        return(BAD);
    }

    if ((list_elt = malloc(sizeof(lispd_addr_list_t))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "add_server: Unable to allocate memory for lispd_addr_list_t: %s", strerror(errno));
        lisp_addr_del(addr);
        return(BAD);
    }
    memset(list_elt,0,sizeof(lispd_addr_list_t));

    list_elt->address = addr;

    /*
     * hook this one to the front of the list
     */

    if (*list) {
        list_elt->next = *list;
        *list = list_elt;
    } else {
        *list = list_elt;
    }

    return(GOOD);
}

/*
 *  add_map_server to map_servers
 */

int add_map_server(
        char         *map_server,
        int          key_type,
        char         *key,
        uint8_t      proxy_reply)

{
    lisp_addr_t             *addr;
    lispd_map_server_list_t *list_elt;
    struct hostent          *hptr;

    if (map_server == NULL || key_type == 0 || key == NULL){
        lispd_log_msg(LISP_LOG_ERR, "Configuraton file: Wrong Map Server configuration.  Check configuration file");
        exit_cleanup();
    }

//    if ((addr = malloc(sizeof(lisp_addr_t))) == NULL) {
//        lispd_log_msg(LISP_LOG_WARNING, "add_map_server: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
//        return(BAD);
//    }

    /*
     *  make sure this is clean
     */
    // XXX alopez: to be revised

//    memset(addr,0,sizeof(lisp_addr_t));

    if (((hptr = gethostbyname2(map_server,AF_INET))  == NULL) &&
            ((hptr = gethostbyname2(map_server,AF_INET6)) == NULL)) {
        lispd_log_msg(LISP_LOG_WARNING, "can gethostbyname2 for map_server (%s)", map_server);
//        free(addr);
        return(BAD);
    }


//    memcpy((void *) &(addr->address),
//            (void *) *(hptr->h_addr_list), sizeof(lisp_addr_t));
//    addr->afi = hptr->h_addrtype;
    addr = lisp_addr_new_afi(LM_AFI_IP);
    ip_addr_init(lisp_addr_get_ip(addr), (void *) *(hptr->h_addr_list), hptr->h_addrtype);


    /*
     * Check that the afi of the map server matches with the default rloc afi (if it's defined).
     */
    if (default_rloc_afi != -1 && default_rloc_afi != addr->afi){
        lispd_log_msg(LISP_LOG_WARNING, "The map server %s will not be added due to the selected default rloc afi",map_server);
        lisp_addr_del(addr);
        return(BAD);
    }

    if ((list_elt = malloc(sizeof(lispd_map_server_list_t))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "add_map_server: Unable to allocate memory for lispd_map_server_list_t: %s", strerror(errno));
        lisp_addr_del(addr);
        return(BAD);
    }

    memset(list_elt,0,sizeof(lispd_map_server_list_t));

    list_elt->address     = addr;
    list_elt->key_type    = key_type;
    list_elt->key         = strdup(key);
    list_elt->proxy_reply = proxy_reply;

    /*
     * hook this one to the front of the list
     */

    if (map_servers) {
        list_elt->next = map_servers;
        map_servers = list_elt;
    } else {
        map_servers = list_elt;
    }

    return(GOOD);
}

/*
 *  add_proxy_etr_entry --
 *
 *  Add a proxy-etr entry
 *
 */

int add_proxy_etr_entry(
        char                        *address,
        int                         priority,
        int                         weight)
{

    lisp_addr_t                     aux_address;
    lisp_addr_t                     rloc;
    locator_t               *locator     = NULL;

    if (address == NULL){
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: The address of the Proxy ETR has not been specified. Discarding the entry");
        return (BAD);
    }

    /* Check the parameters */
    if (priority > 255 || priority < 0) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Priority %d out of range [0..255]", priority);
        return (BAD);
    }

    if (weight > 100 || weight < 0) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Weight %d out of range [0..100]", priority);
        return (BAD);
    }

    /*
     * Check that the afi of the map server matches with the default rloc afi (if it's defined).
     */
    if (default_rloc_afi != -1 && default_rloc_afi != get_afi(address)){
        lispd_log_msg(LISP_LOG_WARNING, "The proxy etr %s will not be added due to the selected default rloc afi",address);
        return(BAD);
    }

    /* Create the proxy-etrs map cache structure if it doesn't exist */
    if (proxy_etrs == NULL){
        if ((get_lisp_addr_from_char ("0.0.0.0", &aux_address))!=GOOD){
            return (BAD);
        }
        proxy_etrs = new_map_cache_entry_no_db (aux_address,0,STATIC_MAP_CACHE_ENTRY,0);
        if (proxy_etrs == NULL){
            return (BAD);
        }
    }

    if (get_lisp_addr_from_char(address, &rloc) == BAD){
        lispd_log_msg(LISP_LOG_ERR, "new_static_rmt_locator: Error parsing RLOC address ... Ignoring static map cache entry");
        return(BAD);
    }

    /* Create de locator representing the proxy-etr and add it to the mapping */
    locator = new_static_rmt_locator(&rloc,UP,priority,weight,255,0);

    if (locator != NULL){
        if ((err=add_locator_to_mapping (proxy_etrs->mapping, locator)) != GOOD){
            return (BAD);
        }
    }else{
        return (BAD);
    }

    return(GOOD);
}

void validate_rloc_probing_parameters (
        int probe_int,
        int probe_retries,
        int probe_retries_interval){

    if (probe_int  < 0){
        rloc_probe_interval = 0;
    }else{
        rloc_probe_interval = probe_int;
    }
    if (rloc_probe_interval > 0){
        lispd_log_msg(LISP_LOG_DEBUG_1, "RLOC Probing Interval: %d", rloc_probe_interval);
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "RLOC Probing dissabled");
    }

    if (rloc_probe_interval != 0){

        if(probe_retries > LISPD_MAX_RETRANSMITS){
            rloc_probe_retries = LISPD_MAX_RETRANSMITS;
            lispd_log_msg(LISP_LOG_WARNING, "RLOC Probing retries should be between 0 and %d. Using %d retries",
                    LISPD_MAX_RETRANSMITS, LISPD_MAX_RETRANSMITS);
        }else if (probe_retries < 0){
            rloc_probe_retries = 0;
            lispd_log_msg(LISP_LOG_WARNING, "RLOC Probing retries should be between 0 and %d. Using 0 retries",
                    LISPD_MAX_RETRANSMITS);
        }else{
            rloc_probe_retries = probe_retries;
        }

        if (rloc_probe_retries > 0){
            if (probe_retries_interval < LISPD_MIN_RETRANSMIT_INTERVAL){
                rloc_probe_retries_interval = LISPD_MIN_RETRANSMIT_INTERVAL;
                lispd_log_msg(LISP_LOG_WARNING, "RLOC Probing interval retries should be between %d and RLOC Probing interval. Using %d seconds",
                        LISPD_MIN_RETRANSMIT_INTERVAL,LISPD_MIN_RETRANSMIT_INTERVAL);
            }else if(probe_retries_interval > rloc_probe_interval){
                rloc_probe_retries_interval = rloc_probe_interval;
                lispd_log_msg(LISP_LOG_WARNING, "RLOC Probing interval retries should be between %d and RLOC Probing interval. Using %d seconds",
                        LISPD_MIN_RETRANSMIT_INTERVAL,rloc_probe_interval);
            }else{
                rloc_probe_retries_interval = probe_retries_interval;
            }
        }
    }
}

lisp_site_prefix *build_lisp_site_prefix(char *eidstr, uint32_t iid, int key_type, char *key,
        uint8_t more_specifics, uint8_t proxy_reply) {

    lisp_addr_t         *eid_prefix         = NULL;
    int                 eid_prefix_length   = 0;
    lisp_site_prefix    *site               = NULL;

    if (iid > MAX_IID) {
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Instance ID %d out of range [0..%d], disabling...", iid, MAX_IID);
        iid = -1;
    }

    if (iid < 0)
        iid = 0;


    /* EID prefix allocated here and added to the site prefix db
     * DON'T delete it!
     */
    eid_prefix = lisp_addr_new();
    if (get_lisp_addr_and_mask_from_char(eidstr,eid_prefix,&eid_prefix_length)!=GOOD){
        lispd_log_msg(LISP_LOG_ERR, "Configuration file: Error parsing EID address ...Ignoring static map cache entry");
        lisp_addr_del(eid_prefix);
        return (BAD);
    }

    /* HACK: change afi from IP to IPPREF and set mask */
    lisp_addr_set_afi(eid_prefix, LM_AFI_IPPREF);
    ip_prefix_set_plen(lisp_addr_get_ippref(eid_prefix), (uint8_t)eid_prefix_length);

    site = lisp_site_prefix_init(eid_prefix, iid, key_type, key, more_specifics, proxy_reply);
    return(site);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */

