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
 *    Florin Coras <fcoras@ac.upc.edu>
 *
 */

#include <netdb.h>

#include "cmdline.h"
#include "confuse.h"
#include "lispd_config.h"
#include "lispd_external.h"
#include "iface_list.h"
#include "lisp_ctrl_device.h"
#include "lisp_xtr.h"
#include "lisp_ms.h"
#include "lisp_control.h"
#include "shash.h"
#include "hash_table.h"
#include "lmlog.h"

#ifdef OPENWRT
#include <uci.h>
#include <libgen.h>
#include <string.h>
#endif


static int add_database_mapping(lisp_xtr_t *, char *, int, char *, int, int,
        int, int);
static int add_local_db_mapping(lisp_xtr_t *, cfg_t *, htable_t *);
static int add_map_server(lisp_xtr_t *, char *, int, char *, uint8_t);
static int add_proxy_etr_entry(lisp_xtr_t *, char *, int, int);
static int add_static_map_cache_entry(lisp_xtr_t *, char *, int, char *, int,
        int, htable_t *);
static int add_server(char *server, lisp_addr_list_t **list);

static void validate_rloc_probing_parameters(int *, int *, int *);

static lisp_site_prefix *build_lisp_site_prefix(lisp_ms_t *, char *, uint32_t,
        int, char *, uint8_t, uint8_t, uint8_t, htable_t *);
static mapping_t *build_mapping_from_config(cfg_t *, htable_t *, int);

static int link_iface_and_mapping(iface_t *, mapping_t *, int, int, int, int);
static int add_rtr_iface(lisp_xtr_t *, char *, int p, int w);


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
        LMLOG(LCRIT, "Could not create UCI context. Exiting ...");
        exit_cleanup();
    }

    uci_conf_dir = dirname(strdup(uci_conf_file_path));
    uci_conf_file = basename(strdup(uci_conf_file_path));


    uci_set_confdir(ctx, uci_conf_dir);

    LMLOG(DBG_1,"Conf dir: %s\n",ctx->confdir);

    uci_load(ctx,uci_conf_file,&pck);

    if (pck == NULL) {
        LMLOG(LCRIT, "Could not load conf file: %s. Exiting ...",uci_conf_file);
        uci_perror(ctx,"Error while loading packet ");
        uci_free_context(ctx);
        exit_cleanup();
    }


    LMLOG(DBG_3,"package uci: %s\n",pck->ctx->confdir);


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
                LMLOG(LWRN, "Map-Request retries should be between 0 and %d. Using default value: %d",
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
                if ((convert_hex_string_to_bytes(uci_site_id,site_id.byte,8)) != GOOD){
                    LMLOG(LCRIT, "Configuration file: Wrong Site-ID format");
                    exit_cleanup();
                }
                if ((convert_hex_string_to_bytes(uci_xtr_id,xtr_id.byte,16)) != GOOD){
                    LMLOG(LCRIT, "Configuration file: Wrong xTR-ID format");
                    exit_cleanup();
                }
            }

            continue;
        }



        if (strcmp(s->type, "map-resolver") == 0){
            uci_address = uci_lookup_option_string(ctx, s, "address");

            if (add_server((char *)uci_address, &map_resolvers) != GOOD){
                LMLOG(LCRIT,"Can't add %s Map Resolver.",uci_address);
            }else{
                LMLOG(DBG_1, "Added %s to map-resolver list", uci_address);
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
                LMLOG(LCRIT, "Can't add %s Map Server.", uci_address);
            }else{
                LMLOG(DBG_1, "Added %s to map-server list", uci_address);
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
                LMLOG(LERR, "Can't add proxy-etr %s", uci_address);
            }else{
                LMLOG(DBG_1, "Added %s to proxy-etr list", uci_address);
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
                LMLOG(LERR, "Can't add EID prefix %s. Discarded ...",
                        uci_eid_prefix);
            }else{
                LMLOG(DBG_1, "Added EID prefix %s in the database.",
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
                LMLOG(LWRN,"Can't add static-map-cache (EID:%s -> RLOC:%s). Discarded ...",
                        uci_eid_prefix,
                        uci_rloc);

            }else{
                LMLOG(DBG_1,"Added static-map-cache (EID:%s -> RLOC:%s)",
                        uci_eid_prefix,
                        uci_rloc);
            }
            continue;
        }


        if (strcmp(s->type, "proxy-itr") == 0){
            uci_address = uci_lookup_option_string(ctx, s, "address");

            if (add_server((char *)uci_address, &proxy_itrs) != GOOD){
                LMLOG(LERR, "Can't add %s to proxy-itr list. Discarded ...", uci_address);
            }else{
                LMLOG(DBG_1, "Added %s to proxy-itr list", uci_address);
            }
            continue;
        }

    }

    validate_rloc_probing_parameters (uci_rloc_probe_int, uci_rloc_probe_retries, uci_rloc_probe_retries_interval);

    if (!proxy_etrs){
        LMLOG(LWRN, "No Proxy-ETR defined. Packets to non-LISP destinations will be "
                "forwarded natively (no LISP encapsulation). This may prevent mobility in some scenarios.");
        sleep(3);
    }

    if (debug_level == 1){
        LMLOG (LINF, "Log levet: Low debug");
    }else if (debug_level == 2){
        LMLOG (LINF, "Log levet: Medium debug");
    }else if (debug_level == 3){
        LMLOG (LINF, "Log levet: High Debug ");
    }

    LMLOG (DBG_1, "****** Summary of the configuration ******");
    local_map_db_dump(DBG_1);
    if (is_loggable(DBG_1)){
        mcache_dump_db(DBG_1);
    }
    dump_map_servers(DBG_1);
    dump_servers(map_resolvers, "Map-Resolvers", DBG_1);
    dump_proxy_etrs(DBG_1);
    dump_servers(proxy_itrs, "Proxy-ITRs", DBG_1);

    uci_free_context(ctx);

    return(GOOD);
}

#else
/* OPENWRT is not defined */


static void
parse_elp_list(cfg_t *cfg, htable_t *ht)
{
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
            if (lisp_addr_ip_from_char(cfg_getstr(senode, "address"),
                    enode->addr) != GOOD) {
                elp_node_del(enode);
                LMLOG(DBG_1, "parse_elp_list: Couldn't parse ELP node %s",
                        cfg_getstr(senode, "address"));
                continue;
            }
            enode->L = cfg_getbool(senode, "lookup") ? 1 : 0;
            enode->P = cfg_getbool(senode, "probe") ? 1 : 0;
            enode->S = cfg_getbool(senode, "strict") ? 1: 0;

            glist_add_tail(enode, elp->nodes);
        }

        lisp_addr_lcaf_set_addr(laddr, (void *)elp);
        LMLOG(DBG_1, "Configuration file: parsed explicit-locator-path: %s",
                lisp_addr_to_char(laddr));

        htable_insert(ht, strdup(name), laddr);
    }

}

static void
parse_rle_list(cfg_t *cfg, htable_t *ht)
{
    rle_node_t *rnode = NULL;
    rle_t *rle = NULL;
    lisp_addr_t *laddr = NULL;
    char *name = NULL;
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
            if (lisp_addr_ip_from_char(cfg_getstr(rlenode, "address"),
                    rnode->addr) != GOOD) {
                rle_node_del(rnode);
                LMLOG(DBG_1, "parse_rle_list: Couldn't parse RLE node %s",
                        cfg_getstr(rlenode, "address"));
            }
            rnode->level = cfg_getint(rlenode, "level");

            glist_add_tail(rnode, rle->nodes);
        }
        lisp_addr_lcaf_set_addr(laddr, (void *)rle);
        LMLOG(DBG_1, "Configuration file: parsed replication-list: %s",
                lisp_addr_to_char(laddr));

        htable_insert(ht, strdup(name), laddr);
    }

}

static void
parse_mcinfo_list(cfg_t *cfg, htable_t *ht)
{
    mc_t *mc = NULL;
    lisp_addr_t *laddr = NULL;
    char *name = NULL;
    int i, count;

    count = 0;
    for (i = 0; i < cfg_size(cfg, "multicast-info"); i++) {
        cfg_t *mcnode = cfg_getnsec(cfg, "multicast-info", i);
        name = cfg_getstr(mcnode, "mc-info-name");

        laddr = lisp_addr_new_afi(LM_AFI_LCAF);
        lisp_addr_lcaf_set_type(laddr, LCAF_MCAST_INFO);

        mc = mc_type_new();
        lisp_addr_ip_from_char(cfg_getstr(mcnode, "source"), mc->src);
        mc->src_plen = cfg_getint(mcnode, "source-mask-length");
        lisp_addr_ip_from_char(cfg_getstr(mcnode, "group"), mc->grp);
        mc->src_plen = cfg_getint(mcnode, "group-mask-length");
        mc->iid = cfg_getint(mcnode, "iid");

        lisp_addr_lcaf_set_addr(laddr, mc);
        LMLOG(DBG_1, "Configuration file: parsed multicast-info: %s",
                lisp_addr_to_char(laddr));

        htable_insert(ht, strdup(name), laddr);
        count ++;
    }

    if (count != 0) {
        LMLOG(LINF, "Parsed configured multicast addresses");
    }
}

static htable_t *
parse_lcafs(cfg_t *cfg)
{
    htable_t *lcaf_ht = NULL;

    /* create lcaf hash table */
    lcaf_ht = htable_new(g_str_hash, g_str_equal, free,
            (h_del_fct)lisp_addr_del);
    parse_elp_list(cfg, lcaf_ht);
    parse_rle_list(cfg, lcaf_ht);
    parse_mcinfo_list(cfg, lcaf_ht);

    return(lcaf_ht);
}

int
configure_rtr(cfg_t *cfg)
{
    int                     i                       = 0;
    int                     n                       = 0;
    int                     ret                     = 0;
    char                    *map_resolver           = NULL;
    htable_t               *lcaf_ht                = NULL;
    lisp_xtr_t *xtr;


    /* CREATE AND CONFIGURE RTR (xTR in fact) */
    if (ctrl_dev_create(RTR_MODE, &ctrl_dev) != GOOD) {
        LMLOG(LCRIT, "Failed to create RTR. Aborting!");
        exit_cleanup();
    }

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    /* CREATE LCAFS HTABLE */

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of database mappings
     * or static map cache entries  */
    lcaf_ht = parse_lcafs(cfg);

    /* RETRIES */
    ret = cfg_getint(cfg, "map-request-retries");
    xtr->map_request_retries = (ret != 0) ? ret : DEFAULT_MAP_REQUEST_RETRIES;


    /* RLOC PROBING CONFIG */
    cfg_t *dm = cfg_getnsec(cfg, "rloc-probing", 0);
    if (dm != NULL) {
        xtr->probe_interval = cfg_getint(dm, "rloc-probe-interval");
        xtr->probe_retries = cfg_getint(dm, "rloc-probe-retries");
        xtr->probe_retries_interval = cfg_getint(dm,
                "rloc-probe-retries-interval");

        validate_rloc_probing_parameters(&xtr->probe_interval,
                &xtr->probe_retries, &xtr->probe_retries_interval);
    } else {
        LMLOG(DBG_1, "Configuration file: RLOC probing not defined. "
                "Setting default values: RLOC Probing Interval: %d sec.",
        RLOC_PROBING_INTERVAL);
    }


    /* MAP-RESOLVER CONFIG  */
    n = cfg_size(cfg, "map-resolver");
    for(i = 0; i < n; i++) {
        if ((map_resolver = cfg_getnstr(cfg, "map-resolver", i)) != NULL) {
            if (add_server(map_resolver, &xtr->map_resolvers) == GOOD){
                LMLOG(DBG_1, "Added %s to map-resolver list", map_resolver);
            }else{
                LMLOG(LCRIT,"Can't add %s Map Resolver.", map_resolver);
            }
        }
    }


    /* INTERFACES CONFIG */
    n = cfg_size(cfg, "rtr-ifaces");
    if (n) {
        cfg_t *rifs = cfg_getsec(cfg, "rtr-ifaces");
        int nr = cfg_size(rifs, "rtr-iface");
        for(i = 0; i < nr; i++) {
            cfg_t *ri = cfg_getnsec(rifs, "rtr-iface", i);
            if (add_rtr_iface(xtr,
                    cfg_getstr(ri, "iface"),
                    cfg_getint(ri, "priority"),
                    cfg_getint(ri, "weight")) == GOOD) {
                LMLOG(DBG_1, "Configured interface %s for RTR",
                        cfg_getstr(ri, "iface"));
            } else{
                LMLOG(LERR, "Can't configure iface %s for RTR",
                        cfg_getstr(ri, "iface"));
            }
        }
    }

    char *iface = cfg_getstr(cfg, "rtr-data-iface");
    if (iface) {
      if (!add_interface(iface))
          return(BAD);
    }

    /* STATIC MAP-CACHE CONFIG */
    n = cfg_size(cfg, "static-map-cache");
    for (i = 0; i < n; i++) {
        cfg_t *smc = cfg_getnsec(cfg, "static-map-cache", i);

        if (!add_static_map_cache_entry(xtr,
                cfg_getstr(smc, "eid-prefix"),
                cfg_getint(smc, "iid"),
                cfg_getstr(smc, "rloc"),
                cfg_getint(smc, "priority"),
                cfg_getint(smc, "weight"), lcaf_ht)

                ) {
            LMLOG(LWRN, "Can't add static-map-cache (EID:%s -> RLOC:%s). "
                    "Discarded ...",
                    cfg_getstr(smc, "eid-prefix"),
                    cfg_getstr(smc, "rloc"));
        } else {
            LMLOG(DBG_1, "Added static-map-cache (EID:%s -> RLOC:%s)",
                    cfg_getstr(smc, "eid-prefix"),
                    cfg_getstr(smc, "rloc"));
        }
    }


    /* RTR DATABASE MAPPINGS (like for instance replication lists) */
    n = cfg_size(cfg, "rtr-database-mapping");
    for (i = 0; i < n; i++) {
        add_local_db_mapping(xtr, cfg_getnsec(cfg, "rtr-database-mapping", i),
                lcaf_ht);
    }


    /* MAP-SERVER CONFIG */
    n = cfg_size(cfg, "map-server");
    for (i = 0; i < n; i++) {
        cfg_t *ms = cfg_getnsec(cfg, "map-server", i);
        if (add_map_server(xtr, cfg_getstr(ms, "address"),
                cfg_getint(ms, "key-type"), cfg_getstr(ms, "key"),
                (cfg_getbool(ms, "proxy-reply") ? 1 : 0)) == GOOD) {
            LMLOG(DBG_1, "Added %s to map-server list",
                    cfg_getstr(ms, "address"));
        } else {
            LMLOG(LWRN, "Can't add %s Map Server.", cfg_getstr(ms, "address"));
        }
    }

    htable_destroy(lcaf_ht);

    return(GOOD);
}

int
configure_xtr(cfg_t *cfg)
{

    int i = 0;
    int n = 0;
    int ret = 0;
    char *map_resolver = NULL;
    char *proxy_itr = NULL;
    int ctr = 0;
    htable_t *lcaf_ht = NULL;
    lisp_xtr_t *xtr;

    /* CREATE AND CONFIGURE XTR */
    if (ctrl_dev_create(xTR_MODE, &ctrl_dev) != GOOD) {
        LMLOG(LCRIT, "Failed to create xTR. Aborting!");
        exit_cleanup();
    }

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    /* CREATE LCAFS HTABLE */

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of database mappings
     * or static map cache entries  */
    lcaf_ht = parse_lcafs(cfg);

    /* RETRIES */
    ret = cfg_getint(cfg, "map-request-retries");
    xtr->map_request_retries = (ret != 0) ? ret : DEFAULT_MAP_REQUEST_RETRIES;


    /* RLOC PROBING CONFIG */
    cfg_t *dm = cfg_getnsec(cfg, "rloc-probing", 0);
    if (dm != NULL) {
        xtr->probe_interval = cfg_getint(dm, "rloc-probe-interval");
        xtr->probe_retries = cfg_getint(dm, "rloc-probe-retries");
        xtr->probe_retries_interval = cfg_getint(dm,
                "rloc-probe-retries-interval");

        validate_rloc_probing_parameters(&xtr->probe_interval,
                &xtr->probe_retries, &xtr->probe_retries_interval);
    } else {
        LMLOG(DBG_1, "Configuration file: RLOC probing not defined. "
                "Setting default values: RLOC Probing Interval: %d sec.",
        RLOC_PROBING_INTERVAL);
    }


    /* NAT Traversal options */
    cfg_t *nt = cfg_getnsec(cfg, "nat-traversal", 0);
    if (nt != NULL) {
        xtr->nat_aware = cfg_getbool(nt, "nat_aware") ? TRUE:FALSE;
        char *nat_site_ID = cfg_getstr(nt, "site_ID");
        char *nat_xTR_ID  = cfg_getstr(nt, "xTR_ID");
        if (xtr->nat_aware == TRUE){
            if ((convert_hex_string_to_bytes(nat_site_ID,
                    xtr->site_id.byte, 8)) != GOOD){
                LMLOG(LCRIT, "Configuration file: Wrong Site-ID format");
                exit_cleanup();
            }
            if ((convert_hex_string_to_bytes(nat_xTR_ID,
                    xtr->xtr_id.byte, 16)) != GOOD){
                LMLOG(LCRIT, "Configuration file: Wrong xTR-ID format");
                exit_cleanup();
            }
        }
    }else {
        xtr->nat_aware = FALSE;
    }


    /* MAP-RESOLVER CONFIG  */
    n = cfg_size(cfg, "map-resolver");
    for(i = 0; i < n; i++) {
        if ((map_resolver = cfg_getnstr(cfg, "map-resolver", i)) != NULL) {
            if (add_server(map_resolver, &xtr->map_resolvers) == GOOD){
                LMLOG(DBG_1, "Added %s to map-resolver list", map_resolver);
            }else{
                LMLOG(LCRIT,"Can't add %s Map Resolver.",map_resolver);
            }
        }
    }

    /* MAP-SERVER CONFIG */
    n = cfg_size(cfg, "map-server");
    for (i = 0; i < n; i++) {
        cfg_t *ms = cfg_getnsec(cfg, "map-server", i);
        if (add_map_server(xtr, cfg_getstr(ms, "address"),
                cfg_getint(ms, "key-type"), cfg_getstr(ms, "key"),
                (cfg_getbool(ms, "proxy-reply") ? 1 : 0)) == GOOD) {
            LMLOG(DBG_1, "Added %s to map-server list",
                    cfg_getstr(ms, "address"));
        } else {
            LMLOG(LWRN, "Can't add %s Map Server.", cfg_getstr(ms, "address"));
        }
    }

    /* PROXY-ETR CONFIG */
    n = cfg_size(cfg, "proxy-etr");
    for(i = 0; i < n; i++) {
        cfg_t *petr = cfg_getnsec(cfg, "proxy-etr", i);
        if (add_proxy_etr_entry(xtr,
                cfg_getstr(petr, "address"),
                cfg_getint(petr, "priority"),
                cfg_getint(petr, "weight")) == GOOD) {
            LMLOG(DBG_1, "Added %s to proxy-etr list", cfg_getstr(petr, "address"));
        } else{
            LMLOG(LERR, "Can't add proxy-etr %s", cfg_getstr(petr, "address"));
        }
    }


    /* PROXY-ITR CONFIG */
    n = cfg_size(cfg, "proxy-itrs");
    for(i = 0; i < n; i++) {
        if ((proxy_itr = cfg_getnstr(cfg, "proxy-itrs", i)) != NULL) {
            if (add_server(proxy_itr, &xtr->pitrs)==GOOD){
                LMLOG(DBG_1, "Added %s to proxy-itr list", proxy_itr);
            }else {
                LMLOG(LERR, "Can't add %s to proxy-itr list. Discarded ...", proxy_itr);
            }
        }
    }

    /* DATABASE MAPPING CONFIG */
    n = cfg_size(cfg, "database-mapping");
    for(i = 0; i < n; i++) {
        ctr ++;
        cfg_t *dm = cfg_getnsec(cfg, "database-mapping", i);
        if (add_database_mapping(xtr, cfg_getstr(dm, "eid-prefix"),
                cfg_getint(dm, "iid"),
                cfg_getstr(dm, "interface"),
                cfg_getint(dm, "priority_v4"),
                cfg_getint(dm, "weight_v4"),
                cfg_getint(dm, "priority_v6"),
                cfg_getint(dm, "weight_v6")) == GOOD) {
            LMLOG(DBG_1, "Added EID %s in the database.",
                    cfg_getstr(dm, "eid-prefix"));
        }else{
            LMLOG(LERR, "Can't add database-mapping %s. Discarded ...",
                    cfg_getstr(dm, "eid-prefix"));
        }
    }

    n = cfg_size(cfg, "database-mapping-new");
    for (i = 0; i < n; i++) {
        add_local_db_mapping(xtr, cfg_getnsec(cfg, "database-mapping-new", i),
                lcaf_ht);
    }

    /* STATIC MAP-CACHE CONFIG */
    n = cfg_size(cfg, "static-map-cache");
    for (i = 0; i < n; i++) {
        cfg_t *smc = cfg_getnsec(cfg, "static-map-cache", i);

        if (!add_static_map_cache_entry(xtr,
                cfg_getstr(smc, "eid-prefix"),
                cfg_getint(smc, "iid"),
                cfg_getstr(smc, "rloc"),
                cfg_getint(smc, "priority"),
                cfg_getint(smc, "weight"), lcaf_ht)

                ) {
            LMLOG(LWRN, "Can't add static-map-cache (EID:%s -> RLOC:%s). "
                    "Discarded ...",
                    cfg_getstr(smc, "eid-prefix"),
                    cfg_getstr(smc, "rloc"));
        } else {
            LMLOG(DBG_1, "Added static-map-cache (EID:%s -> RLOC:%s)",
                    cfg_getstr(smc, "eid-prefix"),
                    cfg_getstr(smc, "rloc"));
        }
    }

    /* destroy the hash table */
    htable_destroy(lcaf_ht);

    return(GOOD);

}

int
configure_ms(cfg_t *cfg)
{
    char *iface = NULL;
    lisp_site_prefix *site = NULL;
    htable_t *lcaf_ht = NULL;
    int i;
    lisp_ms_t *ms;

    /* create and configure xtr */
    if (ctrl_dev_create(MS_MODE, &ctrl_dev) != GOOD) {
        LMLOG(LCRIT, "Failed to create MS. Aborting!");
        exit_cleanup();
    }
    ms = CONTAINER_OF(ctrl_dev, lisp_ms_t, super);


    /* create lcaf hash table */
    lcaf_ht = parse_lcafs(cfg);

    /* CONTROL INTERFACE */
    /* TODO: should work with all interfaces in the future */
    iface = cfg_getstr(cfg, "control-iface");
    if (iface) {
        if (!add_interface(iface)) {
            return(BAD);
        }
    }

    /* LISP-SITE CONFIG */
    for (i = 0; i < cfg_size(cfg, "lisp-site"); i++) {
        cfg_t *ls = cfg_getnsec(cfg, "lisp-site", i);
        site = build_lisp_site_prefix(ms,
                cfg_getstr(ls, "eid-prefix"),
                cfg_getint(ls, "iid"),
                cfg_getint(ls, "key-type"),
                cfg_getstr(ls, "key"),
                cfg_getbool(ls, "accept-more-specifics") ? 1:0,
                cfg_getbool(ls, "proxy-reply") ? 1:0,
                cfg_getbool(ls, "merge") ? 1 : 0,
                lcaf_ht);
        if (site) {
            LMLOG(DBG_1, "Adding lisp site prefix %s to the lisp-sites "
                    "database", lisp_addr_to_char(site->eid_prefix));
            ms_add_lisp_site_prefix(ms, site);
        }else{
            LMLOG(LERR, "Can't add lisp-site prefix %s. Discarded ...",
                    cfg_getstr(ls, "eid-prefix"));
        }
    }

    /* LISP REGISTERED SITES CONFIG */
    for (i = 0; i< cfg_size(cfg, "ms-static-registered-site"); i++ ) {
        cfg_t *mss = cfg_getnsec(cfg, "ms-static-registered-site", i);
        mapping_t *mapping = build_mapping_from_config(mss, lcaf_ht, 0);
        if (ms_add_registered_site_prefix(ms, mapping) != GOOD) {
            LMLOG(DBG_1, "Failed to add static registered site for %s to the registered sites list!",
                    lisp_addr_to_char(mapping_eid(mapping)));
        } else {
            LMLOG(DBG_1, "Added static registered site for %s to the registered sites list!",
                    lisp_addr_to_char(mapping_eid(mapping)));
        }
    }

    /* destroy the hash table */
    htable_destroy(lcaf_ht);
    return(GOOD);
}

int
handle_lispd_config_file(char *lispdconf_conf_file)
{
    int ret = 0;
    cfg_t *cfg = 0;
    char *mode = NULL;


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

    static cfg_opt_t rtr_iface_opts[] = {
            CFG_STR("iface",                0, CFGF_NONE),
            CFG_INT("priority",             255, CFGF_NONE),
            CFG_INT("weight",               0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rtr_ifaces_opts[] = {
            CFG_SEC("rtr-iface",    rtr_iface_opts, CFGF_MULTI),
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
            CFG_BOOL("merge",                   cfg_false, CFGF_NONE),
            CFG_END()
    };

    cfg_opt_t opts[] = {
            CFG_SEC("database-mapping",     db_mapping_opts,        CFGF_MULTI),
            CFG_SEC("database-mapping-new", db_mapping_opts_new,    CFGF_MULTI),
            CFG_SEC("ms-static-registered-site", db_mapping_opts_new, CFGF_MULTI),
            CFG_SEC("rtr-database-mapping", db_mapping_opts_new,    CFGF_MULTI),
            CFG_SEC("static-map-cache",     mc_mapping_opts,        CFGF_MULTI),
            CFG_SEC("map-server",           map_server_opts,        CFGF_MULTI),
            CFG_SEC("rtr-ifaces",           rtr_ifaces_opts,        CFGF_MULTI),
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
        LMLOG(LCRIT, "Couldn't find config file %s, exiting...", config_file);
        exit_cleanup();
    } else if(ret == CFG_PARSE_ERROR) {
        LMLOG(LCRIT, "Parse error in file %s, exiting. Check conf file (see lispd.conf.example)", config_file);
        exit_cleanup();
    }


    /*
     *  lispd config options
     */


    /* Debug level */
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
        LMLOG (LINF, "Log level: Low debug");
    }else if (debug_level == 2){
        LMLOG (LINF, "Log level: Medium debug");
    }else if (debug_level == 3){
        LMLOG (LINF, "Log level: High Debug");
    }


    mode = cfg_getstr(cfg, "operating-mode");
    if (mode) {
        if (strcmp(mode, "xTR") == 0) {
            ret=configure_xtr(cfg);
        } else if (strcmp(mode, "MS") == 0) {
            ret=configure_ms(cfg);
        } else if (strcmp(mode, "RTR") == 0) {
            ret=configure_rtr(cfg);
        }
    }

    cfg_free(cfg);
    return(GOOD);
}



#endif
/* ifdef OPENWRT*/


static int
validate_priority_weight(int p, int w)
{
    /* Check the parameters */
    if (p < (MAX_PRIORITY - 1)|| p > UNUSED_RLOC_PRIORITY) {
        LMLOG(LERR, "Configuration file: Priority %d out of range [%d..%d]",
                p, MIN_PRIORITY, MAX_PRIORITY);
        return (BAD);
    }

    if (w > MAX_WEIGHT || w < MIN_WEIGHT) {
        LMLOG(LERR, "Configuration file: Weight %d out of range [%d..%d]",
                p, MIN_WEIGHT, MAX_WEIGHT);
        return (BAD);
    }
    return (GOOD);
}


static int
link_iface_and_mapping(iface_t *iface, mapping_t *m, int p4, int w4,
        int p6, int w6)
{
    locator_t *locator = NULL;

    /* Assign the mapping to the v4 mappings of the interface. Create IPv4
     * locator and assign to the mapping  */
    if ((p4 >= 0) && (default_rloc_afi != AF_INET6)) {
        if (add_mapping_to_interface(iface, m, AF_INET) != GOOD) {
            return(BAD);
        }
        locator = locator_init_local_full(iface->ipv4_address,
                &(iface->status), p4, w4, 255, 0,
                &(iface->out_socket_v4));
        if (!locator) {
            return(BAD);
        }

        if (mapping_add_locator(m, locator) != GOOD) {
            return(BAD);
        }
    }

    /* Assign the mapping to the v6 mappings of the interface. Create IPv6
     * locator and assign to the mapping  */
    if ((p6 >= 0) && (default_rloc_afi != AF_INET)) {
        if (add_mapping_to_interface(iface, m, AF_INET6) != GOOD) {
            return(BAD);
        }
        locator = locator_init_local_full(iface->ipv6_address,
                &(iface->status), p6, w6, 255, 0,
                &(iface->out_socket_v6));

        if (!locator) {
            return(BAD);
        }

        if (mapping_add_locator(m, locator) != GOOD) {
            return(BAD);
        }
    }

    return(GOOD);

}

static int
add_database_mapping(lisp_xtr_t *xtr, char *eid_str, int iid, char *iface_name,
        int p4, int w4, int p6, int w6)
{
    mapping_t *m = NULL;
    iface_t *interface = NULL;
    lisp_addr_t eid;


    /* XXX: Don't use IIDs with this method */

    /* ADD INTERFACE */
    if (iface_name == NULL){
        LMLOG(LERR, "Configuration file: No interface specified for database"
                " mapping. Ignoring mapping");
        return (BAD);
    }

    /* Check if the interface already exists. If not, add it*/
    if ((interface = get_interface(iface_name)) == NULL) {
        interface = add_interface(iface_name);
        if (!interface) {
            LMLOG(LWRN, "add_database_mapping: Can't create interface %s",
                    iface_name);
            return(BAD);
        }
    }

    /* PARSE AND ADD MAPPING TO XTR*/
    if (iid > MAX_IID || iid < -1) {
        LMLOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "disabling...", iid, MAX_IID);
        iid = -1;
    }

    if (validate_priority_weight(p4, w4) != GOOD
        || validate_priority_weight(p6, w6) != GOOD) {
        return(BAD);
    }

    if (lisp_addr_ippref_from_char(eid_str, &eid) != GOOD) {
        LMLOG(LERR, "Configuration file: Error parsing EID address");
        return (BAD);
    }

    if (iid > 0) {
        lisp_addr_set_afi(&eid, LM_AFI_LCAF);
        /* XXX: mask not defined. Just filling in a value for now */
        lisp_addr_lcaf_set_addr(&eid, iid_type_init(iid, &eid,
                ip_afi_to_default_mask(lisp_addr_ip_afi(&eid))));
    }

    /* Lookup if the mapping exists. If not, a new mapping is created. */
    m = local_map_db_lookup_eid_exact(xtr->local_mdb, &eid);

    if (!m) {
        m = mapping_init_local(&eid);
        if (!m) {
            LMLOG(LERR, "Configuration file: mapping %s could not be created",
                    eid_str);
            return(BAD);
        }
        mapping_set_ttl(m, DEFAULT_MAP_REGISTER_TIMEOUT);

        /* Add the mapping to the local database */
        if (local_map_db_add_mapping(xtr->local_mdb, m) != GOOD) {
            mapping_del(m);
            return(BAD);
        }
    } else {
        if (m->iid != iid) {
            LMLOG(LERR, "Same EID prefix with different iid. This configuration"
                    " is not supported...Ignoring EID prefix.");
            return(BAD);
        }
    }

    /* BIND MAPPING TO IFACE */
    /* FIXME: build rloc to mapping hash */
    if (link_iface_and_mapping(interface, m, p4, w4, p6, w6) != GOOD) {
        return(BAD);
    }

    /* Recalculate the outgoing rloc vectors */
    mapping_compute_balancing_vectors(m);

    /* in case we converted it to an LCAF, need to free memory */
    lisp_addr_dealloc(&eid);
    return(GOOD);
}


char *
get_interface_name_from_address(lisp_addr_t *addr)
{
    char *iface  = NULL;

    if (lisp_addr_afi(addr) != LM_AFI_IP) {
        LMLOG(DBG_1, "get_interface_name_from_address: failed for %s. Function"
                " only supports IP syntax addresses!", lisp_addr_to_char(addr));
        return(NULL);
    }

    iface = shash_lookup(iface_addr_ht, lisp_addr_to_char(addr));
    if (iface) {
        return(iface);
    } else {
        return(NULL);
    }
}

static locator_t *
parse_locator(char *address, int priority, int weight, htable_t *lcaf_ht,
        int local)
{
    char *iface_name = NULL;
    locator_t *locator = NULL;
    iface_t *interface = NULL;
    lisp_addr_t *rloc = NULL; /* for IP RLOCS */
    lisp_addr_t *aux_rloc = NULL, *addr, *lcaf_rloc = NULL;

    if (validate_priority_weight(priority, weight) != GOOD) {
        return(BAD);
    }

    rloc = lisp_addr_new();
    if (lisp_addr_ip_from_char(address, rloc) != GOOD) {
        lisp_addr_del(rloc);
        lcaf_rloc = htable_lookup(lcaf_ht, address);
        if(!lcaf_rloc) {
            LMLOG(LERR, "Configuration file: Error parsing RLOC address %s",
                    address);
            return (NULL);
        }
    }

    /* LOCAL locator */
    if (local) {
        /* decide rloc to be used to lookup the interface */
        if (lcaf_rloc) {
            aux_rloc = lcaf_rloc_get_ip_addr(lcaf_rloc);
            if (!aux_rloc) {
                LMLOG(LERR, "Configuration file: Can't determine RLOC's IP "
                        "address %s", lisp_addr_to_char(lcaf_rloc));
                lisp_addr_del(lcaf_rloc);
                return(NULL);
            }
        } else {
            aux_rloc = rloc;
        }

        if (!(iface_name = get_interface_name_from_address(aux_rloc))) {
            LMLOG(LERR, "Configuration file: Can't find interface for RLOC %s",
                    lisp_addr_to_char(aux_rloc));
            lisp_addr_del(aux_rloc);
            return(NULL);
        }

        if (!(interface = get_interface(iface_name))) {
            if (!(interface = add_interface(iface_name))) {
                lisp_addr_del(aux_rloc);
            }
        }

        if (!lcaf_rloc) {
            addr = iface_address(interface, lisp_addr_ip_afi(aux_rloc));
            locator = locator_init_local_full(addr , &(interface->status),
                    priority, weight, 255, 0, &(interface->out_socket_v4));
        } else {
            /* XXX, TODO : locator addr not linked to interface */
            locator = locator_init_local_full(lisp_addr_clone(lcaf_rloc) ,
                    &(interface->status), priority, weight, 255, 0,
                    &(interface->out_socket_v4));
        }

        if (!locator) {
            LMLOG(DBG_1, "Configuration file: failed to create locator"
                    " with addr %s", address);
            return(NULL);
        }
    /* REMOTE locator */
    } else {

        if (!lcaf_rloc) {
            locator = locator_init_remote_full(rloc, 1, priority, weight, 255,
                    0);
        } else {
            locator = locator_init_remote_full(lcaf_rloc, 1,
                    priority, weight, 255, 0);
        }

        if (!locator) {
            LMLOG(DBG_1, "Configuration file: failed to create locator with "
                    "addr %s", lisp_addr_to_char(rloc));
            lisp_addr_del(rloc);
            return(NULL);
        }
    }

    if (!lcaf_rloc) {
        lisp_addr_del(rloc);
    }

    return(locator);
}

static mapping_t *
build_mapping_from_config(cfg_t *map, htable_t *lcaf_ht, int local)
{
    int i;
    mapping_t *m = NULL;
    locator_t *locator = NULL;
    lisp_addr_t *eid_prefix, *lcaf;
    lisp_addr_t *new_eid = NULL;
    int iid = 0;
    char *address = NULL;

    address = cfg_getstr(map, "eid-prefix");
    eid_prefix = lisp_addr_new();
    if (lisp_addr_ippref_from_char(address, eid_prefix) != GOOD) {
        lisp_addr_del(eid_prefix);
        /* if not found, try in the hash table */
        lcaf = htable_lookup(lcaf_ht, address);
        if (!lcaf) {
            LMLOG(LERR, "Configuration file: Error parsing RLOC address %s",
                    address);
            return (NULL);
        }
        lisp_addr_copy(eid_prefix, lcaf);
    }

    /* add iid to eid-prefix if different from 0 */
    iid = cfg_getint(map, "iid");

    if (iid > MAX_IID || iid < -1) {
        LMLOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "disabling...", iid, MAX_IID);
        iid = 0;
    }

    if (iid > 0) {
        new_eid = lisp_addr_new_afi(LM_AFI_LCAF);
        lisp_addr_lcaf_set_type(new_eid, LCAF_IID);
        /* XXX: mask not defined. Just filling in a value for now */
        lisp_addr_lcaf_set_addr(new_eid, iid_type_init(iid, eid_prefix,
                ip_afi_to_default_mask(lisp_addr_ip_afi(eid_prefix))));

        /* free the old container */
        lisp_addr_del(eid_prefix);
        eid_prefix = new_eid;
    }

    m = (local) ? mapping_init_local(eid_prefix) :
                        mapping_init_remote(eid_prefix);

    lisp_addr_del(eid_prefix);

    for (i = 0; i < cfg_size(map, "rloc"); i++) {
        cfg_t *rl = cfg_getnsec(map, "rloc", i);
        if (local) {
            locator = parse_locator(cfg_getstr(rl, "address"),
                    cfg_getint(rl, "priority"),
                    cfg_getint(rl, "weight"),
                    lcaf_ht, 1);
        } else {
            locator = parse_locator(cfg_getstr(rl, "address"),
                    cfg_getint(rl, "priority"),
                    cfg_getint(rl, "weight"),
                    lcaf_ht, 0);
        }
        if (!locator) {
            LMLOG(LWRN, "Configuration file: couldn't parse locator %s",
                    cfg_getstr(rl, "address"));
            continue;
        }

        mapping_add_locator(m, locator);
    }

    if (mapping_compute_balancing_vectors(m) != GOOD) {
        LMLOG(LWRN, "build_mapping_from_config: Couldn't calculate balancing "
                "vectors");
        mapping_del(m);
        return(BAD);
    }

    return(m);
}

static int
add_local_db_mapping(lisp_xtr_t *xtr, cfg_t *map, htable_t *lcaf_ht)
{
    int i;
    mapping_t *mapping = NULL;
    locator_t *locator = NULL;
    lisp_addr_t *eid_prefix;
    lisp_addr_t *new_eid = NULL;
    int iid = 0;
    char *address = NULL;

    address = cfg_getstr(map, "eid-prefix");
    eid_prefix = lisp_addr_new();
    if (lisp_addr_ippref_from_char(address, eid_prefix) != GOOD) {
        lisp_addr_del(eid_prefix);
        /* if not found, try in the hash table */
        eid_prefix = htable_lookup(lcaf_ht, address);
        if (!eid_prefix) {
            LMLOG(LERR, "Configuration file: Error parsing RLOC address %s",
                    address);
            return (BAD);
        }
    }

    /* add iid to eid-prefix if different from 0 */
    iid = cfg_getint(map, "iid");

    if (iid > MAX_IID || iid < -1) {
        LMLOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "disabling...", iid, MAX_IID);
        iid = 0;
    }

    if (iid != 0) {
        new_eid = lisp_addr_new_afi(LM_AFI_LCAF);
        /* XXX: mask not defined. Just filling in a value for now */
        lisp_addr_lcaf_set_addr(new_eid, iid_type_init(iid, eid_prefix, 32));
        eid_prefix = new_eid;
    }

    mapping = local_map_db_lookup_eid_exact(xtr->local_mdb, eid_prefix);
    if (!mapping) {
        mapping = mapping_init_local(eid_prefix);
        local_map_db_add_mapping(xtr->local_mdb, mapping);
    } else {
        /* no need for the prefix */
        lisp_addr_del(eid_prefix);
    }

    for (i = 0; i < cfg_size(map, "rloc"); i++) {
        cfg_t *rl = cfg_getnsec(map, "rloc", i);
        locator = parse_locator(cfg_getstr(rl, "address"),
                cfg_getint(rl, "priority"), cfg_getint(rl, "weight"),
                lcaf_ht, 1);

        if (!locator) {
            continue;
        }

        mapping_add_locator(mapping, locator);
    }

    return(mapping_compute_balancing_vectors(mapping));
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

static int
add_static_map_cache_entry(lisp_xtr_t *xtr, char *eid, int iid,
        char *rloc_addr, int priority, int weight, htable_t *elp_hash)
{
    mapping_t *mapping;
    locator_t *locator;
    lisp_addr_t rloc;
    lisp_addr_t *lcaf_rloc;
    lisp_addr_t eid_prefix;
    int err;

    if (iid > MAX_IID) {
        LMLOG(LERR, "Configuration file: Instance ID %d out of range [0..%d],"
                " disabling...", iid, MAX_IID);
        iid = -1;
    }

    if (iid < 0) {
        iid = -1;
    }

    if (priority < MAX_PRIORITY || priority > UNUSED_RLOC_PRIORITY) {
        LMLOG(LERR, "Configuration file: Priority %d out of range [%d..%d], "
                "set minimum priority...", priority, MAX_PRIORITY,
                UNUSED_RLOC_PRIORITY);
        priority = MIN_PRIORITY;
    }

    if (lisp_addr_ippref_from_char(eid, &eid_prefix) !=GOOD) {
        LMLOG(LERR, "Configuration file: Error parsing EID address ..."
                "Ignoring static map cache entry");
        return (BAD);
    }

    if (iid != 0) {
        lisp_addr_set_afi(&eid_prefix, LM_AFI_LCAF);
        /* XXX: mask not defined. Just filling in a value for now */
        lisp_addr_lcaf_set_addr(&eid_prefix, iid_type_init(iid, &eid_prefix,
                ip_afi_to_default_mask(lisp_addr_ip_afi(&eid_prefix))));
    }


    if (!(mapping = mapping_init_static(&eid_prefix))) {
        return(BAD);
    }

    if (lisp_addr_ip_from_char(rloc_addr, &rloc) == BAD) {
        lcaf_rloc = htable_lookup(elp_hash, rloc_addr);
        if (!lcaf_rloc) {
            LMLOG(LERR, "Error parsing RLOC address ..."
                    " Ignoring static map cache entry");
            return (BAD);
        }
        locator = locator_init_remote_full(lcaf_rloc, UP, priority, weight, 255,
                0);
    } else {
        locator = locator_init_remote_full(&rloc, UP, priority, weight, 255, 0);

    }

    if (locator != NULL) {
        locator_set_type(locator, STATIC_LOCATOR);
        if ((err = mapping_add_locator(mapping, locator)) != GOOD) {
            return(BAD);
        }
    } else {
        return(BAD);
    }

    tr_mcache_add_static_mapping(xtr, mapping);
    /* if it was converted to IID LCAF */
    lisp_addr_dealloc(&eid_prefix);
    return(GOOD);
}

/*
 *  add a map-resolver to the list
 */

static int
add_server(char *server, lisp_addr_list_t **list)
{

    lisp_addr_t *addr;
    lisp_addr_list_t *list_elt;

    addr = lisp_addr_new();
    if (lisp_addr_ip_from_char(server, addr) != GOOD) {
        lisp_addr_del(addr);
        return(BAD);
    }


    /* Check that the afi of the map server matches with the default rloc afi
     * (if it's defined). */
    if (default_rloc_afi != -1 && default_rloc_afi != lisp_addr_ip_afi(addr)) {
        LMLOG(LWRN, "The server %s will not be added due to the selected "
                "default rloc afi", server);
        lisp_addr_del(addr);
        return (BAD);
    }

    list_elt = xzalloc(sizeof(lisp_addr_list_t));
    list_elt->address = addr;

    /* hook this one to the front of the list  */
    if (*list) {
        list_elt->next = *list;
        *list = list_elt;
    } else {
        *list = list_elt;
    }

    return(GOOD);
}

static int
add_map_server(lisp_xtr_t *xtr, char *map_server, int key_type,
        char *key, uint8_t proxy_reply)
{
    lisp_addr_t *addr;
    map_server_list_t *list_elt;
    struct hostent *hptr;

    if (map_server == NULL || key_type == 0 || key == NULL){
        LMLOG(LERR, "Configuraton file: Wrong Map Server configuration. "
                "Check configuration file");
        exit_cleanup();
    }

    if (((hptr = gethostbyname2(map_server, AF_INET)) == NULL) && ((hptr =
            gethostbyname2(map_server, AF_INET6)) == NULL)) {
        LMLOG(LWRN, "can gethostbyname2 for map_server (%s)", map_server);
        return (BAD);
    }

    addr = lisp_addr_new_afi(LM_AFI_IP);
    lisp_addr_ip_init(addr, *(hptr->h_addr_list), hptr->h_addrtype);

    /* Check that the afi of the map server matches with the default rloc afi
     * (if it's defined). */
    if (default_rloc_afi != -1 && default_rloc_afi != addr->afi){
        LMLOG(LWRN, "The map server %s will not be added due to the selected "
                "default rloc afi", map_server);
        lisp_addr_del(addr);
        return(BAD);
    }

    list_elt = xzalloc(sizeof(map_server_list_t));

    list_elt->address     = addr;
    list_elt->key_type    = key_type;
    list_elt->key         = strdup(key);
    list_elt->proxy_reply = proxy_reply;

    /* hook this one to the front of the list */

    if (xtr->map_servers) {
        list_elt->next = xtr->map_servers;
        xtr->map_servers = list_elt;
    } else {
        xtr->map_servers = list_elt;
    }

    return(GOOD);
}

static int
add_proxy_etr_entry(lisp_xtr_t *xtr, char *address, int priority, int weight)
{
    lisp_addr_t aux_addr;
    lisp_addr_t rloc;
    locator_t *locator = NULL;
    int ret;

    if (address == NULL){
        LMLOG(LERR, "Configuration file: No interface specified for PETR. "
                "Discarding!");
        return (BAD);
    }

    if (validate_priority_weight(priority, weight) != GOOD) {
        return(BAD);
    }

    /* Check that the afi of the map server matches with the default rloc afi
     * (if it's defined). */
    if (default_rloc_afi != -1
        && default_rloc_afi != ip_afi_from_char(address)) {
        LMLOG(LWRN, "The PETR %s will not be added due to the selected "
                "default rloc afi", address);
        return(BAD);
    }

    /* Create the proxy-etrs map cache structure if it doesn't exist */
    if (xtr->petrs == NULL) {
        xtr->petrs = mcache_entry_new();
        lisp_addr_ip_from_char("0.0.0.0", &aux_addr);
        mcache_entry_init_static(xtr->petrs, mapping_init_remote(&aux_addr));
    }

    if (lisp_addr_ip_from_char(address, &rloc) == BAD) {
        LMLOG(LERR, "Error parsing RLOC address. Ignoring proxy-ETR %s",
                address);
        return (BAD);
    }

    /* Create locator representing the proxy-etr and add it to the mapping */
    locator = locator_init_remote_full(&rloc, UP, priority, weight, 255, 0);

    if (locator) {
        ret =  mapping_add_locator(xtr->petrs->mapping, locator);
    } else {
        ret = BAD;
    }

    return(ret);
}

static int
add_rtr_iface(lisp_xtr_t *xtr, char *iface_name, int p, int w)
{
    lisp_addr_t aux_address;
    iface_t *iface;

    if (iface_name == NULL){
        LMLOG(LERR, "Configuration file: No interface specified for RTR. "
                "Discarding!");
        return (BAD);
    }

    if (validate_priority_weight(p, w) != GOOD) {
        return(BAD);
    }

    /* Check if the interface already exists. If not, add it*/
    if ((iface = get_interface(iface_name)) == NULL) {
        iface = add_interface(iface_name);
        if (!iface) {
            LMLOG(LWRN, "add_database_mapping: Can't create interface %s",
                    iface_name);
            return(BAD);
        }
    }

    if (!xtr->all_locs_map) {
        lisp_addr_ip_from_char("0.0.0.0", &aux_address);
        xtr->all_locs_map = mapping_init_local(&aux_address);
    }

    if (link_iface_and_mapping(iface, xtr->all_locs_map, p, w, p, w)
            != GOOD) {
        return(BAD);
    }

    return(GOOD);
}

static void
validate_rloc_probing_parameters(int *interval, int *retries,
        int *retries_int)
{

    if (*interval < 0) {
        *interval = 0;
    }

    if (*interval > 0) {
        LMLOG(DBG_1, "RLOC Probing Interval: %d", *interval);
    } else {
        LMLOG(DBG_1, "RLOC Probing disabled");
    }

    if (*interval != 0) {
        if (*retries > LISPD_MAX_RETRANSMITS) {
            *retries = LISPD_MAX_RETRANSMITS;
            LMLOG(LWRN, "RLOC Probing retries should be between 0 and %d. "
                    "Using %d retries", LISPD_MAX_RETRANSMITS,
                    LISPD_MAX_RETRANSMITS);
        } else if (*retries < 0) {
            *retries = 0;
            LMLOG(LWRN, "RLOC Probing retries should be between 0 and %d. "
                    "Using 0 retries", LISPD_MAX_RETRANSMITS);
        }

        if (*retries > 0) {
            if (*retries_int < LISPD_MIN_RETRANSMIT_INTERVAL) {
                *retries_int = LISPD_MIN_RETRANSMIT_INTERVAL;
                LMLOG(LWRN, "RLOC Probing interval retries should be between "
                        "%d and RLOC Probing interval. Using %d seconds",
                        LISPD_MIN_RETRANSMIT_INTERVAL,
                        LISPD_MIN_RETRANSMIT_INTERVAL);
            } else if (*retries_int > *interval) {
                *retries_int = *interval;
                LMLOG(LWRN, "RLOC Probing interval retries should be between "
                        "%d and RLOC Probing interval. Using %d seconds",
                         LISPD_MIN_RETRANSMIT_INTERVAL, *interval);
            }
        }
    }
}

static lisp_site_prefix *
build_lisp_site_prefix(lisp_ms_t *ms, char *eidstr, uint32_t iid, int key_type,
        char *key, uint8_t more_specifics, uint8_t proxy_reply, uint8_t merge,
        htable_t *lcaf_ht)
{
    lisp_addr_t *eid_prefix = NULL;
    lisp_addr_t *ht_prefix = NULL;
    lisp_site_prefix *site = NULL;

    if (iid > MAX_IID) {
        LMLOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "disabling...", iid, MAX_IID);
        iid = -1;
    }

    if (iid < 0) {
        iid = 0;
    }

    /* DON'T DELETE eid_prefix */
    eid_prefix = lisp_addr_new();
    if (lisp_addr_ippref_from_char(eidstr, eid_prefix) != GOOD) {
        lisp_addr_del(eid_prefix);
        /* if not found, try in the hash table */
        ht_prefix = htable_lookup(lcaf_ht, eidstr);
        if (!ht_prefix) {
            LMLOG(LERR, "Configuration file: Error parsing RLOC address %s",
                    eidstr);
            return (NULL);
        }
        eid_prefix = lisp_addr_clone(ht_prefix);
    }

    site = lisp_site_prefix_init(eid_prefix, iid, key_type, key,
            more_specifics, proxy_reply, merge);
    lisp_addr_del(eid_prefix);
    return(site);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */

