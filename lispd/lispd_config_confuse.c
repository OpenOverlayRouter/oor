/*
 * lispd_config_confuse.c
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
 *    Alberto López     <alopez@ac.upc.edu>
 *
 */

#include <netdb.h>

#include "cmdline.h"
#include "confuse.h"
#include "lispd_config_confuse.h"
#include "lispd_config_functions.h"
#include "lispd_external.h"
#include "iface_list.h"
#include "lisp_ctrl_device.h"
#include "lisp_xtr.h"
#include "lisp_ms.h"
#include "lisp_control.h"
#include "shash.h"
#include "hash_table.h"
#include "lmlog.h"

/***************************** FUNCTIONS DECLARATION *************************/

static int add_local_db_mapping(lisp_xtr_t *, cfg_t *, htable_t *);
static mapping_t *build_mapping_from_config(cfg_t *, htable_t *, int);
static lisp_addr_t *parse_lisp_addr(char *address, htable_t *lcaf_ht);
static lisp_addr_t *parse_eid_in_mapping(cfg_t *map, htable_t *lcaf_ht);
static locator_t *parse_locator(char *address, int priority, int weight,
        htable_t *lcaf_ht, int local, iface_t **iface_);

/********************************** FUNCTIONS ********************************/

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

        elp = elp_type_new();

        for (j = 0; j < cfg_size(selp, "elp-node");j++) {
            cfg_t *senode = cfg_getnsec(selp, "elp-node", j);
            enode = xzalloc(sizeof(elp_node_t));
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

        laddr = lisp_addr_new_afi(LM_AFI_LCAF);
        lisp_addr_lcaf_set_type(laddr, LCAF_EXPL_LOC_PATH);
        lisp_addr_lcaf_set_addr(laddr, elp);
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
            (h_val_del_fct)lisp_addr_del);
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
    htable_t                *lcaf_ht                = NULL;
    lisp_xtr_t              *xtr                    = NULL;


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
        xtr->probe_interval = RLOC_PROBING_INTERVAL;
        xtr->probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
        xtr->probe_retries_interval = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;

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
configure_mn(cfg_t *cfg)
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
    if (ctrl_dev_create(MN_MODE, &ctrl_dev) != GOOD) {
        LMLOG(LCRIT, "Failed to create mobile node. Aborting!");
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
    lisp_site_prefix_t *site = NULL;
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
handle_config_file(char *lispdconf_conf_file)
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
            CFG_INT("iid",                  0, CFGF_NONE),
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
            CFG_INT("iid",                  0, CFGF_NONE),
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

    if (lispdconf_conf_file == NULL){
        lispdconf_conf_file = "/etc/lispd.conf";
    }

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
        }else if (strcmp(mode, "MN") == 0) {
            ret=configure_mn(cfg);
        }
    }

    cfg_free(cfg);
    return(GOOD);
}


/* FOR NOW only used for building Map-Server mappings. It does not link
 * local mappings to local interfaces */
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

    if (iid > MAX_IID || iid < 0) {
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
        iface_t *iface;
        if (local) {
            locator = parse_locator(cfg_getstr(rl, "address"),
                    cfg_getint(rl, "priority"),
                    cfg_getint(rl, "weight"),
                    lcaf_ht, 1, &iface);
        } else {
            locator = parse_locator(cfg_getstr(rl, "address"),
                    cfg_getint(rl, "priority"),
                    cfg_getint(rl, "weight"),
                    lcaf_ht, 0, &iface);
        }
        if (!locator) {
            LMLOG(LWRN, "Configuration file: couldn't parse locator %s",
                    cfg_getstr(rl, "address"));
            continue;
        }

        mapping_add_locator(m, locator);
    }

    return(m);
}


/* Parses an EID (IP or LCAF) and returns an 'lisp_addr_t'. Caller must free
 * the returned value */
static lisp_addr_t *
parse_lisp_addr(char *address, htable_t *lcaf_ht)
{
    lisp_addr_t *eid_prefix, *lcaf;

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
        eid_prefix = lisp_addr_clone(lcaf);
    }

    return(eid_prefix);
}

/* Parses an eid from a mapping configuration and returns it in '_eid'.
 *'_eid' must be freed by the caller. */
static lisp_addr_t *
parse_eid_in_mapping(cfg_t *map, htable_t *lcaf_ht)
{
    lisp_addr_t *new_eid = NULL;
    int iid = 0;
    lisp_addr_t *eid_prefix;

    eid_prefix = parse_lisp_addr(cfg_getstr(map, "eid-prefix"), lcaf_ht);

    if (!eid_prefix) {
        return(NULL);
    }

    /* add iid to eid-prefix if different from 0 */
    iid = cfg_getint(map, "iid");

    if (iid > MAX_IID || iid < 0) {
        LMLOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "disabling...", iid, MAX_IID);
        iid = 0;
    }

    if (iid != 0) {
        new_eid = lisp_addr_new_afi(LM_AFI_LCAF);
        /* XXX: mask not defined. Just filling in a value for now */
        lisp_addr_lcaf_set_addr(new_eid, iid_type_init(iid, eid_prefix, 32));
        /* free the old container */
        lisp_addr_del(eid_prefix);
        eid_prefix = new_eid;
    }

    return(eid_prefix);
}

static locator_t *
parse_locator(char *address, int priority, int weight, htable_t *lcaf_ht,
        int local, iface_t **iface_)
{
    char *iface_name = NULL;
    locator_t *locator = NULL;
    iface_t *iface = NULL;
    lisp_addr_t *rloc = NULL; /* for IP RLOCS */
    lisp_addr_t *aux_rloc = NULL, *addr, *lcaf_clone;

    if (validate_priority_weight(priority, weight) != GOOD) {
        return(BAD);
    }

    rloc = parse_lisp_addr(address, lcaf_ht);
    if (!rloc) {
        return(NULL);
    }

    /* LOCAL locator */
    if (local) {
        /* Decide IP address to be used to lookup the interface */
        if (lisp_addr_is_lcaf(rloc)) {
            aux_rloc = lcaf_rloc_get_ip_addr(rloc);
            if (!aux_rloc) {
                LMLOG(LERR, "Configuration file: Can't determine RLOC's IP "
                        "address %s", lisp_addr_to_char(rloc));
                lisp_addr_del(rloc);
                return(NULL);
            }
        } else {
            aux_rloc = rloc;
        }

        /* Find the interface name associated to the RLOC */
        if (!(iface_name = get_interface_name_from_address(aux_rloc))) {
            LMLOG(LERR, "Configuration file: Can't find interface for RLOC %s",
                    lisp_addr_to_char(aux_rloc));
            lisp_addr_del(aux_rloc);
            return(NULL);
        }

        /* Find the interface */
        if (!(iface = get_interface(iface_name))) {
            if (!(iface = add_interface(iface_name))) {
                lisp_addr_del(aux_rloc);
            }
        }

        if (!lisp_addr_is_lcaf(rloc)) {
            addr = iface_address(iface, lisp_addr_ip_afi(aux_rloc));
            locator = locator_init_local_full(addr , iface->status,
                    priority, weight, 255, 0, &(iface->out_socket_v4));
        } else {
            addr = iface_address(iface, lisp_addr_ip_afi(aux_rloc));
            lcaf_clone = lisp_addr_clone(rloc);
            lcaf_rloc_set_ip_addr(lcaf_clone, addr);
            locator = locator_init_local_full(lcaf_clone ,
                    iface->status, priority, weight, 255, 0,
                    &(iface->out_socket_v4));
        }

        if (!locator) {
            LMLOG(DBG_1, "Configuration file: failed to create locator"
                    " with addr %s", address);
            return(NULL);
        }

        *iface_ = iface;
    /* REMOTE locator */
    } else {
        locator = locator_init_remote_full(rloc, 1, priority, weight, 255, 0);

        if (!locator) {
            LMLOG(DBG_1, "Configuration file: failed to create locator with "
                    "addr %s", lisp_addr_to_char(rloc));
            lisp_addr_del(rloc);
            return(NULL);
        }
        *iface_ = NULL;
    }

    lisp_addr_del(rloc);
    return(locator);
}
static int
add_local_db_mapping(lisp_xtr_t *xtr, cfg_t *map, htable_t *lcaf_ht)
{
    int i;
    mapping_t *m = NULL;
    locator_t *loc = NULL;
    lisp_addr_t *eid_prefix;
    iface_t *iface;

    eid_prefix = parse_eid_in_mapping(map, lcaf_ht);
    if (!eid_prefix) {
        return(BAD);
    }

    m = local_map_db_lookup_eid_exact(xtr->local_mdb, eid_prefix);
    if (!m) {
        m = mapping_init_local(eid_prefix);
        mapping_set_ttl(m, DEFAULT_MAP_REGISTER_TIMEOUT);

        local_map_db_add_mapping(xtr->local_mdb, m);
    }

    /* no need for the prefix */
    lisp_addr_del(eid_prefix);

    for (i = 0; i < cfg_size(map, "rloc"); i++) {
        cfg_t *rl = cfg_getnsec(map, "rloc", i);
        loc = parse_locator(cfg_getstr(rl, "address"),
                cfg_getint(rl, "priority"), cfg_getint(rl, "weight"),
                lcaf_ht, 1, &iface);

        if (!loc) {
            continue;
        }

        mapping_add_locator(m, loc);
    }

    return(mapping_compute_balancing_vectors(m));
}



/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */

