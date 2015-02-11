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

static int add_local_db_mapping(cfg_t *,lisp_xtr_t *, htable_t *);
mapping_t *
parse_mapping(
        cfg_t *             map,
        lisp_ctrl_dev_t *   dev,
        htable_t *          lcaf_ht,
        uint8_t             type);

static glist_t *
parse_rloc_address(
        cfg_t *             rloc,
        lisp_ctrl_dev_t *   dev,
        htable_t *          lcaf_ht,
        uint8_t             type);

static locator_t *
parse_rloc_interface(
        cfg_t *             rloc,
        lisp_ctrl_dev_t *   dev);

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

        laddr = lisp_addr_new_lafi(LM_AFI_LCAF);
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

        laddr = lisp_addr_new_lafi(LM_AFI_LCAF);
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

        laddr = lisp_addr_new_lafi(LM_AFI_LCAF);
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
    char *                  map_resolver            = NULL;
    mapping_t *             mapping                 = NULL;
    htable_t *              lcaf_ht                 = NULL;
    lisp_xtr_t *            xtr                     = NULL;


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
            if (add_server(map_resolver, xtr->map_resolvers) == GOOD){
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
        mapping = parse_mapping(smc,&(xtr->super),lcaf_ht,STATIC_LOCATOR);

        if (mapping == NULL){
            LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                    cfg_getstr(smc, "eid-prefix"));
            continue;
        }
        if (mcache_lookup_exact(xtr->map_cache, mapping_eid(mapping)) == NULL){
            if (tr_mcache_add_static_mapping(xtr, mapping) == GOOD){
                LMLOG(DBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                        lisp_addr_to_char(mapping_eid(mapping)));
            }else{
                LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        mapping_eid(mapping));
                mapping_del(mapping);
            }
        }else{
            LMLOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                    "Discarded ...",cfg_getstr(smc, "eid-prefix"));
            mapping_del(mapping);
            continue;
        }
        continue;
    }


    /* RTR DATABASE MAPPINGS (like for instance replication lists) */
    n = cfg_size(cfg, "rtr-database-mapping");
    for (i = 0; i < n; i++) {
        add_local_db_mapping(cfg_getnsec(cfg, "rtr-database-mapping",i),xtr,lcaf_ht);
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

    int             i               = 0;
    int             n               = 0;
    int             ret             = 0;
    char *          map_resolver    = NULL;
    char *          proxy_itr       = NULL;
    htable_t *      lcaf_ht         = NULL;
    lisp_xtr_t *    xtr             = NULL;
    mapping_t *     mapping         = NULL;

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
            if (add_server(map_resolver, xtr->map_resolvers) == GOOD){
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
            if (add_server(proxy_itr, xtr->pitrs)==GOOD){
                LMLOG(DBG_1, "Added %s to proxy-itr list", proxy_itr);
            }else {
                LMLOG(LERR, "Can't add %s to proxy-itr list. Discarded ...", proxy_itr);
            }
        }
    }

    n = cfg_size(cfg, "database-mapping");
    for (i = 0; i < n; i++) {
        add_local_db_mapping(cfg_getnsec(cfg, "database-mapping", i),xtr,lcaf_ht);
    }

    /* STATIC MAP-CACHE CONFIG */
    n = cfg_size(cfg, "static-map-cache");
    for (i = 0; i < n; i++) {
        cfg_t *smc = cfg_getnsec(cfg, "static-map-cache", i);
        mapping = parse_mapping(smc,&(xtr->super),lcaf_ht,STATIC_LOCATOR);

        if (mapping == NULL){
            LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                    cfg_getstr(smc, "eid-prefix"));
            continue;
        }
        if (mcache_lookup_exact(xtr->map_cache, mapping_eid(mapping)) == NULL){
            if (tr_mcache_add_static_mapping(xtr, mapping) == GOOD){
                LMLOG(DBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                        lisp_addr_to_char(mapping_eid(mapping)));
            }else{
                LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        mapping_eid(mapping));
                mapping_del(mapping);
            }
        }else{
            LMLOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                    "Discarded ...",cfg_getstr(smc, "eid-prefix"));
            mapping_del(mapping);
            continue;
        }
        continue;
    }

    /* destroy the hash table */
    htable_destroy(lcaf_ht);

    return(GOOD);
}

int
configure_mn(cfg_t *cfg)
{

    int             i               = 0;
    int             n               = 0;
    int             ret             = 0;
    char *          map_resolver    = NULL;
    char *          proxy_itr       = NULL;
    htable_t *      lcaf_ht         = NULL;
    lisp_xtr_t *    xtr             = NULL;
    mapping_t *     mapping         = NULL;

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
            if (add_server(map_resolver, xtr->map_resolvers) == GOOD){
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
            if (add_server(proxy_itr, xtr->pitrs)==GOOD){
                LMLOG(DBG_1, "Added %s to proxy-itr list", proxy_itr);
            }else {
                LMLOG(LERR, "Can't add %s to proxy-itr list. Discarded ...", proxy_itr);
            }
        }
    }

    n = cfg_size(cfg, "database-mapping");
    for (i = 0; i < n; i++) {
        add_local_db_mapping(cfg_getnsec(cfg, "database-mapping", i),xtr,lcaf_ht);
    }

    /* STATIC MAP-CACHE CONFIG */
    n = cfg_size(cfg, "static-map-cache");
    for (i = 0; i < n; i++) {
        cfg_t *smc = cfg_getnsec(cfg, "static-map-cache", i);
        mapping = parse_mapping(smc,&(xtr->super),lcaf_ht,STATIC_LOCATOR);

        if (mapping == NULL){
            LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                    cfg_getstr(smc, "eid-prefix"));
            continue;
        }
        if (mcache_lookup_exact(xtr->map_cache, mapping_eid(mapping)) == NULL){
            if (tr_mcache_add_static_mapping(xtr, mapping) == GOOD){
                LMLOG(DBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                        lisp_addr_to_char(mapping_eid(mapping)));
            }else{
                LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        mapping_eid(mapping));
                mapping_del(mapping);
            }
        }else{
            LMLOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                    "Discarded ...",cfg_getstr(smc, "eid-prefix"));
            mapping_del(mapping);
            continue;
        }
        continue;
    }

    /* destroy the hash table */
    htable_destroy(lcaf_ht);

    return(GOOD);
}

int
configure_ms(cfg_t *cfg)
{
    char *                  iface       = NULL;
    lisp_site_prefix_t *    site        = NULL;
    htable_t *              lcaf_ht     = NULL;
    int                     i           = 0;
    lisp_ms_t *             ms          = NULL;
    mapping_t *             mapping     = NULL;

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
        if (site != NULL) {
            if (mdb_lookup_entry(ms->lisp_sites_db, site->eid_prefix) != NULL){
                LMLOG(DBG_1, "Configuration file: Duplicated lisp-site: %s . Discarding...",
                        lisp_addr_to_char(site->eid_prefix));
                lisp_site_prefix_del(site);
                continue;
            }

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

        mapping = parse_mapping(mss,&(ms->super),lcaf_ht,STATIC_LOCATOR);

        if (mapping == NULL){
            LMLOG(LERR, "Can't create static register site for %s",
                    cfg_getstr(mss, "eid-prefix"));
            continue;
        }
        /* If the mapping doesn't exist, add it the the database */
        if (mdb_lookup_entry_exact(ms->reg_sites_db, mapping_eid(mapping)) == NULL){
            if (ms_add_registered_site_prefix(ms, mapping) == GOOD){
                LMLOG(DBG_1, "Added static registered site for %s to the registered sites list!",
                        lisp_addr_to_char(mapping_eid(mapping)));
            }else{
                LMLOG(LERR, "Failed to add static registered site for %s to the registered sites list!",
                        lisp_addr_to_char(mapping_eid(mapping)));
                mapping_del(mapping);
            }
        }else{
            LMLOG(LERR, "Configuration file: Duplicated static registered site for %s. Discarded ...",
                    cfg_getstr(mss, "eid-prefix"));
            mapping_del(mapping);
            continue;
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

    static cfg_opt_t rloc_address_opts[] = {
            CFG_STR("address",       0, CFGF_NONE),
            CFG_INT("priority",      0, CFGF_NONE),
            CFG_INT("weight",        0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rloc_iface_opts[] = {
            CFG_STR("interface",     0, CFGF_NONE),
            CFG_INT("afi",           0, CFGF_NONE),
            CFG_INT("priority",      0, CFGF_NONE),
            CFG_INT("weight",        0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t db_mapping_opts[] = {
            CFG_STR("eid-prefix",           0, CFGF_NONE),
            CFG_INT("iid",                  0, CFGF_NONE),
            CFG_SEC("rloc-address",         rloc_address_opts, CFGF_MULTI),
            CFG_SEC("rloc-iface",           rloc_iface_opts, CFGF_MULTI),
            CFG_END()
    };

    static cfg_opt_t map_cache_mapping_opts[] = {
            CFG_STR("eid-prefix",           0, CFGF_NONE),
            CFG_INT("iid",                  0, CFGF_NONE),
            CFG_SEC("rloc-address",         rloc_address_opts, CFGF_MULTI),
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
            CFG_SEC("ms-static-registered-site", db_mapping_opts, CFGF_MULTI),
            CFG_SEC("rtr-database-mapping", db_mapping_opts,    CFGF_MULTI),
            CFG_SEC("static-map-cache",     map_cache_mapping_opts, CFGF_MULTI),
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

mapping_t *
parse_mapping(
        cfg_t *             map,
        lisp_ctrl_dev_t *   dev,
        htable_t *          lcaf_ht,
        uint8_t             type)
{
    mapping_t *     mapping         = NULL;
    glist_t *       loct_list       = NULL;
    glist_entry_t * it              = NULL;
    locator_t *     locator         = NULL;
    glist_t *       addr_list       = NULL;
    lisp_addr_t *   eid_prefix      = NULL;
    int             ctr             = 0;
    cfg_t *         rl              = NULL;
    lisp_xtr_t *    xtr             = NULL;

    switch (dev->mode){
    case xTR_MODE:
    case MN_MODE:
        xtr  = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
        break;
    default:
        break;
    }

    addr_list = parse_lisp_addr(cfg_getstr(map, "eid-prefix"), lcaf_ht);
    if (addr_list == NULL || glist_size(addr_list) != 1){
        return (NULL);
    }
    eid_prefix = (lisp_addr_t *)glist_first_data(addr_list);

    /* Create mapping */
    if ( type == LOCAL_LOCATOR){
        mapping = mapping_init_local(eid_prefix);
        if (mapping != NULL){
            mapping_set_ttl(mapping, DEFAULT_MAP_REGISTER_TIMEOUT);
        }
    }else{
        mapping = mapping_init_remote(eid_prefix);
    }

    /* no need for the prefix */
    glist_destroy(addr_list);


    if (mapping == NULL){
        return (NULL);
    }
    /* Create and add locators */
    for (ctr = 0; ctr < cfg_size(map, "rloc-address"); ctr++) {
        rl = cfg_getnsec(map, "rloc-address", ctr);
        loct_list = parse_rloc_address(rl,dev,lcaf_ht,type);
        if (loct_list == NULL){
            continue;
        }
        glist_for_each_entry(it,loct_list){
            locator = (locator_t *)glist_entry_data(it);
            if (locator == NULL){
                continue;
            }
            /* Check that the locator is not already added */
            if (mapping_get_loct_with_addr(mapping, locator_addr(locator)) != NULL){
                LMLOG(LERR,"Configuration file: Duplicated RLOC with address %s "
                        "for EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL && type == LOCAL_LOCATOR){
                    iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }
            if (mapping_add_locator(mapping, locator) != GOOD){
                LMLOG(DBG_1,"parse_mapping: Couldn't add RLOC with address %s "
                        "to the mapping with EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL && type == LOCAL_LOCATOR){
                    iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }

        }
        glist_destroy(loct_list);
    }

    if (type == LOCAL_LOCATOR){
        for (ctr = 0; ctr < cfg_size(map, "rloc-iface"); ctr++) {
            rl = cfg_getnsec(map, "rloc-iface", ctr);
            locator = parse_rloc_interface(rl,dev);
            if (locator == NULL){
                continue;
            }
            /* Check that the locator is not already added */
            if (mapping_get_loct_with_addr(mapping, locator_addr(locator)) != NULL){
                LMLOG(LERR,"Configuration file: Duplicated RLOC with address %s "
                        "for EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL){
                    iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }
            if (mapping_add_locator(mapping, locator) != GOOD){
                LMLOG(DBG_1,"parse_mapping: Couldn't add RLOC with address %s "
                        "to the mapping with EID prefix %s. Discarded ...",
                        lisp_addr_to_char(locator_addr(locator)),
                        lisp_addr_to_char(mapping_eid(mapping)));
                if (xtr != NULL){
                    iface_locators_unattach_locator(xtr->iface_locators_table,locator);
                }
                locator_del(locator);
                continue;
            }
        }
    }

    mapping_compute_balancing_vectors(mapping);

    return (mapping);
}

static glist_t *
parse_rloc_address(
        cfg_t *             rloc,
        lisp_ctrl_dev_t *   dev,
        htable_t *          lcaf_ht,
        uint8_t             type)
{
    glist_t *           loct_list       = NULL;
    locator_t *         locator         = NULL;
    glist_t *           addr_list       = NULL;
    glist_entry_t *     it              = NULL;
    lisp_addr_t *       address         = NULL;
    lisp_addr_t *       ip_addr        = NULL;
    iface_t*            iface           = NULL;
    int *               out_socket      = 0;
    char *              addr_str        = NULL;
    char*               iface_name      = NULL;
    int                 priority        = 0;
    int                 weight          = 0;

    lisp_xtr_t *        xtr             = NULL;
    shash_t *           iface_lctrs     = NULL;
    iface_locators *    if_loct         = NULL;

    addr_str = cfg_getstr(rloc, "address");
    priority = cfg_getint(rloc, "priority");
    weight = cfg_getint(rloc, "weight");

    if (validate_priority_weight(priority, weight) != GOOD) {
        return (NULL);
    }

    addr_list = parse_lisp_addr(addr_str, lcaf_ht);
    if (addr_list == NULL || glist_size(addr_list) == 0){
        return (NULL);
    }

    loct_list = glist_new();
    if (loct_list == NULL){
        return (NULL);
    }

    glist_for_each_entry(it,addr_list){
        address = (lisp_addr_t *)glist_entry_data(it);
        if (address == NULL){
            continue;
        }
        if (lisp_addr_lafi(address) == LM_AFI_IPPREF){
            LMLOG(LERR, "Configuration file: RLOC address can not be a prefix: %s ",
                    lisp_addr_to_char(address));
            continue;
        }

        if (type == LOCAL_LOCATOR){
            /* Decide IP address to be used to lookup the interface */

        	ip_addr = lisp_addr_get_ip_addr(address);
        	if (ip_addr == NULL) {
        		LMLOG(LERR, "Configuration file: Can't determine RLOC's IP "
        				"address %s", lisp_addr_to_char(address));
        		return (NULL);
        	}

            /* Find the interface name associated to the RLOC */
            if (!(iface_name = get_interface_name_from_address(ip_addr))) {
                LMLOG(LERR, "Configuration file: Can't find interface for RLOC %s",
                        lisp_addr_to_char(ip_addr));
                continue;
            }

            /* Find the interface */
            if (!(iface = get_interface(iface_name))) {
                if (!(iface = add_interface(iface_name))) {
                    continue;
                }
            }

            out_socket = (lisp_addr_ip_afi(ip_addr) == AF_INET) ? &(iface->out_socket_v4) : &(iface->out_socket_v6);

            locator = locator_init_local_full(address, iface->status,priority, weight,255, 0, out_socket);

            /* If the locator is for a local mapping, associate the locator with the interface */
            if (locator != NULL && (dev->mode == xTR_MODE || dev->mode == MN_MODE)){
                xtr  = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
                iface_lctrs = xtr->iface_locators_table;
                if_loct = (iface_locators *)shash_lookup(iface_lctrs, iface_name);
                if (if_loct == NULL){
                    if_loct = iface_locators_new(iface_name);
                    shash_insert(xtr->iface_locators_table, iface_name, if_loct);
                }
                if (lisp_addr_ip_afi(ip_addr) == AF_INET){
                    glist_add(locator,if_loct->ipv4_locators);
                }else{
                    glist_add(locator,if_loct->ipv6_locators);
                }
            }
        } else {
            locator = locator_init_remote_full(address, UP, priority, weight, 255, 0);
            if (locator != NULL) {
                locator_set_type(locator,type);
            }
        }
        if (locator != NULL){
            glist_add(locator,loct_list);
            LMLOG(DBG_2,"parse_rloc_address: Locator stucture created: \n %s",
                    locator_to_char(locator));
        }
    }
    glist_destroy(addr_list);

    return (loct_list);
}

static locator_t *
parse_rloc_interface(
        cfg_t *             rloc,
        lisp_ctrl_dev_t *   dev)
{
    locator_t *         locator         = NULL;
    lisp_addr_t *       address         = NULL;
    iface_t*            iface           = NULL;
    int *               out_socket      = 0;
    char *              iface_name      = NULL;
    int                 afi             = AF_UNSPEC;
    int                 priority        = 0;
    int                 weight          = 0;

    lisp_xtr_t *        xtr             = NULL;
    shash_t *           iface_lctrs     = NULL;
    iface_locators *    if_loct         = NULL;

    iface_name = cfg_getstr(rloc, "interface");
    afi =  cfg_getint(rloc, "afi");
    priority = cfg_getint(rloc, "priority");
    weight = cfg_getint(rloc, "weight");

    if (validate_priority_weight(priority, weight) != GOOD) {
        return (NULL);
    }

    if (afi != 4 && afi !=6){
        LMLOG(LERR, "Configuration file: The afi of the locator should be \"4\" (IPv4)"
                " or \"6\" (IPv6)");
        return (NULL);
    }

    /* Find the interface */
    if (!(iface = get_interface(iface_name))) {
        if (!(iface = add_interface(iface_name))) {
            return (BAD);
        }
    }

    if (afi == 4){
        out_socket = &(iface->out_socket_v4);
        address = iface->ipv4_address;
        afi = AF_INET;
    }else{
        out_socket = &(iface->out_socket_v4);
        address = iface->ipv6_address;
        afi = AF_INET6;
    }

    locator = locator_init_local_full(address, iface->status,priority, weight,255, 0, out_socket);

    LMLOG(DBG_2,"parse_rloc_address: Locator stucture created: \n %s",
                        locator_to_char(locator));

    /* If the locator is for a local mapping, associate the locator with the interface */
    if (locator != NULL && (dev->mode == xTR_MODE || dev->mode == MN_MODE)){
        xtr  = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
        iface_lctrs = xtr->iface_locators_table;
        if_loct = (iface_locators *)shash_lookup(iface_lctrs, iface_name);
        if (if_loct == NULL){
            if_loct = iface_locators_new(iface_name);
            shash_insert(xtr->iface_locators_table, iface_name, if_loct);
        }
        if (afi == AF_INET){
            glist_add(locator,if_loct->ipv4_locators);
        }else{
            glist_add(locator,if_loct->ipv6_locators);
        }
    }

    return (locator);
}




static int
add_local_db_mapping(
        cfg_t *         map,
        lisp_xtr_t *    xtr,
        htable_t *      lcaf_ht)
{
    mapping_t       *mapping        = NULL;


    mapping = parse_mapping(map,&(xtr->super),lcaf_ht,LOCAL_LOCATOR);

    if (mapping == NULL){
        LMLOG(LERR, "Can't add EID prefix %s. Discarded ...",
                cfg_getstr(map, "eid-prefix"));
        return (BAD);
    }

    if (local_map_db_lookup_eid_exact(xtr->local_mdb, mapping_eid(mapping)) == NULL){
        if (local_map_db_add_mapping(xtr->local_mdb, mapping) == GOOD){
            LMLOG(DBG_1, "Added EID prefix %s in the database.",
                    lisp_addr_to_char(mapping_eid(mapping)));
            iface_locators_attach_mapping(xtr->iface_locators_table,mapping);
        }else{
            LMLOG(LERR, "Can't add EID prefix %s. Discarded ...",
                    lisp_addr_to_char(mapping_eid(mapping)));
            goto err;
        }
    }else{
        LMLOG(LERR, "Configuration file: Duplicated EID prefix %s. Discarded ...",
                cfg_getstr(map, "eid-prefix"));
        goto err;
    }

    return(GOOD);
err:
    iface_locators_unattach_mapping_and_loct(
            xtr->iface_locators_table,
            mapping);
    mapping_del(mapping);
    return(BAD);
}



/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */

