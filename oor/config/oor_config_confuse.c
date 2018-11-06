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

#include <netdb.h>
#ifdef ANDROID
#include "../android/jni/confuse_android/src/confuse.h"
#else
#include <confuse.h>
#endif
#include "oor_config_confuse.h"
#include "oor_config_functions.h"
#include "../cmdline.h"
#include "../iface_list.h"
#include "../oor_external.h"
#include "../control/oor_control.h"
#include "../control/oor_ctrl_device.h"
#include "../control/lisp_ms.h"
#include "../control/lisp_xtr.h"
#include "../control/lisp_ddt_node.h"
#include "../control/lisp_ddt_mr.h"
#include "../data-plane/data-plane.h"
#include "../data-plane/encapsulations/vxlan-gpe.h"
#include "../lib/oor_log.h"
#include "../lib/shash.h"
#include "../lib/util.h"

static void
parse_elp_list(cfg_t *cfg, shash_t *ht)
{
    elp_node_t *enode;
    elp_t *elp;
    lisp_addr_t *laddr;
    char *name;
    int i, j;
    uint8_t good_elp;

    for(i = 0; i < cfg_size(cfg, "explicit-locator-path"); i++) {
        cfg_t *selp = cfg_getnsec(cfg, "explicit-locator-path", i);
        name = cfg_getstr(selp, "elp-name");
        if (name == NULL){
            OOR_LOG(LWRN, "Configuration file: explicit-locator-path requires an elp-name. Discarding ELP");
            continue;
        }

        if (cfg_size(selp, "elp-node") == 0){
            OOR_LOG(LWRN, "Configuration file: explicit-locator-path needs at least one elp node. Discarding ELP");
            continue;
        }

        elp = elp_type_new();

        good_elp = TRUE;
        for (j = 0; j < cfg_size(selp, "elp-node");j++) {
            cfg_t *senode = cfg_getnsec(selp, "elp-node", j);
            if (cfg_getstr(senode, "address") == NULL){
                good_elp = FALSE;
                OOR_LOG(LWRN, "Configuration file: elp-node needs at least the address field. Discarding ELP");
                break;
            }
            enode = xzalloc(sizeof(elp_node_t));
            enode->addr = lisp_addr_new();
            if (lisp_addr_ip_from_char(cfg_getstr(senode, "address"),
                    enode->addr) != GOOD) {
                elp_node_del(enode);
                OOR_LOG(LWRN, "Configuration file: Couldn't parse ELP node %s",
                        cfg_getstr(senode, "address"));
                continue;
            }
            enode->L = cfg_getbool(senode, "lookup") ? 1 : 0;
            enode->P = cfg_getbool(senode, "probe") ? 1 : 0;
            enode->S = cfg_getbool(senode, "strict") ? 1: 0;

            glist_add_tail(enode, elp->nodes);
        }

        if (good_elp == FALSE){
            elp_type_del(elp);
            continue;
        }

        laddr = lisp_addr_new_lafi(LM_AFI_LCAF);
        lisp_addr_lcaf_set_type(laddr, LCAF_EXPL_LOC_PATH);
        lisp_addr_lcaf_set_addr(laddr, elp);
        OOR_LOG(LDBG_1, "Configuration file: parsed explicit-locator-path: %s",
                lisp_addr_to_char(laddr));

        shash_insert(ht, strdup(name), laddr);
    }
}

static void
parse_rle_list(cfg_t *cfg, shash_t *ht)
{
    rle_node_t *rnode;
    rle_t *rle;
    lisp_addr_t *laddr;
    char *name;
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
                OOR_LOG(LDBG_1, "parse_rle_list: Couldn't parse RLE node %s",
                        cfg_getstr(rlenode, "address"));
            }
            rnode->level = cfg_getint(rlenode, "level");

            glist_add_tail(rnode, rle->nodes);
        }
        lisp_addr_lcaf_set_addr(laddr, (void *)rle);
        OOR_LOG(LDBG_1, "Configuration file: parsed replication-list: %s",
                lisp_addr_to_char(laddr));

        shash_insert(ht, strdup(name), laddr);
    }

}

static void
parse_mcinfo_list(cfg_t *cfg, shash_t *ht)
{
    mc_t *mc;
    lisp_addr_t *laddr;
    char *name;
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
        OOR_LOG(LDBG_1, "Configuration file: parsed multicast-info: %s",
                lisp_addr_to_char(laddr));

        shash_insert(ht, strdup(name), laddr);
        count ++;
    }

    if (count != 0) {
        OOR_LOG(LINF, "Parsed configured multicast addresses");
    }
}

static shash_t *
parse_lcafs(cfg_t *cfg)
{
    shash_t *lcaf_ht;

    /* create lcaf hash table */
    lcaf_ht = shash_new_managed((free_value_fn_t)lisp_addr_del);
    parse_elp_list(cfg, lcaf_ht);
    parse_rle_list(cfg, lcaf_ht);
    parse_mcinfo_list(cfg, lcaf_ht);

    return(lcaf_ht);
}


int
parse_mapping_cfg_params(cfg_t *map, conf_mapping_t *conf_mapping, uint8_t is_local, uint8_t is_static)
{

    int ctr;
    cfg_t *rl;
    conf_loc_t *conf_loc;
    conf_loc_iface_t *conf_loc_iface;
    int afi;

    if (cfg_getstr(map, "eid-prefix") == NULL){
        return (BAD);
    }

    conf_mapping->eid_prefix = strdup(cfg_getstr(map, "eid-prefix"));
    conf_mapping->iid = cfg_getint(map, "iid");
    if (!is_static) {
        conf_mapping->ttl = cfg_getint(map, "ttl");
    }

    for (ctr = 0; ctr < cfg_size(map, "rloc-address"); ctr++){
        rl = cfg_getnsec(map, "rloc-address", ctr);

        if (cfg_getstr(rl, "address") == NULL){
            OOR_LOG(LWRN, "Configuration file: Mapping %s with no RLOC address selected",conf_mapping->eid_prefix);
            return (BAD);
        }
        conf_loc = conf_loc_new_init(
                cfg_getstr(rl, "address"),
                cfg_getint(rl, "priority"),
                cfg_getint(rl, "weight"),
                255,0);
        glist_add_tail(conf_loc,conf_mapping->conf_loc_list);
    }

    if (is_local){

        for (ctr = 0; ctr < cfg_size(map, "rloc-iface"); ctr++){
            rl = cfg_getnsec(map, "rloc-iface", ctr);
            afi = cfg_getint(rl, "ip_version");
            if (cfg_getstr(rl, "interface") == NULL){
                OOR_LOG(LWRN, "Configuration file: Mapping %s with no RLOC interface selected",conf_mapping->eid_prefix);
                return (BAD);
            }
            conf_loc_iface = conf_loc_iface_new_init(
                    cfg_getstr(rl, "interface"),
                    afi,
                    cfg_getint(rl, "priority"),
                    cfg_getint(rl, "weight"),
                    255,0);
            glist_add_tail(conf_loc_iface,conf_mapping->conf_loc_iface_list);
        }
    }

    return (GOOD);
}


mapping_t *
parse_mapping(cfg_t *map, oor_ctrl_dev_t *dev, shash_t * lcaf_ht,
        uint8_t is_local, uint8_t is_static)
{
    mapping_t *mapping;
    conf_mapping_t *conf_mapping;

    conf_mapping = conf_mapping_new();

    if (parse_mapping_cfg_params(map, conf_mapping, is_local, is_static) != GOOD){
        return (NULL);
    }
    mapping = process_mapping_config(dev, lcaf_ht, conf_mapping, is_local);

    conf_mapping_destroy(conf_mapping);

    return (mapping);
}


int
parse_map_servers(cfg_t *cfg, lisp_xtr_t *xtr)
{
    int n,i;
    /* MAP-SERVER CONFIG */
    n = cfg_size(cfg, "map-server");
    for (i = 0; i < n; i++) {
        cfg_t *ms = cfg_getnsec(cfg, "map-server", i);
        if (add_map_server(xtr->map_servers, cfg_getstr(ms, "address"),
                cfg_getint(ms, "key-type"), cfg_getstr(ms, "key"),
                (cfg_getbool(ms, "proxy-reply") ? 1 : 0)) == GOOD) {
            OOR_LOG(LDBG_1, "Added %s to map-server list",
                    cfg_getstr(ms, "address"));
        } else {
            OOR_LOG(LWRN, "Can't add %s Map Server.", cfg_getstr(ms, "address"));
        }
    }
    return (GOOD);
}

int
parse_proxy_etrs(cfg_t *cfg, lisp_xtr_t *xtr)
{
    int n,i;
    mcache_entry_t *ipv4_petrs_mc,*ipv6_petrs_mc;

    ipv4_petrs_mc = mcache_get_all_space_entry(xtr->tr.map_cache,AF_INET);
    ipv6_petrs_mc = mcache_get_all_space_entry(xtr->tr.map_cache,AF_INET6);
    /* PROXY-ETR CONFIG */
    n = cfg_size(cfg, "proxy-etr-ipv4");
    for(i = 0; i < n; i++) {
        cfg_t *petr = cfg_getnsec(cfg, "proxy-etr-ipv4", i);
        if(cfg_getstr(petr, "address") == NULL){
            OOR_LOG(LERR,"Configuration file: proxy-etr-ipv4 needs at least the address field");
            return (BAD);
        }

        if (add_proxy_etr_entry(ipv4_petrs_mc,
                cfg_getstr(petr, "address"),
                cfg_getint(petr, "priority"),
                cfg_getint(petr, "weight")) == GOOD) {
            OOR_LOG(LDBG_1, "Added %s to proxy-etr list for IPv4 EIDs", cfg_getstr(petr, "address"));
        } else{
            OOR_LOG(LERR, "Can't add proxy-etr %s", cfg_getstr(petr, "address"));
        }
    }

    n = cfg_size(cfg, "proxy-etr-ipv6");
    for(i = 0; i < n; i++) {
        cfg_t *petr = cfg_getnsec(cfg, "proxy-etr-ipv6", i);
        if(cfg_getstr(petr, "address") == NULL){
            OOR_LOG(LERR,"Configuration file: proxy-etr-ipv6 needs at least the address field");
            return (BAD);
        }

        if (add_proxy_etr_entry(ipv6_petrs_mc,
                cfg_getstr(petr, "address"),
                cfg_getint(petr, "priority"),
                cfg_getint(petr, "weight")) == GOOD) {
            OOR_LOG(LDBG_1, "Added %s to proxy-etr list for IPv6 EIDs", cfg_getstr(petr, "address"));
        } else{
            OOR_LOG(LERR, "Can't add proxy-etr %s", cfg_getstr(petr, "address"));
        }
    }

    /* Calculate forwarding info for petrs */
    if (xtr->tr.fwd_policy->init_map_cache_policy_inf(xtr->tr.fwd_policy_dev_parm,ipv4_petrs_mc) != GOOD){
        OOR_LOG(LDBG_1, "parse_proxy_etrs: Couldn't initiate routing info for PeTRs!.");
        return(BAD);
    }
    if (xtr->tr.fwd_policy->init_map_cache_policy_inf(xtr->tr.fwd_policy_dev_parm,ipv6_petrs_mc) != GOOD){
        OOR_LOG(LDBG_1, "parse_proxy_etrs: Couldn't initiate routing info for PeTRs!.");
        return(BAD);
    }
    return (GOOD);
}

int
parse_proxy_itrs(cfg_t *cfg, lisp_xtr_t *xtr)
{
    int n,i;
    char *proxy_itr;
    n = cfg_size(cfg, "proxy-itrs");
    for(i = 0; i < n; i++) {
        if ((proxy_itr = cfg_getnstr(cfg, "proxy-itrs", i)) != NULL) {
            if (add_server(proxy_itr, xtr->pitrs)==GOOD){
                OOR_LOG(LDBG_1, "Added %s to proxy-itr list", proxy_itr);
            }else {
                OOR_LOG(LERR, "Can't add %s to proxy-itr list. Discarded ...", proxy_itr);
            }
        }
    }
    return (GOOD);
}

int
parse_database_mapping(cfg_t *cfg, lisp_xtr_t *xtr, shash_t *lcaf_ht)
{
    int n,i;
    mapping_t *mapping;
    map_local_entry_t *map_loc_e;

    n = cfg_size(cfg, "database-mapping");
    for (i = 0; i < n; i++) {
        mapping = parse_mapping(cfg_getnsec(cfg, "database-mapping", i),&(xtr->super),lcaf_ht,TRUE,FALSE);
        if (mapping == NULL){
            return (BAD);
        }
        map_loc_e = map_local_entry_new_init(mapping);
        if (map_loc_e == NULL){
            mapping_del(mapping);
            continue;
        }
        if (xtr->tr.fwd_policy->init_map_loc_policy_inf(
                xtr->tr.fwd_policy_dev_parm,map_loc_e,NULL)!= GOOD){
            OOR_LOG(LERR, "Couldn't inititate forward information for mapping with EID: %s. Discarding it...",
                    lisp_addr_to_char(mapping_eid(mapping)));
            map_local_entry_del(map_loc_e);
            continue;
        }

        if (add_local_db_map_local_entry(map_loc_e,xtr) != GOOD){
            map_local_entry_del(map_loc_e);
            continue;
        }
    }

    return (GOOD);
}

int
configure_tunnel_router(cfg_t *cfg, oor_ctrl_dev_t *dev, lisp_tr_t *tr, shash_t *lcaf_ht)
{
    int i,n,ret;
    char *map_resolver;
    char *encap, *encap_str;
    mapping_t *mapping;
    mcache_entry_t *mce;

    /* FWD POLICY STRUCTURES */
#ifdef VPP
    tr->fwd_policy = fwd_policy_class_find("vpp_balancing");
#else
    tr->fwd_policy = fwd_policy_class_find("flow_balancing");
#endif
    tr->fwd_policy_dev_parm = tr->fwd_policy->new_dev_policy_inf(ctrl_dev,NULL);

    if ((encap_str = cfg_getstr(cfg, "encapsulation")) != NULL) {
        encap = str_to_lower_case(encap_str);
        if (strcmp(encap, "lisp") == 0) {
            tr->encap_type = ENCP_LISP;
            tr->encap_port = LISP_DATA_PORT;
        }else if (strcmp(encap, "vxlan-gpe") == 0){
            tr->encap_type = ENCP_VXLAN_GPE;
            tr->encap_port = VXLAN_GPE_DATA_PORT;
        }else{
            OOR_LOG(LERR, "Unknown encapsulation type: %s",encap);
            free(encap);
            return (BAD);
        }
        free(encap);
    }

    /* RETRIES */
    ret = cfg_getint(cfg, "map-request-retries");
    tr->map_request_retries = (ret != 0) ? ret : DEFAULT_MAP_REQUEST_RETRIES;


    /* RLOC PROBING CONFIG */
    cfg_t *dm = cfg_getnsec(cfg, "rloc-probing", 0);
    if (dm != NULL) {
        tr->probe_interval = cfg_getint(dm, "rloc-probe-interval");
        tr->probe_retries = cfg_getint(dm, "rloc-probe-retries");
        tr->probe_retries_interval = cfg_getint(dm,
                "rloc-probe-retries-interval");

        validate_rloc_probing_parameters(&tr->probe_interval,
                &tr->probe_retries, &tr->probe_retries_interval);
    } else {
        OOR_LOG(LDBG_1, "Configuration file: RLOC probing not defined. "
                "Setting default values: RLOC Probing Interval: %d sec.",
                RLOC_PROBING_INTERVAL);
        tr->probe_interval = RLOC_PROBING_INTERVAL;
        tr->probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
        tr->probe_retries_interval = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;

    }


    /* MAP-RESOLVER CONFIG  */
    n = cfg_size(cfg, "map-resolver");
    for(i = 0; i < n; i++) {
        if ((map_resolver = cfg_getnstr(cfg, "map-resolver", i)) != NULL) {
            if (add_server(map_resolver, tr->map_resolvers) == GOOD){
                OOR_LOG(LDBG_1, "Added %s to map-resolver list", map_resolver);
            }else{
                OOR_LOG(LCRIT,"Can't add %s Map Resolver.",map_resolver);
            }
        }
    }

    /* STATIC MAP-CACHE CONFIG */
    n = cfg_size(cfg, "static-map-cache");
    for (i = 0; i < n; i++) {
        cfg_t *smc = cfg_getnsec(cfg, "static-map-cache", i);
        mapping = parse_mapping(smc,dev,lcaf_ht,FALSE,TRUE);

        if (mapping == NULL){
            OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                    cfg_getstr(smc, "eid-prefix"));
            return(BAD);
        }
        if (mcache_lookup_exact(tr->map_cache, mapping_eid(mapping)) == NULL){
            mce = tr_mcache_add_mapping(tr, mapping, MCE_STATIC, ACTIVE);
            if (mce){
                tr_mcache_entry_program_timers(tr,mce);
                OOR_LOG(LDBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                        lisp_addr_to_char(mapping_eid(mapping)));
            }else{
                OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        mapping_eid(mapping));
                mapping_del(mapping);
            }
        }else{
            OOR_LOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                    "Discarded ...",cfg_getstr(smc, "eid-prefix"));
            mapping_del(mapping);
            continue;
        }
        continue;
    }
    return (GOOD);
}

int
configure_rtr(cfg_t *cfg)
{
    lisp_rtr_t *rtr;
    shash_t *lcaf_ht;
    int i,n;

    /* CREATE AND CONFIGURE RTR (xTR in fact) */
    if (ctrl_dev_create(RTR_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create RTR. Aborting!");
        return (BAD);
    }

    lcaf_ht = parse_lcafs(cfg);

    rtr = lisp_rtr_cast(ctrl_dev);
    if (configure_tunnel_router(cfg,&(rtr->super), &rtr->tr, lcaf_ht)!=GOOD){
        return (BAD);
    }

    /* INTERFACES CONFIG */
    n = cfg_size(cfg, "rtr-ifaces");
    if (n) {
        cfg_t *rifs = cfg_getsec(cfg, "rtr-ifaces");
        int nr = cfg_size(rifs, "rtr-iface");
        if (nr == 0){
            OOR_LOG(LERR, "Configuration file: RTR needs at least one data iface");
        }
        for(i = 0; i < nr; i++) {
            cfg_t *ri = cfg_getnsec(rifs, "rtr-iface", i);
            if (cfg_getstr(ri, "iface") == NULL){
                OOR_LOG(LERR, "Configuration file: rtr-iface needs at least the iface name");
                return (BAD);
            }

            if (add_rtr_iface(rtr,
                    cfg_getstr(ri, "iface"),
                    cfg_getint(ri, "ip_version"),
                    cfg_getint(ri, "priority"),
                    cfg_getint(ri, "weight")) == GOOD) {
                OOR_LOG(LDBG_1, "Configured interface %s for RTR",
                        cfg_getstr(ri, "iface"));
            } else{
                OOR_LOG(LERR, "Can't configure iface %s for RTR",
                        cfg_getstr(ri, "iface"));
            }
        }
        if (!rtr->all_locs_map->fwd_policy_info) {
            /* RTR has all the configured interfaces down */
            OOR_LOG(LERR, "Configuration file: All the configured interfaces doesn't exist or are down");
            if (rtr->tr.fwd_policy->init_map_loc_policy_inf(
                    rtr->tr.fwd_policy_dev_parm,rtr->all_locs_map,NULL) != GOOD){
                OOR_LOG(LERR, "Couldn't initiate forward information for rtr localtors.");
                map_local_entry_del(rtr->all_locs_map);
                return (BAD);
            }
        }
    }
    n = cfg_size(cfg, "rtr-ms-node");
    for(i = 0; i < n; i++) {
        cfg_t *rms = cfg_getnsec(cfg, "rtr-ms-node", i);
        if (rtr_add_rtr_ms_node(rtr,
                cfg_getstr(rms, "address"),
                cfg_getstr(rms, "key"),
                cfg_getstr(rms, "draft-version")) != GOOD){
            return (BAD);
        }
    }
    shash_destroy(lcaf_ht);

    return(GOOD);
}

int
configure_xtr(cfg_t *cfg)
{
    lisp_xtr_t *xtr;
    shash_t *lcaf_ht;

    /* CREATE AND CONFIGURE XTR */
    if (ctrl_dev_create(xTR_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create xTR. Aborting!");
        exit_cleanup();
    }

    lcaf_ht = parse_lcafs(cfg);

    xtr = lisp_xtr_cast(ctrl_dev);

    xtr->nat_aware = cfg_getbool(cfg, "nat_traversal_support") ? TRUE:FALSE;
    if(xtr->nat_aware){
        default_rloc_afi = AF_INET;
        OOR_LOG(LDBG_1, "NAT support enabled. Set defaul RLOC to IPv4 family");
    }

    if (configure_tunnel_router(cfg, &(xtr->super), &xtr->tr, lcaf_ht)!=GOOD){
        return (BAD);
    }

    if (parse_map_servers(cfg, xtr) != GOOD){
        return (BAD);
    }
    if (parse_proxy_etrs(cfg, xtr) != GOOD){
        return (BAD);
    }
    if (parse_proxy_itrs(cfg, xtr) != GOOD){
        return (BAD);
    }
    if (parse_database_mapping(cfg, xtr, lcaf_ht) != GOOD){
        return (BAD);
    }

    /* Generate xTR identifier */
    if (tr_set_xTR_ID(xtr) != GOOD){
        OOR_LOG(LERR,"Could not generate xTR-ID");
        return (BAD);
    }
    tr_set_site_ID(xtr, 0);

    /* destroy the hash table */
    shash_destroy(lcaf_ht);

    return (GOOD);
}

int
configure_mn(cfg_t *cfg)
{
    lisp_xtr_t *xtr;
    shash_t *lcaf_ht;

    /* CREATE AND CONFIGURE MN */
    if (ctrl_dev_create(MN_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create mobile node. Aborting!");
        exit_cleanup();
    }

    lcaf_ht = parse_lcafs(cfg);

    xtr = lisp_xtr_cast(ctrl_dev);

    xtr->nat_aware = cfg_getbool(cfg, "nat_traversal_support") ? TRUE:FALSE;
    if(xtr->nat_aware){
        default_rloc_afi = AF_INET;
        OOR_LOG(LDBG_1, "NAT support enabled. Set defaul RLOC to IPv4 family");
    }

    if (configure_tunnel_router(cfg, &(xtr->super), &xtr->tr, lcaf_ht)!=GOOD){
        return (BAD);
    }

    if (parse_map_servers(cfg, xtr) != GOOD){
        return (BAD);
    }
    if (parse_proxy_etrs(cfg, xtr) != GOOD){
        return (BAD);
    }
    if (parse_proxy_itrs(cfg, xtr) != GOOD){
        return (BAD);
    }
    if (parse_database_mapping(cfg, xtr, lcaf_ht) != GOOD){
        return (BAD);
    }

    /* Generate xTR identifier */
    if (tr_set_xTR_ID(xtr) != GOOD){
        OOR_LOG(LERR,"Could not generate xTR-ID");
        return (BAD);
    }
    tr_set_site_ID(xtr, 0);

    /* destroy the hash table */
    shash_destroy(lcaf_ht);

    return (GOOD);
}

int
configure_ms(cfg_t *cfg)
{
    char *iface_name, *rtr_id;
    iface_t *iface=NULL;
    lisp_site_prefix_t *site;
    shash_t *lcaf_ht;
    int i,j,n, res;
    lisp_ms_t *ms;
    mapping_t *mapping;
    glist_t *rtr_id_list;


    if (ctrl_dev_create(MS_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create MS. Aborting!");
        exit_cleanup();
    }
    ms = lisp_ms_cast(ctrl_dev);


    /* create lcaf hash table */
    lcaf_ht = parse_lcafs(cfg);

    /* CONTROL INTERFACE */
    /* TODO: should work with all interfaces in the future */
    iface_name = cfg_getstr(cfg, "control-iface");
    if (iface_name) {
        iface = add_interface(iface_name);
        if (iface == NULL) {
            OOR_LOG(LERR, "Configuration file: Couldn't add the control iface of the Map Server");
            return(BAD);
        }
    }else{
        /* we have no iface_name, so also iface is missing */
        OOR_LOG(LERR, "Configuration file: Specify the control iface of the Map Server");
        return(BAD);
    }

    iface_configure (iface, AF_INET);
    iface_configure (iface, AF_INET6);

    /* LISP-SITE CONFIG */
    for (i = 0; i < cfg_size(cfg, "lisp-site"); i++) {
        cfg_t *ls = cfg_getnsec(cfg, "lisp-site", i);

        if (cfg_getstr(ls, "eid-prefix") == NULL || cfg_getstr(ls, "key") == NULL){
            OOR_LOG(LERR, "Configuration file: MS LISP site requires at least an eid-prefix and a key");
            return (BAD);
        }

        glist_t *str_ddt_ms_peers_lst = glist_new();

        char *ms_peer;
        n = cfg_size(ls, "ddt-ms-peers");
        for(j = 0; j < n; j++) {
            if ((ms_peer = cfg_getnstr(ls, "ddt-ms-peers", j)) != NULL) {
                glist_add_tail(ms_peer, str_ddt_ms_peers_lst);
            }
        }

        site = build_lisp_site_prefix(ms,
                cfg_getstr(ls, "eid-prefix"),
                cfg_getint(ls, "iid"),
                cfg_getint(ls, "key-type"),
                cfg_getstr(ls, "key"),
                cfg_getbool(ls, "accept-more-specifics") ? 1:0,
                        cfg_getbool(ls, "proxy-reply") ? 1:0,
                                cfg_getbool(ls, "merge") ? 1 : 0,
                                        cfg_getbool(ls, "ddt-ms-peers-complete") ? 1 : 0,
                                                str_ddt_ms_peers_lst,
                                                lcaf_ht);

        glist_destroy(str_ddt_ms_peers_lst);

        if (site != NULL) {
            if (mdb_lookup_entry(ms->lisp_sites_db, site->eid_prefix) != NULL){
                OOR_LOG(LDBG_1, "Configuration file: Duplicated lisp-site: %s . Discarding...",
                        lisp_addr_to_char(site->eid_prefix));
                lisp_site_prefix_del(site);
                continue;
            }

            OOR_LOG(LDBG_1, "Adding lisp site prefix %s to the lisp-sites "
                    "database", lisp_addr_to_char(site->eid_prefix));
            ms_add_lisp_site_prefix(ms, site);
        }else{
            OOR_LOG(LERR, "Can't add lisp-site prefix %s. Discarded ...",
                    cfg_getstr(ls, "eid-prefix"));
        }
    }

    /* LISP REGISTERED SITES CONFIG */
    for (i = 0; i< cfg_size(cfg, "ms-static-registered-site"); i++ ) {
        cfg_t *mss = cfg_getnsec(cfg, "ms-static-registered-site", i);

        mapping = parse_mapping(mss,&(ms->super),lcaf_ht,FALSE,FALSE);

        if (mapping == NULL){
            OOR_LOG(LERR, "Can't create static register site for %s",
                    cfg_getstr(mss, "eid-prefix"));
            return (BAD);
        }
        /* If the mapping doesn't exist, add it the the database */
        if (mdb_lookup_entry_exact(ms->reg_sites_db, mapping_eid(mapping)) == NULL){
            if (ms_add_registered_site_prefix(ms, mapping) == GOOD){
                OOR_LOG(LDBG_1, "Added static registered site for %s to the registered sites list!",
                        lisp_addr_to_char(mapping_eid(mapping)));
            }else{
                OOR_LOG(LERR, "Failed to add static registered site for %s to the registered sites list!",
                        lisp_addr_to_char(mapping_eid(mapping)));
                mapping_del(mapping);
            }
        }else{
            OOR_LOG(LERR, "Configuration file: Duplicated static registered site for %s. Discarded ...",
                    cfg_getstr(mss, "eid-prefix"));
            mapping_del(mapping);
            continue;
        }
    }

    /* NAT RTR configuration of the MS */
    for (i = 0; i< cfg_size(cfg, "ms-rtr-node"); i++ ) {
        cfg_t *rtr_cfg = cfg_getnsec(cfg, "ms-rtr-node", i);
        res = ms_add_rtr_node(ms,
                cfg_getstr(rtr_cfg, "name"),
                cfg_getstr(rtr_cfg, "address"),
                cfg_getstr(rtr_cfg, "key"));
        if (res != GOOD){
            return(BAD);
        }
    }

    for (i = 0; i< cfg_size(cfg, "ms-rtrs-set"); i++ ) {
        cfg_t *rtr_set_cfg = cfg_getnsec(cfg, "ms-rtrs-set", i);
        rtr_id_list = glist_new();
        n = cfg_size(rtr_set_cfg, "rtrs");
        for(j = 0; j < n; j++) {
            if ((rtr_id = cfg_getnstr(rtr_set_cfg, "rtrs", j)) != NULL) {
                glist_add(rtr_id,rtr_id_list);
            }
        }
        res = ms_add_rtr_set(ms,
                cfg_getstr(rtr_set_cfg, "name"),
                cfg_getint(rtr_set_cfg, "ttl"),
                rtr_id_list);
        if (res != GOOD){
            glist_destroy(rtr_id_list);
            return(BAD);
        }
        glist_destroy(rtr_id_list);
    }

    if (ms_advertised_rtr_set(ms, cfg_getstr(cfg, "ms-advertised-rtrs-set")) != GOOD){
        return (BAD);
    }

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    return(GOOD);
}

int
configure_ddt(cfg_t *cfg)
{
    char *iface_name;
    iface_t *iface=NULL;
    ddt_authoritative_site_t *asite;
    ddt_delegation_site_t *dsite;
    shash_t *lcaf_ht;
    int i, j, n;
    lisp_ddt_node_t *ddt_node;

    if (ctrl_dev_create(DDT_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create DDT-Node. Aborting!");
        exit_cleanup();
    }
    ddt_node = CONTAINER_OF(ctrl_dev, lisp_ddt_node_t, super);

    /* create lcaf hash table */
    lcaf_ht = parse_lcafs(cfg);


    /* CONTROL INTERFACE */
    /* TODO: should work with all interfaces in the future */
    iface_name = cfg_getstr(cfg, "control-iface");
    if (iface_name) {
        iface = add_interface(iface_name);
        if (iface == NULL) {
            OOR_LOG(LERR, "Configuration file: Couldn't add the control iface of the DDT-Node");
            return(BAD);
        }
    }else{
        /* we have no iface_name, so also iface is missing */
        OOR_LOG(LERR, "Configuration file: Specify the control iface of the DDT-Node");
        return(BAD);
    }

    iface_configure (iface, AF_INET);
    iface_configure (iface, AF_INET6);

    /* AUTHORITATIVE-SITE CONFIG */
    for (i = 0; i < cfg_size(cfg, "ddt-auth-site"); i++) {
        cfg_t *as = cfg_getnsec(cfg, "ddt-auth-site", i);

        if (cfg_getstr(as, "eid-prefix") == NULL ){
            OOR_LOG(LERR, "Configuration file: DDT-Node authoritative site requires at least an eid-prefix ");
            return (BAD);
        }


        asite = build_ddt_authoritative_site(ddt_node,
                cfg_getstr(as, "eid-prefix"),
                cfg_getint(as, "iid"),
                lcaf_ht);

        if (asite != NULL) {
            if (mdb_lookup_entry(ddt_node->auth_sites_db, asite->xeid) != NULL){
                OOR_LOG(LDBG_1, "Configuration file: Duplicated auth-site: %s . Discarding...",
                        lisp_addr_to_char(asite->xeid));
                ddt_authoritative_site_del(asite);
                continue;
            }

            OOR_LOG(LDBG_1, "Adding authoritative site %s to the authoritative sites "
                    "database", lisp_addr_to_char(asite->xeid));
            ddt_node_add_authoritative_site(ddt_node, asite);
        }else{
            OOR_LOG(LERR, "Can't add  authoritative site %s. Discarded ...",
                    cfg_getstr(as, "eid-prefix"));
        }
    }

    /* DELEGATION SITES CONFIG */
    for (i = 0; i< cfg_size(cfg, "ddt-deleg-site"); i++ ) {
        cfg_t *ds = cfg_getnsec(cfg, "ddt-deleg-site", i);
        glist_t *child_nodes_list = glist_new();

        if (cfg_getstr(ds, "eid-prefix") == NULL || cfg_getstr(ds, "delegation-type") == NULL){
            OOR_LOG(LERR, "Configuration file: DDT-Node delegation site requires at least an eid-prefix, and the delegation-type");
            return (BAD);
        }

        char *child_node;
        n = cfg_size(ds, "deleg-nodes");
        for(j = 0; j < n; j++) {
            if ((child_node = cfg_getnstr(ds, "deleg-nodes", j)) != NULL) {
                glist_add_tail(child_node, child_nodes_list);
            }
        }


        char *typechar = cfg_getstr(ds, "delegation-type");
        char *type_char;
        int typeint;
        if (!typechar){
            OOR_LOG (LCRIT, "Configuration file: Unknown delegation type: %s",typechar);
            return (BAD);
        }
        type_char = str_to_lower_case(typechar);
        if (strcmp(type_char,"child_ddt_node") == 0){
            typeint = LISP_ACTION_NODE_REFERRAL;
        }else if (strcmp(type_char,"map_server_ddt_node") == 0){
            typeint = LISP_ACTION_MS_REFERRAL;
        }else{
            OOR_LOG (LCRIT, "Configuration file: Unknown delegation type: %s",typechar);
            free(type_char);
            return (BAD);
        }
        free(type_char);

        dsite = build_ddt_delegation_site(ddt_node,
                cfg_getstr(ds, "eid-prefix"),
                cfg_getint(ds, "iid"),
                typeint,
                child_nodes_list,
                lcaf_ht);

        glist_destroy(child_nodes_list);

        if (dsite != NULL) {
            if (mdb_lookup_entry(ddt_node->deleg_sites_db, dsite_xeid(dsite)) != NULL){
                OOR_LOG(LDBG_1, "Configuration file: Duplicated or overlapped deleg-site: %s . Discarding...",
                        lisp_addr_to_char(dsite_xeid(dsite)));
                ddt_delegation_site_del(dsite);
                continue;
            }

            OOR_LOG(LDBG_1, "Adding delegation site %s to the delegation sites "
                    "database", lisp_addr_to_char(dsite_xeid(dsite)));
            ddt_node_add_delegation_site(ddt_node, dsite);
        }else{
            OOR_LOG(LERR, "Can't add  delegation site %s. Discarded ...",
                    cfg_getstr(ds, "eid-prefix"));
        }
    }
    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    return(GOOD);
}

int
configure_ddt_mr(cfg_t *cfg)
{
    char *iface_name;
    iface_t *iface=NULL;
    shash_t *lcaf_ht;
    int j, n;
    lisp_ddt_mr_t *ddt_mr;


    if (ctrl_dev_create(DDT_MR_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create DDT-Map Resolver. Aborting!");
        exit_cleanup();
    }
    ddt_mr = CONTAINER_OF(ctrl_dev, lisp_ddt_mr_t, super);

    /* create lcaf hash table */
    lcaf_ht = parse_lcafs(cfg);


    /* CONTROL INTERFACE */
    /* TODO: should work with all interfaces in the future */
    iface_name = cfg_getstr(cfg, "control-iface");
    if (iface_name) {
        iface = add_interface(iface_name);
        if (iface == NULL) {
            OOR_LOG(LERR, "Configuration file: Couldn't add the control iface of the DDT-Map Resolver");
            return(BAD);
        }
    }else{
        /* we have no iface_name, so also iface is missing */
        OOR_LOG(LERR, "Configuration file: Specify the control iface of the DDT-Map Resolver");
        return(BAD);
    }

    iface_configure (iface, AF_INET);
    iface_configure (iface, AF_INET6);

    /* ROOT ADDRESSES CONFIG */
    glist_t *root_addresses = glist_new();

    char *root_address;
    n = cfg_size(cfg, "ddt-root-addresses");
    if (n<1) {
        OOR_LOG(LERR, "Configuration file: Specify at least one address for DDT-Root");
        return(BAD);
    }

    for(j = 0; j < n; j++) {
        if ((root_address = cfg_getnstr(cfg, "ddt-root-addresses", j)) != NULL) {
            glist_add_tail(root_address, root_addresses);
        }
    }

    ddt_mr_put_root_addresses(ddt_mr, root_addresses, lcaf_ht);

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    glist_destroy(root_addresses);
    return(GOOD);
}

int
handle_config_file()
{
    int ret;
    cfg_t *cfg;
    char *mode, *mode_str;
    char *log_file;
    char *scope, *scope_str;

    /* xTR specific */
    static cfg_opt_t map_server_opts[] = {
            CFG_STR("address",              0, CFGF_NONE),
            CFG_INT("key-type",             1, CFGF_NONE),
            CFG_STR("key",                  0, CFGF_NONE),
            CFG_BOOL("proxy-reply", cfg_false, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rloc_address_opts[] = {
            CFG_STR("address",       0, CFGF_NONE),
            CFG_INT("priority",      1, CFGF_NONE),
            CFG_INT("weight",        100, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rloc_iface_opts[] = {
            CFG_STR("interface",     0, CFGF_NONE),
            CFG_INT("ip_version",    4, CFGF_NONE),
            CFG_INT("priority",      1, CFGF_NONE),
            CFG_INT("weight",        100, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t db_mapping_opts[] = {
            CFG_STR("eid-prefix",           0, CFGF_NONE),
            CFG_INT("iid",                  0, CFGF_NONE),
            CFG_INT("ttl",DEFAULT_DATA_CACHE_TTL, CFGF_NONE),
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
            CFG_INT("priority",             1, CFGF_NONE),
            CFG_INT("weight",               100, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rtr_iface_opts[] = {
            CFG_STR("iface",                0, CFGF_NONE),
            CFG_INT("ip_version",           4, CFGF_NONE),
            CFG_INT("priority",             1, CFGF_NONE),
            CFG_INT("weight",               100, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rtr_ifaces_opts[] = {
            CFG_SEC("rtr-iface",    rtr_iface_opts, CFGF_MULTI),
            CFG_END()
    };

    static cfg_opt_t rloc_probing_opts[] = {
            CFG_INT("rloc-probe-interval",           0, CFGF_NONE),
            CFG_INT("rloc-probe-retries",            3, CFGF_NONE),
            CFG_INT("rloc-probe-retries-interval",   10, CFGF_NONE),
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
            CFG_INT("key-type",                 1, CFGF_NONE),
            CFG_STR("key",                      0, CFGF_NONE),
            CFG_BOOL("accept-more-specifics",   cfg_false, CFGF_NONE),
            CFG_BOOL("proxy-reply",             cfg_false, CFGF_NONE),
            CFG_BOOL("merge",                   cfg_false, CFGF_NONE),
            CFG_BOOL("ddt-ms-peers-complete",   cfg_true, CFGF_NONE),
            CFG_STR_LIST("ddt-ms-peers",            0, CFGF_NONE),
            CFG_END()
    };

    /* DDT-Node specific */

    static cfg_opt_t ddt_auth_site_opts[] = {
            CFG_STR("eid-prefix",           0, CFGF_NONE),
            CFG_INT("iid",                  0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t ddt_deleg_site_opts[] = {
            CFG_STR("eid-prefix",           0, CFGF_NONE),
            CFG_INT("iid",                  0, CFGF_NONE),
            CFG_STR("delegation-type",             0, CFGF_NONE),
            CFG_STR_LIST("deleg-nodes",            0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rtr_opts[] = {
            CFG_STR("name",                        0, CFGF_NONE),
            CFG_STR("address",                     0, CFGF_NONE),
            CFG_STR("key",                         0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rtr_set_opts[] = {
            CFG_STR("name",                     0, CFGF_NONE),
            CFG_INT("ttl",         OOR_MS_RTR_TTL, CFGF_NONE),
            CFG_STR_LIST("rtrs",                0, CFGF_NONE),
            CFG_END()
    };

    static cfg_opt_t rtr_ms_opts[] = {
            CFG_STR("address",                     0, CFGF_NONE),
            CFG_STR("key",                         0, CFGF_NONE),
            CFG_STR("draft-version","OLD",CFGF_NONE),
            CFG_END()
    };


    cfg_opt_t opts[] = {
            CFG_SEC("database-mapping",     db_mapping_opts,        CFGF_MULTI),
            CFG_SEC("ms-static-registered-site", db_mapping_opts, CFGF_MULTI),
            CFG_SEC("rtr-database-mapping", db_mapping_opts,    CFGF_MULTI),
            CFG_SEC("static-map-cache",     map_cache_mapping_opts, CFGF_MULTI),
            CFG_SEC("map-server",           map_server_opts,        CFGF_MULTI),
            CFG_SEC("rtr-ifaces",           rtr_ifaces_opts,        CFGF_MULTI),
            CFG_SEC("proxy-etr-ipv4",       petr_mapping_opts,      CFGF_MULTI),
            CFG_SEC("proxy-etr-ipv6",       petr_mapping_opts,      CFGF_MULTI),
            CFG_STR("encapsulation",        "LISP",                 CFGF_NONE),
            CFG_SEC("rloc-probing",         rloc_probing_opts,      CFGF_MULTI),
            CFG_INT("map-request-retries",  0, CFGF_NONE),
            CFG_INT("control-port",         0, CFGF_NONE),
            CFG_INT("debug",                0, CFGF_NONE),
            CFG_STR("log-file",             0, CFGF_NONE),
            CFG_STR("ipv6-scope",          "GLOBAL",               CFGF_NONE),
            CFG_INT("rloc-probing-interval",0, CFGF_NONE),
            CFG_STR_LIST("map-resolver",    0, CFGF_NONE),
            CFG_STR_LIST("proxy-itrs",      0, CFGF_NONE),
#ifdef ANDROID
            CFG_BOOL("override-dns",            cfg_false, CFGF_NONE),
            CFG_STR("override-dns-primary",     0, CFGF_NONE),
            CFG_STR("override-dns-secondary",   0, CFGF_NONE),
#endif
            CFG_STR("operating-mode",       0, CFGF_NONE),
            CFG_BOOL("nat_traversal_support", cfg_false, CFGF_NONE),
            CFG_STR("control-iface",        0, CFGF_NONE),
            CFG_STR("rtr-data-iface",        0, CFGF_NONE),
            CFG_SEC("lisp-site",            lisp_site_opts,         CFGF_MULTI),
            CFG_SEC("explicit-locator-path", elp_opts,              CFGF_MULTI),
            CFG_SEC("replication-list",     rle_opts,               CFGF_MULTI),
            CFG_SEC("multicast-info",       mc_info_opts,           CFGF_MULTI),
            CFG_SEC("ddt-auth-site",        ddt_auth_site_opts,     CFGF_MULTI),
            CFG_SEC("ddt-deleg-site",         ddt_deleg_site_opts,      CFGF_MULTI),
            CFG_STR_LIST("ddt-root-addresses",  0, CFGF_NONE),
            CFG_SEC("ms-rtrs-set",              rtr_set_opts,          CFGF_MULTI),
            CFG_SEC("ms-rtr-node",              rtr_opts,              CFGF_MULTI),
            CFG_STR("ms-advertised-rtrs-set",       0, CFGF_NONE),
            CFG_SEC("rtr-ms-node",rtr_ms_opts,CFGF_MULTI),
            CFG_END()
    };

    if (config_file == NULL){
        config_file = strdup("/etc/oor.conf");
    }

    /*
     *  parse config_file
     */

    cfg = cfg_init(opts, CFGF_NOCASE);
    ret = cfg_parse(cfg, config_file);


    if (ret == CFG_FILE_ERROR) {
        OOR_LOG(LCRIT, "Couldn't find config file %s. If you are useing OOR in daemon mode, please indicate a full path file.", config_file);
        cfg_free(cfg);
        return (BAD);
    } else if(ret == CFG_PARSE_ERROR) {
        OOR_LOG(LCRIT, "Parse error in file %s, exiting. Check conf file (see oor.conf.example)", config_file);
        cfg_free(cfg);
        return(BAD);
    }

    /*
     *  oor config options
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
        OOR_LOG (LINF, "Log level: Low debug");
    }else if (debug_level == 2){
        OOR_LOG (LINF, "Log level: Medium debug");
    }else if (debug_level == 3){
        OOR_LOG (LINF, "Log level: High Debug");
    }

    /*
     * Log file
     */

    log_file = cfg_getstr(cfg, "log-file");
    if (daemonize == TRUE){
        open_log_file(log_file);
    }

    scope_str = cfg_getstr(cfg, "ipv6-scope");
    scope = str_to_lower_case(scope_str);
    if (strcmp(scope,"global") == 0){
        ipv6_scope = SCOPE_GLOBAL;
        OOR_LOG (LDBG_1, "Selected IPv6 scope: Global");
    }else if (strcmp(scope,"site") == 0){
        ipv6_scope = SCOPE_SITE_LOCAL;
        OOR_LOG (LDBG_1, "Selected IPv6 scope: Site local");
    }else{
        OOR_LOG (LCRIT, "Configuration file: Unknown IPv6 scope: %s",scope_str);
        free(scope);
        return (BAD);
    }
    free(scope);


    mode_str = cfg_getstr(cfg, "operating-mode");
    if (mode_str) {
        mode = str_to_lower_case(mode_str);
        if (strcmp(mode, "xtr") == 0) {
            ret=configure_xtr(cfg);
        } else if (strcmp(mode, "ms") == 0) {
            ret=configure_ms(cfg);
        } else if (strcmp(mode, "rtr") == 0) {
            ret=configure_rtr(cfg);
        }else if (strcmp(mode, "mn") == 0) {
            ret=configure_mn(cfg);
        }else if (strcmp(mode, "ddt") ==0) {
            ret=configure_ddt(cfg);
        }else if (strcmp(mode, "ddt-mr") ==0) {
            ret=configure_ddt_mr(cfg);
        }else{
            OOR_LOG (LCRIT, "Configuration file: Unknown operating mode: %s",mode);
            cfg_free(cfg);
            free(mode);
            return (BAD);
        }
        free(mode);
    }

    cfg_free(cfg);
    return(ret);
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */

