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


#include "cmdline.h"
#include "oor_config_functions.h"
#include "oor_config_uci.h"
#include "../oor_external.h"
#include "../iface_list.h"
#include "../control/oor_ctrl_device.h"
#include "../control/lisp_xtr.h"
#include "../control/lisp_ms.h"
#include "../control/oor_control.h"
#include "../data-plane/data-plane.h"
#include "../lib/oor_log.h"
#include "../lib/prefixes.h"
#include "../lib/shash.h"
#include "../lib/util.h"
#include <libgen.h>
#include <string.h>
#include <uci.h>

/***************************** FUNCTIONS DECLARATION *************************/

int
configure_xtr(
        struct uci_context      *ctx,
        struct uci_package      *pck);
int
configure_mn(
        struct uci_context      *ctx,
        struct uci_package      *pck);
int
configure_rtr(
        struct uci_context      *ctx,
        struct uci_package      *pck);
int
configure_ms(
        struct uci_context      *ctx,
        struct uci_package      *pck);
int
configure_ddt(
        struct uci_context      *ctx,
        struct uci_package      *pck);
int
configure_ddt_mr(
        struct uci_context      *ctx,
        struct uci_package      *pck);

static mapping_t*
parse_mapping(
        struct uci_context      *ctx,
        struct uci_section      *sect,
        oor_ctrl_dev_t         *dev,
        shash_t                *rloc_set_ht,
        shash_t                *lcaf_ht,
        uint8_t                 is_local);

conf_mapping_t *
uci_parse_conf_mapping(struct uci_context *ctx, struct uci_section *sect,
        shash_t *rloc_set_ht, uint8_t is_local);

static shash_t *
parse_rlocs(
        struct uci_context *ctx,
        struct uci_package *pck);

static shash_t *
parse_rloc_sets(
        struct uci_context      *ctx,
        struct uci_package      *pck,
        shash_t                 *rlocs_ht);
static shash_t *
parse_lcafs(
        struct uci_context      *ctx,
        struct uci_package      *pck);

static int
parse_elp_node(
        struct uci_context      *ctx,
        struct uci_section      *section,
        shash_t                *ht);

/********************************** FUNCTIONS ********************************/

int
handle_config_file()
{
    char *uci_conf_dir;
    char *uci_conf_file;
    char *conf_file_aux;
    struct uci_context *ctx;
    struct uci_package *pck = NULL;
    struct uci_section *sect;
    struct uci_element *element;
    int uci_debug;
    char *uci_log_file;
    char *uci_scope, *scope;
    char *uci_op_mode, *mode;
    int res = BAD;

    ctx = uci_alloc_context();

    if (ctx == NULL) {
        OOR_LOG(LCRIT, "Could not create UCI context. Exiting ...");
        return (BAD);
    }
    conf_file_aux = strdup(config_file);
    /* dirname and basename may modify the argument */
    uci_conf_dir = dirname(config_file);
    uci_conf_file = basename(conf_file_aux);


    uci_set_confdir(ctx, uci_conf_dir);

    OOR_LOG(LDBG_1,"Conf dir: %s   Conf file: %s\n",ctx->confdir, uci_conf_file);

    uci_load(ctx,uci_conf_file,&pck);
    free(conf_file_aux);

    if (pck == NULL) {
        OOR_LOG(LCRIT, "Could not load conf file: %s. Exiting ...",uci_conf_file);
        uci_perror(ctx,"Error while loading file ");
        uci_free_context(ctx);
        return (BAD);
    }


    OOR_LOG(LDBG_3,"package uci: %s\n",pck->ctx->confdir);


    uci_foreach_element(&pck->sections, element) {

        sect = uci_to_section(element);

        if (strcmp(sect->type, "daemon") == 0){

            uci_debug = strtol(uci_lookup_option_string(ctx, sect, "debug"),NULL,10);


            if (debug_level == -1){//Used to not overwrite debug level passed by console
                if (uci_debug > 0)
                    debug_level = uci_debug;
                else
                    debug_level = 0;
                if (debug_level > 3)
                    debug_level = 3;
            }

            uci_log_file = (char *)uci_lookup_option_string(ctx, sect, "log_file");
            if (daemonize == TRUE){
                open_log_file(uci_log_file);
            }

            uci_scope = (char *)uci_lookup_option_string(ctx, sect, "ipv6_scope");
            if (uci_scope != NULL){
                scope = str_to_lower_case(uci_scope);
                if (strcmp(scope,"global") == 0){
                    ipv6_scope = SCOPE_GLOBAL;
                }else if (strcmp(scope,"site") == 0){
                    ipv6_scope = SCOPE_SITE_LOCAL;
                }else{
                    OOR_LOG (LCRIT, "Configuration file: Unknown IPv6 scope: %s",uci_scope);
                    free(scope);
                    return (BAD);
                }
                free(scope);
            }else{
                ipv6_scope = SCOPE_GLOBAL;
            }

            uci_op_mode = (char *)uci_lookup_option_string(ctx, sect, "operating_mode");

            if (uci_op_mode != NULL) {
                mode = str_to_lower_case(uci_op_mode);
                if (strcmp(mode, "xtr") == 0) {
                    res = configure_xtr(ctx, pck);
                } else if (strcmp(mode, "ms") == 0) {
                    res = configure_ms(ctx, pck);
                } else if (strcmp(mode, "rtr") == 0) {
                    res = configure_rtr(ctx, pck);
                }else if (strcmp(mode, "mn") == 0) {
                    res = configure_mn(ctx, pck);
                }else if (strcmp(mode, "ddt") == 0) {
                    res = configure_ddt(ctx, pck);
                }else if (strcmp(mode, "mr") == 0) {
                    res = configure_ddt_mr(ctx, pck);
                }else {
                    OOR_LOG(LCRIT, "Configuration file: Unknown operating mode: %s",uci_op_mode);
                    free(mode);
                    return (BAD);
                }
                free(mode);
            }

            continue;
        }
    }
    return (res);
}

int
configure_xtr(struct uci_context *ctx, struct uci_package *pck)
{
    struct uci_section *sect;
    struct uci_element *element;
    struct uci_element *elem_addr;
    struct uci_option *opt;
    int uci_retries;
    char *uci_address, *boolean_char;
    int uci_key_type;
    char *uci_key;
    char *uci_nat_aware;
    int nat_aware;
    int uci_proxy_reply;
    int uci_priority;
    int uci_weigth;
    char *uci_encap, *encap;
    shash_t *lcaf_ht = NULL, *rlocs_ht = NULL, *rloc_set_ht = NULL;
    lisp_xtr_t *xtr;
    map_local_entry_t *map_loc_e;
    mapping_t *mapping;
    mcache_entry_t *ipv4_petrs_mc,*ipv6_petrs_mc;
    lisp_addr_t *eid_pref;


    /* CREATE AND CONFIGURE XTR */
    if (ctrl_dev_create(xTR_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create xTR device. Aborting!");
        goto err;
    }

    xtr = lisp_xtr_cast(ctrl_dev);

    ipv4_petrs_mc = mcache_get_all_space_entry(xtr->tr.map_cache,AF_INET);
    ipv6_petrs_mc = mcache_get_all_space_entry(xtr->tr.map_cache,AF_INET6);

    /* FWD POLICY STRUCTURES */
    xtr->tr.fwd_policy = fwd_policy_class_find("flow_balancing");
    xtr->tr.fwd_policy_dev_parm = xtr->tr.fwd_policy->new_dev_policy_inf(ctrl_dev,NULL);

    /* CREATE LCAFS HTABLE */

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of database mappings
     * or static map cache entries  */
    lcaf_ht = parse_lcafs(ctx,pck);
    if (!lcaf_ht){
        goto err;
    }

    /* CREATE RLOCs sets HTABLE */
    rlocs_ht = parse_rlocs(ctx,pck);
    if (!rlocs_ht){
        goto err;
    }
    rloc_set_ht = parse_rloc_sets(ctx,pck,rlocs_ht);
    if (!rloc_set_ht){
        goto err;
    }

    /* First of all we need to know if we have NAT support enabled */
    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);
        /* NAT Traversal options */
        /* NAT Traversal options */
        if (strcmp(sect->type, "nat-traversal") == 0){
            uci_nat_aware = (char *)uci_lookup_option_string(ctx, sect, "nat_traversal_support");
            if (uci_nat_aware){
                nat_aware = str_to_boolean(uci_nat_aware);
                if(nat_aware == UNKNOWN){
                    OOR_LOG(LERR,"Configuration file: unknown value \"%s\" for nat_traversal_support",uci_nat_aware);
                    return (BAD);
                }
            }else{
                nat_aware = FALSE;
            }

            if (nat_aware == TRUE){
                xtr->nat_aware  = TRUE;
                default_rloc_afi = AF_INET;
                OOR_LOG(LDBG_1, "NAT support enabled. Set defaul RLOC to IPv4 family");
            }else{
                xtr->nat_aware = FALSE;
            }
            break;
        }
    }


    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);
        if (strcmp(sect->type, "daemon") == 0){

            /* RETRIES */
            if (uci_lookup_option_string(ctx, sect, "map_request_retries") != NULL){
                uci_retries = strtol(uci_lookup_option_string(ctx, sect, "map_request_retries"),NULL,10);
                if (uci_retries >= 0 && uci_retries <= OOR_MAX_RETRANSMITS){
                    xtr->tr.map_request_retries = uci_retries;
                }else if (uci_retries > OOR_MAX_RETRANSMITS){
                    xtr->tr.map_request_retries = OOR_MAX_RETRANSMITS;
                    OOR_LOG(LWRN, "Map-Request retries should be between 0 and %d. "
                            "Using default value: %d",OOR_MAX_RETRANSMITS, OOR_MAX_RETRANSMITS);
                }
            }else{
                OOR_LOG(LWRN,"Configuration file: Map Request Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_MAP_REQUEST_RETRIES);
                xtr->tr.map_request_retries = DEFAULT_MAP_REQUEST_RETRIES;
                continue;
            }
        }

        if (strcmp(sect->type, "encapsulation") == 0){
            uci_encap = (char *)uci_lookup_option_string(ctx, sect, "type");
            if (uci_encap != NULL){
                encap = str_to_lower_case(uci_encap);
                if (strcmp(encap, "lisp") == 0) {
                    xtr->tr.encap_type = ENCP_LISP;
                }else if (strcmp(encap, "vxlangpe") == 0){
                    xtr->tr.encap_type = ENCP_VXLAN_GPE;
                }else{
                    OOR_LOG(LERR, "Unknown encapsulation type: %s",encap);
                    free(encap);
                    return (BAD);
                }
                free(encap);
            }else{
                xtr->tr.encap_type = ENCP_LISP;
            }
        }

        /* RLOC PROBING CONFIG */

        if (strcmp(sect->type, "rloc-probing") == 0){
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_interval") != NULL){
                xtr->tr.probe_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC probe interval not specified."
                        " Disabling RLOC Probing");
                xtr->tr.probe_interval = 0;
                continue;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries") != NULL){
                xtr->tr.probe_retries = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES);
                xtr->tr.probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval") != NULL){
                xtr->tr.probe_retries_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries Intervals not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES_INTERVAL);
                xtr->tr.probe_retries_interval = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;
            }

            validate_rloc_probing_parameters(&xtr->tr.probe_interval,
                    &xtr->tr.probe_retries, &xtr->tr.probe_retries_interval);
            continue;
        }


        /* MAP-RESOLVER CONFIG */
        if (strcmp(sect->type, "map-resolver") == 0){
            opt  = uci_lookup_option(ctx, sect, "address");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    if (add_server(elem_addr->name, xtr->tr.map_resolvers) != GOOD){
                        OOR_LOG(LCRIT,"Can't add %s Map Resolver.",elem_addr->name);
                    }else{
                        OOR_LOG(LDBG_1, "Added %s to map-resolver list", elem_addr->name);
                    }
                }
            }
            continue;
        }

        /* MAP-SERVER CONFIG */
        if (strcmp(sect->type, "map-server") == 0){

            uci_address = (char *)uci_lookup_option_string(ctx, sect, "address");
            if (uci_lookup_option_string(ctx, sect, "key_type") != NULL){
                uci_key_type = strtol(uci_lookup_option_string(ctx, sect, "key_type"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No ket type assigned to the map server \"%s\"."
                        " Set default value: HMAC_SHA_1_96",uci_address);
                uci_key_type = HMAC_SHA_1_96;
            }
            uci_key = (char *)uci_lookup_option_string(ctx, sect, "key");

            boolean_char = (char *)uci_lookup_option_string(ctx, sect, "proxy_reply");
            if (boolean_char){
                uci_proxy_reply = str_to_boolean(boolean_char);
                if(uci_proxy_reply == UNKNOWN){
                    OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in proxy_reply",boolean_char);
                    return (BAD);
                }
            }else{
                uci_proxy_reply = FALSE;
            }

            if (add_map_server(xtr->map_servers,uci_address,
                    uci_key_type,
                    uci_key,
                    uci_proxy_reply) != GOOD ){
                OOR_LOG(LCRIT, "Can't add %s Map Server.", uci_address);
            }else{
                OOR_LOG(LDBG_1, "Added %s to map-server list", uci_address);
            }
            continue;
        }

        /* PROXY-ETR CONFIG */

        if (strcmp(sect->type, "proxy-etr-ipv4") == 0){
            uci_address = (char *)uci_lookup_option_string(ctx, sect, "address");
            if (uci_lookup_option_string(ctx, sect, "priority") != NULL){
                uci_priority = strtol(uci_lookup_option_string(ctx, sect, "priority"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No priority assigned to the proxy-etr \"%s\"."
                        " Set default value: 10",uci_address);
                uci_priority = 10;
            }
            if (uci_lookup_option_string(ctx, sect, "weight") != NULL){
                uci_weigth = strtol(uci_lookup_option_string(ctx, sect, "weight"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No weight assigned to the proxy-etr \"%s\"."
                        " Set default value: 100",uci_address);
                uci_weigth = 100;
            }

            if (add_proxy_etr_entry(ipv4_petrs_mc,uci_address,uci_priority,uci_weigth) != GOOD ){
                OOR_LOG(LERR, "Can't add proxy-etr %s", uci_address);
            }else{
                OOR_LOG(LDBG_1, "Added %s to proxy-etr list", uci_address);
            }
            continue;
        }

        if (strcmp(sect->type, "proxy-etr-ipv6") == 0){
            uci_address = (char *)uci_lookup_option_string(ctx, sect, "address");
            if (uci_lookup_option_string(ctx, sect, "priority") != NULL){
                uci_priority = strtol(uci_lookup_option_string(ctx, sect, "priority"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No priority assigned to the proxy-etr \"%s\"."
                        " Set default value: 10",uci_address);
                uci_priority = 10;
            }
            if (uci_lookup_option_string(ctx, sect, "weight") != NULL){
                uci_weigth = strtol(uci_lookup_option_string(ctx, sect, "weight"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No weight assigned to the proxy-etr \"%s\"."
                        " Set default value: 100",uci_address);
                uci_weigth = 100;
            }

            if (add_proxy_etr_entry(ipv6_petrs_mc,uci_address,uci_priority,uci_weigth) != GOOD ){
                OOR_LOG(LERR, "Can't add proxy-etr %s", uci_address);
            }else{
                OOR_LOG(LDBG_1, "Added %s to proxy-etr list", uci_address);
            }
            continue;
        }

        /* PROXY-ITR CONFIG */
        if (strcmp(sect->type, "proxy-itr") == 0){
            opt  = uci_lookup_option(ctx, sect, "address");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    if (add_server(elem_addr->name, xtr->pitrs) != GOOD){
                        OOR_LOG(LERR, "Can't add %s to proxy-itr list. Discarded ...", elem_addr->name);
                    }else{
                        OOR_LOG(LDBG_1, "Added %s to proxy-itr list", elem_addr->name);
                    }
                }
            }
            continue;
        }

        /* ALLOWED DESTINATION EIDS */
        if (strcmp(sect->type, "allowed-dst-eids") == 0){
            opt = uci_lookup_option(ctx, sect, "eid_prefix");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    uci_address = elem_addr->name;
                    eid_pref = lisp_addr_new();
                    if (lisp_addr_ippref_from_char(uci_address, eid_pref) != GOOD){
                        lisp_addr_del(eid_pref);
                        OOR_LOG(LERR, "Can't add %s to allowed destination EIDs", uci_address);
                        return (BAD);
                    }
                    glist_add(eid_pref, xtr->tr.allowed_dst_eids);
                    OOR_LOG(LDBG_1, "Added %s to allowed destinations", uci_address);
                }
            }
            continue;
        }

        if (strcmp(sect->type, "database-mapping") == 0){
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,TRUE);
            if (mapping == NULL){
                OOR_LOG(LERR, "Can't add EID prefix %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
            }

            map_loc_e = map_local_entry_new_init(mapping);
            if (map_loc_e == NULL){
                mapping_del(mapping);
                continue;
            }

            if ( xtr->tr.fwd_policy->init_map_loc_policy_inf(
                    xtr->tr.fwd_policy_dev_parm,map_loc_e,NULL) != GOOD){
                OOR_LOG(LERR, "Couldn't initiate forward information for mapping with EID: %s. Discarding it...",
                        lisp_addr_to_char(mapping_eid(mapping)));
                map_local_entry_del(map_loc_e);
                continue;
            }

            if (add_local_db_map_local_entry(map_loc_e,xtr) != GOOD){
                map_local_entry_del(map_loc_e);
                continue;
            }

            continue;
        }

        /* STATIC MAP-CACHE CONFIG */
        if (strcmp(sect->type, "static-map-cache") == 0){
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,FALSE);
            if (mapping == NULL){
                OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
            }
            if (mcache_lookup_exact(xtr->tr.map_cache, mapping_eid(mapping)) == NULL){
                if (tr_mcache_add_mapping(&xtr->tr, mapping, MCE_STATIC, ACTIVE) != NULL){
                    OOR_LOG(LDBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                            lisp_addr_to_char(mapping_eid(mapping)));
                }else{
                    OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                            mapping_eid(mapping));
                    mapping_del(mapping);
                }
            }else{
                OOR_LOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                        "Discarded ...",uci_lookup_option_string(ctx, sect, "eid_prefix"));
                mapping_del(mapping);
            }
            continue;
        }
    }

    /* Generate xTR identifier */
    if (tr_set_xTR_ID(xtr) != GOOD){
        OOR_LOG(LERR,"Could not generate xTR-ID");
        return (BAD);
    }
    tr_set_site_ID(xtr, 0);

    /* Calculate forwarding info por proxy-etrs */
    if (xtr->tr.fwd_policy->init_map_cache_policy_inf(xtr->tr.fwd_policy_dev_parm,ipv4_petrs_mc) != GOOD){
        OOR_LOG(LDBG_1, "Couldn't initiate routing info for PeTRs for IPv4 EIDs!.");
        mcache_entry_del(ipv4_petrs_mc);
        goto err;
    }

    if (xtr->tr.fwd_policy->init_map_cache_policy_inf(xtr->tr.fwd_policy_dev_parm,ipv6_petrs_mc) != GOOD){
        OOR_LOG(LDBG_1, "Couldn't initiate routing info for PeTRs for IPv6 EIDs!.");
        mcache_entry_del(ipv6_petrs_mc);
        goto err;
    }

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);
    return(GOOD);
err:
    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);
    return(GOOD);
}

int
configure_mn(struct uci_context *ctx, struct uci_package *pck)
{
    struct uci_section *sect;
    struct uci_element *element;
    struct uci_element *elem_addr;
    struct uci_option *opt;
    int uci_retries;
    char *uci_address, *boolean_char;
    int uci_key_type;
    char *uci_key;
    char *uci_nat_aware;
    char *uci_encap, *encap;
    int nat_aware;
    int uci_proxy_reply;
    int uci_priority;
    int uci_weigth;
    shash_t *lcaf_ht = NULL, *rlocs_ht = NULL, *rloc_set_ht = NULL;
    lisp_xtr_t *xtr;
    map_local_entry_t *map_loc_e;
    mapping_t *mapping;
    mcache_entry_t *ipv4_petrs_mc,*ipv6_petrs_mc;
    lisp_addr_t *eid_pref;


    /* CREATE AND CONFIGURE XTR */
    if (ctrl_dev_create(MN_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create Mobile Node device. Aborting!");
        goto err;
    }

    xtr = lisp_xtr_cast(ctrl_dev);

    ipv4_petrs_mc = mcache_get_all_space_entry(xtr->tr.map_cache,AF_INET);
    ipv6_petrs_mc = mcache_get_all_space_entry(xtr->tr.map_cache,AF_INET6);

    /* FWD POLICY STRUCTURES */
    xtr->tr.fwd_policy = fwd_policy_class_find("flow_balancing");
    xtr->tr.fwd_policy_dev_parm = xtr->tr.fwd_policy->new_dev_policy_inf(ctrl_dev,NULL);

    /* CREATE LCAFS HTABLE */

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of database mappings
     * or static map cache entries  */
    lcaf_ht = parse_lcafs(ctx,pck);
    if (!lcaf_ht){
        goto err;
    }

    /* CREATE RLOCs sets HTABLE */
    rlocs_ht = parse_rlocs(ctx,pck);
    if (!rlocs_ht){
        goto err;
    }
    rloc_set_ht = parse_rloc_sets(ctx,pck,rlocs_ht);
    if (!rloc_set_ht){
        goto err;
    }

    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);
        /* NAT Traversal options */
        /* NAT Traversal options */
        if (strcmp(sect->type, "nat-traversal") == 0){
            uci_nat_aware = (char *)uci_lookup_option_string(ctx, sect, "nat_traversal_support");
            if (uci_nat_aware){
                nat_aware = str_to_boolean(uci_nat_aware);
                if(nat_aware == UNKNOWN){
                    OOR_LOG(LERR,"Configuration file: unknown value \"%s\" for nat_traversal_support",uci_nat_aware);
                    return (BAD);
                }
            }else{
                nat_aware = FALSE;
            }

            if (nat_aware  == TRUE){
                xtr->nat_aware  = TRUE;
                default_rloc_afi = AF_INET;
                OOR_LOG(LDBG_1, "NAT support enabled. Set defaul RLOC to IPv4 family");
            }else{
                xtr->nat_aware = FALSE;
            }
            break;
        }
    }

    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);
        if (strcmp(sect->type, "daemon") == 0){

            /* RETRIES */
            if (uci_lookup_option_string(ctx, sect, "map_request_retries") != NULL){
                uci_retries = strtol(uci_lookup_option_string(ctx, sect, "map_request_retries"),NULL,10);
                if (uci_retries >= 0 && uci_retries <= OOR_MAX_RETRANSMITS){
                    xtr->tr.map_request_retries = uci_retries;
                }else if (uci_retries > OOR_MAX_RETRANSMITS){
                    xtr->tr.map_request_retries = OOR_MAX_RETRANSMITS;
                    OOR_LOG(LWRN, "Map-Request retries should be between 0 and %d. "
                            "Using default value: %d",OOR_MAX_RETRANSMITS, OOR_MAX_RETRANSMITS);
                }
            }else{
                OOR_LOG(LWRN,"Configuration file: Map Request Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_MAP_REQUEST_RETRIES);
                xtr->tr.map_request_retries = DEFAULT_MAP_REQUEST_RETRIES;
                continue;
            }
        }

        if (strcmp(sect->type, "encapsulation") == 0){
            uci_encap = (char *)uci_lookup_option_string(ctx, sect, "type");
            if (uci_encap != NULL){
                encap = str_to_lower_case(uci_encap);
                if (strcmp(encap, "lisp") == 0) {
                    xtr->tr.encap_type = ENCP_LISP;
                }else if (strcmp(encap, "vxlangpe") == 0){
                    xtr->tr.encap_type = ENCP_VXLAN_GPE;
                }else{
                    OOR_LOG(LERR, "Unknown encapsulation type: %s",encap);
                    free(encap);
                    return (BAD);
                }
                free(encap);
            }else{
                xtr->tr.encap_type = ENCP_LISP;
            }
        }

        /* RLOC PROBING CONFIG */

        if (strcmp(sect->type, "rloc-probing") == 0){
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_interval") != NULL){
                xtr->tr.probe_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC probe interval not specified."
                        " Disabling RLOC Probing");
                xtr->tr.probe_interval = 0;
                continue;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries") != NULL){
                xtr->tr.probe_retries = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES);
                xtr->tr.probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval") != NULL){
                xtr->tr.probe_retries_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries Intervals not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES_INTERVAL);
                xtr->tr.probe_retries_interval = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;
            }

            validate_rloc_probing_parameters(&xtr->tr.probe_interval,
                    &xtr->tr.probe_retries, &xtr->tr.probe_retries_interval);
            continue;
        }


        /* MAP-RESOLVER CONFIG */
        if (strcmp(sect->type, "map-resolver") == 0){
            opt  = uci_lookup_option(ctx, sect, "address");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    if (add_server(elem_addr->name, xtr->tr.map_resolvers) != GOOD){
                        OOR_LOG(LCRIT,"Can't add %s Map Resolver.",elem_addr->name);
                    }else{
                        OOR_LOG(LDBG_1, "Added %s to map-resolver list", elem_addr->name);
                    }
                }
            }
            continue;
        }

        /* MAP-SERVER CONFIG */
        if (strcmp(sect->type, "map-server") == 0){

            uci_address = (char *)uci_lookup_option_string(ctx, sect, "address");
            if (uci_lookup_option_string(ctx, sect, "key_type") != NULL){
                uci_key_type = strtol(uci_lookup_option_string(ctx, sect, "key_type"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No ket type assigned to the map server \"%s\"."
                        " Set default value: HMAC_SHA_1_96",uci_address);
                uci_key_type = HMAC_SHA_1_96;
            }
            uci_key = (char *)uci_lookup_option_string(ctx, sect, "key");

            boolean_char = (char *)uci_lookup_option_string(ctx, sect, "proxy_reply");
            if (boolean_char){
                uci_proxy_reply = str_to_boolean(boolean_char);
                if(uci_proxy_reply == UNKNOWN){
                    OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in proxy_reply",boolean_char);
                    return (BAD);
                }
            }else{
                uci_proxy_reply = FALSE;
            }

            if (add_map_server(xtr->map_servers,uci_address,
                    uci_key_type,
                    uci_key,
                    uci_proxy_reply) != GOOD ){
                OOR_LOG(LCRIT, "Can't add %s Map Server.", uci_address);
            }else{
                OOR_LOG(LDBG_1, "Added %s to map-server list", uci_address);
            }
            continue;
        }

        /* PROXY-ETR CONFIG */

        if (strcmp(sect->type, "proxy-etr-ipv4") == 0){
            uci_address = (char *)uci_lookup_option_string(ctx, sect, "address");
            if (uci_lookup_option_string(ctx, sect, "priority") != NULL){
                uci_priority = strtol(uci_lookup_option_string(ctx, sect, "priority"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No priority assigned to the proxy-etr \"%s\"."
                        " Set default value: 10",uci_address);
                uci_priority = 10;
            }
            if (uci_lookup_option_string(ctx, sect, "weight") != NULL){
                uci_weigth = strtol(uci_lookup_option_string(ctx, sect, "weight"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No weight assigned to the proxy-etr \"%s\"."
                        " Set default value: 100",uci_address);
                uci_weigth = 100;
            }

            if (add_proxy_etr_entry(ipv4_petrs_mc,uci_address,uci_priority,uci_weigth) != GOOD ){
                OOR_LOG(LERR, "Can't add proxy-etr %s", uci_address);
            }else{
                OOR_LOG(LDBG_1, "Added %s to proxy-etr list", uci_address);
            }
            continue;
        }

        if (strcmp(sect->type, "proxy-etr-ipv6") == 0){
            uci_address = (char *)uci_lookup_option_string(ctx, sect, "address");
            if (uci_lookup_option_string(ctx, sect, "priority") != NULL){
                uci_priority = strtol(uci_lookup_option_string(ctx, sect, "priority"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No priority assigned to the proxy-etr \"%s\"."
                        " Set default value: 10",uci_address);
                uci_priority = 10;
            }
            if (uci_lookup_option_string(ctx, sect, "weight") != NULL){
                uci_weigth = strtol(uci_lookup_option_string(ctx, sect, "weight"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No weight assigned to the proxy-etr \"%s\"."
                        " Set default value: 100",uci_address);
                uci_weigth = 100;
            }

            if (add_proxy_etr_entry(ipv6_petrs_mc,uci_address,uci_priority,uci_weigth) != GOOD ){
                OOR_LOG(LERR, "Can't add proxy-etr %s", uci_address);
            }else{
                OOR_LOG(LDBG_1, "Added %s to proxy-etr list", uci_address);
            }
            continue;
        }

        /* PROXY-ITR CONFIG */
        if (strcmp(sect->type, "proxy-itr") == 0){
            opt  = uci_lookup_option(ctx, sect, "address");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    if (add_server(elem_addr->name, xtr->pitrs) != GOOD){
                        OOR_LOG(LERR, "Can't add %s to proxy-itr list. Discarded ...", elem_addr->name);
                    }else{
                        OOR_LOG(LDBG_1, "Added %s to proxy-itr list", elem_addr->name);
                    }
                }
            }
            continue;
        }

        /* ALLOWED DESTINATION EIDS */
        if (strcmp(sect->type, "allowed-dst-eids") == 0){
            opt = uci_lookup_option(ctx, sect, "eid_prefix");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    uci_address = elem_addr->name;
                    eid_pref = lisp_addr_new();
                    if (lisp_addr_ippref_from_char(uci_address, eid_pref) != GOOD){
                        lisp_addr_del(eid_pref);
                        OOR_LOG(LERR, "Can't add %s to allowed destination EIDs", uci_address);
                        return (BAD);
                    }
                    glist_add(eid_pref, xtr->tr.allowed_dst_eids);
                    OOR_LOG(LDBG_1, "Added %s to allowed destinations", uci_address);
                }
            }
            continue;
        }

        if (strcmp(sect->type, "database-mapping") == 0){
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,TRUE);
            if (mapping == NULL){
                OOR_LOG(LERR, "Can't add EID prefix %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
            }

            map_loc_e = map_local_entry_new_init(mapping);
            if (map_loc_e == NULL){
                mapping_del(mapping);
                continue;
            }

            if ( xtr->tr.fwd_policy->init_map_loc_policy_inf(
                    xtr->tr.fwd_policy_dev_parm,map_loc_e,NULL) != GOOD){
                OOR_LOG(LERR, "Couldn't initiate forward information for mapping with EID: %s. Discarding it...",
                        lisp_addr_to_char(mapping_eid(mapping)));
                map_local_entry_del(map_loc_e);
                continue;
            }

            if (add_local_db_map_local_entry(map_loc_e,xtr) != GOOD){
                map_local_entry_del(map_loc_e);
                continue;
            }

            continue;
        }

        /* STATIC MAP-CACHE CONFIG */
        if (strcmp(sect->type, "static-map-cache") == 0){
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,FALSE);
            if (mapping == NULL){
                OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
            }
            if (mcache_lookup_exact(xtr->tr.map_cache, mapping_eid(mapping)) == NULL){
                if (tr_mcache_add_mapping(&xtr->tr, mapping, MCE_STATIC, ACTIVE) != NULL){
                    OOR_LOG(LDBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                            lisp_addr_to_char(mapping_eid(mapping)));
                }else{
                    OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                            mapping_eid(mapping));
                    mapping_del(mapping);
                }
            }else{
                OOR_LOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                        "Discarded ...",uci_lookup_option_string(ctx, sect, "eid_prefix"));
                mapping_del(mapping);
            }
            continue;
        }
    }

    /* If allowed_dst_eids not defined, add default route */
    /* For mobile node mode, we use two /1 routes covering the full IP addresses space to cover all traffic*/
    if (glist_size(xtr->tr.allowed_dst_eids) == 0){
        tr_add_mn_default_routes(&xtr->tr);
    }

    /* Generate xTR identifier */
    if (tr_set_xTR_ID(xtr) != GOOD){
        OOR_LOG(LERR,"Could not generate xTR-ID");
        return (BAD);
    }
    tr_set_site_ID(xtr, 0);

    /* Calculate forwarding info por proxy-etrs */
    if (xtr->tr.fwd_policy->init_map_cache_policy_inf(xtr->tr.fwd_policy_dev_parm,ipv4_petrs_mc) != GOOD){
        OOR_LOG(LDBG_1, "Couldn't initiate routing info for PeTRs for IPv4 EIDs!.");
        mcache_entry_del(ipv4_petrs_mc);
        goto err;
    }

    if (xtr->tr.fwd_policy->init_map_cache_policy_inf(xtr->tr.fwd_policy_dev_parm,ipv6_petrs_mc) != GOOD){
        OOR_LOG(LDBG_1, "Couldn't initiate routing info for PeTRs for IPv6 EIDs!.");
        mcache_entry_del(ipv6_petrs_mc);
        goto err;
    }

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);
    return(GOOD);
err:
    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);
    return(GOOD);
}

int
configure_rtr(struct uci_context *ctx, struct uci_package *pck)
{
    lisp_rtr_t *rtr;
    struct uci_section *sect;
    struct uci_element *element;
    struct uci_element *elem_addr;
    struct uci_option *opt;
    shash_t *lcaf_ht;
    shash_t *rlocs_ht;
    shash_t *rloc_set_ht;
    int uci_retries;
    char *uci_iface;
    char *uci_encap, *encap;
    mapping_t *mapping;
    int uci_afi;
    int uci_priority;
    int uci_weigth;

    /* CREATE AND CONFIGURE RTR (RTR in fact) */
    if (ctrl_dev_create(RTR_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create RTR. Aborting!");
        return (BAD);
    }

    rtr = lisp_rtr_cast(ctrl_dev);

    /* FWD POLICY STRUCTURES */
    rtr->tr.fwd_policy = fwd_policy_class_find("flow_balancing");
    rtr->tr.fwd_policy_dev_parm = rtr->tr.fwd_policy->new_dev_policy_inf(ctrl_dev,NULL);

    /* CREATE LCAFS HTABLE */

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of database mappings
     * or static map cache entries  */
    lcaf_ht = parse_lcafs(ctx,pck);
    if (!lcaf_ht){
        return (BAD);
    }

    /* CREATE RLOCs sets HTABLE */
    rlocs_ht = parse_rlocs(ctx,pck);
    if (!rlocs_ht){
        return (BAD);
    }
    rloc_set_ht = parse_rloc_sets(ctx,pck,rlocs_ht);
    if (!rloc_set_ht){
        shash_destroy(rloc_set_ht);
        return (BAD);
    }

    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);
        if (strcmp(sect->type, "daemon") == 0){

            /* RETRIES */
            if (uci_lookup_option_string(ctx, sect, "map_request_retries") != NULL){
                uci_retries = strtol(uci_lookup_option_string(ctx, sect, "map_request_retries"),NULL,10);
                if (uci_retries >= 0 && uci_retries <= OOR_MAX_RETRANSMITS){
                    rtr->tr.map_request_retries = uci_retries;
                }else if (uci_retries > OOR_MAX_RETRANSMITS){
                    rtr->tr.map_request_retries = OOR_MAX_RETRANSMITS;
                    OOR_LOG(LWRN, "Map-Request retries should be between 0 and %d. "
                            "Using default value: %d",OOR_MAX_RETRANSMITS, OOR_MAX_RETRANSMITS);
                }
            }else{
                OOR_LOG(LWRN,"Configuration file: Map Request Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_MAP_REQUEST_RETRIES);
                rtr->tr.map_request_retries = DEFAULT_MAP_REQUEST_RETRIES;
                continue;
            }
        }

        if (strcmp(sect->type, "encapsulation") == 0){
            uci_encap = (char *)uci_lookup_option_string(ctx, sect, "type");
            if (uci_encap != NULL){
                encap = str_to_lower_case(uci_encap);
                if (strcmp(encap, "lisp") == 0) {
                    rtr->tr.encap_type = ENCP_LISP;
                }else if (strcmp(encap, "vxlangpe") == 0){
                    rtr->tr.encap_type = ENCP_VXLAN_GPE;
                }else{
                    OOR_LOG(LERR, "Unknown encapsulation type: %s",encap);
                    free(encap);
                    return (BAD);
                }
                free(encap);
            }else{
                rtr->tr.encap_type = ENCP_LISP;
            }
        }

        /* RLOC PROBING CONFIG */

        if (strcmp(sect->type, "rloc-probing") == 0){
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_interval") != NULL){
                rtr->tr.probe_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC probe interval not specified."
                        " Disabling RLOC Probing");
                rtr->tr.probe_interval = 0;
                continue;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries") != NULL){
                rtr->tr.probe_retries = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES);
                rtr->tr.probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval") != NULL){
                rtr->tr.probe_retries_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries Intervals not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES_INTERVAL);
                rtr->tr.probe_retries_interval = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;
            }

            validate_rloc_probing_parameters(&rtr->tr.probe_interval,
                    &rtr->tr.probe_retries, &rtr->tr.probe_retries_interval);
            continue;
        }

        /* MAP-RESOLVER CONFIG */
        if (strcmp(sect->type, "map-resolver") == 0){
            opt  = uci_lookup_option(ctx, sect, "address");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    if (add_server(elem_addr->name, rtr->tr.map_resolvers) != GOOD){
                        OOR_LOG(LCRIT,"Can't add %s Map Resolver.",elem_addr->name);
                    }else{
                        OOR_LOG(LDBG_1, "Added %s to map-resolver list", elem_addr->name);
                    }
                }
            }
            continue;
        }

        /* STATIC MAP-CACHE CONFIG */
        if (strcmp(sect->type, "static-map-cache") == 0){
            mapping = parse_mapping(ctx,sect,&(rtr->super),rloc_set_ht,lcaf_ht,FALSE);
            if (mapping == NULL){
                OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                return (BAD);
            }
            if (mcache_lookup_exact(rtr->tr.map_cache, mapping_eid(mapping)) == NULL){
                if (tr_mcache_add_mapping(&rtr->tr, mapping, MCE_STATIC, ACTIVE) != NULL){
                    OOR_LOG(LDBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                            lisp_addr_to_char(mapping_eid(mapping)));
                }else{
                    OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                            mapping_eid(mapping));
                    mapping_del(mapping);
                }
            }else{
                OOR_LOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                        "Discarded ...",uci_lookup_option_string(ctx, sect, "eid_prefix"));
                mapping_del(mapping);
                continue;
            }
            continue;
        }

        /* INTERFACES CONFIG */
        if (strcmp(sect->type, "rtr-iface") == 0){
            uci_iface = (char *)uci_lookup_option_string(ctx, sect, "iface");

            if (uci_lookup_option_string(ctx, sect, "ip_version") != NULL){
                uci_afi = strtol(uci_lookup_option_string(ctx, sect, "ip_version"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No IP version selected for the rtr-iface \"%s\"."
                        ,uci_iface);
                return (BAD);
            }
            if (uci_lookup_option_string(ctx, sect, "priority") != NULL){
                uci_priority = strtol(uci_lookup_option_string(ctx, sect, "priority"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No priority assigned to the rtr-iface \"%s\"."
                        " Set default value: 10",uci_iface);
                uci_priority = 10;
            }
            if (uci_lookup_option_string(ctx, sect, "weight") != NULL){
                uci_weigth = strtol(uci_lookup_option_string(ctx, sect, "weight"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: No weight assigned to the rtr-iface \"%s\"."
                        " Set default value: 100",uci_iface);
                uci_weigth = 100;
            }
            if (add_rtr_iface(rtr,
                    uci_iface,
                    uci_afi,
                    uci_priority,
                    uci_weigth) == GOOD) {
                OOR_LOG(LDBG_1, "Configured interface %s for RTR",uci_iface);
            } else{
                OOR_LOG(LERR, "Can't configure iface %s for RTR",uci_iface);
            }
            continue;
        }

        /* NAT conf of the RTR */
        if (strcmp(sect->type, "rtr-ms-node") == 0){
            if (rtr_add_rtr_ms_node(rtr,
                    (char *)uci_lookup_option_string(ctx, sect, "address"),
                    (char *)uci_lookup_option_string(ctx, sect, "key"),
                    (char *)uci_lookup_option_string(ctx, sect, "draft_version")) != GOOD){
                return (BAD);
            }
            continue;
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

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);

    return(GOOD);
}

int
configure_ms(struct uci_context *ctx,struct uci_package *pck)
{
    lisp_ms_t *ms;
    struct uci_section *sect;
    struct uci_option *opt;
    struct uci_element *element, *uci_elem, *elem_addr;
    char *uci_eid_prefix;
    int uci_iid = 0, uci_ttl=0;
    int uci_key_type;
    char *uci_key, *uci_iface,*boolean_char;
    uint8_t uci_more_specifics;
    uint8_t uci_proxy_reply;
    uint8_t uci_merge;
    uint8_t uci_peers_complete;
    mapping_t *mapping;
    lisp_site_prefix_t *site;
    shash_t *lcaf_ht;
    shash_t *rlocs_ht;
    shash_t *rloc_set_ht;
    glist_t *rtr_id_list, *str_ddt_ms_peers_lst;
    iface_t *iface;

    /* create and configure xtr */
    if (ctrl_dev_create(MS_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create MS. Aborting!");
        return (BAD);
    }
    ms = lisp_ms_cast(ctrl_dev);


    /* create lcaf hash table */
    lcaf_ht = parse_lcafs(ctx,pck);
    if (!lcaf_ht){
        return (BAD);
    }

    /* CREATE RLOCs sets HTABLE */
    rlocs_ht = parse_rlocs(ctx,pck);
    if (!rlocs_ht){
        return (BAD);
    }
    rloc_set_ht = parse_rloc_sets(ctx,pck,rlocs_ht);
    if (!rloc_set_ht){
        shash_destroy(rloc_set_ht);
        return (BAD);
    }

    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);

        /* CONTROL INTERFACE */
        /* TODO: should work with all interfaces in the future */
        if (strcmp(sect->type, "ms_basic") == 0){
            uci_iface = (char *)uci_lookup_option_string(ctx, sect, "control_iface");
            if (uci_iface == NULL){
                OOR_LOG(LERR,"Configuration file: No control iface assigned");
                return(BAD);
            }
            if ((iface = add_interface(uci_iface))==NULL) {
                return(BAD);
            }

            iface_configure (iface, AF_INET);
            iface_configure (iface, AF_INET6);
        }

        /* LISP-SITE CONFIG */
        if (strcmp(sect->type, "lisp-site") == 0){
            uci_eid_prefix = (char *)uci_lookup_option_string(ctx, sect, "eid_prefix");
            if (!uci_eid_prefix){
                OOR_LOG(LERR,"Configuration file: No eid_prefix assigned");
                return (BAD);
            }
            if (uci_lookup_option_string(ctx, sect, "key_type") != NULL){
                uci_key_type =  strtol(uci_lookup_option_string(ctx, sect, "key_type"),NULL,10);
            }else {
                OOR_LOG(LERR,"Configuration file: No key-type specified");
                return (BAD);
            }
            uci_key = (char *)uci_lookup_option_string(ctx, sect, "key");
            if (!uci_key){
                OOR_LOG(LERR,"Configuration file: Key could not be null");
                return (BAD);
            }

            boolean_char = (char *)uci_lookup_option_string(ctx, sect, "accept_more_specifics");
            if (boolean_char){
                uci_more_specifics = str_to_boolean(boolean_char);
                if(uci_more_specifics == UNKNOWN){
                    OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in accept_more_specifics", boolean_char);
                    return (BAD);
                }
            }else{
                uci_more_specifics = FALSE;
            }

            boolean_char = (char *)uci_lookup_option_string(ctx, sect, "proxy_reply");
            if (boolean_char){
                uci_proxy_reply = str_to_boolean(boolean_char);
                if(uci_proxy_reply == UNKNOWN){
                    OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in proxy_reply",boolean_char);
                    return (BAD);
                }
            }else{
                uci_proxy_reply = FALSE;
            }

            boolean_char = (char *)uci_lookup_option_string(ctx, sect, "merge");
            if (boolean_char){
                uci_merge = str_to_boolean(boolean_char);
                if(uci_merge == UNKNOWN){
                    OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in merge",boolean_char);
                    return (BAD);
                }
            }else{
                uci_merge = FALSE;
            }

            if (uci_lookup_option_string(ctx, sect, "iid") == NULL){
                uci_iid = 0;
            }else{
                uci_iid = strtol(uci_lookup_option_string(ctx, sect, "iid"),NULL,10);
            }

            boolean_char = (char *)uci_lookup_option_string(ctx, sect, "ddt_ms_peers_complete");
            if (boolean_char){
                uci_peers_complete = str_to_boolean(boolean_char);
                if(uci_peers_complete == UNKNOWN){
                    OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in ddt_ms_peers_complete",boolean_char);
                    return (BAD);
                }
            }else{
                uci_peers_complete = TRUE;
            }

            str_ddt_ms_peers_lst = glist_new();

            /* ddt_ms_peers */
            opt  = uci_lookup_option(ctx, sect, "ddt_ms_peers");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    glist_add_tail(elem_addr->name, str_ddt_ms_peers_lst);
                }
            }

            site = build_lisp_site_prefix(ms,
                    uci_eid_prefix,
                    uci_iid,
                    uci_key_type,
                    uci_key,
                    uci_more_specifics,
                    uci_proxy_reply,
                    uci_merge,
                    uci_peers_complete,
                    str_ddt_ms_peers_lst,
                    lcaf_ht);

            if (site) {
                OOR_LOG(LDBG_1, "Adding lisp site prefix %s to the lisp-sites "
                        "database", lisp_addr_to_char(site->eid_prefix));
                ms_add_lisp_site_prefix(ms, site);
            }else{
                OOR_LOG(LERR, "Can't add lisp-site prefix %s. Discarded ...",
                        uci_eid_prefix);
            }

            glist_destroy(str_ddt_ms_peers_lst);
        }

        /* LISP REGISTERED SITES CONFIG */
        if (strcmp(sect->type, "ms-static-registered-site") == 0){
            mapping = parse_mapping(ctx,sect,&(ms->super),rloc_set_ht,lcaf_ht,FALSE);
            if (mapping == NULL){
                OOR_LOG(LERR, "Can't create static register site for %s",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                return (BAD);
            }
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
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                mapping_del(mapping);
                continue;
            }
            continue;
        }

        /* NAT RTR configuration of the MS */

        if (strcmp(sect->type, "ms-rtr-node") == 0){
            if (ms_add_rtr_node(ms,
                    (char *)uci_lookup_option_string(ctx, sect, "name"),
                    (char *)uci_lookup_option_string(ctx, sect, "address"),
                    (char *)uci_lookup_option_string(ctx, sect, "key")) != GOOD){
                return(BAD);
            }
            continue;
        }

        if (strcmp(sect->type, "ms-rtrs-set") == 0){
            rtr_id_list = glist_new();
            opt  = uci_lookup_option(ctx, sect, "rtrs");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), uci_elem){
                    glist_add(uci_elem->name,rtr_id_list);
                }
            }
            if (uci_lookup_option_string(ctx, sect, "ttl") == NULL){
                uci_ttl = OOR_MS_RTR_TTL;
            }else{
                uci_ttl = strtol(uci_lookup_option_string(ctx, sect, "ttl"),NULL,10);
            }

            if (ms_add_rtr_set(ms,
                    (char *)uci_lookup_option_string(ctx, sect, "name"),
                    uci_ttl,
                    rtr_id_list)!=GOOD){
                glist_destroy(rtr_id_list);
                return (BAD);
            }
            glist_destroy(rtr_id_list);
            continue;
        }

        if (strcmp(sect->type, "ms-advertised-rtrs-set") == 0){
            if (ms_advertised_rtr_set(ms, (char *)uci_lookup_option_string(ctx, sect, "name")) != GOOD){
                return (BAD);
            }
            continue;
        }
    }

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);

    return(GOOD);
}

int
configure_ddt_mr(struct uci_context *ctx,struct uci_package *pck)
{
    lisp_ddt_mr_t *ddt_mr;
    struct uci_section *sect;
    struct uci_option *opt;
    struct uci_element *element, *elem_addr;
    char *uci_iface;
    shash_t *lcaf_ht;

    glist_t *root_addresses = glist_new();
    iface_t *iface;
    uint8_t res = BAD;

    if (ctrl_dev_create(DDT_MR_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create MR. Aborting!");
        return (BAD);
    }
    ddt_mr = CONTAINER_OF(ctrl_dev, lisp_ddt_mr_t, super);


    /* create lcaf hash table */
    lcaf_ht = parse_lcafs(ctx,pck);
    if (!lcaf_ht){
        return (BAD);
    }


    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);

        /* CONTROL INTERFACE */
        /* TODO: should work with all interfaces in the future */
        if (strcmp(sect->type, "mr_basic") == 0){
            uci_iface = (char *)uci_lookup_option_string(ctx, sect, "control_iface");
            if (uci_iface == NULL){
                OOR_LOG(LERR,"Configuration file: No control iface assigned");
                return(BAD);
            }
            if ((iface = add_interface(uci_iface))==NULL) {
                return(BAD);
            }

            iface_configure (iface, AF_INET);
            iface_configure (iface, AF_INET6);
        }

        /* ddt_roots */
        if (strcmp(sect->type, "ddt-root-addresses") == 0){
            opt  = uci_lookup_option(ctx, sect, "address");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    glist_add_tail(elem_addr->name, root_addresses);
                }
            }
        }
    }

    res = ddt_mr_put_root_addresses(ddt_mr, root_addresses, lcaf_ht);
    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    glist_destroy(root_addresses);

    return(res);
}

int
configure_ddt(struct uci_context *ctx,struct uci_package *pck)
{
    lisp_ddt_node_t *ddt_node;
    struct uci_section *sect;
    struct uci_option *opt;
    struct uci_element *element, *elem_addr;
    char *uci_iface, *uci_xeid_prefix, *uci_type, *uci_type_lower;
    int uci_iid = 0;
    shash_t *lcaf_ht;
    ddt_authoritative_site_t *asite;
    ddt_delegation_site_t *dsite;
    iface_t *iface;
    int typeint;
    glist_t *child_nodes_list;

    if (ctrl_dev_create(DDT_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create DDT-Node. Aborting!");
        exit_cleanup();
    }
    ddt_node = CONTAINER_OF(ctrl_dev, lisp_ddt_node_t, super);


    /* create lcaf hash table */
    lcaf_ht = parse_lcafs(ctx,pck);
    if (!lcaf_ht){
        return (BAD);
    }


    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);

        /* CONTROL INTERFACE */
        /* TODO: should work with all interfaces in the future */
        if (strcmp(sect->type, "ddt_node_basic") == 0){
            uci_iface = (char *)uci_lookup_option_string(ctx, sect, "control_iface");
            if (uci_iface == NULL){
                OOR_LOG(LERR,"Configuration file: No control iface assigned");
                return(BAD);
            }
            if ((iface = add_interface(uci_iface))==NULL) {
                return(BAD);
            }

            iface_configure (iface, AF_INET);
            iface_configure (iface, AF_INET6);
        }

        if (strcmp(sect->type, "ddt-auth-site") == 0){

            uci_xeid_prefix = (char *)uci_lookup_option_string(ctx, sect, "eid_prefix");
            if (!uci_xeid_prefix){
                OOR_LOG(LERR,"Configuration file: ddt-auth-site should contain an xeid_prefix");
                return (BAD);
            }

            if (uci_lookup_option_string(ctx, sect, "iid") == NULL){
                uci_iid = 0;
            }else{
                uci_iid = strtol(uci_lookup_option_string(ctx, sect, "iid"),NULL,10);
            }

            asite = build_ddt_authoritative_site(ddt_node,uci_xeid_prefix,uci_iid,lcaf_ht);

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
                OOR_LOG(LERR, "Can't add  authoritative site %s. Discarded ...",uci_xeid_prefix);
            }
        }

        if (strcmp(sect->type, "ddt-deleg-site") == 0){
            uci_xeid_prefix = (char *)uci_lookup_option_string(ctx, sect, "eid_prefix");
            if (!uci_xeid_prefix){
                OOR_LOG(LERR,"Configuration file: ddt-auth-site should contain an xeid_prefix");
                return (BAD);
            }
            if (uci_lookup_option_string(ctx, sect, "iid") == NULL){
                uci_iid = 0;
            }else{
                uci_iid = strtol(uci_lookup_option_string(ctx, sect, "iid"),NULL,10);
            }
            uci_type = (char *)uci_lookup_option_string(ctx, sect, "delegation_type");
            if (uci_type != NULL){
                uci_type_lower = str_to_lower_case(uci_type);
                if (strcmp(uci_type_lower,"child_ddt_node") == 0){
                    typeint = LISP_ACTION_NODE_REFERRAL;
                }else if (strcmp(uci_type_lower,"map_server_ddt_node") == 0){
                    typeint = LISP_ACTION_MS_REFERRAL;
                }else{
                    OOR_LOG (LCRIT, "Configuration file: Unknown delegation type: %s",uci_type);
                    free(uci_type_lower);
                    return (BAD);
                }
                free(uci_type_lower);
            }else{
                OOR_LOG (LCRIT, "Configuration file: ddt-deleg-site for xeid %s should contain the "
                        "field delegation type",uci_xeid_prefix);
                return (BAD);
            }
            child_nodes_list = glist_new();
            opt  = uci_lookup_option(ctx, sect, "deleg_nodes");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    glist_add_tail(elem_addr->name, child_nodes_list);
                }
            }

            dsite = build_ddt_delegation_site(ddt_node,
                    uci_xeid_prefix,
                    uci_iid,
                    typeint,
                    child_nodes_list,
                    lcaf_ht);

            glist_destroy(child_nodes_list);

            if (dsite != NULL) {
                if (mdb_lookup_entry(ddt_node->deleg_sites_db, dsite_xeid(dsite)) != NULL){
                    OOR_LOG(LDBG_1, "Configuration file: Duplicated deleg-site: %s . Discarding...",
                            lisp_addr_to_char(dsite_xeid(dsite)));
                    ddt_delegation_site_del(dsite);
                    continue;
                }

                OOR_LOG(LDBG_1, "Adding delegation site %s to the delegation sites "
                        "database", lisp_addr_to_char(dsite_xeid(dsite)));
                ddt_node_add_delegation_site(ddt_node, dsite);
            }else{
                OOR_LOG(LERR, "Can't add  delegation site %s. Discarded ...",uci_xeid_prefix);
            }
        }
    }

    /* destroy the hash table */
    shash_destroy(lcaf_ht);

    return(GOOD);
}

static mapping_t*
parse_mapping(struct uci_context *ctx, struct uci_section *sect,
        oor_ctrl_dev_t *dev, shash_t *rloc_set_ht, shash_t *lcaf_ht,
        uint8_t is_local)
{
    mapping_t *mapping;
    conf_mapping_t *conf_mapping;

    conf_mapping = uci_parse_conf_mapping(ctx,sect,rloc_set_ht,is_local);
    if (!conf_mapping){
        return (NULL);
    }
    mapping = process_mapping_config(dev, lcaf_ht, conf_mapping, is_local);

    conf_mapping_destroy(conf_mapping);

    return(mapping);
}

conf_mapping_t *
uci_parse_conf_mapping(struct uci_context *ctx, struct uci_section *sect,
        shash_t *rloc_set_ht, uint8_t is_local)
{
    conf_mapping_t *conf_mapping;
    char *uci_eid, *uci_rloc_set;
    glist_t *rloc_list;
    glist_entry_t *rloc_it;
    gconf_loc_t *gconf_loct;

    conf_mapping = conf_mapping_new();
    if (!conf_mapping){
        goto err;
    }
    uci_eid = (char *)uci_lookup_option_string(ctx, sect, "eid_prefix");
    uci_rloc_set = (char *)uci_lookup_option_string(ctx, sect, "rloc_set");
    if (!uci_eid || !uci_rloc_set){
        goto err;
    }
    if (uci_lookup_option_string(ctx, sect, "iid") == NULL){
        conf_mapping->iid = 0;
    }else{
        conf_mapping->iid = strtol(uci_lookup_option_string(ctx, sect, "iid"),NULL,10);
    }
    if (uci_lookup_option_string(ctx, sect, "ttl") == NULL){
        conf_mapping->ttl = DEFAULT_DATA_CACHE_TTL;
    }else{
        conf_mapping->ttl = strtol(uci_lookup_option_string(ctx, sect, "ttl"),NULL,10);
    }

    conf_mapping->eid_prefix = strdup(uci_eid);
    /* Check if the rloc-set exists */
    rloc_list = (glist_t *)shash_lookup(rloc_set_ht,uci_rloc_set);
    if (!rloc_list){
        OOR_LOG(LWRN,"Configuration file: The rloc set %s doesn't exist", uci_rloc_set);
        goto err;
    }
    /* Add the locators to the conf mapping*/
    glist_for_each_entry(rloc_it,rloc_list){
        gconf_loct = (gconf_loc_t *)glist_entry_data(rloc_it);
        switch (gconf_loct->type){
        case CONF_LOCT_ADDR:
            glist_add(conf_loc_clone(gconf_loct->conf_loct),conf_mapping->conf_loc_list);
            break;
        case CONF_LOCT_IFACE:
            glist_add(conf_loc_iface_clone(gconf_loct->conf_loct),conf_mapping->conf_loc_iface_list);
            break;
        }
    }
    return (conf_mapping);
err:
    conf_mapping_destroy(conf_mapping);
    return (NULL);
}


static shash_t *
parse_rlocs(struct uci_context *ctx, struct uci_package *pck)
{
    shash_t *conf_loct_tbl;
    struct uci_section *section;
    struct uci_element *element;
    gconf_loc_t *conf_loct;
    conf_loc_t *conf_loc_addr;
    conf_loc_iface_t *conf_loc_iface;
    char *uci_rloc_name;
    char *uci_address;
    char *uci_iface_name;
    char *boolean_char;
    int uci_afi;
    int uci_priority;
    int uci_weight;
    uint8_t uci_local;

    conf_loct_tbl = shash_new_managed((free_value_fn_t)gconf_loc_destroy);

    /* create lcaf hash table */
    uci_foreach_element(&pck->sections, element) {
        section = uci_to_section(element);

        if (strcmp(section->type, "rloc-address") == 0){
            uci_rloc_name = (char *)uci_lookup_option_string(ctx, section, "name");
            if (uci_rloc_name == NULL){
                OOR_LOG(LERR,"Configuration file: An rloc-address should have a name");
                goto err;
            }
            uci_address = (char *)uci_lookup_option_string(ctx, section, "address");
            if (uci_lookup_option_string(ctx, section, "priority") == NULL){
                OOR_LOG(LERR,"Configuration file: No priority assigned to the rloc \"%s\"",uci_rloc_name);
                goto err;
            }
            uci_priority = strtol(uci_lookup_option_string(ctx, section, "priority"),NULL,10);
            if (uci_lookup_option_string(ctx, section, "weight") == NULL){
                OOR_LOG(LERR,"Configuration file: No weight assigned to the rloc \"%s\"",uci_rloc_name);
                goto err;
            }
            uci_weight = strtol(uci_lookup_option_string(ctx, section, "weight"),NULL,10);

            if (shash_lookup(conf_loct_tbl,uci_rloc_name) != NULL){
                OOR_LOG(LDBG_1,"Configuration file: The RLOC %s is duplicated.", uci_rloc_name);
                goto err;
            }

            boolean_char = (char *)uci_lookup_option_string(ctx, section, "local");
            if (boolean_char){
                uci_local = str_to_boolean(boolean_char);
                if(uci_local == UNKNOWN){
                    OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in local",boolean_char);
                    return (BAD);
                }
            }else{
                uci_local = TRUE;
            }

            conf_loc_addr = conf_loc_new_init(uci_address, uci_priority, uci_weight, 255, 0, uci_local);
            if (!conf_loc_addr){
                goto err;
            }
            conf_loct = gconf_loc_new_init(CONF_LOCT_ADDR,conf_loc_addr);
            if (!conf_loct ){
                goto err;
            }
            shash_insert(conf_loct_tbl, strdup(uci_rloc_name), conf_loct);
        }

        if (strcmp(section->type, "rloc-iface") == 0){
            uci_rloc_name = (char *)uci_lookup_option_string(ctx, section, "name");
            if (uci_rloc_name == NULL){
                OOR_LOG(LERR,"Configuration file: An rloc-iface should have a name");
                goto err;
            }
            uci_iface_name = (char *)uci_lookup_option_string(ctx, section, "interface");
            if (uci_lookup_option_string(ctx, section, "ip_version") == NULL){
                OOR_LOG(LERR,"Configuration file: No afi assigned to the rloc \"%s\"",uci_rloc_name);
                goto err;
            }
            uci_afi = strtol(uci_lookup_option_string(ctx, section, "ip_version"),NULL,10);
            if (uci_lookup_option_string(ctx, section, "priority") == NULL){
                OOR_LOG(LERR,"Configuration file: No priority assigned to the rloc \"%s\"",uci_rloc_name);
                goto err;
            }


            uci_priority = strtol(uci_lookup_option_string(ctx, section, "priority"),NULL,10);
            if (uci_lookup_option_string(ctx, section, "weight") == NULL){
                OOR_LOG(LERR,"Configuration file: No weight assigned to the rloc \"%s\"",uci_rloc_name);
                goto err;
            }
            uci_weight = strtol(uci_lookup_option_string(ctx, section, "weight"),NULL,10);


            if (shash_lookup(conf_loct_tbl,uci_rloc_name) != NULL){
                OOR_LOG(LDBG_1,"Configuration file: The RLOC %s is duplicated.", uci_rloc_name);
                goto err;
            }

            /* Create a basic locator. Locaor or remote information will be added later according
             * who is using the locator*/
            conf_loc_iface = conf_loc_iface_new_init(uci_iface_name, uci_afi, uci_priority,
                    uci_weight, 255, 0);
            if (!conf_loc_iface){
                goto err;
            }
            conf_loct = gconf_loc_new_init(CONF_LOCT_IFACE,conf_loc_iface);
            if (!conf_loct){
                goto err;
            }
            shash_insert(conf_loct_tbl, strdup(uci_rloc_name), conf_loct);
        }
    }
    return (conf_loct_tbl);
err:
    shash_destroy(conf_loct_tbl);
    return (NULL);
}

static shash_t *
parse_rloc_sets(struct uci_context *ctx, struct uci_package *pck, shash_t *rlocs_ht)
{
    struct uci_section *section;
    struct uci_element *element;
    struct uci_element *element_loct;
    struct uci_option *opt;
    char *uci_rloc_set_name;
    shash_t *rloc_sets_ht;
    glist_t *rloc_list;
    gconf_loc_t *gconf_loct;

    /* create lcaf hash table */
    rloc_sets_ht = shash_new_managed((free_value_fn_t)glist_destroy);

    uci_foreach_element(&pck->sections, element) {
        section = uci_to_section(element);

        if (strcmp(section->type, "rloc-set") == 0){
            uci_rloc_set_name = (char *)uci_lookup_option_string(ctx, section, "name");
            if (uci_rloc_set_name == NULL){
                OOR_LOG(LERR,"Configuration file: An rloc-set should have a name");
                goto error;
            }
            rloc_list = (glist_t*)shash_lookup(rloc_sets_ht,uci_rloc_set_name);
            if (rloc_list == NULL){
                rloc_list = glist_new();
                if (rloc_list != NULL){
                    shash_insert(rloc_sets_ht, strdup(uci_rloc_set_name), rloc_list);
                }else{
                    OOR_LOG(LWRN, "parse_rloc_sets: Error creating rloc list");
                    goto error;
                }
            }else{
                OOR_LOG(LERR, "Configuration file: The RLOC set %s is duplicated.",
                        uci_rloc_set_name);
                goto error;
            }
            opt  = uci_lookup_option(ctx, section, "rloc_name");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), element_loct){
                    gconf_loct = shash_lookup(rlocs_ht, element_loct->name);
                    if (gconf_loct == NULL){
                        OOR_LOG(LWRN,"Configuration file: The RLOC name %s of the RLOC set %s doesn't exist",
                                element_loct->name, uci_rloc_set_name);
                        goto error;
                    }

                    if (glist_add_tail(gconf_loct,rloc_list)!=GOOD){
                        OOR_LOG(LDBG_1,"parse_rloc_sets: Error adding locator to the rloc-set");
                    }
                }
            }else{
                OOR_LOG(LWRN, "Configuration file: The RLOC set %s has no rlocs "
                        "associated.",uci_rloc_set_name);
                goto error;
            }

        }
    }

    return (rloc_sets_ht);

    error:
    shash_destroy(rloc_sets_ht);
    return (NULL);
}

static shash_t *
parse_lcafs(struct uci_context *ctx, struct uci_package *pck)
{
    struct uci_section *section;
    struct uci_element *element;
    shash_t *lcaf_ht;

    /* create lcaf hash table */
    lcaf_ht = shash_new_managed((free_value_fn_t)lisp_addr_del);

    uci_foreach_element(&pck->sections, element) {
        section = uci_to_section(element);
        if (strcmp(section->type, "elp-node") == 0){
            if (parse_elp_node(ctx,section,lcaf_ht)!=GOOD){
                shash_destroy(lcaf_ht);
                return (NULL);
            }
        }
    }

    //parse_rle_list(cfg, lcaf_ht);
    //parse_mcinfo_list(cfg, lcaf_ht);

    return(lcaf_ht);
}

static int
parse_elp_node(struct uci_context *ctx, struct uci_section *section, shash_t *ht)
{
    char *uci_elp_name, *boolean_char;
    char *uci_address;
    lisp_addr_t *laddr;
    elp_node_t *elp_node;

    uci_elp_name = (char *)uci_lookup_option_string(ctx, section, "elp_name");
    if (uci_elp_name == NULL){
        OOR_LOG(LERR,"Configuration file: An ELP should have a name");
        return (BAD);
    }
    laddr = (lisp_addr_t *)shash_lookup(ht, uci_elp_name);

    if (laddr == NULL){
        laddr = lisp_addr_elp_new();
        if (laddr == NULL){
            OOR_LOG(LWRN,"parse_elp_node: Couldn't create ELP address");
            return (BAD);
        }
        shash_insert(ht, strdup(uci_elp_name), laddr);
        OOR_LOG(LDBG_3,"parse_elp_node: Added ELP %s to the hash table of LCAF addresses",uci_elp_name);
    }else {
        if (lisp_addr_is_elp(laddr) == FALSE){
            OOR_LOG(LWRN,"Configuration file: Address %s composed of LCAF addresses of different type",
                    uci_elp_name);
            return (BAD);
        }
    }

    elp_node = xzalloc(sizeof(elp_node_t));
    elp_node->addr = lisp_addr_new();

    uci_address = (char *)uci_lookup_option_string(ctx, section, "address");
    if (uci_address == NULL){
        OOR_LOG(LERR,"Configuration file: An ELP node should have an address assigned");
        return (BAD);
    }

    if (lisp_addr_ip_from_char(uci_address, elp_node->addr) != GOOD) {
        elp_node_del(elp_node);
        OOR_LOG(LERR, "Configuration file: Couldn't parse ELP node %s",
                uci_address);
        return (BAD);
    }

    boolean_char = (char *)uci_lookup_option_string(ctx, section, "strict");
    if (boolean_char){
        elp_node->S = str_to_boolean(boolean_char);
        if(elp_node->S == UNKNOWN){
            OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in strict option of ELP",boolean_char);
            return (BAD);
        }
    }else{
        elp_node->S = FALSE;
    }

    boolean_char = (char *)uci_lookup_option_string(ctx, section, "probe");
    if (boolean_char){
        elp_node->P = str_to_boolean(boolean_char);
        if(elp_node->P == UNKNOWN){
            OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in probe option of ELP",boolean_char);
            return (BAD);
        }
    }else{
        elp_node->P = FALSE;
    }

    boolean_char = (char *)uci_lookup_option_string(ctx, section, "lookup");
    if (boolean_char){
        elp_node->L = str_to_boolean(boolean_char);
        if(elp_node->L == UNKNOWN){
            OOR_LOG(LERR,"Configuration file: unknown value \"%s\" in lookup option of ELP",boolean_char);
            return (BAD);
        }
    }else{
        elp_node->L = FALSE;
    }

    elp_add_node(lcaf_elp_get_elp(lisp_addr_get_lcaf(laddr)),elp_node);
    OOR_LOG(LDBG_3,"parse_elp_node: Added %s to the ELP %s",uci_address,uci_elp_name);

    return (GOOD);
}

