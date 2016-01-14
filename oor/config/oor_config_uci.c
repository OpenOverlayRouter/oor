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
#include "../lib/shash.h"
#include "../lib/oor_log.h"
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
static mapping_t*
parse_mapping(
        struct uci_context      *ctx,
        struct uci_section      *sect,
        oor_ctrl_dev_t         *dev,
        shash_t                *rloc_set_ht,
        shash_t                *lcaf_ht,
        glist_t                 *no_addr_loct_l,
        uint8_t                 is_local);

static shash_t *
parse_rlocs(
        struct uci_context      *ctx,
        struct uci_package      *pck,
        shash_t                *lcaf_ht,
        glist_t                 *no_addr_loct_list);

static shash_t *
parse_rloc_sets(
        struct uci_context      *ctx,
        struct uci_package      *pck,
        shash_t                *rlocs_ht,
        shash_t                *lcaf_ht);
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
handle_config_file(char **uci_conf_file_path)
{
    char *uci_conf_dir;
    char *uci_conf_file;
    struct uci_context *ctx;
    struct uci_package *pck = NULL;
    struct uci_section *sect;
    struct uci_element *element;
    int uci_debug;
    char *uci_log_file;
    char *uci_op_mode;
    int res = BAD;


    if (*uci_conf_file_path == NULL){
        *uci_conf_file_path = strdup("/etc/config/oor");
    }

    ctx = uci_alloc_context();

    if (ctx == NULL) {
        OOR_LOG(LCRIT, "Could not create UCI context. Exiting ...");
        exit_cleanup();
    }

    uci_conf_dir = dirname(strdup(*uci_conf_file_path));
    uci_conf_file = basename(strdup(*uci_conf_file_path));


    uci_set_confdir(ctx, uci_conf_dir);

    OOR_LOG(LDBG_1,"Conf dir: %s\n",ctx->confdir);

    uci_load(ctx,uci_conf_file,&pck);

    if (pck == NULL) {
        OOR_LOG(LCRIT, "Could not load conf file: %s. Exiting ...",uci_conf_file);
        uci_perror(ctx,"Error while loading file ");
        uci_free_context(ctx);
        exit_cleanup();
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

            uci_op_mode = (char *)uci_lookup_option_string(ctx, sect, "operating_mode");

            if (uci_op_mode != NULL) {
                if (strcmp(uci_op_mode, "xTR") == 0) {
                    res = configure_xtr(ctx, pck);
                } else if (strcmp(uci_op_mode, "MS") == 0) {
                    res = configure_ms(ctx, pck);
                } else if (strcmp(uci_op_mode, "RTR") == 0) {
                    res = configure_rtr(ctx, pck);
                }else if (strcmp(uci_op_mode, "MN") == 0) {
                    res = configure_mn(ctx, pck);
                }else {
                    OOR_LOG(LCRIT, "Configuration file: Unknown operating mode: %s",uci_op_mode);
                    return (BAD);
                }
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
    char *uci_address;
    int uci_key_type;
    char *uci_key;
    int uci_proxy_reply;
    int uci_priority;
    int uci_weigth;
    shash_t *lcaf_ht;
    shash_t *rlocs_ht;
    shash_t *rloc_set_ht;
    lisp_xtr_t *xtr;
    map_local_entry_t *map_loc_e;
    mapping_t *mapping;
    void *fwd_map_inf;
    glist_t *no_addr_loct_list;

    /* CREATE AND CONFIGURE XTR */
    if (ctrl_dev_create(xTR_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create xTR. Aborting!");
        exit_cleanup();
    }

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    /* FWD POLICY STRUCTURES */
    xtr->fwd_policy = fwd_policy_class_find("flow_balancing");
    xtr->fwd_policy_dev_parm = xtr->fwd_policy->new_dev_policy_inf(ctrl_dev,NULL);

    /* CREATE LCAFS HTABLE */

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of database mappings
     * or static map cache entries  */
    lcaf_ht = parse_lcafs(ctx,pck);

    /* CREATE RLOCs sets HTABLE */
    no_addr_loct_list = glist_new_managed((glist_del_fct)no_addr_loct_del);
    rlocs_ht = parse_rlocs(ctx,pck,lcaf_ht,no_addr_loct_list);
    rloc_set_ht = parse_rloc_sets(ctx,pck,rlocs_ht,lcaf_ht);


    uci_foreach_element(&pck->sections, element) {
            sect = uci_to_section(element);
            if (strcmp(sect->type, "daemon") == 0){

                /* RETRIES */
                if (uci_lookup_option_string(ctx, sect, "map_request_retries") != NULL){
                    uci_retries = strtol(uci_lookup_option_string(ctx, sect, "map_request_retries"),NULL,10);
                    if (uci_retries >= 0 && uci_retries <= OOR_MAX_RETRANSMITS){
                        xtr->map_request_retries = uci_retries;
                    }else if (uci_retries > OOR_MAX_RETRANSMITS){
                        xtr->map_request_retries = OOR_MAX_RETRANSMITS;
                        OOR_LOG(LWRN, "Map-Request retries should be between 0 and %d. "
                                "Using default value: %d",OOR_MAX_RETRANSMITS, OOR_MAX_RETRANSMITS);
                    }
                }else{
                    OOR_LOG(LWRN,"Configuration file: Map Request Retries not specified."
                            " Setting default value: %d sec.",DEFAULT_MAP_REQUEST_RETRIES);
                    xtr->map_request_retries = DEFAULT_MAP_REQUEST_RETRIES;
                    continue;
                }
            }

            /* RLOC PROBING CONFIG */

            if (strcmp(sect->type, "rloc-probing") == 0){
                if (uci_lookup_option_string(ctx, sect, "rloc_probe_interval") != NULL){
                    xtr->probe_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_interval"),NULL,10);
                }else{
                    OOR_LOG(LWRN,"Configuration file: RLOC probe interval not specified."
                            " Disabling RLOC Probing");
                    xtr->probe_interval = 0;
                    continue;
                }
                if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries") != NULL){
                    xtr->probe_retries = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries"),NULL,10);
                }else{
                    OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries not specified."
                            " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES);
                    xtr->probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
                }
                if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval") != NULL){
                    xtr->probe_retries_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval"),NULL,10);
                }else{
                    OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries Intervals not specified."
                            " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES_INTERVAL);
                    xtr->probe_retries_interval = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;
                }

                validate_rloc_probing_parameters(&xtr->probe_interval,
                        &xtr->probe_retries, &xtr->probe_retries_interval);
                continue;
            }

            /* NAT Traversal options */
            if (strcmp(sect->type, "nat-traversal") == 0){
                if (strcmp(uci_lookup_option_string(ctx, sect, "nat_aware"), "on") == 0){
                    nat_aware = TRUE;
                }else{
                    nat_aware = FALSE;
                }
                continue;
            }

            /* MAP-RESOLVER CONFIG */
            if (strcmp(sect->type, "map-resolver") == 0){
                opt  = uci_lookup_option(ctx, sect, "address");
                if (opt != NULL){
                    uci_foreach_element(&(opt->v.list), elem_addr){
                        if (add_server(elem_addr->name, xtr->map_resolvers) != GOOD){
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

                if (strcmp(uci_lookup_option_string(ctx, sect, "proxy_reply"), "on") == 0){
                    uci_proxy_reply = TRUE;
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

            if (strcmp(sect->type, "proxy-etr") == 0){
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

                if (add_proxy_etr_entry(xtr->petrs,uci_address,uci_priority,uci_weigth) != GOOD ){
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

            if (strcmp(sect->type, "database-mapping") == 0){
                mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,TRUE);
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

                fwd_map_inf = xtr->fwd_policy->new_map_loc_policy_inf(xtr->fwd_policy_dev_parm,mapping,NULL);
                if (fwd_map_inf == NULL){
                    OOR_LOG(LERR, "Couldn't create forward information for mapping with EID: %s. Discarding it...",
                            lisp_addr_to_char(mapping_eid(mapping)));
                    map_local_entry_del(map_loc_e);
                    continue;
                }
                map_local_entry_set_fwd_info(map_loc_e, fwd_map_inf, xtr->fwd_policy->del_map_loc_policy_inf);

                if (add_local_db_map_local_entry(map_loc_e,xtr) != GOOD){
                    map_local_entry_del(map_loc_e);
                    continue;
                }

                continue;
            }

            /* STATIC MAP-CACHE CONFIG */
            if (strcmp(sect->type, "static-map-cache") == 0){
                mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,FALSE);
                if (mapping == NULL){
                    OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                            uci_lookup_option_string(ctx, sect, "eid_prefix"));
                    continue;
                }
                if (mcache_lookup_exact(xtr->map_cache, mapping_eid(mapping)) == NULL){
                    if (tr_mcache_add_static_mapping(xtr, mapping) == GOOD){
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
    }
    /* Calculate forwarding info por proxy-etrs */
    fwd_map_inf = xtr->fwd_policy->new_map_cache_policy_inf(xtr->fwd_policy_dev_parm,mcache_entry_mapping(xtr->petrs));
    if (fwd_map_inf == NULL){
        OOR_LOG(LDBG_1, "Couldn't create routing info for PeTRs!.");
        mcache_entry_del(xtr->petrs);
        return(BAD);
    }
    mcache_entry_set_routing_info(xtr->petrs,fwd_map_inf,xtr->fwd_policy->del_map_cache_policy_inf);

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);
    glist_destroy(no_addr_loct_list);

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
    char *uci_address;
    int uci_key_type;
    char *uci_key;
    int uci_proxy_reply;
    int uci_priority;
    int uci_weigth;
    shash_t *lcaf_ht;
    shash_t *rlocs_ht;
    shash_t *rloc_set_ht;
    lisp_xtr_t *xtr;
    map_local_entry_t *map_loc_e;
    mapping_t *mapping;
    void *fwd_map_inf;
    glist_t *no_addr_loct_list;

    /* CREATE AND CONFIGURE XTR */
    if (ctrl_dev_create(MN_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create Mobile Node device. Aborting!");
        exit_cleanup();
    }

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    /* FWD POLICY STRUCTURES */
    xtr->fwd_policy = fwd_policy_class_find("flow_balancing");
    xtr->fwd_policy_dev_parm = xtr->fwd_policy->new_dev_policy_inf(ctrl_dev,NULL);

    /* CREATE LCAFS HTABLE */

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of database mappings
     * or static map cache entries  */
    lcaf_ht = parse_lcafs(ctx,pck);

    /* CREATE RLOCs sets HTABLE */
    no_addr_loct_list = glist_new_managed((glist_del_fct)no_addr_loct_del);
    rlocs_ht = parse_rlocs(ctx,pck,lcaf_ht,no_addr_loct_list);
    rloc_set_ht = parse_rloc_sets(ctx,pck,rlocs_ht,lcaf_ht);


    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);
        if (strcmp(sect->type, "daemon") == 0){

            /* RETRIES */
            if (uci_lookup_option_string(ctx, sect, "map_request_retries") != NULL){
                uci_retries = strtol(uci_lookup_option_string(ctx, sect, "map_request_retries"),NULL,10);
                if (uci_retries >= 0 && uci_retries <= OOR_MAX_RETRANSMITS){
                    xtr->map_request_retries = uci_retries;
                }else if (uci_retries > OOR_MAX_RETRANSMITS){
                    xtr->map_request_retries = OOR_MAX_RETRANSMITS;
                    OOR_LOG(LWRN, "Map-Request retries should be between 0 and %d. "
                            "Using default value: %d",OOR_MAX_RETRANSMITS, OOR_MAX_RETRANSMITS);
                }
            }else{
                OOR_LOG(LWRN,"Configuration file: Map Request Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_MAP_REQUEST_RETRIES);
                xtr->map_request_retries = DEFAULT_MAP_REQUEST_RETRIES;
                continue;
            }
        }

        /* RLOC PROBING CONFIG */

        if (strcmp(sect->type, "rloc-probing") == 0){
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_interval") != NULL){
                xtr->probe_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC probe interval not specified."
                        " Disabling RLOC Probing");
                xtr->probe_interval = 0;
                continue;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries") != NULL){
                xtr->probe_retries = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES);
                xtr->probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval") != NULL){
                xtr->probe_retries_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries Intervals not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES_INTERVAL);
                xtr->probe_retries_interval = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;
            }

            validate_rloc_probing_parameters(&xtr->probe_interval,
                    &xtr->probe_retries, &xtr->probe_retries_interval);
            continue;
        }

        /* NAT Traversal options */
        if (strcmp(sect->type, "nat-traversal") == 0){
            if (strcmp(uci_lookup_option_string(ctx, sect, "nat_aware"), "on") == 0){
                nat_aware = TRUE;
            }else{
                nat_aware = FALSE;
            }
            continue;
        }

        /* MAP-RESOLVER CONFIG */
        if (strcmp(sect->type, "map-resolver") == 0){
            opt  = uci_lookup_option(ctx, sect, "address");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    if (add_server(elem_addr->name, xtr->map_resolvers) != GOOD){
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

            if (strcmp(uci_lookup_option_string(ctx, sect, "proxy_reply"), "on") == 0){
                uci_proxy_reply = TRUE;
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

        if (strcmp(sect->type, "proxy-etr") == 0){
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

            if (add_proxy_etr_entry(xtr->petrs,uci_address,uci_priority,uci_weigth) != GOOD ){
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

        if (strcmp(sect->type, "database-mapping") == 0){
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,TRUE);
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

            fwd_map_inf = xtr->fwd_policy->new_map_loc_policy_inf(xtr->fwd_policy_dev_parm,mapping,NULL);
            if (fwd_map_inf == NULL){
                OOR_LOG(LERR, "Couldn't create forward information for mapping with EID: %s. Discarding it...",
                        lisp_addr_to_char(mapping_eid(mapping)));
                map_local_entry_del(map_loc_e);
                continue;
            }
            map_local_entry_set_fwd_info(map_loc_e, fwd_map_inf, xtr->fwd_policy->del_map_loc_policy_inf);

            if (add_local_db_map_local_entry(map_loc_e,xtr) != GOOD){
                map_local_entry_del(map_loc_e);
                continue;
            }

            continue;
        }

        /* STATIC MAP-CACHE CONFIG */
        if (strcmp(sect->type, "static-map-cache") == 0){
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,FALSE);
            if (mapping == NULL){
                OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
            }
            if (mcache_lookup_exact(xtr->map_cache, mapping_eid(mapping)) == NULL){
                if (tr_mcache_add_static_mapping(xtr, mapping) == GOOD){
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
    }

    /* Calculate forwarding info por proxy-etrs */
    fwd_map_inf = xtr->fwd_policy->new_map_cache_policy_inf(xtr->fwd_policy_dev_parm,mcache_entry_mapping(xtr->petrs));
    if (fwd_map_inf == NULL){
        OOR_LOG(LDBG_1, "Couldn't create routing info for PeTRs!.");
        mcache_entry_del(xtr->petrs);
        return(BAD);
    }
    mcache_entry_set_routing_info(xtr->petrs,fwd_map_inf,xtr->fwd_policy->del_map_cache_policy_inf);

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);
    glist_destroy(no_addr_loct_list);

    return(GOOD);
}

int
configure_rtr(struct uci_context *ctx, struct uci_package *pck)
{
    lisp_xtr_t *xtr;
    struct uci_section *sect;
    struct uci_element *element;
    struct uci_element *elem_addr;
    struct uci_option *opt;
    shash_t *lcaf_ht;
    shash_t *rlocs_ht;
    shash_t *rloc_set_ht;
    int uci_retries;
    char *uci_address;
    int uci_key_type;
    char *uci_key;
    int uci_proxy_reply;
    char *uci_iface;
    mapping_t *mapping;
    int uci_afi;
    int uci_priority;
    int uci_weigth;
    glist_t *no_addr_loct_list;

    /* CREATE AND CONFIGURE RTR (xTR in fact) */
    if (ctrl_dev_create(RTR_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create RTR. Aborting!");
        exit_cleanup();
    }

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    /* FWD POLICY STRUCTURES */
    xtr->fwd_policy = fwd_policy_class_find("flow_balancing");
    xtr->fwd_policy_dev_parm = xtr->fwd_policy->new_dev_policy_inf(ctrl_dev,NULL);

    /* CREATE LCAFS HTABLE */

    /* get a hash table of all the elps. If any are configured,
     * their names could appear in the rloc field of database mappings
     * or static map cache entries  */
    lcaf_ht = parse_lcafs(ctx,pck);

    /* CREATE RLOCs sets HTABLE */
    no_addr_loct_list = glist_new_managed((glist_del_fct)no_addr_loct_del);
    rlocs_ht = parse_rlocs(ctx,pck,lcaf_ht,no_addr_loct_list);
    rloc_set_ht = parse_rloc_sets(ctx,pck,rlocs_ht,lcaf_ht);

    uci_foreach_element(&pck->sections, element) {
        sect = uci_to_section(element);
        if (strcmp(sect->type, "daemon") == 0){

            /* RETRIES */
            if (uci_lookup_option_string(ctx, sect, "map_request_retries") != NULL){
                uci_retries = strtol(uci_lookup_option_string(ctx, sect, "map_request_retries"),NULL,10);
                if (uci_retries >= 0 && uci_retries <= OOR_MAX_RETRANSMITS){
                    xtr->map_request_retries = uci_retries;
                }else if (uci_retries > OOR_MAX_RETRANSMITS){
                    xtr->map_request_retries = OOR_MAX_RETRANSMITS;
                    OOR_LOG(LWRN, "Map-Request retries should be between 0 and %d. "
                            "Using default value: %d",OOR_MAX_RETRANSMITS, OOR_MAX_RETRANSMITS);
                }
            }else{
                OOR_LOG(LWRN,"Configuration file: Map Request Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_MAP_REQUEST_RETRIES);
                xtr->map_request_retries = DEFAULT_MAP_REQUEST_RETRIES;
                continue;
            }
        }

        /* RLOC PROBING CONFIG */

        if (strcmp(sect->type, "rloc-probing") == 0){
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_interval") != NULL){
                xtr->probe_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC probe interval not specified."
                        " Disabling RLOC Probing");
                xtr->probe_interval = 0;
                continue;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries") != NULL){
                xtr->probe_retries = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES);
                xtr->probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval") != NULL){
                xtr->probe_retries_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval"),NULL,10);
            }else{
                OOR_LOG(LWRN,"Configuration file: RLOC Probe Retries Intervals not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES_INTERVAL);
                xtr->probe_retries_interval = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;
            }

            validate_rloc_probing_parameters(&xtr->probe_interval,
                    &xtr->probe_retries, &xtr->probe_retries_interval);
            continue;
        }

        /* MAP-RESOLVER CONFIG */
        if (strcmp(sect->type, "map-resolver") == 0){
            opt  = uci_lookup_option(ctx, sect, "address");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    if (add_server(elem_addr->name, xtr->map_resolvers) != GOOD){
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

            if (strcmp(uci_lookup_option_string(ctx, sect, "proxy_reply"), "on") == 0){
                uci_proxy_reply = TRUE;
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

        /* STATIC MAP-CACHE CONFIG */
        if (strcmp(sect->type, "static-map-cache") == 0){
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,FALSE);
            if (mapping == NULL){
                OOR_LOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
            }
            if (mcache_lookup_exact(xtr->map_cache, mapping_eid(mapping)) == NULL){
                if (tr_mcache_add_static_mapping(xtr, mapping) == GOOD){
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
            if (add_rtr_iface(xtr,
                    uci_iface,
                    uci_afi,
                    uci_priority,
                    uci_weigth) == GOOD) {
                OOR_LOG(LDBG_1, "Configured interface %s for RTR",uci_iface);
            } else{
                OOR_LOG(LERR, "Can't configure iface %s for RTR",uci_iface);
            }
        }
    }

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);
    glist_destroy(no_addr_loct_list);

    return(GOOD);
}

int
configure_ms(struct uci_context *ctx,struct uci_package *pck)
{
    lisp_ms_t *ms;
    struct uci_section *sect;
    struct uci_element *element;
    char *uci_iface;
    char *uci_eid_prefix;
    int uci_iid = 0;
    int uci_key_type;
    char *uci_key;
    uint8_t uci_more_specifics;
    uint8_t uci_proxy_reply;
    uint8_t uci_merge;
    mapping_t *mapping;
    lisp_site_prefix_t *site;
    shash_t *lcaf_ht;
    shash_t *rlocs_ht;
    shash_t *rloc_set_ht;
    glist_t *no_addr_loct_list;
    iface_t *iface;

    /* create and configure xtr */
    if (ctrl_dev_create(MS_MODE, &ctrl_dev) != GOOD) {
        OOR_LOG(LCRIT, "Failed to create MS. Aborting!");
        exit_cleanup();
    }
    ms = CONTAINER_OF(ctrl_dev, lisp_ms_t, super);


    /* create lcaf hash table */
    lcaf_ht = parse_lcafs(ctx,pck);

    /* CREATE RLOCs sets HTABLE */
    no_addr_loct_list = glist_new_managed((glist_del_fct)no_addr_loct_del);
    rlocs_ht = parse_rlocs(ctx,pck,lcaf_ht,no_addr_loct_list);
    rloc_set_ht = parse_rloc_sets(ctx,pck,rlocs_ht,lcaf_ht);

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

            if (iface_address(iface, AF_INET) == NULL){
                iface_setup_addr(iface, AF_INET);
                data_plane->datap_add_iface_addr(iface,AF_INET);
                lctrl->control_data_plane->control_dp_add_iface_addr(lctrl,iface,AF_INET);
            }

            if (iface_address(iface, AF_INET6) == NULL){
                iface_setup_addr(iface, AF_INET6);
                data_plane->datap_add_iface_addr(iface,AF_INET6);
                lctrl->control_data_plane->control_dp_add_iface_addr(lctrl,iface,AF_INET6);
            }
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

            if (uci_lookup_option_string(ctx, sect, "accept_more_specifics") != NULL &&
                    strcmp(uci_lookup_option_string(ctx, sect, "accept_more_specifics"), "on") == 0){
                uci_more_specifics = TRUE;
            }else{
                uci_more_specifics = FALSE;
            }
            if (uci_lookup_option_string(ctx, sect, "proxy_reply") != NULL &&
                    strcmp(uci_lookup_option_string(ctx, sect, "proxy_reply"), "on") == 0){
                uci_proxy_reply = TRUE;
            }else{
                uci_proxy_reply = FALSE;
            }
            if (uci_lookup_option_string(ctx, sect, "merge") != NULL &&
                    strcmp(uci_lookup_option_string(ctx, sect, "merge"), "on") == 0){
                uci_merge = TRUE;
            }else{
                uci_merge = FALSE;
            }
            if (uci_lookup_option_string(ctx, sect, "iid") == NULL){
                uci_iid = 0;
            }else{
                uci_iid = strtol(uci_lookup_option_string(ctx, sect, "iid"),NULL,10);
            }

            site = build_lisp_site_prefix(ms,
                    uci_eid_prefix,
                    uci_iid,
                    uci_key_type,
                    uci_key,
                    uci_more_specifics,
                    uci_proxy_reply,
                    uci_merge,
                    lcaf_ht);
            if (site) {
                OOR_LOG(LDBG_1, "Adding lisp site prefix %s to the lisp-sites "
                        "database", lisp_addr_to_char(site->eid_prefix));
                ms_add_lisp_site_prefix(ms, site);
            }else{
                OOR_LOG(LERR, "Can't add lisp-site prefix %s. Discarded ...",
                        uci_eid_prefix);
            }
        }

        /* LISP REGISTERED SITES CONFIG */
        if (strcmp(sect->type, "ms-static-registered-site") == 0){
            mapping = parse_mapping(ctx,sect,&(ms->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,FALSE);
            if (mapping == NULL){
                OOR_LOG(LERR, "Can't create static register site for %s",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
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
    }

    /* destroy the hash table */
    shash_destroy(lcaf_ht);
    shash_destroy(rlocs_ht);
    shash_destroy(rloc_set_ht);
    glist_destroy(no_addr_loct_list);

    return(GOOD);
}

static mapping_t*
parse_mapping(struct uci_context *ctx, struct uci_section *sect,
        oor_ctrl_dev_t *dev, shash_t *rloc_set_ht, shash_t *lcaf_ht,
        glist_t *no_addr_loct_l, uint8_t is_local)
{
    mapping_t *map;
    locator_t *loct;
    locator_t *aux_loct;
    glist_t *addr_list;
    lisp_addr_t *eid_prefix, *ip_eid_prefix;
    char *uci_eid;
    char *uci_rloc_set;
    int uci_iid;
    glist_t *rloc_list;
    glist_entry_t *it;
    lisp_xtr_t *xtr;

    switch (dev->mode){
    case xTR_MODE:
    case MN_MODE:
        xtr  = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
        break;
    default:
        break;
    }

    uci_eid = (char *)uci_lookup_option_string(ctx, sect, "eid_prefix");

    uci_rloc_set = (char *)uci_lookup_option_string(ctx, sect, "rloc_set");
    if (uci_eid == NULL || uci_rloc_set == NULL){
        return (NULL);
    }
    /* Check if the rloc-set exists */
    rloc_list = (glist_t *)shash_lookup(rloc_set_ht,uci_rloc_set);
    if (rloc_list == NULL){
        OOR_LOG(LWRN,"Configuration file: The rloc set %s doesn't exist", uci_rloc_set);
        return (NULL);
    }
    /* Get EID prefix */
    addr_list = parse_lisp_addr(uci_eid, lcaf_ht);
    if (addr_list == NULL || glist_size(addr_list) != 1){
        return (NULL);
    }
    eid_prefix = (lisp_addr_t *)glist_first_data(addr_list);

    if (uci_lookup_option_string(ctx, sect, "iid") == NULL){
        uci_iid = 0;
    }else{
        uci_iid = strtol(uci_lookup_option_string(ctx, sect, "iid"),NULL,10);
    }
    if (uci_iid > MAX_IID || uci_iid < 0) {
        OOR_LOG(LERR, "Configuration file: Instance ID %d out of range [0..%d], "
                "disabling...",uci_iid, MAX_IID);
        uci_iid = 0;
    }
    if (uci_iid > 0){
        ip_eid_prefix = lisp_addr_clone(eid_prefix);
        eid_prefix = lisp_addr_new_init_iid(uci_iid, ip_eid_prefix, 0);
    }

    /* Create mapping */
    if ( is_local){
        map = mapping_new_init(eid_prefix);
        if (map != NULL){
            mapping_set_ttl(map, DEFAULT_DATA_CACHE_TTL);
        }
    }else{
        map = mapping_new_init(eid_prefix);
    }

    /* no need for the prefix */
    glist_destroy(addr_list);

    if (map == NULL){
        return (NULL);
    }

    /* Add the locators of the rloc-set to the mapping */
    glist_for_each_entry(it,rloc_list){
        aux_loct = (locator_t*)glist_entry_data(it);
        loct = clone_customize_locator(dev,aux_loct,no_addr_loct_l,is_local);
        if (loct == NULL){
            continue;
        }
        if (mapping_add_locator(map, loct) != GOOD){
            if (xtr != NULL && is_local){
                iface_locators_unattach_locator(xtr->iface_locators_table,loct);
            }
            locator_del(loct);
            continue;
        }

    }

    return(map);
}

static shash_t *
parse_rlocs(struct uci_context *ctx, struct uci_package *pck, shash_t *lcaf_ht,
        glist_t *no_addr_loct_l)
{
    struct uci_section *section;
    struct uci_element *element;
    shash_t *rlocs_ht;
    locator_t *locator;
    glist_t *addr_list;
    lisp_addr_t *address;
    iface_t *iface;
    char *uci_rloc_name;
    char *uci_address;
    char *uci_iface_name;
    int uci_afi;
    int uci_priority;
    int uci_weight;
    int afi;
    no_addr_loct *nloct;


    /* create lcaf hash table */
    rlocs_ht = shash_new_managed((free_key_fn_t)locator_del);

    uci_foreach_element(&pck->sections, element) {
        section = uci_to_section(element);

        if (strcmp(section->type, "rloc-address") == 0){
            uci_rloc_name = (char *)uci_lookup_option_string(ctx, section, "name");
            uci_address = (char *)uci_lookup_option_string(ctx, section, "address");
            if (uci_lookup_option_string(ctx, section, "priority") == NULL){
                OOR_LOG(LERR,"Configuration file: No priority assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_priority = strtol(uci_lookup_option_string(ctx, section, "priority"),NULL,10);
            if (uci_lookup_option_string(ctx, section, "weight") == NULL){
                OOR_LOG(LERR,"Configuration file: No weight assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_weight = strtol(uci_lookup_option_string(ctx, section, "weight"),NULL,10);

            if (validate_priority_weight(uci_priority, uci_weight) != GOOD) {
                continue;
            }
            if (shash_lookup(rlocs_ht,uci_rloc_name) != NULL){
                OOR_LOG(LDBG_1,"Configuration file: The RLOC %s is duplicated. Discarding ...", uci_rloc_name);
                continue;
            }
            addr_list = parse_lisp_addr(uci_address, lcaf_ht);
            if (addr_list == NULL || glist_size(addr_list) == 0){
                continue;
            }
            if (glist_size(addr_list) > 1){
                OOR_LOG(LDBG_1,"Configuration file: With OpenWrt, RLOCs configured with FQDN address "
                        "only use the first IP of the DNS resolution.");
            }
            address = (lisp_addr_t *)glist_first_data(addr_list);

            if (lisp_addr_lafi(address) == LM_AFI_IPPREF){
                OOR_LOG(LERR, "Configuration file: RLOC address can not be a prefix: %s ",
                        lisp_addr_to_char(address));
                continue;
            }

            /* Create a basic locator. Locaor or remote information will be added later according
             * who is using the locator*/
            locator = locator_new_init(address,UP,uci_priority,uci_weight,255,0);
            if (locator != NULL){
                shash_insert(rlocs_ht, strdup(uci_rloc_name), locator);
            }
            lisp_addr_del(address);
        }

        if (strcmp(section->type, "rloc-iface") == 0){
            uci_rloc_name = (char *)uci_lookup_option_string(ctx, section, "name");
            uci_iface_name = (char *)uci_lookup_option_string(ctx, section, "interface");
            if (uci_lookup_option_string(ctx, section, "ip_version") == NULL){
                OOR_LOG(LERR,"Configuration file: No afi assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_afi = strtol(uci_lookup_option_string(ctx, section, "ip_version"),NULL,10);
            if (uci_lookup_option_string(ctx, section, "priority") == NULL){
                OOR_LOG(LERR,"Configuration file: No priority assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_priority = strtol(uci_lookup_option_string(ctx, section, "priority"),NULL,10);
            if (uci_lookup_option_string(ctx, section, "weight") == NULL){
                OOR_LOG(LERR,"Configuration file: No weight assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_weight = strtol(uci_lookup_option_string(ctx, section, "weight"),NULL,10);

            if (validate_priority_weight(uci_priority, uci_weight) != GOOD) {
                continue;
            }

            if (uci_afi != 4 && uci_afi !=6){
                OOR_LOG(LERR, "Configuration file: The afi of the locator should be \"4\" (IPv4)"
                        " or \"6\" (IPv6)");
                return (NULL);
            }

            if (shash_lookup(rlocs_ht,uci_rloc_name) != NULL){
                OOR_LOG(LDBG_1,"Configuration file: The RLOC %s is duplicated. Discarding ...", uci_rloc_name);
                continue;
            }

            /* Find the interface */
            if (!(iface = get_interface(uci_iface_name))) {
                if (!(iface = add_interface(uci_iface_name))) {
                    return (BAD);
                }
            }

            if (uci_afi == 4){
                if (iface_address(iface, AF_INET) == NULL){
                    /* Configure address of the interface */
                    iface_setup_addr(iface, AF_INET);
                    data_plane->datap_add_iface_addr(iface,AF_INET);
                    lctrl->control_data_plane->control_dp_add_iface_addr(lctrl,iface,AF_INET);
                }
                address = iface->ipv4_address;
                afi = AF_INET;
            }else{
                if (iface_address(iface, AF_INET6) == NULL){
                    /* Configure address of the interface */
                    iface_setup_addr(iface, AF_INET6);
                    data_plane->datap_add_iface_addr(iface,AF_INET6);
                    lctrl->control_data_plane->control_dp_add_iface_addr(lctrl,iface,AF_INET6);
                }
                address = iface->ipv6_address;
                afi = AF_INET6;
            }

            /* Create a basic locator. Locaor or remote information will be added later according
             * who is using the locator*/
            locator = locator_new_init(address,UP,uci_priority,uci_weight,255,0);
            if (locator != NULL){
                shash_insert(rlocs_ht, strdup(uci_rloc_name), locator);
            }
            /* If iface is not initialized, modify addres of the aux locator indicating the IP afi.
             * This information will be used during the process of association of the cloned locator
             * with the iface */
            if (lisp_addr_is_no_addr(address)){
                nloct = no_addr_loct_new_init(locator, uci_iface_name, afi);
                glist_add(nloct,no_addr_loct_l);
            }
        }
    }

    return (rlocs_ht);
}

static shash_t *
parse_rloc_sets(struct uci_context *ctx, struct uci_package *pck, shash_t *rlocs_ht,
        shash_t *lcaf_ht)
{
    struct uci_section *section;
    struct uci_element *element;
    struct uci_element *element_loct;
    struct uci_option *opt;
    char *uci_rloc_set_name;
    shash_t *rloc_sets_ht;
    glist_t *rloc_list;
    locator_t *loct;

    /* create lcaf hash table */
    rloc_sets_ht = shash_new_managed((free_key_fn_t)glist_destroy);

    uci_foreach_element(&pck->sections, element) {
        section = uci_to_section(element);

        if (strcmp(section->type, "rloc-set") == 0){
            uci_rloc_set_name = (char *)uci_lookup_option_string(ctx, section, "name");
            if (uci_rloc_set_name == NULL){
                continue;
            }
            rloc_list = (glist_t*)shash_lookup(rloc_sets_ht,uci_rloc_set_name);
            if (rloc_list == NULL){
                rloc_list = glist_new();
                if (rloc_list != NULL){
                    shash_insert(rloc_sets_ht, strdup(uci_rloc_set_name), rloc_list);
                }else{
                    OOR_LOG(LWRN, "parse_rloc_sets: Error creating rloc list");
                    continue;
                }
            }else{
                OOR_LOG(LWRN, "Configuration file: The RLOC set %s is duplicated. Discarding... ",
                        uci_rloc_set_name);
                continue;
            }
            opt  = uci_lookup_option(ctx, section, "rloc_name");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), element_loct){
                    loct = shash_lookup(rlocs_ht, element_loct->name);
                    if (loct == NULL){
                        OOR_LOG(LWRN,"Configuration file: The RLOC name %s of the RLOC set %s doesn't exist",
                                element_loct->name, uci_rloc_set_name);
                        continue;
                    }

                    if (glist_add_tail(loct,rloc_list)!=GOOD){
                        OOR_LOG(LDBG_1,"parse_rloc_sets: Error adding locator to the rloc-set");
                    }
                }
            }else{
                OOR_LOG(LWRN, "Configuration file: The RLOC set %s has no rlocs "
                        "associated.",uci_rloc_set_name);
            }

        }
    }

    return (rloc_sets_ht);
}

static shash_t *
parse_lcafs(struct uci_context *ctx, struct uci_package *pck)
{
    struct uci_section *section;
    struct uci_element *element;
    shash_t *lcaf_ht;

    /* create lcaf hash table */
    lcaf_ht = shash_new_managed((free_key_fn_t)lisp_addr_del);

    uci_foreach_element(&pck->sections, element) {
        section = uci_to_section(element);

        if (strcmp(section->type, "elp-node") == 0){
            parse_elp_node(ctx,section,lcaf_ht);
        }
    }

    //parse_rle_list(cfg, lcaf_ht);
    //parse_mcinfo_list(cfg, lcaf_ht);

    return(lcaf_ht);
}

static int
parse_elp_node(struct uci_context *ctx, struct uci_section *section, shash_t *ht)
{
    char *uci_elp_name;
    char *uci_address;
    lisp_addr_t *laddr;
    elp_node_t *elp_node;

    uci_elp_name = (char *)uci_lookup_option_string(ctx, section, "elp_name");
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

    if (lisp_addr_ip_from_char(uci_address, elp_node->addr) != GOOD) {
        elp_node_del(elp_node);
        OOR_LOG(LDBG_1, "parse_elp_list: Couldn't parse ELP node %s",
                uci_address);
        return (BAD);
    }

    if (strcmp(uci_lookup_option_string(ctx, section, "strict"), "on") == 0){
        elp_node->S = TRUE;
    }else{
        elp_node->S = FALSE;
    }

    if (strcmp(uci_lookup_option_string(ctx, section, "probe"), "on") == 0){
        elp_node->P = TRUE;
    }else{
        elp_node->P = FALSE;
    }

    if (strcmp(uci_lookup_option_string(ctx, section, "lookup"), "on") == 0){
        elp_node->L = TRUE;
    }else{
        elp_node->L = FALSE;
    }

    elp_add_node(lcaf_elp_get_elp(lisp_addr_get_lcaf(laddr)),elp_node);
    OOR_LOG(LDBG_3,"parse_elp_node: Added %s to the ELP %s",uci_address,uci_elp_name);

    return (GOOD);
}
