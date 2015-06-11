/*
 * lispd_config_uci.c
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
 *    Albert López <alopez@ac.upc.edu>
 *
 */


#include "cmdline.h"
#include "lispd_config_functions.h"
#include "lispd_config_uci.h"
#include "lispd_external.h"
#include "iface_list.h"
#include "lisp_ctrl_device.h"
#include "lisp_xtr.h"
#include "lisp_ms.h"
#include "lisp_control.h"
#include "shash.h"
#include "hash_table.h"
#include "lmlog.h"
#include <uci.h>
#include <libgen.h>
#include <string.h>

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
        lisp_ctrl_dev_t         *dev,
        htable_t                *rloc_set_ht,
        htable_t                *lcaf_ht,
        glist_t                 *no_addr_loct_l,
        uint8_t                 type);

static htable_t *
parse_rlocs(
        struct uci_context      *ctx,
        struct uci_package      *pck,
        htable_t                *lcaf_ht,
        glist_t                 *no_addr_loct_list);

static htable_t *
parse_rloc_sets(
        struct uci_context      *ctx,
        struct uci_package      *pck,
        htable_t                *rlocs_ht,
        htable_t                *lcaf_ht);
static htable_t *
parse_lcafs(
        struct uci_context      *ctx,
        struct uci_package      *pck);

static int
parse_elp_node(
        struct uci_context      *ctx,
        struct uci_section      *section,
        htable_t                *ht);

/********************************** FUNCTIONS ********************************/

int
handle_config_file(char *uci_conf_file_path)
{
    char*               uci_conf_dir                   = NULL;
    char*               uci_conf_file                  = NULL;
    struct uci_context* ctx                            = NULL;
    struct uci_package* pck                            = NULL;
    struct uci_section* sect                           = NULL;
    struct uci_element* element                        = NULL;
    int                 uci_debug                      = 0;
    const char*         uci_op_mode                    = NULL;
    int                 res                            = 0;


    if (uci_conf_file_path == NULL){
        uci_conf_file_path = "/etc/config/lispd";
    }

    ctx = uci_alloc_context();

    if (ctx == NULL) {
        LMLOG(LCRIT, "Could not create UCI context. Exiting ...");
        exit_cleanup();
    }

    uci_conf_dir = dirname(strdup(uci_conf_file_path));
    uci_conf_file = basename(strdup(uci_conf_file_path));


    uci_set_confdir(ctx, uci_conf_dir);

    LMLOG(LDBG_1,"Conf dir: %s\n",ctx->confdir);

    uci_load(ctx,uci_conf_file,&pck);

    if (pck == NULL) {
        LMLOG(LCRIT, "Could not load conf file: %s. Exiting ...",uci_conf_file);
        uci_perror(ctx,"Error while loading packet ");
        uci_free_context(ctx);
        exit_cleanup();
    }


    LMLOG(LDBG_3,"package uci: %s\n",pck->ctx->confdir);


    uci_foreach_element(&pck->sections, element) {
        uci_debug = 0;
        uci_op_mode = NULL;

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

            uci_op_mode = uci_lookup_option_string(ctx, sect, "operating_mode");

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
                    LMLOG(LCRIT, "Configuration file: Unknown operating mode: %s",uci_op_mode);
                    return (BAD);
                }
            }
            continue;
        }
    }
    return (res);
}

int
configure_xtr(
        struct uci_context      *ctx,
        struct uci_package      *pck)
{
    struct uci_section  *sect               = NULL;
    struct uci_element  *element            = NULL;
    struct uci_element  *elem_addr          = NULL;
    struct uci_option   *opt                = NULL;
    int                 uci_retries         = 0;
    const char*         uci_address         = NULL;
    int                 uci_key_type        = 0;
    const char*         uci_key             = NULL;
    int                 uci_proxy_reply     = 0;
    int                 uci_priority        = 0;
    int                 uci_weigth          = 0;
    htable_t *          lcaf_ht             = NULL;
    htable_t *          rlocs_ht            = NULL;
    htable_t *          rloc_set_ht         = NULL;
    lisp_xtr_t *        xtr                 = NULL;
    map_local_entry_t * map_loc_e           = NULL;
    mapping_t *         mapping             = NULL;
    void *              fwd_map_inf         = NULL;
    glist_t *           no_addr_loct_list   = NULL;

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
                    if (uci_retries >= 0 && uci_retries <= LISPD_MAX_RETRANSMITS){
                        xtr->map_request_retries = uci_retries;
                    }else if (uci_retries > LISPD_MAX_RETRANSMITS){
                        xtr->map_request_retries = LISPD_MAX_RETRANSMITS;
                        LMLOG(LWRN, "Map-Request retries should be between 0 and %d. "
                                "Using default value: %d",LISPD_MAX_RETRANSMITS, LISPD_MAX_RETRANSMITS);
                    }
                }else{
                    LMLOG(LWRN,"Configuration file: Map Request Retries not specified."
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
                    LMLOG(LWRN,"Configuration file: RLOC probe interval not specified."
                            " Disabling RLOC Probing");
                    xtr->probe_interval = 0;
                    continue;
                }
                if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries") != NULL){
                    xtr->probe_retries = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries"),NULL,10);
                }else{
                    LMLOG(LWRN,"Configuration file: RLOC Probe Retries not specified."
                            " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES);
                    xtr->probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
                }
                if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval") != NULL){
                    xtr->probe_retries_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval"),NULL,10);
                }else{
                    LMLOG(LWRN,"Configuration file: RLOC Probe Retries Intervals not specified."
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
                uci_address = uci_lookup_option_string(ctx, sect, "address");

                if (add_server((char *)uci_address, xtr->map_resolvers) != GOOD){
                    LMLOG(LCRIT,"Can't add %s Map Resolver.",uci_address);
                }else{
                    LMLOG(LDBG_1, "Added %s to map-resolver list", uci_address);
                }
                continue;
            }

            /* MAP-SERVER CONFIG */
            if (strcmp(sect->type, "map-server") == 0){

                uci_address = uci_lookup_option_string(ctx, sect, "address");
                if (uci_lookup_option_string(ctx, sect, "key_type") != NULL){
                    uci_key_type = strtol(uci_lookup_option_string(ctx, sect, "key_type"),NULL,10);
                }else{
                    LMLOG(LWRN,"Configuration file: No ket type assigned to the map server \"%s\"."
                            " Set default value: HMAC_SHA_1_96",uci_address);
                    uci_key_type = HMAC_SHA_1_96;
                }

                uci_key = uci_lookup_option_string(ctx, sect, "key");

                if (strcmp(uci_lookup_option_string(ctx, sect, "proxy_reply"), "on") == 0){
                    uci_proxy_reply = TRUE;
                }else{
                    uci_proxy_reply = FALSE;
                }

                if (add_map_server(xtr->map_servers,(char *)uci_address,
                        uci_key_type,
                        (char *)uci_key,
                        uci_proxy_reply) != GOOD ){
                    LMLOG(LCRIT, "Can't add %s Map Server.", uci_address);
                }else{
                    LMLOG(LDBG_1, "Added %s to map-server list", uci_address);
                }
                continue;
            }

            /* PROXY-ETR CONFIG */

            if (strcmp(sect->type, "proxy-etr") == 0){
                uci_address = uci_lookup_option_string(ctx, sect, "address");
                if (uci_lookup_option_string(ctx, sect, "priority") != NULL){
                    uci_priority = strtol(uci_lookup_option_string(ctx, sect, "priority"),NULL,10);
                }else{
                    LMLOG(LWRN,"Configuration file: No priority assigned to the proxy-etr \"%s\"."
                            " Set default value: 10",uci_address);
                    uci_priority = 10;
                }
                if (uci_lookup_option_string(ctx, sect, "weight") != NULL){
                    uci_weigth = strtol(uci_lookup_option_string(ctx, sect, "weight"),NULL,10);
                }else{
                    LMLOG(LWRN,"Configuration file: No weight assigned to the proxy-etr \"%s\"."
                            " Set default value: 100",uci_address);
                    uci_weigth = 100;
                }

                if (add_proxy_etr_entry(xtr->petrs,
                        (char *)uci_address,
                        uci_priority,
                        uci_weigth) != GOOD ){
                    LMLOG(LERR, "Can't add proxy-etr %s", uci_address);
                }else{
                    LMLOG(LDBG_1, "Added %s to proxy-etr list", uci_address);
                }
                continue;
            }

            /* PROXY-ITR CONFIG */
            if (strcmp(sect->type, "proxy-itr") == 0){
                opt  = uci_lookup_option(ctx, sect, "address");
                if (opt != NULL){
                    uci_foreach_element(&(opt->v.list), elem_addr){
                        if (add_server(elem_addr->name, xtr->pitrs) != GOOD){
                            LMLOG(LERR, "Can't add %s to proxy-itr list. Discarded ...", uci_address);
                        }else{
                            LMLOG(LDBG_1, "Added %s to proxy-itr list", uci_address);
                        }
                    }
                }
                continue;
            }

            if (strcmp(sect->type, "database-mapping") == 0){
                mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,LOCAL_LOCATOR);
                if (mapping == NULL){
                    LMLOG(LERR, "Can't add EID prefix %s. Discarded ...",
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
                    LMLOG(LERR, "Couldn't create forward information for mapping with EID: %s. Discarding it...",
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
                mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,STATIC_LOCATOR);
                if (mapping == NULL){
                    LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                            uci_lookup_option_string(ctx, sect, "eid_prefix"));
                    continue;
                }
                if (mcache_lookup_exact(xtr->map_cache, mapping_eid(mapping)) == NULL){
                    if (tr_mcache_add_static_mapping(xtr, mapping) == GOOD){
                        LMLOG(LDBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                                lisp_addr_to_char(mapping_eid(mapping)));
                    }else{
                        LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                                mapping_eid(mapping));
                        mapping_del(mapping);
                    }
                }else{
                    LMLOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                            "Discarded ...",uci_lookup_option_string(ctx, sect, "eid_prefix"));
                    mapping_del(mapping);
                    continue;
                }
                continue;
            }
    }

    /* destroy the hash table */
    htable_destroy(lcaf_ht);
    htable_destroy(rlocs_ht);
    htable_destroy(rloc_set_ht);
    glist_destroy(no_addr_loct_list);

    return(GOOD);
}

int
configure_mn(
        struct uci_context      *ctx,
        struct uci_package      *pck)
{
    struct uci_section *sect                = NULL;
    struct uci_element *element             = NULL;
    struct uci_element *elem_addr           = NULL;
    struct uci_option * opt                 = NULL;
    int                 uci_retries         = 0;
    const char *        uci_address         = NULL;
    int                 uci_key_type        = 0;
    const char *        uci_key             = NULL;
    int                 uci_proxy_reply     = 0;
    int                 uci_priority        = 0;
    int                 uci_weigth          = 0;
    htable_t *          lcaf_ht             = NULL;
    htable_t *          rlocs_ht            = NULL;
    htable_t *          rloc_set_ht         = NULL;
    lisp_xtr_t *        xtr                 = NULL;
    map_local_entry_t * map_loc_e           = NULL;
    mapping_t *         mapping             = NULL;
    void *              fwd_map_inf         = NULL;
    glist_t *           no_addr_loct_list   = NULL;

    /* CREATE AND CONFIGURE XTR */
    if (ctrl_dev_create(MN_MODE, &ctrl_dev) != GOOD) {
        LMLOG(LCRIT, "Failed to create Mobile Node device. Aborting!");
        exit_cleanup();
    }

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

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
                if (uci_retries >= 0 && uci_retries <= LISPD_MAX_RETRANSMITS){
                    xtr->map_request_retries = uci_retries;
                }else if (uci_retries > LISPD_MAX_RETRANSMITS){
                    xtr->map_request_retries = LISPD_MAX_RETRANSMITS;
                    LMLOG(LWRN, "Map-Request retries should be between 0 and %d. "
                            "Using default value: %d",LISPD_MAX_RETRANSMITS, LISPD_MAX_RETRANSMITS);
                }
            }else{
                LMLOG(LWRN,"Configuration file: Map Request Retries not specified."
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
                LMLOG(LWRN,"Configuration file: RLOC probe interval not specified."
                        " Disabling RLOC Probing");
                xtr->probe_interval = 0;
                continue;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries") != NULL){
                xtr->probe_retries = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: RLOC Probe Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES);
                xtr->probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval") != NULL){
                xtr->probe_retries_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: RLOC Probe Retries Intervals not specified."
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
            uci_address = uci_lookup_option_string(ctx, sect, "address");

            if (add_server((char *)uci_address, xtr->map_resolvers) != GOOD){
                LMLOG(LCRIT,"Can't add %s Map Resolver.",uci_address);
            }else{
                LMLOG(LDBG_1, "Added %s to map-resolver list", uci_address);
            }
            continue;
        }

        /* MAP-SERVER CONFIG */
        if (strcmp(sect->type, "map-server") == 0){

            uci_address = uci_lookup_option_string(ctx, sect, "address");
            if (uci_lookup_option_string(ctx, sect, "key_type") != NULL){
                uci_key_type = strtol(uci_lookup_option_string(ctx, sect, "key_type"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: No ket type assigned to the map server \"%s\"."
                        " Set default value: HMAC_SHA_1_96",uci_address);
                uci_key_type = HMAC_SHA_1_96;
            }
            uci_key = uci_lookup_option_string(ctx, sect, "key");

            if (strcmp(uci_lookup_option_string(ctx, sect, "proxy_reply"), "on") == 0){
                uci_proxy_reply = TRUE;
            }else{
                uci_proxy_reply = FALSE;
            }

            if (add_map_server(xtr->map_servers,(char *)uci_address,
                    uci_key_type,
                    (char *)uci_key,
                    uci_proxy_reply) != GOOD ){
                LMLOG(LCRIT, "Can't add %s Map Server.", uci_address);
            }else{
                LMLOG(LDBG_1, "Added %s to map-server list", uci_address);
            }
            continue;
        }

        /* PROXY-ETR CONFIG */

        if (strcmp(sect->type, "proxy-etr") == 0){
            uci_address = uci_lookup_option_string(ctx, sect, "address");
            if (uci_lookup_option_string(ctx, sect, "priority") != NULL){
                uci_priority = strtol(uci_lookup_option_string(ctx, sect, "priority"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: No priority assigned to the proxy-etr \"%s\"."
                        " Set default value: 10",uci_address);
                uci_priority = 10;
            }
            if (uci_lookup_option_string(ctx, sect, "weight") != NULL){
                uci_weigth = strtol(uci_lookup_option_string(ctx, sect, "weight"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: No weight assigned to the proxy-etr \"%s\"."
                        " Set default value: 100",uci_address);
                uci_weigth = 100;
            }

            if (add_proxy_etr_entry(xtr->petrs,
                    (char *)uci_address,
                    uci_priority,
                    uci_weigth) != GOOD ){
                LMLOG(LERR, "Can't add proxy-etr %s", uci_address);
            }else{
                LMLOG(LDBG_1, "Added %s to proxy-etr list", uci_address);
            }
            continue;
        }

        /* PROXY-ITR CONFIG */
        if (strcmp(sect->type, "proxy-itr") == 0){
            opt  = uci_lookup_option(ctx, sect, "address");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), elem_addr){
                    if (add_server(elem_addr->name, xtr->pitrs) != GOOD){
                        LMLOG(LERR, "Can't add %s to proxy-itr list. Discarded ...", uci_address);
                    }else{
                        LMLOG(LDBG_1, "Added %s to proxy-itr list", uci_address);
                    }
                }
            }
            continue;
        }

        if (strcmp(sect->type, "database-mapping") == 0){
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,LOCAL_LOCATOR);
            if (mapping == NULL){
                LMLOG(LERR, "Can't add EID prefix %s. Discarded ...",
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
                LMLOG(LERR, "Couldn't create forward information for mapping with EID: %s. Discarding it...",
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
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,STATIC_LOCATOR);
            if (mapping == NULL){
                LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
            }
            if (mcache_lookup_exact(xtr->map_cache, mapping_eid(mapping)) == NULL){
                if (tr_mcache_add_static_mapping(xtr, mapping) == GOOD){
                    LMLOG(LDBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                            lisp_addr_to_char(mapping_eid(mapping)));
                }else{
                    LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                            mapping_eid(mapping));
                    mapping_del(mapping);
                }
            }else{
                LMLOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                        "Discarded ...",uci_lookup_option_string(ctx, sect, "eid_prefix"));
                mapping_del(mapping);
                continue;
            }
            continue;
        }
    }

    /* destroy the hash table */
    htable_destroy(lcaf_ht);
    htable_destroy(rlocs_ht);
    htable_destroy(rloc_set_ht);
    glist_destroy(no_addr_loct_list);

    return(GOOD);
}

int
configure_rtr(
        struct uci_context      *ctx,
        struct uci_package      *pck)
{
    lisp_xtr_t *            xtr                     = NULL;
    struct uci_section *    sect                    = NULL;
    struct uci_element *    element                 = NULL;
    htable_t *              lcaf_ht                 = NULL;
    htable_t *              rlocs_ht                = NULL;
    htable_t *              rloc_set_ht             = NULL;
    int                     uci_retries             = 0;
    const char *            uci_address             = NULL;
    int                     uci_key_type            = 0;
    const char *            uci_key                 = NULL;
    int                     uci_proxy_reply         = 0;
    const char *            uci_iface               = NULL;
    mapping_t *             mapping                 = NULL;
    int                     uci_afi                 = 0;
    int                     uci_priority            = 0;
    int                     uci_weigth              = 0;
    glist_t *               no_addr_loct_list       = NULL;


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
                if (uci_retries >= 0 && uci_retries <= LISPD_MAX_RETRANSMITS){
                    xtr->map_request_retries = uci_retries;
                }else if (uci_retries > LISPD_MAX_RETRANSMITS){
                    xtr->map_request_retries = LISPD_MAX_RETRANSMITS;
                    LMLOG(LWRN, "Map-Request retries should be between 0 and %d. "
                            "Using default value: %d",LISPD_MAX_RETRANSMITS, LISPD_MAX_RETRANSMITS);
                }
            }else{
                LMLOG(LWRN,"Configuration file: Map Request Retries not specified."
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
                LMLOG(LWRN,"Configuration file: RLOC probe interval not specified."
                        " Disabling RLOC Probing");
                xtr->probe_interval = 0;
                continue;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries") != NULL){
                xtr->probe_retries = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: RLOC Probe Retries not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES);
                xtr->probe_retries = DEFAULT_RLOC_PROBING_RETRIES;
            }
            if (uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval") != NULL){
                xtr->probe_retries_interval = strtol(uci_lookup_option_string(ctx, sect, "rloc_probe_retries_interval"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: RLOC Probe Retries Intervals not specified."
                        " Setting default value: %d sec.",DEFAULT_RLOC_PROBING_RETRIES_INTERVAL);
                xtr->probe_retries_interval = DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;
            }

            validate_rloc_probing_parameters(&xtr->probe_interval,
                    &xtr->probe_retries, &xtr->probe_retries_interval);
            continue;
        }

        /* MAP-RESOLVER CONFIG */
        if (strcmp(sect->type, "map-resolver") == 0){
            uci_address = uci_lookup_option_string(ctx, sect, "address");

            if (add_server((char *)uci_address, xtr->map_resolvers) != GOOD){
                LMLOG(LCRIT,"Can't add %s Map Resolver.",uci_address);
            }else{
                LMLOG(LDBG_1, "Added %s to map-resolver list", uci_address);
            }
            continue;
        }

        /* MAP-SERVER CONFIG */
        if (strcmp(sect->type, "map-server") == 0){

            uci_address = uci_lookup_option_string(ctx, sect, "address");
            if (uci_lookup_option_string(ctx, sect, "key_type") != NULL){
                uci_key_type = strtol(uci_lookup_option_string(ctx, sect, "key_type"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: No ket type assigned to the map server \"%s\"."
                        " Set default value: HMAC_SHA_1_96",uci_address);
                uci_key_type = HMAC_SHA_1_96;
            }
            uci_key = uci_lookup_option_string(ctx, sect, "key");

            if (strcmp(uci_lookup_option_string(ctx, sect, "proxy_reply"), "on") == 0){
                uci_proxy_reply = TRUE;
            }else{
                uci_proxy_reply = FALSE;
            }

            if (add_map_server(xtr->map_servers,(char *)uci_address,
                    uci_key_type,
                    (char *)uci_key,
                    uci_proxy_reply) != GOOD ){
                LMLOG(LCRIT, "Can't add %s Map Server.", uci_address);
            }else{
                LMLOG(LDBG_1, "Added %s to map-server list", uci_address);
            }
            continue;
        }

        /* STATIC MAP-CACHE CONFIG */
        if (strcmp(sect->type, "static-map-cache") == 0){
            mapping = parse_mapping(ctx,sect,&(xtr->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,STATIC_LOCATOR);
            if (mapping == NULL){
                LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
            }
            if (mcache_lookup_exact(xtr->map_cache, mapping_eid(mapping)) == NULL){
                if (tr_mcache_add_static_mapping(xtr, mapping) == GOOD){
                    LMLOG(LDBG_1, "Added static Map Cache entry with EID prefix %s in the database.",
                            lisp_addr_to_char(mapping_eid(mapping)));
                }else{
                    LMLOG(LERR, "Can't add static Map Cache entry with EID prefix %s. Discarded ...",
                            mapping_eid(mapping));
                    mapping_del(mapping);
                }
            }else{
                LMLOG(LERR, "Configuration file: Duplicated static Map Cache entry with EID prefix %s."
                        "Discarded ...",uci_lookup_option_string(ctx, sect, "eid_prefix"));
                mapping_del(mapping);
                continue;
            }
            continue;
        }

        /* INTERFACES CONFIG */
        if (strcmp(sect->type, "rtr-iface") == 0){
            uci_iface = uci_lookup_option_string(ctx, sect, "iface");

            if (uci_lookup_option_string(ctx, sect, "afi") != NULL){
                uci_afi = strtol(uci_lookup_option_string(ctx, sect, "afi"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: No priority assigned to the rtr-iface \"%s\"."
                        " Set default value: 10",uci_iface);
                return (BAD);
            }
            if (uci_lookup_option_string(ctx, sect, "priority") != NULL){
                uci_priority = strtol(uci_lookup_option_string(ctx, sect, "priority"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: No priority assigned to the rtr-iface \"%s\"."
                        " Set default value: 10",uci_iface);
                uci_priority = 10;
            }
            if (uci_lookup_option_string(ctx, sect, "weight") != NULL){
                uci_weigth = strtol(uci_lookup_option_string(ctx, sect, "weight"),NULL,10);
            }else{
                LMLOG(LWRN,"Configuration file: No weight assigned to the rtr-iface \"%s\"."
                        " Set default value: 100",uci_iface);
                uci_weigth = 100;
            }
            if (add_rtr_iface(xtr,
                    (char *)uci_iface,
                    uci_afi,
                    uci_priority,
                    uci_weigth) == GOOD) {
                LMLOG(LDBG_1, "Configured interface %s for RTR",uci_iface);
            } else{
                LMLOG(LERR, "Can't configure iface %s for RTR",uci_iface);
            }
        }
    }

    /* destroy the hash table */
    htable_destroy(lcaf_ht);
    htable_destroy(rlocs_ht);
    htable_destroy(rloc_set_ht);
    glist_destroy(no_addr_loct_list);

    return(GOOD);
}

int
configure_ms(
        struct uci_context      *ctx,
        struct uci_package      *pck)
{
    lisp_ms_t*              ms                  = NULL;
    struct uci_section*     sect                = NULL;
    struct uci_element*     element             = NULL;
    const char*             uci_iface           = NULL;
    const char*             uci_eid_prefix      = NULL;
    int                     uci_iid             = 0;
    int                     uci_key_type        = 0;
    const char*             uci_key             = NULL;
    uint8_t                 uci_more_specifics  = 0;
    uint8_t                 uci_proxy_reply     = 0;
    uint8_t                 uci_merge           = 0;
    mapping_t*              mapping             = NULL;
    lisp_site_prefix_t *    site                = NULL;
    htable_t *              lcaf_ht             = NULL;
    htable_t *              rlocs_ht            = NULL;
    htable_t *              rloc_set_ht         = NULL;
    glist_t *               no_addr_loct_list   = NULL;

    /* create and configure xtr */
    if (ctrl_dev_create(MS_MODE, &ctrl_dev) != GOOD) {
        LMLOG(LCRIT, "Failed to create MS. Aborting!");
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
            uci_iface = uci_lookup_option_string(ctx, sect, "control-iface");
            if (!add_interface((char *)uci_iface)) {
                return(BAD);
            }
        }

        /* LISP-SITE CONFIG */
        if (strcmp(sect->type, "lisp-site") == 0){
            uci_eid_prefix = uci_lookup_option_string(ctx, sect, "eid_prefix");
            if (uci_lookup_option_string(ctx, sect, "key_type") == NULL){
                LMLOG(LERR,"Configuration file: No key type assigned");
                return (BAD);
            }
            uci_key_type =  strtol(uci_lookup_option_string(ctx, sect, "key_type"),NULL,10);
            uci_key = uci_lookup_option_string(ctx, sect, "key");
            if (strcmp(uci_lookup_option_string(ctx, sect, "accept_more_specifics"), "on") == 0){
                uci_more_specifics = TRUE;
            }else{
                uci_more_specifics = FALSE;
            }
            if (strcmp(uci_lookup_option_string(ctx, sect, "proxy_reply"), "on") == 0){
                uci_proxy_reply = TRUE;
            }else{
                uci_proxy_reply = FALSE;
            }
            if (strcmp(uci_lookup_option_string(ctx, sect, "uci_merge"), "on") == 0){
                uci_merge = TRUE;
            }else{
                uci_merge = FALSE;
            }

            site = build_lisp_site_prefix(ms,
                    (char *)uci_eid_prefix,
                    uci_iid,
                    uci_key_type,
                    (char *)uci_key,
                    uci_more_specifics,
                    uci_proxy_reply,
                    uci_merge,
                    lcaf_ht);
            if (site) {
                LMLOG(LDBG_1, "Adding lisp site prefix %s to the lisp-sites "
                        "database", lisp_addr_to_char(site->eid_prefix));
                ms_add_lisp_site_prefix(ms, site);
            }else{
                LMLOG(LERR, "Can't add lisp-site prefix %s. Discarded ...",
                        uci_eid_prefix);
            }
        }

        /* LISP REGISTERED SITES CONFIG */
        if (strcmp(sect->type, "ms-static-registered-site") == 0){
            mapping = parse_mapping(ctx,sect,&(ms->super),rloc_set_ht,lcaf_ht,no_addr_loct_list,STATIC_LOCATOR);
            if (mapping == NULL){
                LMLOG(LERR, "Can't create static register site for %s",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                continue;
            }
            if (mdb_lookup_entry_exact(ms->reg_sites_db, mapping_eid(mapping)) == NULL){
                if (ms_add_registered_site_prefix(ms, mapping) == GOOD){
                    LMLOG(LDBG_1, "Added static registered site for %s to the registered sites list!",
                                        lisp_addr_to_char(mapping_eid(mapping)));
                }else{
                    LMLOG(LERR, "Failed to add static registered site for %s to the registered sites list!",
                            lisp_addr_to_char(mapping_eid(mapping)));
                    mapping_del(mapping);
                }
            }else{
                LMLOG(LERR, "Configuration file: Duplicated static registered site for %s. Discarded ...",
                        uci_lookup_option_string(ctx, sect, "eid_prefix"));
                mapping_del(mapping);
                continue;
            }
            continue;
        }
    }

    /* destroy the hash table */
    htable_destroy(lcaf_ht);
    htable_destroy(rlocs_ht);
    htable_destroy(rloc_set_ht);
    glist_destroy(no_addr_loct_list);

    return(GOOD);
}

static mapping_t*
parse_mapping(
        struct uci_context      *ctx,
        struct uci_section      *sect,
        lisp_ctrl_dev_t         *dev,
        htable_t                *rloc_set_ht,
        htable_t                *lcaf_ht,
        glist_t                 *no_addr_loct_l,
        uint8_t                 type)
{
    mapping_t *         map             = NULL;
    locator_t *         loct            = NULL;
    locator_t *         aux_loct        = NULL;
    glist_t *           addr_list       = NULL;
    lisp_addr_t *       eid_prefix      = NULL;
    const char *        uci_eid         = NULL;
    const char *        uci_rloc_set    = NULL;
    glist_t *           rloc_list       = NULL;
    glist_entry_t*      it              = NULL;
    lisp_xtr_t *        xtr             = NULL;

    switch (dev->mode){
    case xTR_MODE:
    case MN_MODE:
        xtr  = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);
        break;
    default:
        break;
    }

    uci_eid = uci_lookup_option_string(ctx, sect, "eid_prefix");
    uci_rloc_set = uci_lookup_option_string(ctx, sect, "rloc_set");
    if (uci_eid == NULL || uci_rloc_set == NULL){
        return (NULL);
    }
    /* Check if the rloc-set exists */
    rloc_list = (glist_t *)htable_lookup(rloc_set_ht,uci_rloc_set);
    if (rloc_list == NULL){
        LMLOG(LWRN,"Configuration file: The rloc set %s doesn't exist", uci_rloc_set);
        return (NULL);
    }
    /* Get EID prefix */
    addr_list = parse_lisp_addr((char *)uci_eid, lcaf_ht);
    if (addr_list == NULL || glist_size(addr_list) != 1){
        return (NULL);
    }
    eid_prefix = (lisp_addr_t *)glist_first_data(addr_list);

    /* Create mapping */
    if ( type == LOCAL_LOCATOR){
        map = mapping_new_init(eid_prefix);
        if (map != NULL){
            mapping_set_ttl(map, DEFAULT_MAP_REGISTER_TIMEOUT);
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
        loct = clone_customize_locator(dev,aux_loct,no_addr_loct_l,type);
        if (loct == NULL){
            continue;
        }
        if (mapping_add_locator(map, loct) != GOOD){
            if (xtr != NULL && type == LOCAL_LOCATOR){
                iface_locators_unattach_locator(xtr->iface_locators_table,loct);
            }
            locator_del(loct);
            continue;
        }

    }

    return(map);
}

static htable_t *
parse_rlocs(
        struct uci_context      *ctx,
        struct uci_package      *pck,
        htable_t                *lcaf_ht,
        glist_t                 *no_addr_loct_l)
{
    struct uci_section *section             = NULL;
    struct uci_element *element             = NULL;
    htable_t *          rlocs_ht            = NULL;
    locator_t *         locator             = NULL;
    glist_t *           addr_list           = NULL;
    lisp_addr_t *       address             = NULL;
    iface_t*            iface               = NULL;
    const char *        uci_rloc_name       = NULL;
    const char *        uci_address         = NULL;
    const char *        uci_iface_name      = NULL;
    int                 uci_afi             = AF_UNSPEC;
    int                 uci_priority        = 0;
    int                 uci_weight          = 0;
    int                 afi                 = AF_UNSPEC;
    no_addr_loct *      nloct               = NULL;


    /* create lcaf hash table */
    rlocs_ht = htable_new(g_str_hash, g_str_equal, free,
            (h_val_del_fct)locator_del);

    uci_foreach_element(&pck->sections, element) {
        section = uci_to_section(element);

        if (strcmp(section->type, "rloc-address") == 0){
            uci_rloc_name = uci_lookup_option_string(ctx, section, "name");
            uci_address = uci_lookup_option_string(ctx, section, "address");
            if (uci_lookup_option_string(ctx, section, "priority") == NULL){
                LMLOG(LERR,"Configuration file: No priority assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_priority = strtol(uci_lookup_option_string(ctx, section, "priority"),NULL,10);
            if (uci_lookup_option_string(ctx, section, "weight") == NULL){
                LMLOG(LERR,"Configuration file: No weight assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_weight = strtol(uci_lookup_option_string(ctx, section, "weight"),NULL,10);

            if (validate_priority_weight(uci_priority, uci_weight) != GOOD) {
                continue;
            }
            if (htable_lookup(rlocs_ht,uci_rloc_name) != NULL){
                LMLOG(LDBG_1,"Configuration file: The RLOC %s is duplicated. Discarding ...", uci_rloc_name);
                continue;
            }
            addr_list = parse_lisp_addr((char *)uci_address, lcaf_ht);
            if (addr_list == NULL || glist_size(addr_list) == 0){
                continue;
            }
            if (glist_size(addr_list) > 1){
                LMLOG(LDBG_1,"Configuration file: With OpenWrt, RLOCs configured with FQDN address "
                        "only use the first IP of the DNS resolution.");
            }
            address = (lisp_addr_t *)glist_first_data(addr_list);

            if (lisp_addr_lafi(address) == LM_AFI_IPPREF){
                LMLOG(LERR, "Configuration file: RLOC address can not be a prefix: %s ",
                        lisp_addr_to_char(address));
                continue;
            }

            /* Create a basic locator. Locaor or remote information will be added later according
             * who is using the locator*/
            locator = locator_init(address,UP,uci_priority,uci_weight,255,0,STATIC_LOCATOR);
            if (locator != NULL){
                htable_insert(rlocs_ht, strdup(uci_rloc_name), locator);
            }
            lisp_addr_del(address);
        }

        if (strcmp(section->type, "rloc-iface") == 0){
            uci_rloc_name = uci_lookup_option_string(ctx, section, "name");
            uci_iface_name = uci_lookup_option_string(ctx, section, "interface");
            if (uci_lookup_option_string(ctx, section, "afi") == NULL){
                LMLOG(LERR,"Configuration file: No afi assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_afi = strtol(uci_lookup_option_string(ctx, section, "afi"),NULL,10);
            if (uci_lookup_option_string(ctx, section, "priority") == NULL){
                LMLOG(LERR,"Configuration file: No priority assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_priority = strtol(uci_lookup_option_string(ctx, section, "priority"),NULL,10);
            if (uci_lookup_option_string(ctx, section, "weight") == NULL){
                LMLOG(LERR,"Configuration file: No weight assigned to the rloc \"%s\"",uci_rloc_name);
                return (BAD);
            }
            uci_weight = strtol(uci_lookup_option_string(ctx, section, "weight"),NULL,10);

            if (validate_priority_weight(uci_priority, uci_weight) != GOOD) {
                continue;
            }

            if (uci_afi != 4 && uci_afi !=6){
                LMLOG(LERR, "Configuration file: The afi of the locator should be \"4\" (IPv4)"
                        " or \"6\" (IPv6)");
                return (NULL);
            }

            if (htable_lookup(rlocs_ht,uci_rloc_name) != NULL){
                LMLOG(LDBG_1,"Configuration file: The RLOC %s is duplicated. Discarding ...", uci_rloc_name);
                continue;
            }

            /* Find the interface */
            if (!(iface = get_interface((char *)uci_iface_name))) {
                if (!(iface = add_interface((char *)uci_iface_name))) {
                    return (BAD);
                }
            }

            if (uci_afi == 4){
                address = iface->ipv4_address;
                afi = AF_INET;
            }else{
                address = iface->ipv6_address;
                afi = AF_INET6;
            }

            /* Create a basic locator. Locaor or remote information will be added later according
             * who is using the locator*/
            locator = locator_init(address,UP,uci_priority,uci_weight,255,0,STATIC_LOCATOR);
            if (locator != NULL){
                htable_insert(rlocs_ht, strdup(uci_rloc_name), locator);
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

static htable_t *
parse_rloc_sets(
        struct uci_context      *ctx,
        struct uci_package      *pck,
        htable_t                *rlocs_ht,
        htable_t                *lcaf_ht)
{
    struct uci_section *    section            = NULL;
    struct uci_element *    element            = NULL;
    struct uci_element *    element_loct       = NULL;
    struct uci_option *     opt                = NULL;
    const char *            uci_rloc_set_name  = NULL;

    htable_t *              rloc_sets_ht       = NULL;
    glist_t *               rloc_list          = NULL;
    locator_t *             loct               = NULL;



    /* create lcaf hash table */
    rloc_sets_ht = htable_new(g_str_hash, g_str_equal, free,
            (h_val_del_fct)glist_destroy);

    uci_foreach_element(&pck->sections, element) {
        section = uci_to_section(element);

        if (strcmp(section->type, "rloc-set") == 0){
            uci_rloc_set_name = uci_lookup_option_string(ctx, section, "name");
            if (uci_rloc_set_name == NULL){
                continue;
            }
            rloc_list = (glist_t*)htable_lookup(rloc_sets_ht,uci_rloc_set_name);
            if (rloc_list == NULL){
                rloc_list = glist_new();
                if (rloc_list != NULL){
                    htable_insert(rloc_sets_ht, strdup(uci_rloc_set_name), rloc_list);
                }else{
                    LMLOG(LWRN, "parse_rloc_sets: Error creating rloc list");
                    continue;
                }
            }else{
                LMLOG(LWRN, "Configuration file: The RLOC set %s is duplicated. Discarding... ",
                        uci_rloc_set_name);
                continue;
            }
            opt  = uci_lookup_option(ctx, section, "rloc_name");
            if (opt != NULL){
                uci_foreach_element(&(opt->v.list), element_loct){
                    loct = htable_lookup(rlocs_ht, element_loct->name);
                    if (loct == NULL){
                        LMLOG(LWRN,"Configuration file: The RLOC name %s of the RLOC set %s doesn't exist",
                                element_loct->name, uci_rloc_set_name);
                        continue;
                    }

                    if (glist_add_tail(loct,rloc_list)!=GOOD){
                        LMLOG(LDBG_1,"parse_rloc_sets: Error adding locator to the rloc-set");
                    }
                }
            }else{
                LMLOG(LWRN, "Configuration file: The RLOC set %s has no rlocs "
                        "associated.",uci_rloc_set_name);
            }

        }
    }

    return (rloc_sets_ht);
}

static htable_t *
parse_lcafs(
        struct uci_context      *ctx,
        struct uci_package      *pck)
{
    struct uci_section  *section          = NULL;
    struct uci_element  *element          = NULL;
    htable_t            *lcaf_ht          = NULL;

    /* create lcaf hash table */
    lcaf_ht = htable_new(g_str_hash, g_str_equal, free,
            (h_val_del_fct)lisp_addr_del);

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
parse_elp_node(
        struct uci_context      *ctx,
        struct uci_section      *section,
        htable_t                *ht)
{
    const char *    uci_elp_name    = NULL;
    const char *    uci_address     = NULL;
    lisp_addr_t *   laddr           = NULL;
    elp_node_t *    elp_node        = NULL;


    uci_elp_name = uci_lookup_option_string(ctx, section, "elp_name");
    laddr = (lisp_addr_t *)htable_lookup(ht, uci_elp_name);

    if (laddr == NULL){
        laddr = lisp_addr_elp_new();
        if (laddr == NULL){
            LMLOG(LWRN,"parse_elp_node: Couldn't create ELP address");
            return (BAD);
        }
        htable_insert(ht, strdup(uci_elp_name), laddr);
    }else {
        if (lisp_addr_is_elp(laddr) == FALSE){
            LMLOG(LWRN,"Configuration file: Address %s composed of LCAF addresses of different type",
                    uci_elp_name);
            return (BAD);
        }
    }

    elp_node = xzalloc(sizeof(elp_node_t));
    elp_node->addr = lisp_addr_new();

    uci_address = uci_lookup_option_string(ctx, section, "address");

    if (lisp_addr_ip_from_char((char *)uci_address, elp_node->addr) != GOOD) {
        elp_node_del(elp_node);
        LMLOG(LDBG_1, "parse_elp_list: Couldn't parse ELP node %s",
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

    return (GOOD);
}
