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

#include <unistd.h>
#include "../lib/iface_locators.h"
#include "../lib/sockets.h"
#include "../lib/mem_util.h"
#include "../lib/oor_log.h"
#include "../lib/timers_utils.h"
#include "../lib/util.h"
#include "lisp_xtr.h"


typedef struct _timer_map_reg_argument {
    map_local_entry_t  *mle;
    map_server_elt     *ms;
} timer_map_reg_argument;

typedef struct _timer_encap_map_reg_argument {
    map_local_entry_t  *mle;
    map_server_elt     *ms;
    locator_t          *src_loct;
    lisp_addr_t        *rtr_rloc;
} timer_encap_map_reg_argument;

typedef struct _timer_inf_req_argument {
    map_local_entry_t *mle;
    locator_t *loct;
    map_server_elt *ms;
}timer_inf_req_argument;


static oor_ctrl_dev_t *xtr_ctrl_alloc();
static int xtr_ctrl_construct(oor_ctrl_dev_t *dev);
static void xtr_ctrl_dealloc(oor_ctrl_dev_t *dev);
static void xtr_ctrl_destruct(oor_ctrl_dev_t *dev);
static void xtr_run(oor_ctrl_dev_t *dev);
static int xtr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc);
static int xtr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t status);
int xtr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status);
int xtr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway);
static fwd_info_t * xtr_get_forwarding_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple);
/*************************** PROCESS MESSAGES ********************************/
static int xtr_recv_enc_ctrl_msg(lisp_xtr_t *xtr, lbuf_t *msg, void **ecm_hdr, uconn_t *int_uc);
static int xtr_recv_map_request(lisp_xtr_t *xtr, lbuf_t *buf,  void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc);
static inline int xtr_recv_map_reply(lisp_xtr_t *xtr, lbuf_t *buf, uconn_t *uc);
static int xtr_recv_map_notify(lisp_xtr_t *xtr, lbuf_t *buf);
static int xtr_recv_info_nat(lisp_xtr_t *xtr, lbuf_t *buf, uconn_t *uc);
static int xtr_build_and_send_map_reg(lisp_xtr_t * xtr, mapping_t * m, map_server_elt *ms,
        uint64_t nonce);
static int xtr_build_and_send_encap_map_reg(lisp_xtr_t * xtr, mapping_t * m, map_server_elt *ms,
        lisp_addr_t *etr_addr, lisp_addr_t *rtr_addr, uint64_t nonce);
static int xtr_build_and_send_smr_mreq(lisp_xtr_t *xtr, mapping_t *smap,
        lisp_addr_t *deid, lisp_addr_t *drloc);
static int xtr_build_and_send_info_req(lisp_xtr_t * xtr, mapping_t * m, locator_t *loct,
        map_server_elt *ms, uint64_t nonce);
/**************************** LOGICAL PROCESSES ******************************/
/****************************** Map Register *********************************/
static int xtr_program_map_register_for_mapping(lisp_xtr_t *xtr, map_local_entry_t *mle);
static int xtr_map_register_cb(oor_timer_t *timer);
/****************************** Encap Map Register ***************************/
static int xtr_encap_map_register_cb(oor_timer_t *timer);
static int xtr_program_encap_map_reg_of_loct_for_map(lisp_xtr_t *xtr, map_local_entry_t *mle,
        locator_t *src_loct);
/*********************************** SMR *************************************/
static void xtr_smr_process_start(lisp_xtr_t *xtr);
static int xtr_smr_notify_mcache_entry(lisp_xtr_t  *xtr, mapping_t *src_map,
        mapping_t *dst_map);
static int xtr_smr_process_start_cb(oor_timer_t *timer);
static int xtr_program_smr(lisp_xtr_t *xtr, int time);
static glist_t * xtr_get_map_local_entry_to_smr(lisp_xtr_t *xtr);
/****************************** Info Request *********************************/
static int xtr_program_initial_info_request_process(lisp_xtr_t *xtr);
static int xtr_program_info_req_per_loct(lisp_xtr_t *xtr, map_local_entry_t *mle, locator_t *loct);
static int xtr_info_request_cb(oor_timer_t *timer);
/**************************** AUXILIAR FUNCTIONS *****************************/
static int xtr_iface_event_signaling(lisp_xtr_t * xtr, iface_locators * if_loct);
/****************************** NAT traversal ********************************/
static int xtr_update_nat_info(lisp_xtr_t *xtr, map_local_entry_t *mle, locator_t *loct,
        glist_t *rtr_list);
static void xtr_update_rtrs_caches(lisp_xtr_t *xtr);
static void xtr_update_rtrs_cache_afi(lisp_xtr_t *xtr, int afi);
static glist_t * nat_select_rtrs(glist_t * rtr_list);
/*****************************************************************************/
static map_local_entry_t * get_map_loc_ent_containing_loct_ptr(local_map_db_t *local_db, locator_t *locator);
/******************************* TIMERS **************************************/
static timer_map_reg_argument * timer_map_reg_argument_new_init(map_local_entry_t *mle,
        map_server_elt *ms);
static void timer_map_reg_arg_free(timer_map_reg_argument * timer_arg);
static timer_encap_map_reg_argument * timer_encap_map_reg_argument_new_init(map_local_entry_t *mle,
        map_server_elt *ms, locator_t *src_loct, lisp_addr_t *rtr_addr);
static void timer_encap_map_reg_arg_free(timer_encap_map_reg_argument * timer_arg);
static void timer_encap_map_reg_stop_using_locator(map_local_entry_t *mle, locator_t *loct);
static timer_inf_req_argument * timer_inf_req_argument_new_init(map_local_entry_t *mle, locator_t *loct,
        map_server_elt *ms);
static void timer_inf_req_arg_free(timer_inf_req_argument * timer_arg);
static void timer_inf_req_stop_using_locator(map_local_entry_t *mle, locator_t *loct);



/* implementation of ctrl base functions */
ctrl_dev_class_t xtr_ctrl_class = {
        .alloc = xtr_ctrl_alloc,
        .construct = xtr_ctrl_construct,
        .dealloc = xtr_ctrl_dealloc,
        .destruct = xtr_ctrl_destruct,
        .run = xtr_run,
        .recv_msg = xtr_recv_msg,
        .if_link_update = xtr_if_link_update,
        .if_addr_update = xtr_if_addr_update,
        .route_update = xtr_route_update,
        .get_fwd_entry = xtr_get_forwarding_entry
};


static oor_ctrl_dev_t *
xtr_ctrl_alloc()
{
    lisp_xtr_t *xtr;
    xtr = xzalloc(sizeof(lisp_xtr_t));
    return(&xtr->super);
}

static int
xtr_ctrl_construct(oor_ctrl_dev_t *dev)
{
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    lisp_addr_t addr;
    mapping_t *pxtr_4_map, *pxtr_6_map;
    mcache_entry_t *def_ipv4_mc, *def_ipv6_mc;


    lisp_tr_init(&xtr->tr);

    /* set up databases */
    xtr->local_mdb = local_map_db_new();
    xtr->map_servers = glist_new_managed((glist_del_fct)map_server_elt_del);
    xtr->pitrs = glist_new_managed((glist_del_fct)lisp_addr_del);
    def_ipv4_mc = mcache_entry_new();
    def_ipv6_mc = mcache_entry_new();

    if (!xtr->local_mdb || !xtr->map_servers || !xtr->pitrs ||
            !def_ipv4_mc || !def_ipv6_mc) {
        return(BAD);
    }

    /* Add entries used to add the PeTR or RTRs in case of NAT */

    lisp_addr_ippref_from_char(FULL_IPv4_ADDRESS_SPACE, &addr);
    pxtr_4_map = mapping_new_init(&addr);
    mapping_set_action(pxtr_4_map,ACT_NATIVE_FWD);
    mcache_entry_init_static(def_ipv4_mc, pxtr_4_map);
    mcache_add_entry(xtr->tr.map_cache,mcache_entry_eid(def_ipv4_mc),def_ipv4_mc);

    lisp_addr_ippref_from_char(FULL_IPv6_ADDRESS_SPACE, &addr);
    pxtr_6_map = mapping_new_init(&addr);
    mapping_set_action(pxtr_6_map,ACT_NATIVE_FWD);
    mcache_entry_init_static(def_ipv6_mc, pxtr_6_map);
    mcache_add_entry(xtr->tr.map_cache,mcache_entry_eid(def_ipv6_mc),def_ipv6_mc);

    OOR_LOG(LDBG_1, "Finished constructing xTR");

    return(GOOD);
}

static void
xtr_ctrl_dealloc(oor_ctrl_dev_t *dev) {
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    free(xtr);
    OOR_LOG(LDBG_1, "Freed xTR ...");
}

static void
xtr_ctrl_destruct(oor_ctrl_dev_t *dev)
{
    map_local_entry_t * map_loc_e;
    void *it;
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    lisp_tr_uninit(&xtr->tr);

    local_map_db_foreach_entry(xtr->local_mdb, it) {
        map_loc_e = (map_local_entry_t *)it;
        ctrl_unregister_mapping_dp(dev,map_local_entry_mapping(map_loc_e));
    } local_map_db_foreach_end;

    local_map_db_del(xtr->local_mdb);

    glist_destroy(xtr->pitrs);
    glist_destroy(xtr->map_servers);
    oor_timer_stop(xtr->smr_timer);
    OOR_LOG(LDBG_1,"xTR device destroyed");
}

static void
xtr_run(oor_ctrl_dev_t *dev)
{
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    map_local_entry_t *map_loc_e;
    mcache_entry_t *ipv4_petrs_mc,*ipv6_petrs_mc;
    locator_t *loct;
    void *it;
    int num_eids = 0;



    if (xtr->super.mode == MN_MODE){
        OOR_LOG(LDBG_1, "\nStarting xTR MN ...\n");
    }
    if (xtr->super.mode == xTR_MODE){
        OOR_LOG(LDBG_1, "\nStarting xTR ...\n");
    }

    if (glist_size(xtr->map_servers) == 0) {
        OOR_LOG(LWRN, "**** NO MAP SERVER CONFIGURED. Your EID will not be registered in the Mapping System.");
        oor_timer_sleep(2);
    }

    if (glist_size(xtr->tr.map_resolvers) == 0) {
        OOR_LOG(LCRIT, "**** NO MAP RESOLVER CONFIGURED. You can not request mappings from the mapping system");
        oor_timer_sleep(2);
    }

    ipv4_petrs_mc = get_proxy_etrs_for_afi(&xtr->tr, AF_INET);
    ipv6_petrs_mc = get_proxy_etrs_for_afi(&xtr->tr, AF_INET6);;
    if (mcache_has_locators(ipv4_petrs_mc) == FALSE && mcache_has_locators(ipv6_petrs_mc) == FALSE) {
        OOR_LOG(LWRN, "No Proxy-ETR defined. Packets to non-LISP destinations "
                "will be forwarded natively (no LISP encapsulation). This "
                "may prevent mobility in some scenarios.");
        oor_timer_sleep(2);
    } else {
        xtr->tr.fwd_policy->updated_map_cache_inf(xtr->tr.fwd_policy_dev_parm,ipv4_petrs_mc);
        notify_datap_rm_fwd_from_entry(&(xtr->super),mcache_entry_eid(ipv4_petrs_mc),FALSE);
        xtr->tr.fwd_policy->updated_map_cache_inf(xtr->tr.fwd_policy_dev_parm,ipv6_petrs_mc);
        notify_datap_rm_fwd_from_entry(&(xtr->super),mcache_entry_eid(ipv6_petrs_mc),FALSE);
    }

    /* Check configured parameters when NAT-T activated. */
    if (xtr->nat_aware == TRUE) {
        if (glist_size(xtr->map_servers) > 1) {
            OOR_LOG(LERR, "NAT aware on -> This version of OOR is limited to one Map Server.");
            exit_cleanup();
        }

        if (glist_size(xtr->map_servers) == 1 &&
                lisp_addr_ip_afi(((map_server_elt *)glist_first_data(xtr->map_servers))->address) != AF_INET) {
            OOR_LOG(LERR, "NAT aware on -> This version of OOR is limited to IPv4 Map Server.");
            exit_cleanup();
        }

        if (glist_size(xtr->tr.map_resolvers) > 0) {
            OOR_LOG(LINF, "NAT aware on -> No Map Resolver will be used.");
            glist_remove_all(xtr->tr.map_resolvers);
        }
        if (xtr->tr.probe_interval > 0) {
            xtr->tr.probe_interval = 0;
            OOR_LOG(LINF, "NAT aware on -> disabling RLOC probing");
        }
        /* Set local locators to unreachable*/
        local_map_db_foreach_entry(xtr->local_mdb, it) {
            map_loc_e = (map_local_entry_t *)it;
            num_eids++;
            if (num_eids > 1){
                OOR_LOG(LERR, "NAT aware on -> Only one EID prefix supported.");
                exit_cleanup();
            }
            mapping_foreach_locator(map_local_entry_mapping(map_loc_e),loct){
                locator_set_R_bit(loct,0);
                /* We don't support LCAF in NAT */
                if (lisp_addr_lafi(locator_addr(loct)) == LM_AFI_LCAF){
                    OOR_LOG(LERR, "NAT aware on -> This version of OOR doesn't support LCAF when NAT is enabled.");
                    exit_cleanup();
                }
            }mapping_foreach_locator_end;
            OOR_LOG(LERR, "NAT aware on -> Removing PETRs");
            /* Remove PeTR. The locators will be used for RTRs */
            mapping_remove_locators(mcache_entry_mapping(ipv4_petrs_mc));
            mapping_remove_locators(mcache_entry_mapping(ipv6_petrs_mc));
        } local_map_db_foreach_end;
    }

    if (xtr->super.mode == MN_MODE){
        /* Check number of EID prefixes */

        if (local_map_db_num_ip_eids(xtr->local_mdb, AF_INET) > 1) {
            OOR_LOG(LERR, "OOR in mobile node mode only supports one IPv4 EID "
                    "prefix and one IPv6 EID prefix");
            exit_cleanup();
        }
        if (local_map_db_num_ip_eids(xtr->local_mdb, AF_INET6) > 1) {
            OOR_LOG(LERR, "OOR in mobile node mode only supports one IPv4 EID "
                    "prefix and one IPv6 EID prefix");
            exit_cleanup();
        }
    }

    OOR_LOG(LDBG_1, "\n");
    OOR_LOG(LDBG_1, "    ****** Summary of the xTR configuration ******\n");
    local_map_db_dump(xtr->local_mdb, LDBG_1);
    mcache_dump_db(xtr->tr.map_cache, LDBG_1);

    map_servers_dump(xtr, LDBG_1);
    OOR_LOG(LDBG_1, "************* %13s ***************", "Map Resolvers");
    glist_dump(xtr->tr.map_resolvers, (glist_to_char_fct)lisp_addr_to_char, LDBG_1);
    OOR_LOG(LDBG_1, "*******************************************\n");

    proxy_etrs_dump(xtr, LDBG_1);

    OOR_LOG(LDBG_1, "************* %13s ***************", "Proxy-ITRs");
    glist_dump(xtr->pitrs, (glist_to_char_fct)lisp_addr_to_char, LDBG_1);
    OOR_LOG(LDBG_1, "*******************************************\n");

    local_map_db_foreach_entry(xtr->local_mdb, it) {
        /* Register EID prefix to control */
        map_loc_e = (map_local_entry_t *)it;

        if (ctrl_register_mapping_dp(&(xtr->super),map_local_entry_mapping(map_loc_e))!=GOOD){
            OOR_LOG(LERR, "Couldn't register the mapping %s in the data plane",
                    lisp_addr_to_char(map_local_entry_eid(map_loc_e)));
            exit_cleanup();
        }
        /* Update forwarding info of the local mappings. When it is created during conf file process,
         * the local rlocs are not set. For this reason should be calculated again. It can not be removed
         * from the conf file process -> In future could appear fwd_map_info parameters*/
        xtr->tr.fwd_policy->updated_map_loc_inf(xtr->tr.fwd_policy_dev_parm,map_loc_e);

    } local_map_db_foreach_end;


    if (xtr->nat_aware){
        xtr_program_initial_info_request_process(xtr);
    }else{
        /*  Register to the Map-Server(s) */
        xtr_program_map_register(xtr);
        /* SMR proxy-ITRs list to be updated with new mappings */
        xtr_program_smr(xtr, 1);
    }

    /* RLOC Probing proxy ETRs */
    tr_program_mce_rloc_probing(&xtr->tr, ipv4_petrs_mc);
    tr_program_mce_rloc_probing(&xtr->tr, ipv6_petrs_mc);
}


static int
xtr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc)
{
    int ret = 0;
    lisp_msg_type_e type;
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    void *ecm_hdr = NULL;
    uconn_t *int_uc, *ext_uc = NULL, aux_uc;

    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (xtr_recv_enc_ctrl_msg(xtr, msg, &ecm_hdr, &aux_uc)!=GOOD){
            return (BAD);
        }
        type = lisp_msg_type(msg);
        ext_uc = uc;
        int_uc = &aux_uc;
        OOR_LOG(LDBG_1, "xTR: Received Encapsulated %s", lisp_msg_hdr_to_char(msg));
    }else{
        int_uc = uc;
    }

    switch (type) {
    case LISP_MAP_REQUEST:
        ret = xtr_recv_map_request(xtr, msg, ecm_hdr, int_uc, ext_uc);
        break;
    case LISP_MAP_REPLY:
        ret = xtr_recv_map_reply(xtr, msg, int_uc);
        break;
    case LISP_MAP_REGISTER:
        break;
    case LISP_MAP_NOTIFY:
        ret = xtr_recv_map_notify(xtr, msg);
        break;
    case LISP_INFO_NAT:
        ret = xtr_recv_info_nat(xtr, msg, int_uc);
        break;
    default:
        OOR_LOG(LDBG_1, "xTR: Unidentified type (%d) control message received",
                type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        OOR_LOG(LDBG_1,"xTR: Failed to process LISP control message");
        return (BAD);
    } else {
        OOR_LOG(LDBG_3, "xTR: Completed processing of LISP control message");
        return (ret);
    }
}

static int
xtr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t status)
{
    lisp_xtr_t * xtr = lisp_xtr_cast(dev);
    iface_locators * if_loct = NULL;
    locator_t * locator = NULL;
    map_local_entry_t * map_loc_e = NULL;
    glist_entry_t * it = NULL;
    glist_entry_t * it_m = NULL;

    if_loct = (iface_locators *)shash_lookup(xtr->tr.iface_locators_table,iface_name);
    if (if_loct  == NULL){
        OOR_LOG(LDBG_2, "xtr_if_status_change: Iface %s not found in the list of ifaces for xTR device",
                iface_name);
        return (BAD);
    }
    /* Change the status of the affected locators */
    glist_for_each_entry(it,if_loct->ipv4_locators){
        locator = (locator_t *)glist_entry_data(it);
        locator_set_state(locator,status);
    }
    glist_for_each_entry(it,if_loct->ipv6_locators){
        locator = (locator_t *)glist_entry_data(it);
        locator_set_state(locator,status);
    }
    /* Transition check */
    if (if_loct->status_changed == TRUE){
        if_loct->status_changed = FALSE;
    }else{
        if_loct->status_changed = TRUE;
    }
    /* Recalculate forwarding info of the affected mappings */
    glist_for_each_entry(it_m, if_loct->map_loc_entries){
        map_loc_e = (map_local_entry_t *)glist_entry_data(it_m);
        xtr->tr.fwd_policy->updated_map_loc_inf(xtr->tr.fwd_policy_dev_parm,map_loc_e);
        notify_datap_rm_fwd_from_entry(&(xtr->super),map_local_entry_eid(map_loc_e),TRUE);
    }

    xtr_iface_event_signaling(xtr, if_loct);

    return (GOOD);
}

int
xtr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status)
{
    lisp_xtr_t * xtr = lisp_xtr_cast(dev);
    iface_locators * if_loct = NULL;
    glist_t * loct_list = NULL;
    glist_t * locators = NULL;
    locator_t * locator = NULL;
    map_local_entry_t * map_loc_e = NULL;
    mapping_t * mapping = NULL;
    int afi = AF_UNSPEC;
    glist_entry_t * it = NULL;
    glist_entry_t * it_aux = NULL;
    glist_entry_t * it_m = NULL;
    lisp_addr_t ** prev_addr = NULL;

    if_loct = (iface_locators *)shash_lookup(xtr->tr.iface_locators_table,iface_name);
    if (if_loct  == NULL){
        OOR_LOG(LDBG_2, "xtr_if_addr_update: Iface %s not found in the list of ifaces for xTR device",
                iface_name);
        return (BAD);
    }

    if (lisp_addr_cmp(old_addr, new_addr) == 0){
        return (GOOD);
    }

    /*Check if the address has been removed*/
    if (lisp_addr_is_no_addr(new_addr)){
        /* Process removed address */
        if (lisp_addr_lafi(old_addr) == AF_INET){
            locators = if_loct->ipv4_locators;
            prev_addr = &(if_loct->ipv4_prev_addr);
        }else{
            locators = if_loct->ipv6_locators;
            prev_addr = &(if_loct->ipv6_prev_addr);
        }
        glist_for_each_entry_safe(it,it_aux,locators){
            locator = (locator_t *)glist_entry_data(it);
            if (!lisp_addr_is_ip(locator_addr(locator))){
                OOR_LOG(LERR,"OOR doesn't support change of non IP locator!!!");
            }
            map_loc_e = get_map_loc_ent_containing_loct_ptr(xtr->local_mdb,locator);
            if(map_loc_e == NULL){
                continue;
            }
            mapping = map_local_entry_mapping(map_loc_e);
            mapping_desactivate_locator(mapping,locator);
            /* Recalculate forwarding info of the mappings with activated locators */
            xtr->tr.fwd_policy->updated_map_loc_inf(xtr->tr.fwd_policy_dev_parm,map_loc_e);
            notify_datap_rm_fwd_from_entry(&(xtr->super),map_local_entry_eid(map_loc_e),TRUE);
        }

        /* prev_addr is the previous address before starting the transition process */
        if (*prev_addr == NULL){
            *prev_addr = lisp_addr_clone(old_addr);
        }

        goto done;
    }
    /* Process new address */
    afi = lisp_addr_lafi(new_addr) == LM_AFI_IP ? lisp_addr_ip_afi(new_addr)  : AF_UNSPEC;
    switch(afi){
    case AF_INET:
        locators = if_loct->ipv4_locators;
        prev_addr = &(if_loct->ipv4_prev_addr);
        break;
    case AF_INET6:
        locators = if_loct->ipv6_locators;
        prev_addr = &(if_loct->ipv6_prev_addr);
        break;
    default:
        OOR_LOG(LDBG_2, "xtr_if_addr_update: AFI of the new address not known");
        return (BAD);
    }
    /* Update the address of the affected locators */
    glist_for_each_entry_safe(it,it_aux,locators){
        locator = (locator_t *)glist_entry_data(it);
        /* The locator was not active during init process */
        if (lisp_addr_is_no_addr(locator_addr(locator))==TRUE){

            /* If locator was not active, activate it */
            map_loc_e = get_map_loc_ent_containing_loct_ptr(xtr->local_mdb,locator);
            if(map_loc_e == NULL){
                continue;
            }
            /* Check if exists an active locator with the same address.
             * If it exists, remove not activated locator: Duplicated */
            mapping = map_local_entry_mapping(map_loc_e);
            if (mapping_get_loct_with_addr(mapping,new_addr) != NULL){
                OOR_LOG(LDBG_2, "xtr_if_addr_change: A non active locator is duplicated. Removing it");
                loct_list = mapping_get_loct_lst_with_afi(mapping,LM_AFI_NO_ADDR,0);
                iface_locators_unattach_locator(xtr->tr.iface_locators_table,locator);
                glist_remove_obj_with_ptr(locator,loct_list);
                continue;
            }
            /* Activate locator */
            mapping_activate_locator(mapping,locator,new_addr);
            /* Recalculate forwarding info of the mappings with activated locators */
            xtr->tr.fwd_policy->updated_map_loc_inf(xtr->tr.fwd_policy_dev_parm,map_loc_e);
            notify_datap_rm_fwd_from_entry(&(xtr->super),map_local_entry_eid(map_loc_e),TRUE);
        }else{
            if (!lisp_addr_is_ip(locator_addr(locator))){
                OOR_LOG(LERR,"OOR doesn't support change of non IP locator!!!");
            }
            locator_clone_addr(locator,new_addr);
        }

    }
    /* Transition check */
    /* prev_addr is the previous address before starting the transition process */
    if (*prev_addr != NULL){
        if (lisp_addr_cmp(*prev_addr, new_addr) == 0){
            lisp_addr_del(*prev_addr);
            *prev_addr = NULL;
        }
    }else{
        if (old_addr != NULL){
            *prev_addr = lisp_addr_clone(old_addr);
        }else{
            *prev_addr = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
        }
    }
    /* Reorder locators */
    glist_for_each_entry(it_m, if_loct->map_loc_entries){
        map_loc_e = (map_local_entry_t *)glist_entry_data(it_m);
        mapping = map_local_entry_mapping(map_loc_e);
        mapping_sort_locators(mapping, new_addr);
    }

done:
    xtr_iface_event_signaling(xtr, if_loct);

    return (GOOD);
}

int
xtr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    lisp_xtr_t * xtr = lisp_xtr_cast(dev);
    iface_locators * if_loct = NULL;

    if_loct = (iface_locators *)shash_lookup(xtr->tr.iface_locators_table,iface_name);
    xtr_iface_event_signaling(xtr, if_loct);
    return (GOOD);
}

static fwd_info_t *
xtr_get_forwarding_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    lisp_xtr_t *xtr = lisp_xtr_cast(dev);
    fwd_info_t  *fwd_info;
    mcache_entry_t *mce = NULL, *mce_petrs = NULL;
    map_local_entry_t *map_loc_e = NULL;
    lisp_addr_t *eid, *simple_eid;
    lisp_addr_t *src_eid, *dst_eid;
    int iidmlen;
    uint8_t native_fwd = FALSE;

    fwd_info = fwd_info_new();
    if(fwd_info == NULL){
        OOR_LOG(LWRN, "tr_get_fwd_entry: Couldn't allocate memory for fwd_info_t");
        return (NULL);
    }

    /* lookup local mapping for source EID */
    map_loc_e = local_map_db_lookup_eid(xtr->local_mdb, &tuple->src_addr, FALSE);
    if (!map_loc_e){
        // In VPP we should continue with the pocess in order to crete a route to the gatway address
#ifndef VPP
        OOR_LOG(LDBG_3, "The source address %s is not a local EID. This should never happen", lisp_addr_to_char(&tuple->src_addr));
        return (NULL);
#else
        native_fwd = TRUE;
        fwd_info->neg_map_reply_act = ACT_NATIVE_FWD;
        eid = &tuple->src_addr;
        simple_eid = eid;
#endif
    }else{
        eid = map_local_entry_eid(map_loc_e);
        simple_eid = lisp_addr_get_ip_pref_addr(eid);
        if (lisp_addr_is_iid(eid)){
            tuple->iid = lcaf_iid_get_iid(lisp_addr_get_lcaf(eid));
        }else{
            tuple->iid = 0;
        }
    }


    if (tuple->iid > 0){
        iidmlen = (lisp_addr_ip_afi(&tuple->src_addr) == AF_INET) ? 32: 128;
        src_eid = lisp_addr_new_init_iid(tuple->iid, &tuple->src_addr, iidmlen);
        dst_eid = lisp_addr_new_init_iid(tuple->iid, &tuple->dst_addr, iidmlen);
    }else{
        src_eid = lisp_addr_clone(&tuple->src_addr);
        dst_eid = lisp_addr_clone(&tuple->dst_addr);
    }

    /* Get the mcache entry for destination EID */

    if (xtr->nat_aware){
        // Map cache entry of RTRs
        mce = mcache_get_all_space_entry(xtr->tr.map_cache, lisp_addr_ip_afi( &tuple->dst_addr));
    }else{
        mce = mcache_lookup(xtr->tr.map_cache, dst_eid);
    }
    if (!mce) {
        /* No map cache entry, initiate map cache miss process */
        OOR_LOG(LDBG_1, "No map cache for EID %s. Sending Map-Request!",
                lisp_addr_to_char(dst_eid));
        handle_map_cache_miss(&xtr->tr, dst_eid, src_eid);
        /* Get the temporal mce created */
        mce = mcache_lookup(xtr->tr.map_cache, dst_eid);
        fwd_info->associated_entry = lisp_addr_clone(mcache_entry_eid(mce));
    } else{
        fwd_info->associated_entry = lisp_addr_clone(mcache_entry_eid(mce));
        if (mcache_entry_active(mce) == NOT_ACTIVE) {
            OOR_LOG(LDBG_2, "Already sent Map-Request for %s. Waiting for reply!",
                    lisp_addr_to_char(dst_eid));
        }
    }

    mce_petrs = get_proxy_etrs_for_afi(&xtr->tr, lisp_addr_ip_afi(simple_eid));

    /* native_fwd can be TRUE for VPP if src packet is not an EID */
    if (!native_fwd){
        xtr->tr.fwd_policy->get_fwd_info(xtr->tr.fwd_policy_dev_parm,map_loc_e,mce,mce_petrs,tuple, fwd_info);
    }

    /* Assign encapsulated that should be used */
    fwd_info->encap = xtr->tr.encap_type;
    lisp_addr_del(src_eid);
    lisp_addr_del(dst_eid);
    return (fwd_info);
}

inline lisp_xtr_t *
lisp_xtr_cast(oor_ctrl_dev_t *dev)
{
    /* make sure */
    lm_assert(dev->ctrl_class == &xtr_ctrl_class);
    return(CONTAINER_OF(dev, lisp_xtr_t, super));
}

/*************************** PROCESS MESSAGES ********************************/
static int
xtr_recv_enc_ctrl_msg(lisp_xtr_t *xtr, lbuf_t *msg, void **ecm_hdr, uconn_t *int_uc)
{
    packet_tuple_t inner_tuple;

    *ecm_hdr = lisp_msg_pull_ecm_hdr(msg);

    if (ECM_SECURITY_BIT(*ecm_hdr)){
        switch (lisp_ecm_auth_type(msg)){
        default:
            OOR_LOG(LDBG_2, "Not supported ECM auth type %d",lisp_ecm_auth_type(msg));
            return (BAD);
        }
    }

    if (lisp_msg_parse_int_ip_udp(msg) != GOOD) {
        return (BAD);
    }
    pkt_parse_inner_5_tuple(msg, &inner_tuple);
    uconn_init(int_uc, inner_tuple.dst_port, inner_tuple.src_port, &inner_tuple.dst_addr,&inner_tuple.src_addr);
    *ecm_hdr = lbuf_lisp_hdr(msg);
    return (GOOD);
}
static int
xtr_recv_map_request(lisp_xtr_t *xtr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    lisp_addr_t *seid = NULL;
    lisp_addr_t *deid = NULL;
    lisp_addr_t *smr_src_eid, *smr_req_eid, *aux_eid;
    map_local_entry_t *map_loc_e = NULL;
    mapping_t *map = NULL;
    glist_t *itr_rlocs = NULL;
    void *mreq_hdr = NULL;
    void *mrep_hdr = NULL;
    int i = 0;
    lbuf_t *mrep = NULL;
    lbuf_t  b;
    uconn_t send_uc;

    /* local copy of the buf that can be modified */
    b = *buf;

    seid = lisp_addr_new();
    deid = lisp_addr_new();

    mreq_hdr = lisp_msg_pull_hdr(&b);

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }


    if (MREQ_RLOC_PROBE(mreq_hdr) && MREQ_REC_COUNT(mreq_hdr) > 1) {
        OOR_LOG(LDBG_1, "More than one EID record in RLOC probe. Discarding!");
        goto err;
    }

    if (MREQ_SMR(mreq_hdr) && MREQ_REC_COUNT(mreq_hdr) > 1) {
        OOR_LOG(LDBG_1, "More than one EID record in SMR request. Discarding!");
        goto err;
    }

    /* Process additional ITR RLOCs */
    itr_rlocs = laddr_list_new();
    lisp_msg_parse_itr_rlocs(&b, itr_rlocs);

    /* Process records and build Map-Reply */
    mrep = lisp_msg_create(LISP_MAP_REPLY);
    for (i = 0; i < MREQ_REC_COUNT(mreq_hdr); i++) {
        if (lisp_msg_parse_eid_rec(&b, deid) != GOOD) {
            goto err;
        }


        OOR_LOG(LDBG_1, " dst-eid: %s", lisp_addr_to_char(deid));

        /* Check the existence of the requested EID */
        map_loc_e = local_map_db_lookup_eid(xtr->local_mdb, deid, TRUE);
        if (!map_loc_e) {
            OOR_LOG(LDBG_1,"EID %s not locally configured!",
                    lisp_addr_to_char(deid));
            goto err;
        }
        map = map_local_entry_mapping(map_loc_e);
        lisp_msg_put_mapping(mrep, map, MREQ_RLOC_PROBE(mreq_hdr)
                ? &int_uc->la: NULL);

        /* If packet is a Solicit Map Request, process it */
        if (lisp_addr_lafi(seid) != LM_AFI_NO_ADDR && MREQ_SMR(mreq_hdr)) {
            /* The req EID of the received msg which is a prefix will be the src EID of the new msg. It is converted to IP */
            aux_eid = lisp_addr_get_ip_pref_addr(deid);
            lisp_addr_set_lafi(aux_eid,LM_AFI_IP); //aux_eid is part of deid-> we convert deid to IP
            smr_src_eid = deid;
            smr_req_eid = seid;
            if(tr_reply_to_smr(&xtr->tr,smr_src_eid,smr_req_eid) != GOOD) {
                goto err;
            }
            /* Return if RLOC probe bit is not set */
            if (!MREQ_RLOC_PROBE(mreq_hdr)) {
                goto done;
            };
        }
    }
    mrep_hdr = lisp_msg_hdr(mrep);
    MREP_RLOC_PROBE(mrep_hdr) = MREQ_RLOC_PROBE(mreq_hdr);
    MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);

    /* SEND MAP-REPLY */
    if (map_reply_fill_uconn(&xtr->super, itr_rlocs, int_uc, ext_uc, &send_uc) != GOOD){
        OOR_LOG(LDBG_1, "Couldn't send Map-Reply, no itr_rlocs reachable");
        goto err;
    }
    OOR_LOG(LDBG_1, "Sending %s", lisp_msg_hdr_to_char(mrep));
    send_msg(&xtr->super, mrep, &send_uc);

done:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    lisp_addr_del(deid);
    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    lisp_addr_del(deid);
    return(BAD);
}


static inline int
xtr_recv_map_reply(lisp_xtr_t *xtr, lbuf_t *buf, uconn_t *uc)
{
    return (tr_recv_map_reply(&xtr->tr,buf,uc));
}

static int
xtr_recv_map_notify(lisp_xtr_t *xtr, lbuf_t *buf)
{
    lisp_addr_t *eid;
    map_local_entry_t *map_loc_e;
    mapping_t *m;
    void *hdr, *auth_hdr;
    locator_t *probed ;
    map_server_elt *ms;
    nonces_list_t *nonces_lst;
    oor_timer_t *timer;
    timer_map_reg_argument *timer_arg_mn;
    timer_encap_map_reg_argument *timer_arg_emn;
    int i, res = BAD;
    lbuf_t b;

    /* local copy */
    b = *buf;
    hdr = lisp_msg_pull_hdr(&b);

    /* Check NONCE */
    nonces_lst = htable_nonces_lookup(nonces_ht, MNTF_NONCE(hdr));
    if (!nonces_lst){
        OOR_LOG(LDBG_1, "No Map Register sent with nonce: %"PRIx64
                " Discarding message!", htonll(MNTF_NONCE(hdr)));
        return(BAD);
    }
    timer = nonces_list_timer(nonces_lst);

    if (MNTF_I_BIT(hdr)==1){
        OOR_LOG(LDBG_1,"Received Data Map-Notify");
        timer_arg_emn = (timer_encap_map_reg_argument *)oor_timer_cb_argument(timer);
        ms = timer_arg_emn->ms;
        if (MNTF_R_BIT(hdr)==1){
            /* We subtract the RTR authentication field. Is not used in the authentication
             * calculation of the map notify.*/
            // XXX Speculate that this field is removed by RTR so length is 0
            lbuf_set_size(buf, lbuf_size(buf) - sizeof(auth_record_hdr_t));
        }
    }else{
        timer_arg_mn = (timer_map_reg_argument *)oor_timer_cb_argument(timer);
        ms = timer_arg_mn->ms;
    }

    auth_hdr = lisp_msg_pull_auth_field(&b);
    res = lisp_msg_check_auth_field(buf,auth_hdr, ms->key);

    if (res != GOOD){
        OOR_LOG(LDBG_1, "Map-Notify message is invalid");
        return(BAD);
    }

    for (i = 0; i < MNTF_REC_COUNT(hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(&b, m, &probed) != GOOD) {
            mapping_del(m);
            return(BAD);
        }

        eid = mapping_eid(m);
        map_loc_e = local_map_db_lookup_eid_exact(xtr->local_mdb, eid);
        if (!map_loc_e) {
            OOR_LOG(LDBG_1, "Map-Notify confirms registration of UNKNOWN EID %s."
                    " Dropping!", lisp_addr_to_char(eid));
            continue;
        }

        OOR_LOG(LDBG_1, "Map-Notify message confirms correct registration of %s",
                lisp_addr_to_char(eid));
        OOR_LOG(LDBG_1, "Scheduling next Map-Register in %d seconds",
                MAP_REGISTER_INTERVAL);

        mapping_del(m);
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        oor_timer_start(timer,MAP_REGISTER_INTERVAL);
    }

    return(GOOD);
}


static int
xtr_recv_info_nat(lisp_xtr_t *xtr, lbuf_t *buf, uconn_t *uc)
{
    lisp_addr_t *inf_reply_eid, *inf_req_eid, *nat_lcaf_addr, *rtr_addr;
    void *info_nat_hdr, *info_nat_hdr_2, *auth_hdr;
    lbuf_t  b;
    nonces_list_t *nonces_lst;
    timer_inf_req_argument *timer_arg;
    int len, ttl;
    glist_t *rtr_lst, *final_rtr_lst;
    glist_entry_t *rtr_it;
    map_local_entry_t *mle;
    mapping_t *map;
    uint8_t smr_required = FALSE;

    /* local copy of the buf that can be modified */
    b = *buf;
    info_nat_hdr = lisp_msg_pull_hdr(&b);

    if (INF_REQ_R_bit(info_nat_hdr) == INFO_REQUEST){
        OOR_LOG(LDBG_1, "xTR received an Info-Request. Discarding message");
        return(BAD);
    }

    /* Check NONCE */
    nonces_lst = htable_nonces_lookup(nonces_ht, INF_REQ_NONCE(info_nat_hdr));
    if (!nonces_lst){
        OOR_LOG(LDBG_2, " Nonce %"PRIx64" doesn't match any Info-Request nonce. "
                "Discarding message!", htonll(INF_REQ_NONCE(info_nat_hdr)));
        return(BAD);
    }

    timer_arg = oor_timer_cb_argument(nonces_list_timer(nonces_lst));
    mle = timer_arg->mle;

    auth_hdr = lisp_msg_pull_auth_field(&b);

    info_nat_hdr_2 = lbuf_pull(&b, sizeof(info_nat_hdr_2_t));

    /* Get EID prefix for the info reply and compare with the one of the info request*/
    inf_reply_eid = lisp_addr_new();
    len = lisp_addr_parse(lbuf_data(&b), inf_reply_eid);
    if (len <= 0) {
        lisp_addr_del(inf_reply_eid);
        return(BAD);
    }
    lbuf_pull(&b, len);
    lisp_addr_set_plen(inf_reply_eid, INF_REQ_2_EID_MASK(info_nat_hdr_2));

    inf_req_eid = map_local_entry_eid(mle);

    if (lisp_addr_cmp(inf_reply_eid,inf_req_eid)!=0){
        OOR_LOG(LDBG_2, "EID from Info-Request and Info-Reply are different (%s - %s)",
                lisp_addr_to_char(inf_req_eid),lisp_addr_to_char(inf_reply_eid));
        lisp_addr_del(inf_reply_eid);
        return (BAD);
    }
    lisp_addr_del(inf_reply_eid);

    /* We obtain the key to use in the authentication process from the argument of the timer */
    if (lisp_msg_check_auth_field(buf,auth_hdr,timer_arg->ms->key) != GOOD) {
        OOR_LOG(LDBG_1, "Info-Reply message validation failed for EID %s with key "
                "%s. Stopping processing!", lisp_addr_to_char(inf_req_eid),
                timer_arg->ms->key);
        return (BAD);
    }

    nat_lcaf_addr = lisp_addr_new();
    len = lisp_addr_parse(lbuf_data(&b), nat_lcaf_addr);
    if (len <= 0) {
        lisp_addr_del(nat_lcaf_addr);
        OOR_LOG(LDBG_2, "tr_recv_info_nat: Can not parse NAT LCAF address");
        return(BAD);
    }

    rtr_lst = nat_type_get_rtr_addr_lst(lcaf_addr_get_nat(lisp_addr_get_lcaf(nat_lcaf_addr)));

    /* Select the RTR list to use */
    final_rtr_lst = nat_select_rtrs(rtr_lst);
    if (glist_size(final_rtr_lst) == 0){
        OOR_LOG(LDBG_1, "Info-Reply Message doesn't have any compatible RTR");
        glist_destroy(final_rtr_lst);
        lisp_addr_del(nat_lcaf_addr);
        return (BAD);
    }

    /* Check if selected RTR list has changed */
    map = map_local_entry_mapping(mle);
    glist_for_each_entry(rtr_it,final_rtr_lst){
        rtr_addr = (lisp_addr_t *)glist_entry_data(rtr_it);
        if (!mapping_get_loct_with_addr(map,rtr_addr)){
            smr_required = TRUE;
            break;
        }
    }

    if (xtr_update_nat_info(xtr,mle,timer_arg->loct,final_rtr_lst) == GOOD){
        /* Configure Encap Map Register */
        xtr_program_encap_map_reg_of_loct_for_map(xtr, mle,timer_arg->loct);
        /* Reprogram time for next Info Request interval */
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        ttl = ntohl(INF_REQ_2_TTL(info_nat_hdr_2));
        oor_timer_start(nonces_lst->timer, ttl*60);
        OOR_LOG(LDBG_1,"Info-Request of %s to %s from locator %s scheduled in %d minutes.",
                lisp_addr_to_char(map_local_entry_eid(mle)), lisp_addr_to_char(timer_arg->ms->address),
                lisp_addr_to_char(locator_addr(timer_arg->loct)), ttl);
    }

    /* SMR proxy-ITRs list to be updated with new mappings */
    if (smr_required){
        OOR_LOG(LDBG_1,"Selected RTR list has changed. Programing SMR");
        xtr_program_smr(xtr, 1);
    }

    lisp_addr_del(nat_lcaf_addr);
    glist_destroy(final_rtr_lst);
    return (GOOD);
}

/* build and send generic map-register with one record
 * for each map server */
static int
xtr_build_and_send_map_reg(lisp_xtr_t * xtr, mapping_t * m, map_server_elt *ms,
        uint64_t nonce)
{
    lbuf_t * b = NULL;
    void * hdr, *auth_hdr;
    lisp_addr_t * drloc = NULL;
    uconn_t uc;

    b = lisp_msg_mreg_create(m, ms->key_type);

    if (!b) {
        return(BAD);
    }

    hdr = lisp_msg_hdr(b);
    MREG_PROXY_REPLY(hdr) = ms->proxy_reply;
    MREG_NONCE(hdr) = nonce;

    auth_hdr = hdr + sizeof(info_nat_hdr_t);
    if (lisp_msg_fill_auth_data(b,auth_hdr,ms->key_type,
            ms->key) != GOOD) {
        return(BAD);
    }
    drloc =  ms->address;
    OOR_LOG(LDBG_1, "%s, EID: %s, MS: %s", lisp_msg_hdr_to_char(b),
            lisp_addr_to_char(mapping_eid(m)), lisp_addr_to_char(drloc));

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
    send_msg(&xtr->super, b, &uc);

    lisp_msg_destroy(b);

    return(GOOD);
}

static int
xtr_build_and_send_encap_map_reg(lisp_xtr_t * xtr, mapping_t * m, map_server_elt *ms,
        lisp_addr_t *etr_addr, lisp_addr_t *rtr_addr, uint64_t nonce)
{
    lbuf_t * b;
    void * hdr, *auth_hdr;
    uconn_t uc;

    b = lisp_msg_mreg_create(m, ms->key_type);
    lisp_msg_put_xtr_id_site_id(b, &xtr->xtr_id, &xtr->site_id);
    hdr = lisp_msg_hdr(b);

    MREG_NONCE(hdr) = nonce;
    MREG_PROXY_REPLY(hdr) = 1;
    MREG_IBIT(hdr) = 1;
    MREG_RBIT(hdr) = 1;

    if (lisp_addr_ip_afi(ms->address) != lisp_addr_ip_afi(etr_addr)){
        OOR_LOG(LDBG_1, "build_and_send_ecm_map_reg: Map Server AFI not compatible with selected"
                " local RLOC (%s)", lisp_addr_to_char(etr_addr));
        lisp_msg_destroy(b);
        return (BAD);
    }

    auth_hdr = hdr + sizeof(map_register_hdr_t);
    if (lisp_msg_fill_auth_data(b, auth_hdr, ms->key_type, ms->key) != GOOD) {
        OOR_LOG(LDBG_2, "build_and_send_ecm_map_reg: Error filling the authentication data");
        return(BAD);
    }

    lisp_msg_encap(b, LISP_CONTROL_PORT, LISP_CONTROL_PORT, etr_addr,ms->address);
    hdr = lisp_msg_ecm_hdr(b);

    /* TODO To use when implementing draft version 4 or higher */
    ECM_RTR_PROCESS_BIT(hdr) = 1;

    OOR_LOG(LDBG_1, "%s, Inner IP: %s -> %s, EID: %s, RTR: %s",
             lisp_msg_hdr_to_char(b), lisp_addr_to_char(etr_addr),
             lisp_addr_to_char(ms->address), lisp_addr_to_char(mapping_eid(m)),
             lisp_addr_to_char(rtr_addr));



    uconn_init(&uc, xtr->tr.encap_port, LISP_CONTROL_PORT, etr_addr, rtr_addr);
    send_msg(&xtr->super, b, &uc);

    lisp_msg_destroy(b);
    return(GOOD);
}

static int
xtr_build_and_send_smr_mreq(lisp_xtr_t *xtr, mapping_t *smap,
        lisp_addr_t *deid, lisp_addr_t *drloc)
{
    uconn_t uc;
    lbuf_t * b = NULL;
    lisp_addr_t *seid = NULL;
    lisp_addr_t *srloc = NULL;
    void *hdr = NULL;
    glist_t *itr_rlocs = NULL;
    int res = GOOD;

    seid = mapping_eid(smap);
    itr_rlocs = ctrl_default_rlocs(ctrl_dev_get_ctrl_t(&xtr->super));

    /* build Map-Request */
    b = lisp_msg_mreq_create(seid, itr_rlocs, deid);

    if (b == NULL){
        lisp_msg_destroy(b);
        return (BAD);
    }

    hdr = lisp_msg_hdr(b);
    MREQ_SMR(hdr) = 1;
    OOR_LOG(LDBG_1, "%s, itr-rlocs: %s, src-eid: %s, req-eid: %s ", lisp_msg_hdr_to_char(b),
            laddr_list_to_char(itr_rlocs), lisp_addr_to_char(seid), lisp_addr_to_char(deid));
    glist_destroy(itr_rlocs);

    srloc = ctrl_default_rloc(xtr->super.ctrl, lisp_addr_ip_afi(drloc));
    if (!srloc) {
        OOR_LOG(LDBG_2, "No compatible RLOC was found to send SMR Map-Request "
                "for local EID %s", lisp_addr_to_char(seid));
        lisp_msg_destroy(b);
        return(BAD);
    }

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, srloc, drloc);
    res = send_msg(&xtr->super, b, &uc);
    lisp_msg_destroy(b);

    return(res);
}

/* build and send generic map-register with one record
 * for each map server */
static int
xtr_build_and_send_info_req(lisp_xtr_t * xtr, mapping_t * m, locator_t *loct,
        map_server_elt *ms, uint64_t nonce)
{
    lbuf_t * b = NULL;
    void *hdr, *auth_hdr;
    lisp_addr_t *srloc, *drloc;
    uconn_t uc;

    b = lisp_msg_inf_req_create(m, ms->key_type);
    if (!b) {
        return(BAD);
    }
    hdr = lisp_msg_hdr(b);
    INF_REQ_NONCE(hdr) = nonce;

    auth_hdr = hdr + sizeof(info_nat_hdr_t);
    if (lisp_msg_fill_auth_data(b, auth_hdr, ms->key_type, ms->key) != GOOD) {
        return(BAD);
    }
    srloc = locator_addr(loct);
    drloc =  ms->address;
    OOR_LOG(LDBG_1, "%s, EID: %s, MS: %s", lisp_msg_hdr_to_char(b),
            lisp_addr_to_char(mapping_eid(m)), lisp_addr_to_char(drloc));

    uconn_init(&uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, srloc, drloc);
    send_msg(&xtr->super, b, &uc);

    lisp_msg_destroy(b);

    return(GOOD);
}

/**************************** LOGICAL PROCESSES ******************************/
/****************************** Map Register *********************************/

int
xtr_program_map_register(lisp_xtr_t *xtr)
{
    void *map_local_entry_it;
    map_local_entry_t *mle;
    oor_timer_t *timer;
    timer_map_reg_argument *timer_arg;
    map_server_elt *ms;
    glist_entry_t *ms_it;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }

    local_map_db_foreach_entry(xtr->local_mdb, map_local_entry_it) {
        mle = (map_local_entry_t *)map_local_entry_it;
        /* Cancel timers associated to the map register of the local map entry */
        stop_timers_of_type_from_obj(mle,MAP_REGISTER_TIMER,ptrs_to_timers_ht, nonces_ht);
        /* Configure map register for each map server */
        glist_for_each_entry(ms_it,xtr->map_servers){
            ms = (map_server_elt *)glist_entry_data(ms_it);
            timer_arg = timer_map_reg_argument_new_init(mle,ms);
            timer = oor_timer_with_nonce_new(MAP_REGISTER_TIMER, xtr, xtr_map_register_cb,
                    timer_arg,(oor_timer_del_cb_arg_fn)timer_map_reg_arg_free);
            htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
            xtr_map_register_cb(timer);
        }
    } local_map_db_foreach_end;

    return(GOOD);
}

int
xtr_program_map_register_for_mapping(lisp_xtr_t *xtr, map_local_entry_t *mle)
{
    oor_timer_t *timer;
    timer_map_reg_argument *timer_arg;
    map_server_elt *ms;
    glist_entry_t *ms_it;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }

    /* Cancel timers associated to the map register of the local map entry */
    stop_timers_of_type_from_obj(mle,MAP_REGISTER_TIMER,ptrs_to_timers_ht, nonces_ht);
    /* Configure map register for each map server */
    glist_for_each_entry(ms_it,xtr->map_servers){
        ms = (map_server_elt *)glist_entry_data(ms_it);
        timer_arg = timer_map_reg_argument_new_init(mle,ms);
        timer = oor_timer_with_nonce_new(MAP_REGISTER_TIMER, xtr, xtr_map_register_cb,
                timer_arg,(oor_timer_del_cb_arg_fn)timer_map_reg_arg_free);
        htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
        xtr_map_register_cb(timer);
    }

    return(GOOD);
}

static int
xtr_map_register_cb(oor_timer_t *timer)
{
    timer_map_reg_argument *timer_arg = oor_timer_cb_argument(timer);
    nonces_list_t *nonces_lst = oor_timer_nonces(timer);
    lisp_xtr_t *xtr = oor_timer_owner(timer);
    mapping_t *map = map_local_entry_mapping(timer_arg->mle);
    map_server_elt *ms = timer_arg->ms;
    uint64_t nonce;

    if ((nonces_list_size(nonces_lst) -1) < 10000){// xtr->probe_retries){
        nonce = nonce_new();
        if (xtr_build_and_send_map_reg(xtr, map, ms, nonce) != GOOD){
            return (BAD);
        }
        if (nonces_list_size(nonces_lst) > 0) {
            OOR_LOG(LDBG_1,"Sent Map-Register retry for mapping %s to %s "
                    "(%d retries)", lisp_addr_to_char(mapping_eid(map)),
                    lisp_addr_to_char(ms->address), nonces_list_size(nonces_lst));
        } else {
            OOR_LOG(LDBG_1,"Sent Map-Register for mapping %s to %s "
                    , lisp_addr_to_char(mapping_eid(map)),
                    lisp_addr_to_char(ms->address));
        }
        htable_nonces_insert(nonces_ht, nonce,nonces_lst);
        oor_timer_start(timer, OOR_INITIAL_MREG_TIMEOUT);
        return (GOOD);
    }else{
        /* If we have reached maximum number of retransmissions, change remote
         *  locator status */

        /* Reprogram time for next Map Register interval */
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        oor_timer_start(timer, MAP_REGISTER_INTERVAL);
        OOR_LOG(LWRN,"Map-Register of %s to %s dit not receive reply. Retrying in %d seconds",
                lisp_addr_to_char(mapping_eid(map)), lisp_addr_to_char(ms->address),
                MAP_REGISTER_INTERVAL);

        return (BAD);
    }
}

/****************************** Encap Map Register ***************************/

static int
xtr_encap_map_register_cb(oor_timer_t *timer)
{
    timer_encap_map_reg_argument *timer_arg = oor_timer_cb_argument(timer);
    nonces_list_t *nonces_lst = oor_timer_nonces(timer);
    lisp_xtr_t *xtr = oor_timer_owner(timer);
    mapping_t *map = map_local_entry_mapping(timer_arg->mle);
    map_server_elt *ms = timer_arg->ms;
    lisp_addr_t *etr_addr = locator_addr(timer_arg->src_loct);
    lisp_addr_t *rtr_addr = timer_arg->rtr_rloc;
    uint64_t nonce;

    if ((nonces_list_size(nonces_lst) -1) < xtr->tr.probe_retries){
        nonce = nonce_new();
        if (xtr_build_and_send_encap_map_reg(xtr, map, ms, etr_addr, rtr_addr, nonce) != GOOD){
            return (BAD);
        }
        if (nonces_list_size(nonces_lst) > 0) {
            OOR_LOG(LDBG_1,"Sent Encap Map-Register retry for mapping %s to MS %s from RLOC %s through RTR %s"
                    "(%d retries)", lisp_addr_to_char(mapping_eid(map)), lisp_addr_to_char(ms->address),
                    lisp_addr_to_char(etr_addr),lisp_addr_to_char(rtr_addr),nonces_list_size(nonces_lst));
        } else {
            OOR_LOG(LDBG_1,"Sent Encap Map-Register for mapping %s to MS %s from RLOC %s through RTR %s"
                    , lisp_addr_to_char(mapping_eid(map)),lisp_addr_to_char(ms->address),
                    lisp_addr_to_char(etr_addr),lisp_addr_to_char(rtr_addr));
        }
        htable_nonces_insert(nonces_ht, nonce,nonces_lst);
        oor_timer_start(timer, OOR_INITIAL_MREG_TIMEOUT);
        return (GOOD);
    }else{
        /* If we have reached maximum number of retransmissions, change remote
         *  locator status */

        /* Reprogram time for next Map Register interval */
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        oor_timer_start(timer, MAP_REGISTER_INTERVAL);
        OOR_LOG(LDBG_1,"Encap Map-Register for mapping %s to MS %s from RLOC %s through RTR %s did not receive reply."
                " Retry in %d seconds", lisp_addr_to_char(mapping_eid(map)),lisp_addr_to_char(ms->address),
                lisp_addr_to_char(etr_addr),lisp_addr_to_char(rtr_addr), MAP_REGISTER_INTERVAL);

        return (BAD);
    }
}


int
xtr_program_encap_map_reg_of_loct_for_map(lisp_xtr_t *xtr, map_local_entry_t *mle,
        locator_t *src_loct)
{
    oor_timer_t *timer;
    timer_encap_map_reg_argument *timer_arg;
    map_server_elt *ms;
    glist_t *timers_lst, *rtr_addr_lst;
    glist_entry_t *ms_it, *timers_it, *rtr_it;
    lisp_addr_t *rtr_addr;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }
    /*
     * We configure the timers using the map_local_entry_t pointer instead of locator
     * as we want to isolate locatars form timers
     */

    /* Cancel timers associated to encap map register associated to the locator */
    timers_lst = htable_ptrs_timers_get_timers_of_type_from_obj(ptrs_to_timers_ht, mle, ENCAP_MAP_REGISTER_TIMER);

    glist_for_each_entry(timers_it,timers_lst){
        timer = (oor_timer_t *)glist_entry_data(timers_it);
        timer_arg = oor_timer_cb_argument(timer);
        if(src_loct == timer_arg->src_loct){
            stop_timer_from_obj(mle,timer,ptrs_to_timers_ht, nonces_ht);
            // Continue processing as it could be more than one map server, RTR
        }
    }
    glist_destroy(timers_lst);
    /* Configure encap map register for each RTR associated with the locator and MS*/
    rtr_addr_lst = mle_rtr_addr_list_of_loct(mle, locator_addr(src_loct));
    glist_for_each_entry(rtr_it,rtr_addr_lst){
        rtr_addr = (lisp_addr_t *)glist_entry_data(rtr_it);
        glist_for_each_entry(ms_it,xtr->map_servers){
            ms = (map_server_elt *)glist_entry_data(ms_it);
            timer_arg = timer_encap_map_reg_argument_new_init(mle,ms,src_loct,rtr_addr);
            timer = oor_timer_with_nonce_new(ENCAP_MAP_REGISTER_TIMER, xtr, xtr_encap_map_register_cb,
                    timer_arg,(oor_timer_del_cb_arg_fn)timer_encap_map_reg_arg_free);
            htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
            xtr_encap_map_register_cb(timer);
        }
    }
    return(GOOD);
}

/*********************************** SMR *************************************/

/* Send a solicit map request for each rloc of all eids in the map cache
 * database */
static void
xtr_smr_process_start(lisp_xtr_t *xtr)
{
    map_local_entry_t * map_loc_e = NULL;
    glist_t * map_loc_e_list = NULL; //<map_local_entry_t *>
    glist_entry_t * it = NULL;

    OOR_LOG(LDBG_1,"\n**** Re-Register and send SMRs for mappings with updated "
            "RLOCs ****");

    /* Get a list of mappings that require smrs */
    map_loc_e_list = xtr_get_map_local_entry_to_smr(xtr);

    /* Send map register and SMR request for each mapping */
    //glist_dump(map_loc_e_list,(glist_to_char_fct)map_local_entry_to_char,LDBG_1);

    glist_for_each_entry(it, map_loc_e_list) {
        map_loc_e = (map_local_entry_t *)glist_entry_data(it);
        xtr_smr_start_for_locl_mapping(xtr, map_loc_e);
    }

    glist_destroy(map_loc_e_list);
    OOR_LOG(LDBG_2,"*** Finished sending notifications ***\n");
}

void
xtr_smr_start_for_locl_mapping(lisp_xtr_t *xtr, map_local_entry_t *map_loc_e)
{
    mcache_entry_t * mce;
    mapping_t * mcache_map;
    mapping_t * map;
    glist_entry_t * it_pitr;
    lisp_addr_t * pitr_addr;
    lisp_addr_t * eid;

    assert(map_loc_e);

    map = map_local_entry_mapping(map_loc_e);
    eid = mapping_eid(map);

    if (!xtr->nat_aware){
        xtr_program_map_register_for_mapping(xtr, map_loc_e);
    }

    OOR_LOG(LDBG_1, "Start SMR for local EID %s", lisp_addr_to_char(eid));

    /* TODO: spec says SMRs should be sent only to peer ITRs that sent us
     * traffic in the last minute. Should change this in the future*/
    /* XXX: works ONLY with IP */
    mcache_foreach_active_entry_in_ip_eid_db(xtr->tr.map_cache, eid, mce) {
        mcache_map = mcache_entry_mapping(mce);
        xtr_smr_notify_mcache_entry(xtr, map, mcache_map);
    } mcache_foreach_active_entry_in_ip_eid_db_end;

    /* SMR proxy-itr */
    OOR_LOG(LDBG_1, "Sending SMRs to PITRs");
    glist_for_each_entry(it_pitr, xtr->pitrs){
        pitr_addr = (lisp_addr_t *)glist_entry_data(it_pitr);
        xtr_build_and_send_smr_mreq(xtr, map, eid, pitr_addr);
    }

}

/* solicit SMRs for 'src_map' to all locators of 'dst_map'*/
static int
xtr_smr_notify_mcache_entry(lisp_xtr_t  *xtr, mapping_t *src_map,
        mapping_t *dst_map)
{
    lisp_addr_t *deid = NULL, *drloc = NULL;
    locator_t *loct = NULL;

    deid = mapping_eid(dst_map);

    mapping_foreach_active_locator(dst_map, loct){
        if (loct->state == UP){
            drloc = locator_addr(loct);
            xtr_build_and_send_smr_mreq(xtr, src_map, deid, drloc);
        }
    }mapping_foreach_active_locator_end;

    return(GOOD);
}

static int
xtr_smr_process_start_cb(oor_timer_t *timer)
{
    xtr_smr_process_start((lisp_xtr_t *)oor_timer_cb_argument(timer));
    return(GOOD);
}

static int
xtr_program_smr(lisp_xtr_t *xtr, int time)
{

    OOR_LOG(LDBG_1,"Rescheduling SMR in %d seconds",time);

    if (!xtr->smr_timer) {
        xtr->smr_timer = oor_timer_without_nonce_new(SMR_TIMER, xtr, xtr_smr_process_start_cb, xtr, NULL);
    }

    oor_timer_start(xtr->smr_timer, time);
    return(GOOD);
}


/*
 * Return the list of mappings that has experimented changes in their
 * locators. At the same time iface_locators status is reseted
 * @param xtr
 * @return glist_t with the list of modified mappings (mapping_t *)
 */
static glist_t *
xtr_get_map_local_entry_to_smr(lisp_xtr_t *xtr)
{
    glist_t * map_loc_e_to_smr = glist_new();//<map_local_entry_t>
    glist_t * iface_locators_list = NULL;
    iface_locators * if_loct = NULL;
    glist_entry_t * it = NULL;
    glist_entry_t * it_loc = NULL;
    glist_t * locators[2] = {NULL,NULL};
    map_local_entry_t * map_loc_e = NULL;
    locator_t * locator = NULL;
    int ctr;

    iface_locators_list = shash_values(xtr->tr.iface_locators_table);

    glist_for_each_entry(it,iface_locators_list){
        if_loct = (iface_locators *)glist_entry_data(it);
        /* Select affected locators */
        if (if_loct->status_changed == TRUE){
            locators[0] = if_loct->ipv4_locators;
            locators[1] = if_loct->ipv6_locators;
        }else{
            if(if_loct->ipv4_prev_addr != NULL){
                locators[0] = if_loct->ipv4_locators;
            }
            if(if_loct->ipv6_prev_addr != NULL){
                locators[1] = if_loct->ipv6_locators;
            }
        }
        /* Reset iface_locators status */
        if_loct->status_changed = FALSE;
        lisp_addr_del(if_loct->ipv4_prev_addr);
        lisp_addr_del(if_loct->ipv6_prev_addr);
        if_loct->ipv4_prev_addr = NULL;
        if_loct->ipv6_prev_addr = NULL;
        /* Select not repeated mappings*/
        for (ctr=0 ; ctr<2 ; ctr++){
            if (locators[ctr] != NULL){
                glist_for_each_entry(it_loc,locators[ctr]){
                    locator = (locator_t *)glist_entry_data(it_loc);
                    map_loc_e = get_map_loc_ent_containing_loct_ptr(xtr->local_mdb, locator);
                    if (map_loc_e != NULL && glist_contain(map_loc_e, map_loc_e_to_smr) == FALSE){
                        glist_add(map_loc_e, map_loc_e_to_smr);
                    }
                }
            }
        }
    }
    glist_destroy(iface_locators_list);
    return (map_loc_e_to_smr);
}

/****************************** Info Request *********************************/

static int
xtr_program_initial_info_request_process(lisp_xtr_t *xtr)
{
    void *map_local_entry_it;
    oor_timer_t *timer;
    timer_inf_req_argument *timer_arg;
    map_local_entry_t *mle;
    mapping_t *map;
    locator_t *loct;
    map_server_elt *ms;
    glist_entry_t *ms_it;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }

    local_map_db_foreach_entry(xtr->local_mdb, map_local_entry_it) {
        mle = (map_local_entry_t *)map_local_entry_it;
        map = map_local_entry_mapping(mle);
        /* Cancel timers associated to the info request process of the local map entry */
        stop_timers_of_type_from_obj(mle,INFO_REQUEST_TIMER,ptrs_to_timers_ht, nonces_ht);
        mapping_foreach_active_locator(map,loct){
            glist_for_each_entry(ms_it,xtr->map_servers){
                ms = (map_server_elt *)glist_entry_data(ms_it);
                timer_arg = timer_inf_req_argument_new_init(mle,loct,ms);
                map_local_entry_dump(mle,LINF);
                timer = oor_timer_with_nonce_new(INFO_REQUEST_TIMER, xtr, xtr_info_request_cb,
                        timer_arg,(oor_timer_del_cb_arg_fn)timer_inf_req_arg_free);
                htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
                xtr_info_request_cb(timer);
            }
        }mapping_foreach_active_locator_end;
    } local_map_db_foreach_end;

    return(GOOD);
}

static int
xtr_program_info_req_per_loct(lisp_xtr_t *xtr, map_local_entry_t *mle, locator_t *loct)
{
    oor_timer_t *timer;
    timer_inf_req_argument *timer_arg;
    map_server_elt *ms;
    glist_entry_t *ms_it;

    if (glist_size(xtr->map_servers) == 0){
        return (BAD);
    }
    /* Program info request for each Map Server */
    glist_for_each_entry(ms_it,xtr->map_servers){
        ms = (map_server_elt *)glist_entry_data(ms_it);
        timer_arg = timer_inf_req_argument_new_init(mle,loct,ms);
        timer = oor_timer_with_nonce_new(INFO_REQUEST_TIMER, xtr, xtr_info_request_cb,
                timer_arg,(oor_timer_del_cb_arg_fn)timer_inf_req_arg_free);
        htable_ptrs_timers_add(ptrs_to_timers_ht, mle, timer);
        oor_timer_start(timer, OOR_INF_REQ_HANDOVER_TIMEOUT);
    }

    return(GOOD);
}

static int
xtr_info_request_cb(oor_timer_t *timer)
{
    timer_inf_req_argument *timer_arg = oor_timer_cb_argument(timer);
    nonces_list_t *nonces_lst = oor_timer_nonces(timer);
    lisp_xtr_t *xtr = oor_timer_owner(timer);
    mapping_t *map = map_local_entry_mapping(timer_arg->mle);
    locator_t *loct = timer_arg->loct;
    map_server_elt *ms = timer_arg->ms;
    uint64_t nonce;

    if ((nonces_list_size(nonces_lst) -1) < xtr->tr.map_request_retries){
        nonce = nonce_new();
        if (nonces_list_size(nonces_lst) > 0) {
            OOR_LOG(LDBG_1,"Sent Info-Request retry for mapping %s to %s from locator %s"
                    "(%d retries)", lisp_addr_to_char(mapping_eid(map)),
                    lisp_addr_to_char(ms->address), lisp_addr_to_char(locator_addr(loct)),
                    nonces_list_size(nonces_lst));
        } else {
            timer_encap_map_reg_stop_using_locator(timer_arg->mle, loct);
            OOR_LOG(LDBG_1,"Sent Info-Request for mapping %s to %s from locator %s",
                    lisp_addr_to_char(mapping_eid(map)),lisp_addr_to_char(ms->address),
                    lisp_addr_to_char(locator_addr(loct)));
        }

        if (xtr_build_and_send_info_req(xtr, map, loct, ms, nonce) != GOOD){
            return (BAD);
        }

        htable_nonces_insert(nonces_ht, nonce,nonces_lst);
        oor_timer_start(timer, OOR_INITIAL_INF_REQ_TIMEOUT);
        return (GOOD);
    }else{
        /* We reached maximum number of retransmissions */

        /* Reprogram time for next Info Request interval */
        htable_nonces_reset_nonces_lst(nonces_ht,nonces_lst);
        oor_timer_start(timer, OOR_SLEEP_INF_REQ_TIMEOUT);
        OOR_LOG(LWRN,"Info-Request of %s to %s from locator %s did not receive reply. Retrying in %d seconds",
                lisp_addr_to_char(mapping_eid(map)), lisp_addr_to_char(ms->address),
                lisp_addr_to_char(locator_addr(loct)), OOR_SLEEP_INF_REQ_TIMEOUT);

        return (BAD);
    }
}

/**************************** AUXILIAR FUNCTIONS *****************************/

/* Configure SMR or info request depending on NAT traversal */
static int
xtr_iface_event_signaling(lisp_xtr_t * xtr, iface_locators * if_loct)
{
    locator_t *loct;
    lisp_addr_t *loct_addr;
    map_local_entry_t *mle;
    glist_t *timers_lst;
    glist_entry_t *mle_it, *timer_it;
    mapping_t *map;
    oor_timer_t *timer;


    if(xtr->nat_aware == TRUE){
        if (glist_size(if_loct->ipv4_locators) == 0){
            return (GOOD);
        }
        loct = glist_first_data(if_loct->ipv4_locators);
        loct_addr = locator_addr(loct);
        if (lisp_addr_is_no_addr(loct_addr)==TRUE){
            return (GOOD);
        }
        glist_for_each_entry(mle_it,if_loct->map_loc_entries){
            mle = (map_local_entry_t *)glist_entry_data(mle_it);
            map = map_local_entry_mapping(mle);
            loct = mapping_get_loct_with_addr(map,loct_addr);

            /* Stop timers associtated with the locator */
            timer_inf_req_stop_using_locator(mle, loct);
            timer_encap_map_reg_stop_using_locator(mle, loct);

            if (locator_state(loct) == UP){
                OOR_LOG(LDBG_2,"xtr_if_event: Reconfiguring Info-Request process for locator %s of "
                        "the mapping %s.", lisp_addr_to_char(loct_addr),
                        lisp_addr_to_char(mapping_eid(map)));
                xtr_program_info_req_per_loct(xtr, mle, loct);
            }else{
                /* Reprogram all the Encap Map Registers of the other interfaces associated to the mapping
                 * If status is up this process will be done when receiving the Info Reply*/
                timers_lst = htable_ptrs_timers_get_timers_of_type_from_obj(ptrs_to_timers_ht,
                           mle, ENCAP_MAP_REGISTER_TIMER);
                glist_for_each_entry(timer_it, timers_lst){
                    timer = (oor_timer_t *)glist_entry_data(timer_it);
                    oor_timer_start(timer, OOR_INF_REQ_HANDOVER_TIMEOUT);
                }
                glist_destroy(timers_lst);
            }
        }
    }else{
        xtr_program_smr(xtr, OOR_SMR_TIMEOUT);
    }
    return (GOOD);
}


/****************************** NAT traversal ********************************/

static int
xtr_update_nat_info(lisp_xtr_t *xtr, map_local_entry_t *mle, locator_t *loct,
        glist_t *rtr_list)
{
    mle_nat_info_update(mle, loct, rtr_list);
    /* Update forwarding info of the local entry*/
    xtr->tr.fwd_policy->updated_map_loc_inf(xtr->tr.fwd_policy_dev_parm,mle);
    notify_datap_rm_fwd_from_entry(&(xtr->super),map_local_entry_eid(mle),TRUE);
    /* Update forwarding info of rtrs */
    xtr_update_rtrs_caches(xtr);

    return (GOOD);
}

static void
xtr_update_rtrs_caches(lisp_xtr_t *xtr)
{
    xtr_update_rtrs_cache_afi(xtr, AF_INET);
    xtr_update_rtrs_cache_afi(xtr, AF_INET6);
}

static void
xtr_update_rtrs_cache_afi(lisp_xtr_t *xtr, int afi)
{
    lisp_addr_t *rtr_addr;
    map_local_entry_t *mle;
    mcache_entry_t *rtrs_mce;
    mapping_t *map;
    locator_t *rtr_loct;
    glist_t *rtr_addr_list;
    glist_entry_t *addr_it;

    rtrs_mce  = mcache_get_all_space_entry(xtr->tr.map_cache, afi);

    // XXX check before if we have any change in order to avoid modify the data plane
    map = mcache_entry_mapping(rtrs_mce);
    /* Remove the list of rtr locators */
    mapping_remove_locators(map);

    /* Regenerate rtr list using the information of local map entries */
    local_map_db_foreach_entry(xtr->local_mdb,mle){
        rtr_addr_list = mle_rtr_addr_list(mle);
        glist_for_each_entry(addr_it, rtr_addr_list){
            rtr_addr = (lisp_addr_t *)glist_entry_data(addr_it);
            rtr_loct = locator_new_init(rtr_addr,UP,0,1,1,100,255,0);
            mapping_add_locator(map,rtr_loct);
        }
        glist_destroy(rtr_addr_list);
    }local_map_db_foreach_end;


    /* Update forwarding info of rtrs */
    xtr->tr.fwd_policy->updated_map_cache_inf(xtr->tr.fwd_policy_dev_parm,rtrs_mce);
    notify_datap_rm_fwd_from_entry(&(xtr->super),mcache_entry_eid(rtrs_mce),FALSE);
}

static glist_t *
nat_select_rtrs(glist_t * rtr_list)
{
    glist_t *final_rtr_list = glist_new_managed((glist_del_fct)lisp_addr_del);
    lisp_addr_t *rtr_addr;

    addr_list_rm_not_compatible_addr(rtr_list, IPv4_SUPPORT);

    //TODO Select RTR process
    rtr_addr = (lisp_addr_t *)glist_first_data(rtr_list);
    if (rtr_addr){
        glist_add(lisp_addr_clone(rtr_addr), final_rtr_list);
    }
    return (final_rtr_list);
}

/**********************************  Dump ************************************/

void
proxy_etrs_dump(lisp_xtr_t *xtr, int log_level)
{
    locator_t *locator = NULL;
    mcache_entry_t *    ipv4_petrs_mc,*ipv6_petrs_mc;
    ipv4_petrs_mc = mcache_get_all_space_entry(xtr->tr.map_cache,AF_INET);
    ipv6_petrs_mc = mcache_get_all_space_entry(xtr->tr.map_cache,AF_INET6);

    OOR_LOG(log_level, "****************** Proxy ETR List for IPv4 EIDs **********************");
    OOR_LOG(log_level, "|               Locator (RLOC)            | Status | Priority/Weight |");

    /* Start rloc probing for each locator of the mapping */
    mapping_foreach_active_locator(mcache_entry_mapping(ipv4_petrs_mc),locator){
        OOR_LOG(log_level,"%s",locator_to_char(locator));
    }mapping_foreach_active_locator_end;
    OOR_LOG(log_level, "**********************************************************************\n");

    OOR_LOG(log_level, "****************** Proxy ETR List for IPv6 EIDs **********************");
    OOR_LOG(log_level, "|               Locator (RLOC)            | Status | Priority/Weight |");

    /* Start rloc probing for each locator of the mapping */
    mapping_foreach_active_locator(mcache_entry_mapping(ipv6_petrs_mc),locator){
        OOR_LOG(log_level,"%s",locator_to_char(locator));
    }mapping_foreach_active_locator_end;
    OOR_LOG(log_level, "**********************************************************************\n");
}

void
map_servers_dump(lisp_xtr_t *xtr, int log_level)
{
    map_server_elt *    ms          = NULL;
    glist_entry_t *     it          = NULL;
    char                str[80];
    size_t  str_size = sizeof(str);

    if (glist_size(xtr->map_servers) == 0 || is_loggable(log_level) == FALSE) {
        return;
    }

    OOR_LOG(log_level, "******************* Map-Servers list ********************************");
    OOR_LOG(log_level, "|               Locator (RLOC)            |       Key Type          |");

    glist_for_each_entry(it, xtr->map_servers) {
        ms = (map_server_elt *)glist_entry_data(it);
        snprintf(str,str_size, "| %39s |", lisp_addr_to_char(ms->address));
        if (ms->key_type == NO_KEY) {
            snprintf(str + strlen(str), str_size - strlen(str), "          NONE           |");
        } else if (ms->key_type == HMAC_SHA_1_96) {
            snprintf(str + strlen(str), str_size - strlen(str), "     HMAC-SHA-1-96       |");
        } else {
            snprintf(str + strlen(str), str_size - strlen(str), "    HMAC-SHA-256-128     |");
        }
        OOR_LOG(log_level, "%s", str);
    }
    OOR_LOG(log_level, "*********************************************************************\n");
}

/**************************** Map Server struct ******************************/
map_server_elt *
map_server_elt_new_init(lisp_addr_t *address,uint8_t key_type, char *key,
        uint8_t proxy_reply)
{
    map_server_elt *ms = NULL;
    ms = xzalloc(sizeof(map_server_elt));
    if (ms == NULL){
        OOR_LOG(LWRN,"Couldn't allocate memory for a map_server_elt structure");
        return (NULL);
    }
    ms->address     = lisp_addr_clone(address);
    ms->key_type    = key_type;
    ms->key         = strdup(key);
    ms->proxy_reply = proxy_reply;

    return (ms);
}

void
map_server_elt_del (map_server_elt *map_server)
{
    if (map_server == NULL){
        return;
    }
    lisp_addr_del (map_server->address);
    free(map_server->key);
    free(map_server);
}


static map_local_entry_t *
get_map_loc_ent_containing_loct_ptr(local_map_db_t *local_db, locator_t *locator)
{
    map_local_entry_t *map_loc_e;
    map_local_entry_t *map_loc_e_res = NULL;
    mapping_t *mapping = NULL;
    uint8_t found = FALSE;
    void *it = NULL;
    local_map_db_foreach_entry_with_break(local_db, it, found) {
        map_loc_e = (map_local_entry_t *)it;
        mapping = map_local_entry_mapping(map_loc_e);
        if (mapping_has_locator(mapping, locator) == TRUE){
            found = TRUE;
            map_loc_e_res = map_loc_e;
        }
    } local_map_db_foreach_with_break_end(found);
    if (!map_loc_e_res){
        OOR_LOG(LDBG_2, "get_map_loc_ent_containing_loct_ptr: No mapping has been found with locator %s",
                lisp_addr_to_char(locator_addr(locator)));
    }
    return (map_loc_e_res);

}


/******************************* TIMERS **************************************/
/************************** Map Register timer *******************************/
static timer_map_reg_argument *
timer_map_reg_argument_new_init(map_local_entry_t *mle,
        map_server_elt *ms)
{
    timer_map_reg_argument *timer_arg = xmalloc(sizeof(timer_map_reg_argument));
    timer_arg->mle = mle;
    timer_arg->ms = ms;

    return(timer_arg);
}

static void
timer_map_reg_arg_free(timer_map_reg_argument * timer_arg)
{
    free(timer_arg);
}
/*********************** Encap Map Register timer ****************************/
static timer_encap_map_reg_argument *
timer_encap_map_reg_argument_new_init(map_local_entry_t *mle,
        map_server_elt *ms, locator_t *src_loct, lisp_addr_t *rtr_addr)
{
    timer_encap_map_reg_argument *timer_arg = xmalloc(sizeof(timer_encap_map_reg_argument));
    timer_arg->mle = mle;
    timer_arg->ms = ms;
    timer_arg->src_loct = src_loct;
    timer_arg->rtr_rloc = lisp_addr_clone(rtr_addr);
    return(timer_arg);
}

static void
timer_encap_map_reg_arg_free(timer_encap_map_reg_argument * timer_arg)
{
    lisp_addr_del(timer_arg->rtr_rloc);
    free(timer_arg);
}

/*
 * Stop all the timers of type ENCAP_MAP_REGISTER_TIMER associated with the map local entry
 * introduced as a parameter and using the specified locator.
 */
static void
timer_encap_map_reg_stop_using_locator(map_local_entry_t *mle, locator_t *loct)
{
    glist_t *timers_lst;
    glist_entry_t *timer_it;
    oor_timer_t *timer;
    timer_encap_map_reg_argument * timer_arg;

    timers_lst = htable_ptrs_timers_get_timers_of_type_from_obj(ptrs_to_timers_ht,
            mle, ENCAP_MAP_REGISTER_TIMER);
    glist_for_each_entry(timer_it,timers_lst){
        timer = (oor_timer_t *)glist_entry_data(timer_it);
        timer_arg = (timer_encap_map_reg_argument *)oor_timer_cb_argument(timer);
        if (timer_arg->src_loct == loct){
            stop_timer_from_obj(mle,timer,ptrs_to_timers_ht,nonces_ht);
        }
    }
    glist_destroy(timers_lst);
}
/************************** Info Request timer *******************************/
static timer_inf_req_argument *
timer_inf_req_argument_new_init(map_local_entry_t *mle, locator_t *loct,
        map_server_elt *ms)
{
    timer_inf_req_argument *timer_arg = xmalloc(sizeof(timer_inf_req_argument));
    timer_arg->mle = mle;
    timer_arg->loct = loct;
    timer_arg->ms = ms;
    return (timer_arg);
}

static void
timer_inf_req_arg_free(timer_inf_req_argument * timer_arg)
{
    free(timer_arg);
}

/*
 * Stop all the timers of type INFO_REQUEST_TIMER associated with the map local entry
 * introduced as a parameter and using the specified locator.
 */
static void
timer_inf_req_stop_using_locator(map_local_entry_t *mle, locator_t *loct)
{
    glist_t *timers_lst;
    glist_entry_t *timer_it;
    oor_timer_t *timer;
    timer_inf_req_argument * timer_arg;

    timers_lst = htable_ptrs_timers_get_timers_of_type_from_obj(ptrs_to_timers_ht,
            mle, INFO_REQUEST_TIMER);
    glist_for_each_entry(timer_it,timers_lst){
        timer = (oor_timer_t *)glist_entry_data(timer_it);
        timer_arg = (timer_inf_req_argument *)oor_timer_cb_argument(timer);
        if (timer_arg->loct == loct){
            stop_timer_from_obj(mle,timer,ptrs_to_timers_ht,nonces_ht);
        }
    }
    glist_destroy(timers_lst);
}
