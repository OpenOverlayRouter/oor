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
#include "../lib/map_cache_rtr_data.h"
#include "../lib/mem_util.h"
#include "../lib/oor_log.h"
#include "../lib/packets.h"
#include "../lib/prefixes.h"
#include "../lib/sockets.h"
#include "../lib/timers_utils.h"
#include "../lib/util.h"
#include "lisp_rtr.h"

/************************* Structure definitions *****************************/
typedef struct nat_loct_conn_inf_t_{
    lisp_addr_t *pub_xtr_addr;
    lisp_addr_t *priv_xtr_addr;
    lisp_addr_t *rtr_addr;
    lisp_addr_t *ms_addr;
    uint16_t pub_xtr_port;
}nat_loct_conn_inf_t;

typedef struct _timer_rtr_nat_loc_exp_arg {
    mcache_entry_t *mce;
    rloc_nat_data_t *rloc_nat_data;
} timer_rtr_nat_loc_exp_arg;



static oor_ctrl_dev_t *rtr_ctrl_alloc();
static int rtr_ctrl_construct(oor_ctrl_dev_t *dev);
static void rtr_ctrl_dealloc(oor_ctrl_dev_t *dev);
static void rtr_ctrl_destruct(oor_ctrl_dev_t *dev);
static void rtr_run(oor_ctrl_dev_t *dev);
static int rtr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc);
static int rtr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t status);
int rtr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status);
int rtr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway);
static fwd_info_t *rtr_get_forwarding_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple);
inline lisp_rtr_t * lisp_rtr_cast(oor_ctrl_dev_t *dev);
/*************************** PROCESS MESSAGES ********************************/
static int rtr_recv_enc_ctrl_msg(lisp_rtr_t *rtr, lbuf_t *msg, uconn_t *ext_uc, void **ecm_hdr, uconn_t *int_uc);
static int rtr_recv_map_request(lisp_rtr_t *rtr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc);
static inline int rtr_recv_map_reply(lisp_rtr_t *xtr, lbuf_t *buf, uconn_t *uc);
static int rtr_recv_map_register(lisp_rtr_t *rtr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc);
static int rtr_recv_map_notify(lisp_rtr_t *rtr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc);
/******************************* TIMERS **************************************/
/************************ RTR_NAT_LOCT_EXPIRE_TIMER arg***********************/
static timer_rtr_nat_loc_exp_arg * timer_rtr_nat_loc_exp_arg_new_init(mcache_entry_t *mce,
        rloc_nat_data_t *rloc_nat_data);
static void timer_rtr_nat_loc_exp_arg_free(timer_rtr_nat_loc_exp_arg * timer_arg);
int rtr_nat_loc_expire_cb(oor_timer_t *timer);
/**************************** AUXILIAR FUNCTIONS *****************************/
static inline nat_loct_conn_inf_t * nat_loct_con_info_new_init(uconn_t *ext_uc, uconn_t *int_uc);
static inline void nat_loct_con_info_destroy(nat_loct_conn_inf_t *loct_info);
int rtr_expires_map_reg_cb(oor_timer_t *timer);
int rtr_proc_rtr_auth_data(lisp_rtr_t *rtr,lbuf_t *msg, lisp_addr_t *ms_addr);


/* implementation of ctrl base functions */
ctrl_dev_class_t rtr_ctrl_class = {
        .alloc = rtr_ctrl_alloc,
        .construct = rtr_ctrl_construct,
        .dealloc = rtr_ctrl_dealloc,
        .destruct = rtr_ctrl_destruct,
        .run = rtr_run,
        .recv_msg = rtr_recv_msg,
        .if_link_update = rtr_if_link_update,
        .if_addr_update = rtr_if_addr_update,
        .route_update = rtr_route_update,
        .get_fwd_entry = rtr_get_forwarding_entry
};


static oor_ctrl_dev_t *
rtr_ctrl_alloc()
{
    lisp_rtr_t *rtr;
    rtr = xzalloc(sizeof(lisp_rtr_t));
    return(&rtr->super);
}

static int
rtr_ctrl_construct(oor_ctrl_dev_t *dev)
{
    lisp_rtr_t *rtr = lisp_rtr_cast(dev);
    lisp_addr_t aux_addr;
    mapping_t * mapping;

    lisp_tr_init(&rtr->tr);

    lisp_addr_set_lafi(&aux_addr,LM_AFI_NO_ADDR);

    mapping = mapping_new();
    mapping_set_eid(mapping,&aux_addr);
    if (mapping == NULL){
        OOR_LOG(LDBG_1, "rtr_ctrl_construct: Can't allocate mapping!");
        return (BAD);
    }
    rtr->all_locs_map = map_local_entry_new_init(mapping);
    if(rtr->all_locs_map == NULL){
        OOR_LOG(LDBG_1, "rtr_ctrl_construct: Can't allocate map_local_entry_t!");
        return (BAD);
    }

    rtr->rtr_ms_table = shash_new_managed((free_value_fn_t)rtr_ms_node_destroy);

    OOR_LOG(LDBG_1, "Finished Constructing rtr");

    return(GOOD);
}

static void
rtr_ctrl_dealloc(oor_ctrl_dev_t *dev) {
    lisp_rtr_t *rtr = lisp_rtr_cast(dev);
    free(rtr);
    OOR_LOG(LDBG_1, "Freed rtr ...");
}

static void
rtr_ctrl_destruct(oor_ctrl_dev_t *dev)
{
    lisp_rtr_t *rtr = lisp_rtr_cast(dev);

    lisp_tr_uninit(&rtr->tr);
    map_local_entry_del(rtr->all_locs_map);
    shash_destroy(rtr->rtr_ms_table);

    OOR_LOG(LDBG_1,"rtr device destroyed");
}



static void
rtr_run(oor_ctrl_dev_t *dev)
{
    lisp_rtr_t *rtr = lisp_rtr_cast(dev);
    mapping_t * mapping = NULL;
    glist_t *rtr_ms_list;

    OOR_LOG(LINF, "\nStarting RTR ...\n");

    if (glist_size(tr_map_resolvers(&rtr->tr)) == 0) {
        OOR_LOG(LCRIT, "**** NO MAP RESOLVER CONFIGURES. You can not request mappings to the mapping system");
        oor_timer_sleep(2);
    }
    OOR_LOG(LINF, "****** Summary of the configuration ******\n");
    rtr_ms_list = shash_values(rtr->rtr_ms_table);
    OOR_LOG(LINF, "*** Configured MSs (NAT Traversal) ***");
    glist_dump(rtr_ms_list, (glist_to_char_fct)rtr_ms_node_to_char, LINF);
    glist_destroy(rtr_ms_list);

    mcache_dump_db(rtr->tr.map_cache, LINF);

    mapping = map_local_entry_mapping(rtr->all_locs_map);
    OOR_LOG(LINF, "Active interfaces status");
    rtr->tr.fwd_policy->updated_map_loc_inf(rtr->tr.fwd_policy_dev_parm,rtr->all_locs_map);
    OOR_LOG(LINF, "%s", mapping_to_char(mapping));
}

static int
rtr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc)
{
    int ret = 0;
    lisp_msg_type_e type;
    lisp_rtr_t *rtr = lisp_rtr_cast(dev);
    void *ecm_hdr = NULL;
    uconn_t *int_uc, *ext_uc = NULL, aux_uc;

    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (rtr_recv_enc_ctrl_msg(rtr, msg, uc, &ecm_hdr, &aux_uc)!=GOOD){
            return (BAD);
        }
        type = lisp_msg_type(msg);
        ext_uc = uc;
        int_uc = &aux_uc;
        OOR_LOG(LDBG_1, "RTR: Received Encapsulated %s", lisp_msg_hdr_to_char(msg));
    }else{
        int_uc = uc;
    }

    switch (type) {
    case LISP_MAP_REQUEST:
        ret = rtr_recv_map_request(rtr, msg, ecm_hdr, int_uc, ext_uc);
        break;
    case LISP_MAP_REPLY:
        ret = rtr_recv_map_reply(rtr, msg, int_uc);
        break;
    case LISP_MAP_REGISTER:
        ret = rtr_recv_map_register(rtr, msg, ecm_hdr, int_uc, ext_uc);
        break;
    case LISP_MAP_NOTIFY:
        ret = rtr_recv_map_notify(rtr, msg,  ecm_hdr, int_uc, ext_uc);
        break;
    case LISP_INFO_NAT:
        OOR_LOG(LDBG_1, "Info Request/Reply message not supported by RTRs. Discarding ...");
        break;
    default:
        OOR_LOG(LDBG_1, "rtr: Unidentified type (%d) control message received",
                type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        OOR_LOG(LDBG_1,"rtr: Failed to process LISP control message");
        return (BAD);
    } else {
        OOR_LOG(LDBG_3, "rtr: Completed processing of LISP control message");
        return (ret);
    }
}


static int
rtr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t status)
{
    lisp_rtr_t * rtr = lisp_rtr_cast(dev);
    iface_locators * if_loct = NULL;
    locator_t * locator = NULL;
    map_local_entry_t * map_loc_e = NULL;
    glist_entry_t * it = NULL;
    glist_entry_t * it_m = NULL;

    if_loct = (iface_locators *)shash_lookup(rtr->tr.iface_locators_table,iface_name);
    if (if_loct  == NULL){
        OOR_LOG(LDBG_2, "rtr_if_status_change: Iface %s not found in the list of ifaces for rtr device",
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
        rtr->tr.fwd_policy->updated_map_loc_inf(rtr->tr.fwd_policy_dev_parm,map_loc_e);
        notify_datap_rm_fwd_from_entry(&(rtr->super),map_local_entry_eid(map_loc_e),TRUE);
    }

    rtr->tr.fwd_policy->updated_map_loc_inf(rtr->tr.fwd_policy_dev_parm,rtr->all_locs_map);
    notify_datap_reset_all_fwd(&(rtr->super));

    return (GOOD);
}

int
rtr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status)
{
    lisp_rtr_t * rtr = lisp_rtr_cast(dev);
    iface_locators * if_loct = NULL;
    glist_t * loct_list = NULL;
    glist_t * locators = NULL;
    locator_t * locator = NULL;
    mapping_t * mapping = NULL;
    int afi = AF_UNSPEC;
    glist_entry_t * it = NULL;
    glist_entry_t * it_aux = NULL;
    lisp_addr_t ** prev_addr = NULL;

    if_loct = (iface_locators *)shash_lookup(rtr->tr.iface_locators_table,iface_name);
    if (if_loct  == NULL){
        OOR_LOG(LDBG_2, "rtr_if_addr_update: Iface %s not found in the list of ifaces for rtr device",
                iface_name);
        return (BAD);
    }

    if (old_addr != NULL && lisp_addr_cmp(old_addr, new_addr) == 0){
        return (GOOD);
    }

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
        OOR_LOG(LDBG_2, "rtr_if_addr_update: Afi of the new address not known");
        return (BAD);
    }
    /* Update the address of the affected locators */
    glist_for_each_entry_safe(it,it_aux,locators){
        locator = (locator_t *)glist_entry_data(it);
        /* The locator was not active during init process */
        if (lisp_addr_is_no_addr(locator_addr(locator))==TRUE){

            /* If locator was not active, activate it */
            mapping = map_local_entry_mapping(rtr->all_locs_map);
            if (mapping_has_locator(mapping, locator) == FALSE){
                continue;
            }
            /* Check if exists an active locator with the same address.
             * If it exists, remove not activated locator: Duplicated */

            if (mapping_get_loct_with_addr(mapping,new_addr) != NULL){
                OOR_LOG(LDBG_2, "rtr_if_addr_change: A non active locator is duplicated. Removing it");
                loct_list = mapping_get_loct_lst_with_afi(mapping,LM_AFI_NO_ADDR,0);
                iface_locators_unattach_locator(rtr->tr.iface_locators_table,locator);
                glist_remove_obj_with_ptr(locator,loct_list);
                continue;
            }
            /* Activate locator */
            mapping_activate_locator(mapping,locator,new_addr);
        }else{
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
    mapping = map_local_entry_mapping(rtr->all_locs_map);
    mapping_sort_locators(mapping, new_addr);
    /* Recalculate forwarding info */
    rtr->tr.fwd_policy->updated_map_loc_inf(rtr->tr.fwd_policy_dev_parm,rtr->all_locs_map);
    notify_datap_reset_all_fwd(&(rtr->super));

    return (GOOD);
}

int
rtr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    return (GOOD);
}

static fwd_info_t *
rtr_get_forwarding_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    lisp_rtr_t *rtr = lisp_rtr_cast(dev);
    fwd_info_t  *fwd_info;
    mcache_entry_t *mce = NULL, *mce_petrs = NULL;
    map_local_entry_t *map_loc_e = NULL;
    lisp_addr_t *src_eid, *dst_eid;
    int iidmlen;
    uint8_t native_fwd = FALSE;

    fwd_info = fwd_info_new();
    if(fwd_info == NULL){
        OOR_LOG(LWRN, "tr_get_fwd_entry: Couldn't allocate memory for fwd_info_t");
        return (NULL);
    }

    /* When RTR, iid is obtained from the desencapsulated packet */
    map_loc_e = rtr->all_locs_map;

    if (tuple->iid > 0){
        iidmlen = (lisp_addr_ip_afi(&tuple->src_addr) == AF_INET) ? 32: 128;
        src_eid = lisp_addr_new_init_iid(tuple->iid, &tuple->src_addr, iidmlen);
        dst_eid = lisp_addr_new_init_iid(tuple->iid, &tuple->dst_addr, iidmlen);
    }else{
        src_eid = lisp_addr_clone(&tuple->src_addr);
        dst_eid = lisp_addr_clone(&tuple->dst_addr);
    }

    mce = mcache_lookup(rtr->tr.map_cache, dst_eid);
    if (!mce) {
        /* No map cache entry, initiate map cache miss process */
        OOR_LOG(LDBG_1, "No map cache for EID %s. Sending Map-Request!",
                lisp_addr_to_char(dst_eid));
        handle_map_cache_miss(&rtr->tr, dst_eid, src_eid);
        /* Get the temporal mce created */
        mce = mcache_lookup(rtr->tr.map_cache, dst_eid);
        fwd_info->associated_entry = lisp_addr_clone(mcache_entry_eid(mce));
    } else{
        fwd_info->associated_entry = lisp_addr_clone(mcache_entry_eid(mce));
        if (mcache_entry_active(mce) == NOT_ACTIVE) {
            OOR_LOG(LDBG_2, "Already sent Map-Request for %s. Waiting for reply!",
                    lisp_addr_to_char(dst_eid));
        }
    }


    if (!native_fwd){
        rtr->tr.fwd_policy->get_fwd_info(rtr->tr.fwd_policy_dev_parm,map_loc_e,mce,mce_petrs,tuple, fwd_info);
    }

    /* Assign encapsulated that should be used */
    fwd_info->encap = rtr->tr.encap_type;
    lisp_addr_del(src_eid);
    lisp_addr_del(dst_eid);
    return (fwd_info);
}


inline lisp_rtr_t *
lisp_rtr_cast(oor_ctrl_dev_t *dev)
{
    /* make sure */
    lm_assert(dev->ctrl_class == &rtr_ctrl_class);
    return(CONTAINER_OF(dev, lisp_rtr_t, super));
}

/*************************** PROCESS MESSAGES ********************************/


static int
rtr_recv_enc_ctrl_msg(lisp_rtr_t *rtr, lbuf_t *msg, uconn_t *ext_uc, void **ecm_hdr, uconn_t *int_uc)
{
    packet_tuple_t inner_tuple;

    *ecm_hdr = lisp_msg_pull_ecm_hdr(msg);
    if (ECM_SECURITY_BIT(*ecm_hdr)){
        switch (lisp_ecm_auth_type(msg)){
        case RTR_AUTH_DATA:
            if (rtr_proc_rtr_auth_data(rtr,msg,&ext_uc->ra)!=GOOD){
                return (BAD);
            }
            break;
        default:
            OOR_LOG(LDBG_2, "Unknown ECM auth type %d",lisp_ecm_auth_type(msg));
            return (BAD);
        }
    }

    /* Check if the internal IP and UDP has been already processed (in the security part). If not, process them*/
    if (!lbuf_l3(msg)){
        if (lisp_msg_parse_int_ip_udp(msg) != GOOD) {
            return (BAD);
        }
    }

    pkt_parse_inner_5_tuple(msg, &inner_tuple);
    uconn_init(int_uc, inner_tuple.dst_port, inner_tuple.src_port, &inner_tuple.dst_addr,&inner_tuple.src_addr);
    *ecm_hdr = lbuf_lisp_hdr(msg);
    return (GOOD);
}

static int
rtr_recv_map_request(lisp_rtr_t *rtr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    lisp_addr_t *seid, *deid;
    glist_t *itr_rlocs = NULL;
    void *mreq_hdr, *mrep_hdr;
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

    if (!MREQ_RLOC_PROBE(mreq_hdr) && !MREQ_SMR(mreq_hdr)){
        OOR_LOG(LDBG_1, "RTR receive a Map Request without Probe or SMR bit. Discarding!");
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
        lisp_msg_put_neg_mapping(mrep, deid, 0, ACT_NO_ACTION, A_NO_AUTHORITATIVE);

        /* XXX HOW to process Rloc Probing */

        /* If packet is a Solicit Map Request, process it */
        if (lisp_addr_lafi(seid) != LM_AFI_NO_ADDR && MREQ_SMR(mreq_hdr)) {
            if(tr_reply_to_smr(&rtr->tr,deid,seid) != GOOD) {
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
    if (map_reply_fill_uconn(&rtr->tr, itr_rlocs, int_uc, ext_uc, &send_uc) != GOOD){
        OOR_LOG(LDBG_1, "Couldn't send Map Reply, no itr_rlocs reachable");
        goto err;
    }
    OOR_LOG(LDBG_1, "Sending %s", lisp_msg_hdr_to_char(mrep));
    send_msg(&rtr->super, mrep, &send_uc);

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
rtr_recv_map_reply(lisp_rtr_t *rtr, lbuf_t *buf, uconn_t *uc)
{
    return (tr_recv_map_reply(&rtr->tr,buf,uc));
}

static int
rtr_recv_map_register(lisp_rtr_t *rtr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    lbuf_t b;
    void *hdr = NULL, *new_ecm_hdr;
    oor_timer_t *timer;
    lisp_addr_t *ms_addr;
    nat_loct_conn_inf_t *conn_info;
    uconn_t fwd_uc;
    rtr_ms_node_t *ms_node;

    b = *buf;
    hdr = lisp_msg_pull_hdr(&b);

    if (!ecm_hdr){
        OOR_LOG(LDBG_1, "RTR doesn't accept Map Registers. Discarding message ...");
        return (BAD);
    }

    if (ECM_RTR_PROCESS_BIT(ecm_hdr) == 0 && MREG_RBIT(hdr) == 0){
        OOR_LOG(LDBG_1, "Received a Map Register without the R bit set. Discarding message ...");
        return (BAD);
    }

    ms_addr = &int_uc->la;
    ms_node = shash_lookup(rtr->rtr_ms_table, lisp_addr_to_char(ms_addr));
    if (!ms_node){
        OOR_LOG(LDBG_1, "Unknown Map Server for the received Encap Map Register . Discarding message ...");
        return (BAD);
    }

    if(ms_node->nat_version == NAT_PREV_DRAFT_4){
        /* Forward Map Register (no Encap Map Reg) to the Map Server */
        lbuf_point_to_lisp(&b);
    }else{
        lbuf_point_to_l3(&b);
        new_ecm_hdr = lisp_msg_push_encap_lisp_header(&b);
        ECM_RTR_RELAYED_BIT(new_ecm_hdr)=1;
    }
    uconn_init(&fwd_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, ms_addr);
    send_msg(&rtr->super, &b, &fwd_uc);

    /* We store the udp connection in the timer. This will be used when receiving the Map
     * Notify to create the nat locator data. If the timer expires without receiving Map Notify,
     * this structure is removed */
    conn_info = nat_loct_con_info_new_init(ext_uc,int_uc);

    timer = oor_timer_with_nonce_new(RTR_NAT_MAP_REG_NOTIFY_TIMER, rtr, rtr_expires_map_reg_cb,
            conn_info,(oor_timer_del_cb_arg_fn)nat_loct_con_info_destroy);
    htable_ptrs_timers_add(ptrs_to_timers_ht, conn_info, timer);
    htable_nonces_insert(nonces_ht, MREG_NONCE(hdr),oor_timer_nonces(timer));
    oor_timer_start(timer, OOR_INITIAL_MRQ_TIMEOUT);

    return (GOOD);
}

static int
rtr_recv_map_notify(lisp_rtr_t *rtr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    void *hdr, *auth_hdr;
    nonces_list_t *nonces_lst;
    oor_timer_t *timer;
    lbuf_t b;
    int res, i;
    glist_t *recv_map_lst, *timer_lst;
    glist_entry_t *map_it;
    mcache_entry_t *mce;
    mapping_t *recv_map,*map;
    locator_t *probed = NULL;
    lisp_addr_t *eid;
    nat_loct_conn_inf_t *loct_conn_inf;
    lisp_site_id site_id;
    lisp_xtr_id xtr_id;
    uint32_t iid;
    uconn_t fwd_uc;
    rloc_nat_data_t * rloc_nat_info;
    timer_rtr_nat_loc_exp_arg *timer_arg;
    rtr_ms_node_t *ms_node;


    b = *buf;
    hdr = lisp_msg_pull_hdr(&b);

    /* Check NONCE */
    nonces_lst = htable_nonces_lookup(nonces_ht, MNTF_NONCE(hdr));
    if (!nonces_lst){
        OOR_LOG(LDBG_1, "No Map Register resent with nonce: %"PRIx64
                " Discarding message!", MNTF_NONCE(hdr));
        return(BAD);
    }
    timer = nonces_list_timer(nonces_lst);
    loct_conn_inf = (nat_loct_conn_inf_t *)oor_timer_cb_argument(timer);

    ms_node = shash_lookup(rtr->rtr_ms_table,lisp_addr_to_char(loct_conn_inf->ms_addr));
    if (!ms_node){
        OOR_LOG(LDBG_1, "RTR: Unknown Map Server %s. Discarding message!",
                lisp_addr_to_char(loct_conn_inf->ms_addr));
        return(BAD);
    }

    if (MNTF_I_BIT(hdr) == 0){
        OOR_LOG(LDBG_1,"Received Map Notify without I bit enabled. Discarding message");
        return (BAD);
    }

    /* NAT draft version 3 */
    if (!ecm_hdr){
        if (MNTF_R_BIT(hdr) == 0){
            OOR_LOG(LDBG_1,"Received Map Notify without R bit enabled. Discarding message");
            return (BAD);
        }

        /* Find the RTR auth_hdr and validate RTR authentication*/
        auth_hdr = hdr + lbuf_size(buf) - auth_data_get_len_for_type(HMAC_SHA_1_96) - sizeof(auth_record_hdr_t);
        res = lisp_msg_check_auth_field(buf,auth_hdr, ms_node->key);
        if (res != GOOD){
            OOR_LOG(LDBG_1, "Map-Notify message is invalid");
            return(BAD);
        }
    }else {
        if (ECM_RTR_PROCESS_BIT(ecm_hdr) == 0){
            OOR_LOG(LDBG_1,"Received Encap Map Notify without R bit enabled. Discarding message");
            return (BAD);
        }
    }

    lisp_msg_pull_auth_field(&b);

    recv_map_lst = glist_new_managed((glist_del_fct)mapping_del);
    for (i = 0; i < MREG_REC_COUNT(hdr); i++) {
        recv_map = mapping_new();
        if (lisp_msg_parse_mapping_record(&b, recv_map, &probed) != GOOD) {
            glist_destroy(recv_map_lst);
            OOR_LOG(LDBG_1,"rtr_recv_map_notify: Error parsing a record of the Map Notify."
                    " Discarding message");
            return (BAD);
        }
        /* To be sure that we store the network address and not a IP-> 10.0.0.0/24 instead of 10.0.0.1/24 */
        eid = mapping_eid(recv_map);
        pref_conv_to_netw_pref(eid);
        /* Add mapping to list to post process */
        glist_add(recv_map,recv_map_lst);
    }
    lisp_msg_parse_xtr_id_site_id(&b, &xtr_id, &site_id);

    /* Process received mappings */
    glist_for_each_entry(map_it,recv_map_lst){
        recv_map = (mapping_t *)glist_entry_data(map_it);
        eid = mapping_eid(recv_map);
        /* Find if the mcache entry exist, if not create it */
        mce = mcache_lookup_exact(rtr->tr.map_cache, eid);
        if (!mce){
            map = mapping_new_init(eid);
            mce = tr_mcache_add_mapping(&rtr->tr, map, MCE_DYNAMIC, ACTIVE);
            /* Add specific data */
            mce->dev_specific_data = mc_rtr_data_nat_new();
            mce->dev_data_del = (dev_specific_data_del_fct)mc_rtr_data_destroy;
        }

        res = mc_rtr_data_mapping_update(mce, recv_map, loct_conn_inf->rtr_addr,loct_conn_inf->pub_xtr_addr,
                loct_conn_inf->pub_xtr_port,loct_conn_inf->priv_xtr_addr,&xtr_id);
        /* If the mapping has changed, reset the entries of the data plane associated with
         * the affected cache entry */
        if (res == UPDATED){
            rtr->tr.fwd_policy->updated_map_cache_inf(rtr->tr.fwd_policy_dev_parm,mce);
            notify_datap_rm_fwd_from_entry(&rtr->super, eid, FALSE);
        }
        /* Configure timers */

        rloc_nat_info = mc_rtr_data_get_rloc_nat_data(mce, &xtr_id, loct_conn_inf->priv_xtr_addr);
        if (!rloc_nat_info){
            OOR_LOG(LDBG_1,"rtr_recv_map_notify: RLOC nat info not found. It should never happen");
            continue;
        }
        // Get timer associated to it or create it if it doesn't exist yet
        timer_lst = htable_ptrs_timers_get_timers(ptrs_to_timers_ht,rloc_nat_info);
        if (!timer_lst){
            timer_arg = timer_rtr_nat_loc_exp_arg_new_init(mce, rloc_nat_info);
            timer = oor_timer_without_nonce_new(RTR_NAT_LOCT_EXPIRE_TIMER,rtr, (oor_timer_callback_t)rtr_nat_loc_expire_cb,
                    timer_arg, (oor_timer_del_cb_arg_fn)timer_rtr_nat_loc_exp_arg_free);
            htable_ptrs_timers_add(ptrs_to_timers_ht,rloc_nat_info, timer);
        }else{
            // This type of object only have one timer associated with it.
            timer = glist_first_data(timer_lst);
        }
        /* XXX We maintain the entry 30 more seconds than the MS site expiration time to avoid to request for the expired entry
         * due to a map cahce miss before the entry expires in the Map Server */
        oor_timer_start(timer, MS_SITE_EXPIRATION + 30);
    }
    glist_destroy(recv_map_lst);

    /* Prepare the Map Notify to send to the ETR */
    /* NAT draft version 3 */
    if (!ecm_hdr){
        // Set the authentication RTR address to 0 and remove the size of previous authentication
        lisp_msg_fill_auth_data(&b,auth_hdr, NO_KEY, NULL);
        lbuf_set_size(&b,lbuf_size(&b) - auth_data_get_len_for_type(ms_node->key_type));
        // As we doesn't have IP and UDP header of the received map Notify, we should recreate it
        lbuf_point_to_lisp(&b);
        // XXX we lose some fields of the headers but it is the best we can do
        pkt_push_inner_udp_and_ip(&b, int_uc->lp, int_uc->rp, lisp_addr_ip(&int_uc->ra), lisp_addr_ip(loct_conn_inf->priv_xtr_addr));
    }else{

    }




    /* Resend Map Notify as a data Map Notify -> Encapsualate message in a data packet */
    iid = MAX_IID;
    lbuf_point_to_l3(&b);

    lisp_data_push_hdr(&b, iid);
    uconn_init(&fwd_uc, LISP_CONTROL_PORT, loct_conn_inf->pub_xtr_port, loct_conn_inf->rtr_addr,loct_conn_inf->pub_xtr_addr);
    res = send_msg(&rtr->super, &b, &fwd_uc);

    /* Program the expiration time of the NAT information for the locator */

    return (res);
}

/******************************* TIMERS **************************************/
/************************ RTR_NAT_LOCT_EXPIRE_TIMER arg***********************/

static timer_rtr_nat_loc_exp_arg *
timer_rtr_nat_loc_exp_arg_new_init(mcache_entry_t *mce, rloc_nat_data_t *rloc_nat_data)
{
    timer_rtr_nat_loc_exp_arg *timer_arg;

    timer_arg = xmalloc(sizeof(timer_rtr_nat_loc_exp_arg));
    if (!timer_arg){
        OOR_LOG(LDBG_2,"timer_rtr_nat_loc_exp_arg_new_init: Couldn't allocate memory for a "
                "timer_rtr_nat_loc_exp_arg");
        return (NULL);
    }

    timer_arg->mce = mce;
    timer_arg->rloc_nat_data = rloc_nat_data;

    return(timer_arg);
}

static void
timer_rtr_nat_loc_exp_arg_free(timer_rtr_nat_loc_exp_arg * timer_arg)
{
    free(timer_arg);
}

/* Remove an rtr nat loc . If the cache entry does not have associated any nat loc,
 * remove the cache entry */
int
rtr_nat_loc_expire_cb(oor_timer_t *timer)
{
    lisp_rtr_t *rtr = (lisp_rtr_t *)oor_timer_owner(timer);
    timer_rtr_nat_loc_exp_arg *timer_arg = oor_timer_cb_argument(timer);
    mcache_entry_t *mce = timer_arg->mce;
    mc_rm_rtr_rloc_nat_data(mce, timer_arg->rloc_nat_data);

    if (mapping_locator_count(mcache_entry_mapping(mce)) == 0){
        OOR_LOG(LDBG_1,"Got expiration for EID %s", lisp_addr_to_char(mcache_entry_eid(mce)));
        tr_mcache_remove_entry(&rtr->tr, mce);
    }else{
        /* Notify of the change of the map cache entry to the data plane */
        notify_datap_rm_fwd_from_entry(&rtr->super,mcache_entry_eid(mce),FALSE);
    }
    return (GOOD);
}

/**************************** AUXILIAR FUNCTIONS *****************************/
inline nat_loct_conn_inf_t *
nat_loct_con_info_new_init(uconn_t *ext_uc, uconn_t *int_uc)
{
    nat_loct_conn_inf_t *loct_conn_inf = xzalloc(sizeof (nat_loct_conn_inf_t));
    if (!loct_conn_inf){
        return (NULL);
    }
    loct_conn_inf->priv_xtr_addr = lisp_addr_clone(&int_uc->ra);
    loct_conn_inf->pub_xtr_addr = lisp_addr_clone(&ext_uc->ra);
    loct_conn_inf->rtr_addr = lisp_addr_clone(&ext_uc->la);
    loct_conn_inf->ms_addr = lisp_addr_clone(&int_uc->la);
    loct_conn_inf->pub_xtr_port = ext_uc->rp;

    return(loct_conn_inf);
}

inline void
nat_loct_con_info_destroy(nat_loct_conn_inf_t *loct_conn_inf)
{
    lisp_addr_del(loct_conn_inf->priv_xtr_addr);
    lisp_addr_del(loct_conn_inf->pub_xtr_addr);
    lisp_addr_del(loct_conn_inf->rtr_addr);
    lisp_addr_del(loct_conn_inf->ms_addr);
    free(loct_conn_inf);
}

int
rtr_expires_map_reg_cb(oor_timer_t *timer)
{
    nat_loct_conn_inf_t *conn_info;
    conn_info = (nat_loct_conn_inf_t *)oor_timer_cb_argument(timer);
    stop_timers_from_obj(conn_info,ptrs_to_timers_ht,nonces_ht);
    // Argument is removed in stop_timer
    return (GOOD);
}

int
rtr_proc_rtr_auth_data(lisp_rtr_t *rtr,lbuf_t *msg, lisp_addr_t *ms_addr)
{
    rtr_ms_node_t *ms_node;
    void *ecm_auth_hdr;

    ms_node = shash_lookup(rtr->rtr_ms_table,lisp_addr_to_char(ms_addr));
    if (!ms_node){
        OOR_LOG(LDBG_1, "RTR: Unknown Map Server %s. Discarding message!",
                lisp_addr_to_char(ms_addr));
        return(BAD);
    }
    ecm_auth_hdr = lisp_msg_pull_rtr_auth_field(msg);

    if (lisp_msg_parse_int_ip_udp(msg) != GOOD) {
        return (BAD);
    }

    if (lisp_msg_check_rtr_auth_data(msg, ecm_auth_hdr, ms_node->key) != GOOD){
        OOR_LOG(LDBG_1, "RTR: Invalid RTR authentication field");
        return(BAD);
    }
    return (GOOD);
}

/************************** rtr_ms_node_t functions **************************/

rtr_ms_node_t *
rtr_ms_node_new_init(lisp_addr_t *addr, char *key, nat_version version)
{
    rtr_ms_node_t *ms_node;
    ms_node = xzalloc(sizeof(rtr_ms_node_t));
    if (!ms_node){
        OOR_LOG(LWRN,"rtr_ms_node_new_init: Couldn't allocate memory for a rtr_ms_node_t structure");
        return(NULL);
    }
    ms_node->addr = lisp_addr_clone(addr);
    ms_node->key = strdup(key);
    ms_node->key_type = HMAC_SHA_1_96;
    ms_node->nat_version = version;

    return (ms_node);
}

void
rtr_ms_node_destroy(rtr_ms_node_t *ms_node)
{
    lisp_addr_del(ms_node->addr);
    free(ms_node->key);
    free(ms_node);
}

char *
rtr_ms_node_to_char(rtr_ms_node_t *ms_node)
{
    static char buf[500];
    size_t buf_size = sizeof(buf);
    if (ms_node == NULL){
        sprintf(buf, "_NULL_");
        return (buf);
    }

    *buf = '\0';
    snprintf(buf + strlen(buf),buf_size - strlen(buf),"MS addr: %s, ", lisp_addr_to_char(ms_node->addr));
    snprintf(buf + strlen(buf),buf_size - strlen(buf),"Key: ******, ");
    snprintf(buf + strlen(buf),buf_size - strlen(buf),"Nat draft version: %s",
            ms_node->nat_version == NAT_PREV_DRAFT_4 ? "< 4" : ">4");
    return (buf);
}


