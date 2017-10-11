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
#include "lisp_rtr.h"

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
static int rtr_recv_map_request(lisp_rtr_t *rtr, lbuf_t *buf, uconn_t *uc);
static inline int rtr_recv_map_reply(lisp_rtr_t *xtr, lbuf_t *buf, uconn_t *uc);
static int rtr_recv_map_register(lisp_rtr_t *rtr, lbuf_t *buf, uconn_t *uc);
static int rtr_recv_map_notify(lisp_rtr_t *rtr, lbuf_t *buf, uconn_t *uc);



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

    OOR_LOG(LDBG_1,"rtr device destroyed");
}



static void
rtr_run(oor_ctrl_dev_t *dev)
{
    lisp_rtr_t *rtr = lisp_rtr_cast(dev);
    mapping_t * mapping = NULL;

    OOR_LOG(LINF, "\nStarting RTR ...\n");

    if (glist_size(tr_map_resolvers(&rtr->tr)) == 0) {
        OOR_LOG(LCRIT, "**** NO MAP RESOLVER CONFIGURES. You can not request mappings to the mapping system");
        oor_timer_sleep(2);
    }

    OOR_LOG(LINF, "****** Summary of the configuration ******");
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

    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (lisp_msg_ecm_decap(msg, &uc->rp) != GOOD) {
            return (BAD);
        }
        type = lisp_msg_type(msg);
    }

    switch (type) {
    case LISP_MAP_REQUEST:
        ret = rtr_recv_map_request(rtr, msg, uc);
        break;
    case LISP_MAP_REPLY:
        ret = rtr_recv_map_reply(rtr, msg, uc);
        break;
    case LISP_MAP_REGISTER:
        ret = rtr_recv_map_register(rtr, msg, uc);
        break;
    case LISP_MAP_NOTIFY:
        ret = rtr_recv_map_notify(rtr, msg, uc);
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

    //// rtr_iface_event_signaling(rtr, if_loct);

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

    ////rtr_iface_event_signaling(rtr, if_loct);

    return (GOOD);
}

int
rtr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    lisp_rtr_t * rtr = lisp_rtr_cast(dev);
    iface_locators * if_loct = NULL;

    if_loct = (iface_locators *)shash_lookup(rtr->tr.iface_locators_table,iface_name);
    //// rtr_iface_event_signaling(rtr, if_loct);
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
rtr_recv_map_request(lisp_rtr_t *rtr, lbuf_t *buf, uconn_t *uc)
{
    lisp_addr_t *seid, *deid;
    glist_t *itr_rlocs;
    void *mreq_hdr, *mrep_hdr;
    int i = 0;
    lbuf_t *mrep;
    lbuf_t  b;

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
    if (map_reply_fill_uconn(&rtr->tr, itr_rlocs, uc) != GOOD){
        OOR_LOG(LDBG_1, "Couldn't send Map Reply, no itr_rlocs reachable");
        goto err;
    }
    OOR_LOG(LDBG_1, "Sending %s", lisp_msg_hdr_to_char(mrep));
    send_msg(&rtr->super, mrep, uc);

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
rtr_recv_map_register(lisp_rtr_t *rtr, lbuf_t *buf, uconn_t *uc)
{
    return (GOOD);
}

static int
rtr_recv_map_notify(lisp_rtr_t *rtr, lbuf_t *buf, uconn_t *uc)
{
    return (GOOD);
}




