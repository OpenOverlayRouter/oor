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

#include "lisp_ddt_mr.h"
#include "../defs.h"
#include "../lib/cksum.h"
#include "../lib/oor_log.h"
#include "../lib/pointers_table.h"
#include "../lib/prefixes.h"
#include "../lib/timers_utils.h"


static int ddt_mr_recv_map_request(lisp_ddt_mr_t *, lbuf_t *, void *, uconn_t*, uconn_t *);
static int ddt_mr_recv_map_referral(lisp_ddt_mr_t *, lbuf_t *, void *, uconn_t*, uconn_t *);
static int ddt_mr_recv_msg(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);
static inline lisp_ddt_mr_t *lisp_ddt_mr_cast(oor_ctrl_dev_t *dev);
static int pending_request_do_cycle(oor_timer_t *timer);
static int mref_mc_entry_expiration_timer_cb(oor_timer_t *t);
static void mref_mc_entry_start_expiration_timer(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *mce);
static void mref_mc_entry_start_expiration_timer2(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *mce, int time);

timer_pendreq_cycle_argument *timer_pendreq_cycle_arg_new_init(ddt_pending_request_t *pendreq,lisp_ddt_mr_t *mapres, lisp_addr_t *localaddress);

void timer_pendreq_cycle_arg_free(timer_pendreq_cycle_argument * timer_arg);

/* Called when the timer associated with an EID entry expires. */
static int
mref_mc_entry_expiration_timer_cb(oor_timer_t *timer)
{
    ddt_mcache_entry_t *mce = oor_timer_cb_argument(timer);
    mref_mapping_t *map = ddt_mcache_entry_mapping(mce);
    lisp_addr_t *addr = mref_mapping_eid(map);
    lisp_ddt_mr_t *ddt_mr = oor_timer_owner(timer);

    OOR_LOG(LDBG_1,"Got expiration for EID %s", lisp_addr_to_char(addr));
    mdb_remove_entry(ddt_mr->mref_cache_db, cache_entry_xeid(mce));
    return(GOOD);
}

static void
mref_mc_entry_start_expiration_timer(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *mce)
{
    int time = mref_mapping_ttl(ddt_mcache_entry_mapping(mce))*60;
    mref_mc_entry_start_expiration_timer2(ddt_mr, mce, time);
}

static void
mref_mc_entry_start_expiration_timer2(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *mce, int time)
{
    /* Expiration cache timer */
    oor_timer_t *timer;

    timer = oor_timer_create(EXPIRE_MAP_CACHE_TIMER);
    oor_timer_init(timer,ddt_mr,mref_mc_entry_expiration_timer_cb,mce,NULL,NULL);
    htable_ptrs_timers_add(ptrs_to_timers_ht, mce, timer);

    oor_timer_start(timer, time);

    if (time > 60){
        OOR_LOG(LDBG_1,"The mapping cache entry for EID %s will expire in %d minutes.",
                lisp_addr_to_char(mref_mapping_eid(ddt_mcache_entry_mapping(mce))),time/60);
    }else{
        OOR_LOG(LDBG_1,"The mapping cache entry for EID %s will expire in %d seconds.",
                lisp_addr_to_char(mref_mapping_eid(ddt_mcache_entry_mapping(mce))),time);
    }
}

static int
get_etr_from_lcaf(lisp_addr_t *laddr, lisp_addr_t **dst)
{
    lcaf_addr_t *lcaf = NULL;
    elp_node_t *enode;

    lcaf = lisp_addr_get_lcaf(laddr);
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_EXPL_LOC_PATH:
        /* we're looking for the ETR, so the destination is the last elp hop */
        enode = glist_last_data(lcaf_elp_node_list(lcaf));
        *dst = enode->addr;
        break;
    default:
        *dst = NULL;
        OOR_LOG(LDBG_1, "get_locator_from_lcaf: Type % not supported!, ",
                lcaf_addr_get_type(lcaf));
        return (BAD);
    }
    return (GOOD);
}

static int
ddt_mr_recv_map_request(lisp_ddt_mr_t *ddt_mr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{

    lisp_addr_t *   seid        = NULL;
    lisp_addr_t *   deid        = NULL;
    glist_t *       itr_rlocs   = NULL;
    glist_t *       referral_addrs =NULL;
    void *          mreq_hdr    = NULL;
    //void *          mref_hdr    = NULL;
    //mref_mapping_record_hdr_t *  rec            = NULL;
    int             throughroot;
    int             i;
    lbuf_t *        mrep        = NULL;
    lbuf_t  b;
    ddt_pending_request_t *    pendreq            = NULL;
    ddt_mcache_entry_t *       cacheentry           = NULL;
    ddt_original_request_t *original = NULL;
    oor_timer_t *timer;
    timer_pendreq_cycle_argument *timer_arg;

    // local copy of the buf that can be modified
    b = *buf;

    seid = lisp_addr_new();
    throughroot = NOT_GONE_THROUGH_ROOT;

    OOR_LOG(LDBG_1, "int_uc-la: %s\nint_uc-ra: %s\next_uc-la: %s\next_uc-ra: %s", lisp_addr_to_char(&int_uc->la)
            , lisp_addr_to_char(&int_uc->ra), lisp_addr_to_char(&ext_uc->la), lisp_addr_to_char(&ext_uc->ra));



    mreq_hdr = lisp_msg_pull_hdr(&b);

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }


    OOR_LOG(LDBG_1, " src-eid: %s", lisp_addr_to_char(seid));
    if (MREQ_RLOC_PROBE(mreq_hdr)) {
        OOR_LOG(LDBG_2, "Probe bit set. Discarding!");
        return(BAD);
    }

    if (MREQ_SMR(mreq_hdr)) {
        OOR_LOG(LDBG_2, "SMR bit set. Discarding!");
        return(BAD);
    }



    // PROCESS ITR RLOCs
    itr_rlocs = laddr_list_new();
    lisp_msg_parse_itr_rlocs(&b, itr_rlocs);

    for (i = 0; i < MREQ_REC_COUNT(mreq_hdr); i++) {
        deid = lisp_addr_new();

        // PROCESS EID REC
        if (lisp_msg_parse_eid_rec(&b, deid) != GOOD) {
            goto err;
        }

        // CHECK IF PENDING REQUEST EXISTS FOR THE EID
        pendreq = mdb_lookup_entry_exact(ddt_mr->pending_requests_db, deid);
        if (pendreq) {
            // add the original request to the pending request's list of
            // original requests, it will substitute a previous instance of itself if necessary
            original = xzalloc(sizeof(ddt_original_request_t));
            original->nonce = MREQ_NONCE(mreq_hdr);
            original->source_address = lisp_addr_clone(seid);
            original->itr_locs = itr_rlocs;
            pending_request_add_original(pendreq, original);

        }else{
            // CHECK IF MATCH IN CACHE
            cacheentry = mdb_lookup_entry(ddt_mr->mref_cache_db, deid);
            if (!cacheentry) {
                cacheentry = ddt_mr->root_entry;
                throughroot = GONE_THROUGH_ROOT;
            }
            // check match type and act depending on it
            switch (ddt_mcache_entry_type(cacheentry)){
            case LISP_ACTION_DELEGATION_HOLE:
                // send negative Map-Reply
                //TODO check what action it should really have
                mrep = lisp_msg_neg_mrep_create(deid, 15, ACT_NO_ACTION,
                        A_AUTHORITATIVE, MREQ_NONCE(mreq_hdr));
                send_msg(&ddt_mr->super, mrep, ext_uc);
                lisp_msg_destroy(mrep);
                break;

            case LISP_ACTION_MS_ACK:
                // forward DDT Map-Request to Map Server
                // TODO check if this really does as intended
                referral_addrs = mref_mapping_get_ref_addrs(cacheentry->mapping);
                glist_entry_t *it;
                uconn_t fwd_uc;

                /* Set buffer to forward the encapsulated message*/
                lbuf_point_to_lisp_hdr(&b);

                glist_for_each_entry(it,referral_addrs){
                    lisp_addr_t *drloc = NULL;
                    lisp_addr_t *addr = glist_entry_data(it);

                    drloc = lisp_addr_get_ip_addr(addr);

                    if (lisp_addr_lafi(drloc) == LM_AFI_LCAF) {
                        get_etr_from_lcaf(drloc, &drloc);
                    }

                    uconn_init(&fwd_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
                    send_msg(&ddt_mr->super, &b, &fwd_uc);
                }
                break;

            default:
                pendreq = ddt_pending_request_init(deid);
                OOR_LOG(LDBG_1, "Pending request created. Target address is %s",
                        lisp_addr_to_char(pendreq->target_address));
                if(throughroot == GONE_THROUGH_ROOT){
                    pending_request_set_root_cache_entry(pendreq, ddt_mr);
                }else{
                    pending_request_set_new_cache_entry(pendreq, cacheentry);
                }

                OOR_LOG(LDBG_1, "Cache entry set. Number of rlocs:%d",
                                glist_size(pendreq->current_delegation_rlocs));

                original = xzalloc(sizeof(ddt_original_request_t));
                original->nonce = MREQ_NONCE(mreq_hdr);
                original->source_address = lisp_addr_clone(seid);
                original->itr_locs = itr_rlocs;
                pending_request_add_original(pendreq, original);
                ddt_mr_add_pending_request(ddt_mr, pendreq);



                timer_arg = timer_pendreq_cycle_arg_new_init(pendreq,ddt_mr,lisp_addr_clone(&ext_uc->la));
                timer = oor_timer_with_nonce_new(PENDING_REQUEST_CYCLE_TIMER,ddt_mr,pending_request_do_cycle,
                        timer_arg,(oor_timer_del_cb_arg_fn)timer_pendreq_cycle_arg_free);
                htable_ptrs_timers_add(ptrs_to_timers_ht,pendreq,timer);
                pending_request_do_cycle(timer);
            }
        }
    }

    glist_destroy(itr_rlocs);
    lisp_addr_del(seid);

    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_del(deid);
    lisp_addr_del(seid);
    return(BAD);
}

static int
ddt_mr_recv_map_referral(lisp_ddt_mr_t *ddt_mr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    //TODO map referral logic here
    return (GOOD);
}


int
ddt_mr_add_cache_entry(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *entry)
{
    if (!entry)
        return(BAD);

    if(!mdb_add_entry(ddt_mr->mref_cache_db, cache_entry_xeid(entry), entry))
        return(BAD);

    mref_mc_entry_start_expiration_timer(ddt_mr, entry);

    return(GOOD);
}



int
ddt_mr_add_pending_request(lisp_ddt_mr_t *ddt_mr, ddt_pending_request_t *request)
{
    if (!request) {
        return(BAD);
    }

    if (!mdb_add_entry(ddt_mr->pending_requests_db, pending_request_xeid(request), request))
        return(BAD);
    return(GOOD);
}

int
ddt_mr_set_root_entry(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *root_entry){

    ddt_mr->root_entry = root_entry;

    return (GOOD);
}


void
ddt_mr_dump_root_entry(lisp_ddt_mr_t *ddtmr, int log_level)
{
    if (is_loggable(log_level) == FALSE){
        return;
    }
    ddt_mcache_entry_t *entry = NULL;

    OOR_LOG(log_level,"****************    DDT Map-Resolver    ******************\n");
    OOR_LOG(log_level,"**************** Map-Referral cache(DDT-Root) ******************\n");
        entry = ddtmr->root_entry;
        ddt_map_cache_entry_dump(entry, log_level);
    OOR_LOG(log_level,"*******************************************************\n");

}


static inline lisp_ddt_mr_t *
lisp_ddt_mr_cast(oor_ctrl_dev_t *dev)
{
    /* make sure */
    lm_assert(dev->ctrl_class == &ddt_mr_ctrl_class);
    return(CONTAINER_OF(dev, lisp_ddt_mr_t, super));
}

static int
ddt_mr_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc)
{
    int ret = 0;
    lisp_msg_type_e type;
    lisp_ddt_mr_t *ddt_mr;
    void *ecm_hdr = NULL;
    uconn_t *int_uc, *ext_uc = NULL, aux_uc;
    packet_tuple_t inner_tuple;

    ddt_mr = lisp_ddt_mr_cast(dev);
    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {

        if (lisp_msg_ecm_decap(msg, &uc->rp) != GOOD) {
           return (BAD);
        }
        type = lisp_msg_type(msg);
        pkt_parse_inner_5_tuple(msg, &inner_tuple);
        uconn_init(&aux_uc, inner_tuple.dst_port, inner_tuple.src_port, &inner_tuple.dst_addr,&inner_tuple.src_addr);
        ext_uc = uc;
        int_uc = &aux_uc;
        ecm_hdr = lbuf_lisp_hdr(msg);
    }else{
        int_uc = uc;
    }


     switch(type) {
     case LISP_MAP_REQUEST:
         ret = ddt_mr_recv_map_request(ddt_mr, msg, ecm_hdr, int_uc, ext_uc);
         break;
     case LISP_MAP_REFERRAL:
         ret = ddt_mr_recv_map_referral(ddt_mr, msg, ecm_hdr, int_uc, ext_uc);
     case LISP_MAP_REGISTER:
     case LISP_MAP_REPLY:
     case LISP_MAP_NOTIFY:
     case LISP_INFO_NAT:
         OOR_LOG(LDBG_3, "DDT-Map Resolver: Received control message with type %d."
                 " Discarding!", type);
         break;
     default:
         OOR_LOG(LDBG_3, "DDT-Map Resolver: Received unidentified type (%d) control "
                 "message", type);
         ret = BAD;
         break;
     }

     if (ret != GOOD) {
         OOR_LOG(LDBG_1, "DDT-Map Resolver: Failed to process  control message");
         return(BAD);
     } else {
         OOR_LOG(LDBG_3, "DDT-Map Resolver: Completed processing of control message");
         return(ret);
     }
}


int
ddt_mr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t state)
{
    return (GOOD);
}
int
ddt_mr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status)
{
    return (GOOD);
}
int
ddt_mr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    return (GOOD);
}

fwd_info_t *
ddt_mr_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    return (NULL);
}

static oor_ctrl_dev_t *
ddt_mr_ctrl_alloc()
{
    lisp_ddt_mr_t *ddt_mr;
    ddt_mr = xzalloc(sizeof(lisp_ddt_mr_t));
    return(&ddt_mr->super);
}

static int
ddt_mr_ctrl_construct(oor_ctrl_dev_t *dev)
{
    lisp_ddt_mr_t *ddt_mr = lisp_ddt_mr_cast(dev);

    ddt_mr->mref_cache_db = mdb_new();
    ddt_mr->pending_requests_db = mdb_new();

    if (!ddt_mr->mref_cache_db || !ddt_mr->pending_requests_db) {
        return(BAD);
    }

    OOR_LOG(LDBG_1, "Finished Constructing DDT Map Resolver");

    return(GOOD);
}

static void
ddt_mr_ctrl_destruct(oor_ctrl_dev_t *dev)
{
	lisp_ddt_mr_t *ddt_mr = lisp_ddt_mr_cast(dev);
    mdb_del(ddt_mr->mref_cache_db, (mdb_del_fct)mref_cache_entry_del);
    mdb_del(ddt_mr->pending_requests_db, (mdb_del_fct)ddt_pending_request_del);
}

void
ddt_mr_ctrl_dealloc(oor_ctrl_dev_t *dev)
{
    lisp_ddt_mr_t *ddt_mr = lisp_ddt_mr_cast(dev);
    OOR_LOG(LDBG_1, "Freeing DDT Map Resolver ...");
    free(ddt_mr);
}

void
ddt_mr_ctrl_run(oor_ctrl_dev_t *dev)
{
    lisp_ddt_mr_t *ddt_mr = lisp_ddt_mr_cast(dev);

    OOR_LOG (LDBG_1, "****** Summary of the configuration ******");
    ddt_mr_dump_root_entry(ddt_mr, LDBG_1);

    OOR_LOG(LDBG_1, "Starting DDT Map Resolver ...");
}



ddt_pending_request_t
*ddt_pending_request_init(lisp_addr_t *target_address)
{
    ddt_pending_request_t *request = xzalloc(sizeof(ddt_pending_request_t));;
    request-> target_address = target_address;
    request-> original_requests = glist_new();
    request-> gone_through_root = NOT_GONE_THROUGH_ROOT;

    return(request);
}

void
pending_request_set_new_cache_entry(ddt_pending_request_t *pendreq, ddt_mcache_entry_t *current_cache_entry)
{
    pendreq-> current_cache_entry = current_cache_entry;
    pendreq-> current_delegation_rlocs = mref_mapping_get_ref_addrs(ddt_mcache_entry_mapping(current_cache_entry));
    pendreq-> current_rloc = NULL;
    pendreq-> retry_number = 0;
}

void
pending_request_set_root_cache_entry(ddt_pending_request_t *pendreq, lisp_ddt_mr_t *mapres)
{
    pendreq-> gone_through_root = GONE_THROUGH_ROOT;
    pendreq-> current_cache_entry = NULL;
    pendreq-> current_delegation_rlocs = mref_mapping_get_ref_addrs(ddt_mcache_entry_mapping(mapres->root_entry));
    pendreq-> current_rloc = NULL;
    pendreq-> retry_number = 0;
}

void
pending_request_add_original(ddt_pending_request_t *pending, ddt_original_request_t *original)
{
    glist_entry_t *it = NULL;
    glist_for_each_entry(it,pending->original_requests){
        ddt_original_request_t *request = glist_entry_data(it);
        if(lisp_addr_cmp(request->source_address,original->source_address)==0){
            glist_remove(it,pending->original_requests);
        }
    }
    glist_add(original,pending->original_requests);
}

static int
pending_request_do_cycle(oor_timer_t *timer){

    timer_pendreq_cycle_argument *timer_arg = (timer_pendreq_cycle_argument *)oor_timer_cb_argument(timer);
    nonces_list_t *nonces_list = oor_timer_nonces(timer);
    ddt_pending_request_t *pendreq = timer_arg->pendreq;
    lisp_ddt_mr_t *mapres = timer_arg->mapres;
    uint64_t nonce;
    glist_t *rlocs = NULL;

    OOR_LOG(LDBG_1, "Moving to next rloc");

    // advance the current rloc being used from the list of rlocs
    if(!pendreq->current_rloc){
        pendreq->current_rloc = glist_first(pendreq->current_delegation_rlocs);
    }else{
        if(pendreq->current_rloc == glist_last(pendreq->current_delegation_rlocs)){
            pendreq-> retry_number++;
            pendreq->current_rloc = glist_first(pendreq->current_delegation_rlocs);
        }else{
            pendreq->current_rloc = glist_next(pendreq->current_rloc);
        }
    }

    OOR_LOG(LDBG_1, "Moved to next rloc:");
    OOR_LOG(LDBG_1, lisp_addr_to_char(glist_entry_data(pendreq->current_rloc)));

    // check if max retries exceeded
    if(pendreq->retry_number >= DEFAULT_MAP_REQUEST_RETRIES){
        OOR_LOG(LDBG_1, "Max retries exceeded");
        if(pendreq->gone_through_root == GONE_THROUGH_ROOT){
            OOR_LOG(LDBG_1, "Has gone through root");
            // send negative map reply/es and eliminate pending request
            glist_entry_t *it = NULL;
            OOR_LOG(LDBG_1, "Before foreachentry");
            glist_for_each_entry(it,pendreq->original_requests){
                ddt_original_request_t *request = glist_entry_data(it);
                lbuf_t *        mrep        = NULL;
                uconn_t orig_uc;
                OOR_LOG(LDBG_1, "About to create mrep");
                //TODO check if this action is correct, also the authoritative
                mrep = lisp_msg_neg_mrep_create(pendreq->target_address, 15, ACT_NO_ACTION,
                        A_NO_AUTHORITATIVE, request->nonce);

                OOR_LOG(LDBG_1, "Created mrep");

                lisp_addr_t *drloc = NULL;

                OOR_LOG(LDBG_1, "drloc created");

                OOR_LOG(LDBG_1, "lafi of source address:%d", lisp_addr_lafi(request->source_address));
                OOR_LOG(LDBG_1, lisp_addr_to_char(request->source_address));

                drloc = lisp_addr_get_ip_addr(request->source_address);

                OOR_LOG(LDBG_1, "drloc set");

                if(!drloc){
                    OOR_LOG(LDBG_1, "drloc is null");
                }

                if (lisp_addr_lafi(drloc) == LM_AFI_LCAF) {
                    OOR_LOG(LDBG_1, "entered if");
                    get_etr_from_lcaf(drloc, &drloc);
                }

                OOR_LOG(LDBG_1, "Configured drloc");

                uconn_init(&orig_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
                OOR_LOG(LDBG_1, "Configured uconn");
                send_msg(&mapres->super, mrep, &orig_uc);
                lisp_msg_destroy(mrep);

            }

            OOR_LOG(LDBG_1, "Has sent negative map-replies to original askers");

            ddt_pending_request_del_full(pendreq,mapres);

            OOR_LOG(LDBG_1, "Has eliminated pending request");

        }else{
            OOR_LOG(LDBG_1, "Has not gone through root");
            // switch to the root entry and retry
            pending_request_set_root_cache_entry(pendreq,mapres);
            pending_request_do_cycle(timer);
        }
    }else{
        // send map request to the new rloc and set timer
        rlocs = ctrl_default_rlocs(mapres->super.ctrl);
        lbuf_t *        mreq        = NULL;
        void *mr_hdr = NULL;
        void *ec_hdr = NULL;
        uconn_t dest_uc;

        mreq =lisp_msg_mreq_create(timer_arg->local_address, rlocs, pendreq->target_address);
        mr_hdr = lisp_msg_hdr(mreq);
        nonce = nonce_new();
        MREQ_NONCE(mr_hdr) = nonce;

        lisp_msg_encap(mreq, LISP_CONTROL_PORT, LISP_CONTROL_PORT, timer_arg->local_address, glist_entry_data(pendreq->current_rloc));

        ec_hdr = lisp_msg_ecm_hdr(mreq);
        ECM_DDT_BIT(ec_hdr) = 1;

        lisp_addr_t *drloc, *srloc;

        drloc = lisp_addr_get_ip_addr(glist_entry_data(pendreq->current_rloc));

        if (lisp_addr_lafi(drloc) == LM_AFI_LCAF) {
            get_etr_from_lcaf(drloc, &drloc);
        }

        srloc = lisp_addr_get_ip_addr(timer_arg->local_address);

        if (lisp_addr_lafi(srloc) == LM_AFI_LCAF) {
            get_etr_from_lcaf(srloc, &srloc);
        }
        uconn_init(&dest_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, srloc, drloc);
        send_msg(&mapres->super, mreq, &dest_uc);

        OOR_LOG(LDBG_1, "message sent");

        htable_nonces_reset_nonces_lst(nonces_ht, nonces_list);
        htable_nonces_insert(nonces_ht, nonce, nonces_list);
        oor_timer_start(timer, OOR_INITIAL_MRQ_TIMEOUT);
        OOR_LOG(LDBG_1, "timer reset");

    }
    return (GOOD);

}

void
mref_cache_entry_del(ddt_mcache_entry_t *entry)
{
    if (!entry)
        return;
    ddt_mcache_entry_del(entry);
}


void
ddt_pending_request_del(ddt_pending_request_t *request)
{
    if (!request)
        return;
    stop_timers_from_obj(request,ptrs_to_timers_ht, nonces_ht);
    if (request->target_address)
            free(request->target_address);
    if (request->original_requests)
                free(request->original_requests);
    if (request->current_delegation_rlocs)
                free(request->current_delegation_rlocs);
    if (request->current_rloc)
                free(request->current_rloc);
    free(request);
}

void
ddt_pending_request_del_full(ddt_pending_request_t *request, lisp_ddt_mr_t *mapres)
{
    if (!request)
        return;
    stop_timers_from_obj(request,ptrs_to_timers_ht, nonces_ht);
    mdb_remove_entry(mapres->pending_requests_db,pending_request_xeid(request));
    if (request->target_address)
            free(request->target_address);
    if (request->original_requests)
                free(request->original_requests);
    if (request->current_delegation_rlocs)
                free(request->current_delegation_rlocs);
    if (request->current_rloc)
                free(request->current_rloc);
    free(request);
}

timer_pendreq_cycle_argument *
timer_pendreq_cycle_arg_new_init(ddt_pending_request_t *pendreq,lisp_ddt_mr_t *mapres, lisp_addr_t *localaddress)
{
    timer_pendreq_cycle_argument *timer_arg = xmalloc(sizeof(timer_pendreq_cycle_argument));
    timer_arg->pendreq = pendreq;
    timer_arg->mapres = mapres;
    timer_arg->local_address = localaddress;

    return(timer_arg);
}

void
timer_pendreq_cycle_arg_free(timer_pendreq_cycle_argument * timer_arg)
{
    free(timer_arg);
}

ctrl_dev_class_t ddt_mr_ctrl_class = {
        .alloc = ddt_mr_ctrl_alloc,
        .construct = ddt_mr_ctrl_construct,
        .dealloc = ddt_mr_ctrl_dealloc,
        .destruct = ddt_mr_ctrl_destruct,
        .run = ddt_mr_ctrl_run,
        .recv_msg = ddt_mr_recv_msg,
        .if_link_update = ddt_mr_if_link_update,
        .if_addr_update = ddt_mr_if_addr_update,
        .route_update = ddt_mr_route_update,
        .get_fwd_entry = ddt_mr_get_fwd_entry
};
