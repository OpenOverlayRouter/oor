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


static int ddt_mr_recv_map_request(lisp_ddt_mr_t *, lbuf_t *, void *, uconn_t*, uconn_t *);
static int ddt_mr_recv_map_referral(lisp_ddt_mr_t *, lbuf_t *, void *, uconn_t*, uconn_t *);
static int ddt_mr_recv_msg(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);
static inline lisp_ddt_mr_t *lisp_ddt_mr_cast(oor_ctrl_dev_t *dev);

static int
ddt_mr_recv_map_request(lisp_ddt_mr_t *ddt_mr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    //TODO recieve map request logic here
    /*
    lisp_addr_t *   seid        = NULL;
    lisp_addr_t *   deid        = NULL;
    glist_t *       itr_rlocs   = NULL;
    void *          mreq_hdr    = NULL;
    void *          mref_hdr    = NULL;
    //mref_mapping_record_hdr_t *  rec            = NULL;
    int             i           = 0;
    lbuf_t *        mref        = NULL;
    lbuf_t  b;
    ddt_authoritative_site_t *    asite            = NULL;
    ddt_delegation_site_t *       dsite           = NULL;

    // local copy of the buf that can be modified
    b = *buf;

    seid = lisp_addr_new();


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

        // CHECK IF NODE IS AUTHORITATIVE FOR THE EID
        asite = mdb_lookup_entry(ddt_node->auth_sites_db, deid);
        if (!asite) {
            // send NOT_AUTHORITATIVE map-referral with Incomplete = 1
            // and TTL = 0
            mref = lisp_msg_neg_mref_create(deid, 0, LISP_ACTION_NOT_AUTHORITATIVE, A_NO_AUTHORITATIVE,
                                1, MREQ_NONCE(mreq_hdr));
            OOR_LOG(LDBG_1,"The node is not authoritative for the requested EID %s, sending NOT_AUTHORITATIVE message",
                    lisp_addr_to_char(deid));
            OOR_LOG(LDBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mref),
                    lisp_addr_to_char(deid));
            send_msg(&ddt_node->super, mref, ext_uc);
            lisp_msg_destroy(mref);
            lisp_addr_del(deid);

        }else{
            // CHECK IF DELEGATION EXISTS FOR THE EID
            dsite = mdb_lookup_entry(ddt_node->deleg_sites_db, deid);
            if (dsite) {
                    mref = lisp_msg_create(LISP_MAP_REFERRAL);

                    lisp_msg_put_mref_mapping(mref, dsite->mapping);

                    mref_hdr = lisp_msg_hdr(mref);
                    MREF_NONCE(mref_hdr) = MREQ_NONCE(mreq_hdr);

                    // SEND MAP-REFERRAL
                    if (send_msg(&ddt_node->super, mref, ext_uc) != GOOD) {
                        OOR_LOG(LDBG_1, "Couldn't send Map-Referral!");
                    }else{
                        OOR_LOG(LDBG_1, "Map-Referral sent!");
                    }
                    lisp_msg_destroy(mref);
                    lisp_addr_del(deid);

                }else{
                    // send DELEGATION_HOLE map-referral with
                    // TTL = DEFAULT_NEGATIVE_REFERRAL_TTL
                    mref = lisp_msg_neg_mref_create(deid, DEFAULT_NEGATIVE_REFERRAL_TTL, LISP_ACTION_DELEGATION_HOLE,
                            A_AUTHORITATIVE, 0, MREQ_NONCE(mreq_hdr));
                    OOR_LOG(LDBG_1,"No delegation exists for the requested EID %s, sending DELEGATION_HOLE message",
                            lisp_addr_to_char(deid));
                    OOR_LOG(LDBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mref),
                            lisp_addr_to_char(deid));
                    send_msg(&ddt_node->super, mref, ext_uc);
                    lisp_msg_destroy(mref);
                    lisp_addr_del(deid);
                }
        }
    }

    glist_destroy(itr_rlocs);
    lisp_addr_del(seid);



    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mref);
    lisp_addr_del(deid);
    lisp_addr_del(seid);
    return(BAD);

    */
    return (GOOD);

}

static int
ddt_mr_recv_map_referral(lisp_ddt_mr_t *ddt_mr, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
    //TODO map referral logic here
    return (GOOD);
}


int
ddt_mr_add_cache_entry(lisp_ddt_mr_t *ddt_mr, mref_cache_entry_t *entry)
{
    if (!entry)
        return(BAD);

    if(!mdb_add_entry(ddt_mr->mref_cache_db, cache_entry_xeid(entry), entry))
        return(BAD);
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
ddt_mr_set_root_entry(lisp_ddt_mr_t *ddt_mr, mref_cache_entry_t *root_entry){

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
        entry = ddtmr->root_entry->entry;
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


mref_cache_entry_t
*mref_cache_entry_init(ddt_mcache_entry_t *entry)
{
    mref_cache_entry_t *cache_entry;

    cache_entry = xzalloc(sizeof(mref_cache_entry_t));

    cache_entry->entry = entry;

    return(cache_entry);
}


ddt_pending_request_t
*ddt_pending_request_init(lisp_addr_t *target_address)
{
    ddt_pending_request_t *request = NULL;
    request-> target_address = target_address;
    request-> original_requests = glist_new();
    request-> gone_through_root = 0;
    request-> retry_number = 0;

    return(request);
}

void
mref_cache_entry_del(mref_cache_entry_t *entry)
{
    if (!entry)
        return;
    if (entry->entry)
        free(entry->entry);
    free(entry);
}

void
ddt_pending_request_del(ddt_pending_request_t *request)
{
    if (!request)
        return;
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
