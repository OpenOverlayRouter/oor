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
#include "../lib/prefixes.h"
#include "../lib/timers_utils.h"
#include "../liblisp/lisp_messages.h"

static oor_ctrl_dev_t *ddt_mr_ctrl_alloc();
static int ddt_mr_ctrl_construct(oor_ctrl_dev_t *dev);
void ddt_mr_ctrl_dealloc(oor_ctrl_dev_t *dev);
static void ddt_mr_ctrl_destruct(oor_ctrl_dev_t *dev);
void ddt_mr_ctrl_run(oor_ctrl_dev_t *dev);
static int ddt_mr_recv_msg(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);
int ddt_mr_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t state);
int ddt_mr_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
		lisp_addr_t *new_addr, uint8_t status);
int ddt_mr_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
		lisp_addr_t *dst_pref, lisp_addr_t *gateway);
fwd_info_t *ddt_mr_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple);

static int ddt_mr_recv_map_request(lisp_ddt_mr_t *, lbuf_t *, void *, uconn_t*, uconn_t *);
static int ddt_mr_recv_map_referral(lisp_ddt_mr_t *, lbuf_t *, void *, uconn_t*, uconn_t *);
static int ddt_mr_recv_enc_ctrl_msg(lisp_ddt_mr_t *mr, lbuf_t *msg, void **ecm_hdr, uconn_t *int_uc);
static inline lisp_ddt_mr_t *lisp_ddt_mr_cast(oor_ctrl_dev_t *dev);
static int pending_request_do_cycle(oor_timer_t *timer);
static int mref_mc_entry_expiration_timer_cb(oor_timer_t *t);
static void mref_mc_entry_start_expiration_timer(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *mce);
static void mref_mc_entry_start_expiration_timer2(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *mce, int time);

timer_pendreq_cycle_argument *timer_pendreq_cycle_arg_new_init(ddt_pending_request_t *pendreq,lisp_ddt_mr_t *mapres, lisp_addr_t *localaddress);

void timer_pendreq_cycle_arg_free(timer_pendreq_cycle_argument * timer_arg);

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


/* Called when the timer associated with an EID entry expires. */
static int
mref_mc_entry_expiration_timer_cb(oor_timer_t *timer)
{
	ddt_mcache_entry_t *mce = oor_timer_cb_argument(timer);
	mref_mapping_t *map = ddt_mcache_entry_mapping(mce);
	lisp_addr_t *addr = mref_mapping_eid(map);
	lisp_ddt_mr_t *ddt_mr = oor_timer_owner(timer);

	OOR_LOG(LDBG_1,"Got expiration for map referral entry with XEID %s. Removing it and its offsprings", lisp_addr_to_char(addr));
	mdb_pruning_entry_and_data(ddt_mr->mref_cache_db, cache_entry_xeid(mce), (mdb_del_fct)ddt_mcache_entry_del);
	ddt_mr_dump_db(ddt_mr->mref_cache_db, LDBG_3);
	return(GOOD);
}

static void
mref_mc_entry_start_expiration_timer(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *mce)
{
	int time = mref_mapping_ttl(ddt_mcache_entry_mapping(mce))*60;
	mref_mc_entry_start_expiration_timer2(ddt_mr, mce, 30);
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
		OOR_LOG(LDBG_1,"The mapping referral entry for EID %s will expire in %d minutes.",
				lisp_addr_to_char(mref_mapping_eid(ddt_mcache_entry_mapping(mce))),time/60);
	}else{
		OOR_LOG(LDBG_1,"The mapping referral entry for EID %s will expire in %d seconds.",
				lisp_addr_to_char(mref_mapping_eid(ddt_mcache_entry_mapping(mce))),time);
	}
}

static int
ddt_mr_recv_enc_ctrl_msg(lisp_ddt_mr_t *mr, lbuf_t *msg, void **ecm_hdr, uconn_t *int_uc)
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
	glist_entry_t *it;
	uconn_t fwd_uc;

	// local copy of the buf that can be modified
	b = *buf;

	seid = lisp_addr_new();
	throughroot = NOT_GONE_THROUGH_ROOT;

	OOR_LOG(LDBG_1, "\t <int_uc-la: %s - int_uc-ra: %s> <ext_uc-la: %s - ext_uc-ra: %s>", lisp_addr_to_char(&int_uc->la)
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
			original = ddt_original_request_new();
			original->nonce = MREQ_NONCE(mreq_hdr);
			original->source_eid_address = lisp_addr_clone(seid);
			original->source_rloc_address = lisp_addr_clone(&int_uc->ra);
			original->itr_locs = glist_clone(itr_rlocs, (glist_clone_obj)lisp_addr_clone);
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
				mrep = lisp_msg_neg_mrep_create(ddt_mcache_entry_eid(cacheentry), 15, ACT_NO_ACTION,
						A_AUTHORITATIVE, MREQ_NONCE(mreq_hdr));
				send_msg(&ddt_mr->super, mrep, ext_uc);
				lisp_msg_destroy(mrep);
				break;

			case LISP_ACTION_MS_ACK:
				// forward DDT Map-Request to Map Server
				// in the current implementation, this case will never be entered
				// more details in the recv_map_referral function
				referral_addrs = mref_mapping_get_ref_addrs(cacheentry->mapping);

				/* Set buffer to forward the encapsulated message*/
				lbuf_point_to_lisp_hdr(&b);

				glist_for_each_entry(it,referral_addrs){
					lisp_addr_t *drloc = NULL;
					lisp_addr_t *addr = glist_entry_data(it);

					drloc = lisp_addr_get_ip_addr(addr);

					uconn_init(&fwd_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
					send_msg(&ddt_mr->super, &b, &fwd_uc);
				}
				glist_destroy(referral_addrs);
				break;

			default:
				pendreq = ddt_pending_request_init(deid);
				if(throughroot == GONE_THROUGH_ROOT){
					pending_request_set_root_cache_entry(pendreq, ddt_mr->root_entry);
				}else{
					pending_request_set_new_cache_entry(pendreq, cacheentry);
				}

				original = xzalloc(sizeof(ddt_original_request_t));
				original->nonce = MREQ_NONCE(mreq_hdr);
				original->source_eid_address = lisp_addr_clone(seid);
				original->source_rloc_address = lisp_addr_clone(&int_uc->ra);
				original->itr_locs = glist_clone(itr_rlocs, (glist_clone_obj)lisp_addr_clone);
				pending_request_add_original(pendreq, original);
				ddt_mr_add_pending_request(ddt_mr, pendreq);



				timer_arg = timer_pendreq_cycle_arg_new_init(pendreq,ddt_mr,&ext_uc->la);
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
	nonces_list_t *nonces_lst;
	oor_timer_t *timer;
	timer_pendreq_cycle_argument *timer_arg;
	ddt_pending_request_t *pendreq;
	mref_mapping_t *m;
	void *          mref_hdr    = NULL;
	//mref_mapping_record_hdr_t *  rec            = NULL;
	int             i,records,morespecific;
	//lbuf_t *        mref        = NULL;
	lbuf_t  b;
	ddt_mcache_entry_t *ddt_entry;
	glist_t *rlocs_list = NULL;
	lisp_addr_t *src_ip, *dst_ip;

	// local copy of the buf that can be modified
	b = *buf;


	mref_hdr = lisp_msg_pull_hdr(&b);

	/* we are currently skipping the step of "auth signature valid */

	// check if nonce matches any pending request
	nonces_lst = htable_nonces_lookup(nonces_ht, MREF_NONCE(mref_hdr));
	if (!nonces_lst){
		OOR_LOG(LDBG_2, " Nonce %"PRIx64" doesn't match any Pending Request nonce. "
				"Discarding message!", MREF_NONCE(mref_hdr));
		return(BAD);
	}

	if (MREF_REC_COUNT(mref_hdr) >1){
		OOR_LOG(LINF,"Received Map Referral with multiple records. Only first one will be processed");
	}
	records = 1;

	for (i = 0; i < records; i++) {
		m = mref_mapping_new();
		if (lisp_msg_parse_mref_mapping_record(&b, m) != GOOD) {
			goto err;
		}
		// check if new pfx is less specific than last
		timer = nonces_list_timer(nonces_lst);
		timer_arg = (timer_pendreq_cycle_argument *)oor_timer_cb_argument(timer);
		pendreq = timer_arg->pendreq;
		if(pendreq->current_cache_entry == ddt_mr->root_entry){
			// pending request was using Root, new prefix CANNOT be less specific
		}else{
			if(pref_is_prefix_b_part_of_a(ddt_mcache_entry_eid(pendreq->current_cache_entry),
					mref_mapping_eid(m))){
				// new prefix is equal or more specific than the existing one
			}else{
				OOR_LOG(LDBG_2, " New prefix %s is not more specific than existing prefix %s "
						"Discarding message!", lisp_addr_to_char(mref_mapping_eid(m)),
						lisp_addr_to_char(ddt_mcache_entry_eid(pendreq->current_cache_entry)));
				return (BAD);
			}
		}
		// check map referral type and proceed according to it
		switch(mref_mapping_action(m)){
		case LISP_ACTION_NODE_REFERRAL:
		case LISP_ACTION_MS_REFERRAL:
			//check if prefix is equal to last used
			if(pendreq->current_cache_entry == ddt_mr->root_entry){
				// pending request was using Root, new prefix must be more specific
				morespecific = TRUE;
			}else{
				if(pref_is_prefix_b_part_of_a(mref_mapping_eid(m),
						ddt_mcache_entry_eid(pendreq->current_cache_entry))){
					// new prefix is equal to the existing one
					morespecific = FALSE;
				}else{
					//new prefix is part of the old, but not equal
					morespecific=TRUE;
				}
			}
			if(morespecific){
				//cache and follow the referral
				ddt_entry = ddt_mcache_entry_new();
				ddt_mcache_entry_init(ddt_entry,m);
				ddt_mr_add_cache_entry(ddt_mr,ddt_entry);
				pending_request_set_new_cache_entry(pendreq,ddt_entry);
				htable_nonces_reset_nonces_lst(nonces_ht, nonces_lst);
				pending_request_do_cycle(timer);
				return (GOOD);
			}else{
				/* Same behaviour than LISP_ACTION_NOT_AUTHORITATIVE */
			}
		case LISP_ACTION_NOT_AUTHORITATIVE:
			if(pendreq->gone_through_root == GONE_THROUGH_ROOT){
				/*
				 * The pending request is silently discarded; i.e., all state
				 * for the request that caused this answer is removed, and no answer
				 * is returned to the original requester.
				 */
				//send negative map-reply/es
				send_negative_mrep_to_original_askers(ddt_mr,pendreq, pendreq->target_address);
				map_resolver_remove_ddt_pending_request(ddt_mr,pendreq);
			}else{
				//send request to Root
				pending_request_set_root_cache_entry(pendreq,ddt_mr->root_entry);
				htable_nonces_reset_nonces_lst(nonces_ht, nonces_lst);
				pending_request_do_cycle(timer);
			}
			break;

		case LISP_ACTION_MS_ACK:
			rlocs_list= glist_new();

			// check incomplete bit
			/* Since there is no synchronization among a group of MS peers, we won't
			 * save the MS-ACK in the cache, as the addresses would need to be checked
			 * one by one anyway. With no synchronization, forwarding the Map Request to all
			 * peers could have unpredictable results if the prefix is registered in some of
			 * them, but not in some others.
			 * With this code, we only forward all original requests to the MS that returned
			 * the MS-ACK, and don't save the Map-Referral to the cache, regardless of it
			 * being incomplete or not.
			 * If in a future specification of LISP-DDT, synchronization among MS peers is
			 * enforced, the parts in comment in the following lines regarding the
			 * incomplete bit could be un-commented for faster performance
			 */

			/*
            if(mref_mapping_incomplete(m)){*/
			// forward original requests to map server
			if(!ext_uc){
				glist_add(&int_uc->ra,rlocs_list);
			}else{
				glist_add(&ext_uc->ra,rlocs_list);
			}
			/*}else{
                // cache and forward original requests to map servers
                ddt_entry = ddt_mcache_entry_new();
                ddt_mcache_entry_init(ddt_entry,m);
                ddt_mr_add_cache_entry(ddt_mr,ddt_entry);
                rlocs_list = mref_mapping_get_ref_addrs(m);
            }*/

			glist_entry_t *it = NULL;
			glist_for_each_entry(it,pendreq->original_requests){
				lisp_addr_t *drloc;
				ddt_original_request_t *request = glist_entry_data(it);
				lbuf_t *        mreq        = NULL;
				uconn_t orig_uc;
				void *mr_hdr = NULL;
				glist_entry_t *it2 = NULL;
				glist_for_each_entry(it2, rlocs_list){
					mreq =lisp_msg_mreq_create(request->source_eid_address, request->itr_locs, pendreq->target_address);
					mr_hdr = lisp_msg_hdr(mreq);
					MREQ_NONCE(mr_hdr) = request->nonce;

					src_ip = request->source_rloc_address;
					dst_ip = lisp_addr_clone(lisp_addr_get_ip_pref_addr(pendreq->target_address));
					lisp_addr_set_lafi(dst_ip, LM_AFI_IP);

					lisp_msg_encap(mreq, LISP_CONTROL_PORT, LISP_CONTROL_PORT, src_ip, dst_ip);
					/* we don't set the DDT-Originated bit here, because we are going to delete
					 * the pending request after forwarding the original requests, so there's
					 * no point in the MS sending back MS-ACKs
					 */

					drloc = lisp_addr_get_ip_addr(glist_entry_data(it2));

					uconn_init(&orig_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
					send_msg(&ddt_mr->super, mreq, &orig_uc);

					lisp_msg_destroy(mreq);
				}
			}
			map_resolver_remove_ddt_pending_request(ddt_mr,pendreq);
			break;

		case LISP_ACTION_NOT_REGISTERED:
			/* there is no specification of what a mapping with this code must do if matched
			 * in the cache, so there's no point in saving them, as of now*/
			// try the next rloc in the list:
			pendreq->recieved_not_registered = 1;
			pending_request_do_cycle(timer);
			break;

		case LISP_ACTION_DELEGATION_HOLE:
			// cache and return negative map-reply
			ddt_entry = ddt_mcache_entry_new();
			ddt_mcache_entry_init(ddt_entry,m);
			ddt_mr_add_cache_entry(ddt_mr,ddt_entry);
			send_negative_mrep_to_original_askers(ddt_mr,pendreq,
					ddt_mcache_entry_eid(ddt_entry));
			map_resolver_remove_ddt_pending_request(ddt_mr,pendreq);
			break;

		default:
			// unknown/wrong type, do nothing
			break;
		}
	}
	return (GOOD);

	err:
	return(BAD);
}


int
ddt_mr_add_cache_entry(lisp_ddt_mr_t *ddt_mr, ddt_mcache_entry_t *entry)
{
	if (!entry){
		return(BAD);
	}

	if(!mdb_add_entry(ddt_mr->mref_cache_db, cache_entry_xeid(entry), entry)){
		return(BAD);
	}

	mref_mc_entry_start_expiration_timer(ddt_mr, entry);
	ddt_mr_dump_db(ddt_mr->mref_cache_db, LDBG_3);

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


void ddt_mr_dump_db(mdb_t *mcdb, int log_level)
{
    if (is_loggable(log_level) == FALSE) {
        return;
    }

    ddt_mcache_entry_t *mce;
    void *it;

    OOR_LOG(log_level,"**************** LISP Map Referral Cache ******************\n");
    mdb_foreach_entry(mcdb, it) {
        mce = (ddt_mcache_entry_t *)it;
        ddt_map_cache_entry_dump(mce, log_level);
    } mdb_foreach_entry_end;
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
	int ret = BAD;
	lisp_msg_type_e type;
	lisp_ddt_mr_t *ddt_mr;
	void *ecm_hdr = NULL;
	uconn_t *int_uc, *ext_uc = NULL, aux_uc;

	ddt_mr = lisp_ddt_mr_cast(dev);
	type = lisp_msg_type(msg);

	if (type == LISP_ENCAP_CONTROL_TYPE) {
		if (ddt_mr_recv_enc_ctrl_msg(ddt_mr, msg, &ecm_hdr, &aux_uc)!=GOOD){
			return (BAD);
		}
		type = lisp_msg_type(msg);
		ext_uc = uc;
		int_uc = &aux_uc;
		OOR_LOG(LDBG_1, "Map-Resolver: Received Encapsulated %s", lisp_msg_hdr_to_char(msg));
	}else{
		int_uc = uc;
	}

	switch(type) {
	case LISP_MAP_REQUEST:
		ret = ddt_mr_recv_map_request(ddt_mr, msg, ecm_hdr, int_uc, ext_uc);
		break;
	case LISP_MAP_REFERRAL:
		ret = ddt_mr_recv_map_referral(ddt_mr, msg, ecm_hdr, int_uc, ext_uc);
		break;
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
	mref_cache_entry_del(ddt_mr->root_entry);
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
	request-> original_requests = glist_new_managed((glist_del_fct)ddt_original_request_del);
	request-> gone_through_root = NOT_GONE_THROUGH_ROOT;

	return(request);
}

/*
 * We call "htable_nonces_reset_nonces_lst" after the following two functions when
 * calling them from recv_map_referral or pending_request_do_cycle so possible map-referrals
 * for the previous cache entry don't interfere with the pending request anymore.
 * For example,  a MS-Referral or Node-Referral that arrives late would most likely
 * have a prefix EQUAL to the new cache entry's prefix, thus making the Map Resolver "find"
 * a false Referral Loop, in the case of set_new_cache_entry.
 * In the case of set_root_cache_entry, a delayed negative MS/Node-Referral arriving would
 * make the Map Resolver prematurely give up on the pending request, which has already gone
 * through root now.
 */

void
pending_request_set_new_cache_entry(ddt_pending_request_t *pendreq, ddt_mcache_entry_t *current_cache_entry)
{
	pendreq-> current_cache_entry = current_cache_entry;
	pendreq-> current_delegation_rlocs = mref_mapping_get_ref_addrs(ddt_mcache_entry_mapping(current_cache_entry));
	pendreq-> current_rloc = NULL;
	pendreq-> retry_number = 0;
	pendreq-> recieved_not_registered = 0;
}

void
pending_request_set_root_cache_entry(ddt_pending_request_t *pendreq, ddt_mcache_entry_t *root_entry)
{
	pending_request_set_new_cache_entry(pendreq, root_entry);
	pendreq->gone_through_root = GONE_THROUGH_ROOT;
}

/*
 * add the original request to the pending request's list of
 * original requests, it will substitute a previous instance of itself if necessary
 */
void
pending_request_add_original(ddt_pending_request_t *pending, ddt_original_request_t *original)
{
	glist_entry_t *it = NULL;
	glist_for_each_entry(it,pending->original_requests){
		ddt_original_request_t *request = glist_entry_data(it);
		if(lisp_addr_cmp(request->source_eid_address,original->source_eid_address)==0
				&& lisp_addr_cmp(request->source_rloc_address,original->source_rloc_address)==0){
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
	ddt_original_request_t *last_original_requester = glist_last_data(pendreq->original_requests);
	lisp_ddt_mr_t *mapres = timer_arg->mapres;
	uint64_t nonce;
	//lisp_addr_t src_eid;
	lisp_addr_t *drloc;

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

	// check if max retries exceeded
	if(pendreq->retry_number >= DEFAULT_MAP_REQUEST_RETRIES){
		if(pendreq->gone_through_root == GONE_THROUGH_ROOT){
			// send negative map reply/es and eliminate pending request
			send_negative_mrep_to_original_askers(mapres,pendreq,pendreq->target_address);

			map_resolver_remove_ddt_pending_request(mapres,pendreq);

		}else if(pendreq->retry_number >=1 && pendreq->recieved_not_registered == 1){
			// send negative map reply/es and eliminate pending request
			send_negative_mrep_to_original_askers(mapres,pendreq,pendreq->target_address);
			map_resolver_remove_ddt_pending_request(mapres,pendreq);
		}else{
			// switch to the root entry and retry
			pending_request_set_root_cache_entry(pendreq,mapres->root_entry);
			htable_nonces_reset_nonces_lst(nonces_ht, nonces_list);
			pending_request_do_cycle(timer);
		}
	}else{
		// send map request to the new rloc and set timer
		lbuf_t *        mreq        = NULL;
		void *mr_hdr = NULL;
		void *ec_hdr = NULL;
		uconn_t dest_uc;
		lisp_addr_t *src_ip, *dst_ip;

		mreq =lisp_msg_mreq_create(last_original_requester->source_eid_address, last_original_requester->itr_locs, pendreq->target_address);
		mr_hdr = lisp_msg_hdr(mreq);
		nonce = nonce_new();
		MREQ_NONCE(mr_hdr) = nonce;

		src_ip = last_original_requester->source_rloc_address;
		dst_ip = lisp_addr_clone(lisp_addr_get_ip_pref_addr(pendreq->target_address));
		lisp_addr_set_lafi(dst_ip, LM_AFI_IP);

		lisp_msg_encap(mreq, LISP_CONTROL_PORT, LISP_CONTROL_PORT, src_ip, dst_ip);

		ec_hdr = lisp_msg_ecm_hdr(mreq);
		ECM_DDT_BIT(ec_hdr) = 1;

		drloc = lisp_addr_get_ip_addr(glist_entry_data(pendreq->current_rloc));

		uconn_init(&dest_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
		OOR_LOG(LDBG_1, "Sending Encap %s", lisp_msg_hdr_to_char(mreq));
		send_msg(&mapres->super, mreq, &dest_uc);
		lisp_addr_del(dst_ip);

		htable_nonces_insert(nonces_ht, nonce, nonces_list);
		oor_timer_start(timer, OOR_INITIAL_MRQ_TIMEOUT);

		lisp_msg_destroy(mreq);
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
		lisp_addr_del(request->target_address);
	if (request->original_requests)
		glist_destroy(request->original_requests);
	glist_destroy(request->current_delegation_rlocs);
	free(request);
}

void
map_resolver_remove_ddt_pending_request(lisp_ddt_mr_t *mapres, ddt_pending_request_t *request)
{
	if (!request)
		return;
	mdb_remove_entry(mapres->pending_requests_db,pending_request_xeid(request));
	ddt_pending_request_del(request);
}

timer_pendreq_cycle_argument *
timer_pendreq_cycle_arg_new_init(ddt_pending_request_t *pendreq,lisp_ddt_mr_t *mapres, lisp_addr_t *localaddress)
{
	timer_pendreq_cycle_argument *timer_arg = xmalloc(sizeof(timer_pendreq_cycle_argument));
	timer_arg->pendreq = pendreq;
	timer_arg->mapres = mapres;
	timer_arg->local_address = lisp_addr_clone(localaddress);

	return(timer_arg);
}

void
timer_pendreq_cycle_arg_free(timer_pendreq_cycle_argument * timer_arg)
{
	lisp_addr_del(timer_arg->local_address);
	free(timer_arg);
}

void send_negative_mrep_to_original_askers(lisp_ddt_mr_t *mapres, ddt_pending_request_t * pendreq, lisp_addr_t *eid_pref)
{
	glist_entry_t *it = NULL;
	glist_for_each_entry(it,pendreq->original_requests){
		ddt_original_request_t *request = glist_entry_data(it);
		lbuf_t *        mrep        = NULL;
		uconn_t orig_uc;
		mrep = lisp_msg_neg_mrep_create(eid_pref, 15, ACT_NO_ACTION,
				A_NO_AUTHORITATIVE, request->nonce);
		lisp_addr_t *drloc = NULL;

		drloc = lisp_addr_get_ip_addr(glist_entry_data(glist_first(request->itr_locs)));

		uconn_init(&orig_uc, LISP_CONTROL_PORT, LISP_CONTROL_PORT, NULL, drloc);
		send_msg(&mapres->super, mrep, &orig_uc);
		lisp_msg_destroy(mrep);
	}
}

ddt_original_request_t * ddt_original_request_new()
{
	return (xzalloc(sizeof(ddt_original_request_t)));
}

void ddt_original_request_del (ddt_original_request_t *request)
{
	ddt_original_request_t **req_ptr = &request;
	lisp_addr_del(request->source_eid_address);
	lisp_addr_del(request->source_rloc_address);
	glist_destroy(request->itr_locs);
	free(request);
	*req_ptr = NULL;
}
