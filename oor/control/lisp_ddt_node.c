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

#include "lisp_ddt_node.h"
#include "../defs.h"
#include "../lib/cksum.h"
#include "../lib/oor_log.h"
#include "../lib/prefixes.h"

static oor_ctrl_dev_t *ddt_node_ctrl_alloc();
static int
ddt_node_ctrl_construct(oor_ctrl_dev_t *dev);
void ddt_node_ctrl_dealloc(oor_ctrl_dev_t *dev);
static void ddt_node_ctrl_destruct(oor_ctrl_dev_t *dev);
void ddt_node_ctrl_run(oor_ctrl_dev_t *dev);
static int ddt_node_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc);
int ddt_node_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t state);
int ddt_node_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
		lisp_addr_t *new_addr, uint8_t status);
int ddt_node_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
		lisp_addr_t *dst_pref, lisp_addr_t *gateway);
fwd_info_t *ddt_node_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple);

static int ddt_node_recv_map_request(lisp_ddt_node_t *, lbuf_t *, void *, uconn_t*, uconn_t *);
static int ddt_node_recv_enc_ctrl_msg(lisp_ddt_node_t *ddtnod, lbuf_t *msg, void **ecm_hdr, uconn_t *int_uc);
static int ddt_node_recv_msg(oor_ctrl_dev_t *, lbuf_t *, uconn_t *);
static inline lisp_ddt_node_t *lisp_ddt_node_cast(oor_ctrl_dev_t *dev);

ctrl_dev_class_t ddt_node_ctrl_class = {
		.alloc = ddt_node_ctrl_alloc,
		.construct = ddt_node_ctrl_construct,
		.dealloc = ddt_node_ctrl_dealloc,
		.destruct = ddt_node_ctrl_destruct,
		.run = ddt_node_ctrl_run,
		.recv_msg = ddt_node_recv_msg,
		.if_link_update = ddt_node_if_link_update,
		.if_addr_update = ddt_node_if_addr_update,
		.route_update = ddt_node_route_update,
		.get_fwd_entry = ddt_node_get_fwd_entry
};


static int
ddt_node_recv_enc_ctrl_msg(lisp_ddt_node_t *ddtnod, lbuf_t *msg, void **ecm_hdr, uconn_t *int_uc)
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
ddt_node_recv_map_request(lisp_ddt_node_t *ddt_node, lbuf_t *buf, void *ecm_hdr, uconn_t *int_uc, uconn_t *ext_uc)
{
	lisp_addr_t *   seid        = NULL;
	lisp_addr_t *   deid        = NULL;
	lisp_addr_t *   neg_pref;
	glist_t *       itr_rlocs   = NULL;
	void *          mreq_hdr    = NULL;
	void *          mref_hdr    = NULL;
	//mref_mapping_record_hdr_t *  rec            = NULL;
	int             i           = 0;
	lbuf_t *        mref        = NULL;
	lbuf_t  b;
	ddt_authoritative_site_t *    asite           = NULL;
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

		}else{
			// CHECK IF DELEGATION EXISTS FOR THE EID
			dsite = mdb_lookup_entry(ddt_node->deleg_sites_db, deid);
			if (dsite) {
				mref = lisp_msg_create(LISP_MAP_REFERRAL);

				lisp_msg_put_mref_mapping(mref, dsite->mapping);

				mref_hdr = lisp_msg_hdr(mref);
				MREF_NONCE(mref_hdr) = MREQ_NONCE(mreq_hdr);

				/* SEND MAP-REFERRAL */
				if (send_msg(&ddt_node->super, mref, ext_uc) != GOOD) {
					OOR_LOG(LDBG_1, "Couldn't send Map-Referral!");
				}else{
					OOR_LOG(LDBG_1, "Map-Referral sent!");
				}
			}else{
				/* send DELEGATION_HOLE map-referral with TTL = DEFAULT_NEGATIVE_REFERRAL_TTL
				   and  the least-specific XEID-prefix that does not match any XEID-prefix
				   delegated by the DDT node */
				neg_pref = mdb_get_shortest_negative_prefix(ddt_node->deleg_sites_db, deid);
				mref = lisp_msg_neg_mref_create(neg_pref, DEFAULT_NEGATIVE_REFERRAL_TTL, LISP_ACTION_DELEGATION_HOLE,
						A_AUTHORITATIVE, 0, MREQ_NONCE(mreq_hdr));
				OOR_LOG(LDBG_1,"No delegation exists for the requested EID %s, sending DELEGATION_HOLE message "
						"for prefix %s",lisp_addr_to_char(deid), lisp_addr_to_char(neg_pref));
				OOR_LOG(LDBG_2, "%s, EID: %s, NEGATIVE", lisp_msg_hdr_to_char(mref),
						lisp_addr_to_char(neg_pref));
				send_msg(&ddt_node->super, mref, ext_uc);
				lisp_addr_del(neg_pref);
			}
		}
		lisp_msg_destroy(mref);
		lisp_addr_del(deid);
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

}


int
ddt_node_add_authoritative_site(lisp_ddt_node_t *ddt_node, ddt_authoritative_site_t *as)
{
	if (!as)
		return(BAD);

	if(!mdb_add_entry(ddt_node->auth_sites_db, asite_xeid(as), as))
		return(BAD);
	return(GOOD);
}

void *
ddt_node_remove_authoritative_site(lisp_ddt_node_t *ddt_node, lisp_addr_t *xeid)
{
    return(mdb_remove_entry(ddt_node->auth_sites_db, xeid));
}

int
ddt_node_add_delegation_site(lisp_ddt_node_t *ddt_node, ddt_delegation_site_t *ds)
{
	if (!ds) {
		return(BAD);
	}

	if (!mdb_add_entry(ddt_node->deleg_sites_db, dsite_xeid(ds), ds))
		return(BAD);
	return(GOOD);
}

void *
ddt_node_remove_delegation_site(lisp_ddt_node_t *ddt_node, lisp_addr_t *xeid)
{
    return(mdb_remove_entry(ddt_node->deleg_sites_db, xeid));
}


void
ddt_node_dump_authoritative_sites(lisp_ddt_node_t *ddtn, int log_level)
{
	if (is_loggable(log_level) == FALSE){
		return;
	}

	void *it = NULL;
	ddt_authoritative_site_t *asite = NULL;

	OOR_LOG(log_level,"****************** DDT-NODE authoritative prefixes **************\n");
	mdb_foreach_entry(ddtn->auth_sites_db, it) {
		asite = it;
		OOR_LOG(log_level, "Xeid: %s",
				lisp_addr_to_char(asite->xeid));
	} mdb_foreach_entry_end;
	OOR_LOG(log_level,"*******************************************************\n");
}

void
ddt_node_dump_delegation_sites(lisp_ddt_node_t *ddtn, int log_level)
{
	if (is_loggable(log_level) == FALSE){
		return;
	}

	ddt_delegation_site_t *it = NULL;
	ddt_delegation_site_t *dsite = NULL;
	locator_t *loct = NULL;

	OOR_LOG(log_level,"**************** DDT-Node delegation sites ******************\n");
	mdb_foreach_entry(ddtn->deleg_sites_db, it) {
		dsite = it;
		OOR_LOG(log_level, "Xeid: %s, Delegation type: %s Delegation Nodes:",
				lisp_addr_to_char(mref_mapping_eid(dsite->mapping)),
				(mref_mapping_action(dsite->mapping)==0) ? "Child Node" : "Map Server");
		/*
        glist_dump(dsite->child_nodes, (glist_to_char_fct)lisp_addr_to_char, log_level);
		 */
		mref_mapping_foreach_referral(dsite->mapping,loct){
			OOR_LOG(log_level, "    - %s",lisp_addr_to_char(locator_addr(loct)));
		}mref_mapping_foreach_referral_end;
	} mdb_foreach_entry_end;
	OOR_LOG(log_level,"*******************************************************\n");

}


static inline lisp_ddt_node_t *
lisp_ddt_node_cast(oor_ctrl_dev_t *dev)
{
	/* make sure */
	lm_assert(dev->ctrl_class == &ddt_node_ctrl_class);
	return(CONTAINER_OF(dev, lisp_ddt_node_t, super));
}

static int
ddt_node_recv_msg(oor_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *uc)
{
	int ret = BAD;
	lisp_msg_type_e type;
	lisp_ddt_node_t *ddt_node;
	void *ecm_hdr = NULL;
	uconn_t *int_uc, *ext_uc = NULL, aux_uc;

	ddt_node = lisp_ddt_node_cast(dev);
	type = lisp_msg_type(msg);

	if (type == LISP_ENCAP_CONTROL_TYPE) {
		if (ddt_node_recv_enc_ctrl_msg(ddt_node, msg, &ecm_hdr, &aux_uc)!=GOOD){
			return (BAD);
		}
		type = lisp_msg_type(msg);
		ext_uc = uc;
		int_uc = &aux_uc;
		OOR_LOG(LDBG_1, "DDT NODE: Received Encapsulated %s", lisp_msg_hdr_to_char(msg));
	}else{
		int_uc = uc;
	}

	switch(type) {
	case LISP_MAP_REQUEST:
		ret = ddt_node_recv_map_request(ddt_node, msg, ecm_hdr, int_uc, ext_uc);
		break;
	case LISP_MAP_REGISTER:
	case LISP_MAP_REPLY:
	case LISP_MAP_NOTIFY:
	case LISP_INFO_NAT:
		OOR_LOG(LDBG_3, "DDT-Node: Received control message with type %d."
				" Discarding!", type);
		break;
	default:
		OOR_LOG(LDBG_3, "DDT-Node: Received unidentified type (%d) control "
				"message", type);
		ret = BAD;
		break;
	}

	if (ret != GOOD) {
		OOR_LOG(LDBG_1, "DDT-Node: Failed to process  control message");
		return(BAD);
	} else {
		OOR_LOG(LDBG_3, "DDT-Node: Completed processing of control message");
		return(ret);
	}
}


int
ddt_node_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t state)
{
	return (GOOD);
}
int
ddt_node_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
		lisp_addr_t *new_addr, uint8_t status)
{
	return (GOOD);
}
int
ddt_node_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *src_pref,
		lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
	return (GOOD);
}

fwd_info_t *
ddt_node_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
	return (NULL);
}

static oor_ctrl_dev_t *
ddt_node_ctrl_alloc()
{
	lisp_ddt_node_t *ddt_node;
	ddt_node = xzalloc(sizeof(lisp_ddt_node_t));
	return(&ddt_node->super);
}

static int
ddt_node_ctrl_construct(oor_ctrl_dev_t *dev)
{
	lisp_ddt_node_t *ddt_node = lisp_ddt_node_cast(dev);

	ddt_node->auth_sites_db = mdb_new();
	ddt_node->deleg_sites_db = mdb_new();

	if (!ddt_node->auth_sites_db || !ddt_node->deleg_sites_db) {
		return(BAD);
	}

	OOR_LOG(LDBG_1, "Finished Constructing DDT Node");

	return(GOOD);
}

static void
ddt_node_ctrl_destruct(oor_ctrl_dev_t *dev)
{
	lisp_ddt_node_t *ddt_node = lisp_ddt_node_cast(dev);
	mdb_del(ddt_node->deleg_sites_db, (mdb_del_fct)ddt_authoritative_site_del);
	mdb_del(ddt_node->auth_sites_db, (mdb_del_fct)ddt_delegation_site_del);
}

void
ddt_node_ctrl_dealloc(oor_ctrl_dev_t *dev)
{
	lisp_ddt_node_t *ddt_node = lisp_ddt_node_cast(dev);
	OOR_LOG(LDBG_1, "Freeing DDT Node ...");
	free(ddt_node);
}

void
ddt_node_ctrl_run(oor_ctrl_dev_t *dev)
{
	lisp_ddt_node_t *ddt_node = lisp_ddt_node_cast(dev);

	OOR_LOG (LDBG_1, "****** Summary of the configuration ******");
	ddt_node_dump_authoritative_sites(ddt_node, LDBG_1);
	ddt_node_dump_delegation_sites(ddt_node, LDBG_1);

	OOR_LOG(LDBG_1, "Starting DDT Node ...");
}


ddt_authoritative_site_t
*ddt_authoritative_site_init(lisp_addr_t *eid, uint32_t iid)
{
	ddt_authoritative_site_t *as = NULL;
	int iidmlen;

	as = xzalloc(sizeof(ddt_authoritative_site_t));
	if (iid > 0){
		iidmlen = (lisp_addr_ip_afi(eid) == AF_INET) ? 32: 128;
		as->xeid = lisp_addr_new_init_iid(iid, eid, iidmlen);
	}else{
		as->xeid = lisp_addr_clone(eid);
	}

	return(as);
}


ddt_delegation_site_t
*ddt_delegation_site_init(lisp_addr_t *eid, uint32_t iid, int type, glist_t *child_nodes)
{
	ddt_delegation_site_t *ds = NULL;
	int iidmlen;
	mref_mapping_t *mapping = NULL;
	lisp_addr_t *xeid;

	ds = xzalloc(sizeof(ddt_delegation_site_t));
	if (iid > 0){
		iidmlen = (lisp_addr_ip_afi(eid) == AF_INET) ? 32: 128;
		xeid = lisp_addr_new_init_iid(iid, eid, iidmlen);
	}else{
		xeid = lisp_addr_clone(eid);
	}

	mapping = mref_mapping_new_init_full(xeid,DEFAULT_REGISTERED_TTL,type,
			A_AUTHORITATIVE, 0, child_nodes, NULL, NULL);

	ds->mapping = mapping;
	return(ds);
}

void
ddt_authoritative_site_del(ddt_authoritative_site_t *as)
{
	if (!as)
		return;
	lisp_addr_del(as->xeid);
	free(as);
}

void
ddt_delegation_site_del(ddt_delegation_site_t *ds)
{
	if (!ds)
		return;
	free(ds);
}


