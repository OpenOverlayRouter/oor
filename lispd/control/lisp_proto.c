/*
 * lisp_proto.c
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
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
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#include "lisp_proto.h"
#include <defs.h>


static int
handle_petr_probe_reply(lisp_ctrl_dev_t *dev, mapping_t *m, locator_t *probed,
        uint64_t nonce)
{
    mapping_t *old_map = NULL, *pmap = NULL;
    rmt_locator_extended_info *rmt_ext_inf = NULL;
    locators_list_t *loc_list[2] = { NULL, NULL };
    lisp_addr_t *src_eid = NULL;
    locator_t *loc = NULL, *aux_loc = NULL;
    int ctr;

    pmap = mcache_entry_mapping(proxy_etrs);
    if (proxy_etrs && lisp_addr_cmp(src_eid, mapping_eid(pmap)) == 0) {

        /* find locator */
        old_map = mcache_entry_mapping(proxy_etrs);
        loc_list[0] = pmap->head_v4_locators_list;
        loc_list[1] = pmap->head_v6_locators_list;
        for (ctr = 0; ctr < 2; ctr++) {
            while (loc_list[ctr] != NULL) {
                aux_loc = loc_list[ctr]->locator;
                rmt_ext_inf = aux_loc->extended_info;
                if ((nonce_check(rmt_ext_inf->rloc_probing_nonces, nonce))
                        == GOOD) {
                    free(rmt_ext_inf->rloc_probing_nonces);
                    rmt_ext_inf->rloc_probing_nonces = NULL;
                    loc = aux_loc;
                    break;
                }
                loc_list[ctr] = loc_list[ctr]->next;
            }
            if (loc) {
                break;
            }
        }

    }

    if (!loc) {
        lmlog(DBG_1, "Nonce of Negative Map-Reply Probe doesn't match "
                "any nonce of Proxy-ETR locators");
        return (BAD);
    } else {
        lmlog(DBG_1, "Map-Reply Probe for %s has not been requested! "
                "Discarding!", lisp_addr_to_char(src_eid));
        return (BAD);
    }

    lmlog(DBG_1, "Map-Reply probe reachability to the PETR with RLOC %s",
            lisp_addr_to_char(locator_addr(loc)));

    rmt_ext_inf = loc->extended_info;
    if (!rmt_ext_inf->probe_timer){
       lmlog(DBG_1," Map-Reply Probe was not requested! Discarding!");
       return (BAD);
    }

    /* Reprogramming timers of rloc probing */
    program_rloc_probing(dev, old_map, probed, 0);

    return (GOOD);
}

/* Process a record from map-reply probe message */
static int
handle_locator_probe_reply(lisp_ctrl_dev_t *dev, mapping_t *m, locator_t *probed,
        uint64_t nonce)
{
    lisp_addr_t *src_eid = NULL;
    locator_t *loc = NULL, *aux_loc = NULL;
    mapping_t *old_map = NULL, *pmap = NULL;
    locators_list_t *loc_list[2] = {NULL, NULL};
    rmt_locator_extended_info *rmt_ext_inf = NULL;
    int ctr = 0;
    map_cache_db_t *mcdb;

    src_eid = maping_eid(m);

    mcdb = dev->tr_class->get_map_cache(dev);
    /* Lookup src EID in map cache */
    old_map = mcache_lookup_mapping(mcdb, src_eid);
    if(!old_map) {
        lmlog(DBG_1, "Source EID %s couldn't be found in the map-cache",
                lisp_addr_to_char(src_eid));
        return(BAD);
    }

    /* Find probed locator in mapping */
    loc = mapping_get_locator(old_map, locator_addr(probed));
    if (!loc){
        lmlog(DBG_2,"Probed locator %s not part of the the mapping %s",
                lisp_addr_to_char(locator_addr(probed)),
                lisp_addr_to_char(mapping_eid(old_map)));
        return (ERR_NO_EXIST);
    }

    /* Compare nonces */
    rmt_ext_inf = loc->extended_info;
    if (!rmt_ext_inf || !rmt_ext_inf->rloc_probing_nonces) {
        lmlog(DBG_1, "Locator %s has no nonces!",
                lisp_addr_to_char(locator_addr(loc)));
        return(BAD);
    }

    /* Check if the nonce of the message match with the one stored in the
     * structure of the locator */
    if ((nonce_check(rmt_ext_inf->rloc_probing_nonces, nonce)) == GOOD) {
        free(rmt_ext_inf->rloc_probing_nonces);
        rmt_ext_inf->rloc_probing_nonces = NULL;
    } else {
        lmlog(DBG_1, "Nonce of Map-Reply Probe doesn't match nonce of the "
                "Map-Request Probe. Discarding message ...");
        return (BAD);
    }

    lmlog(DBG_1," Successfully pobed RLOC %s of cache entry with EID %s",
                lisp_addr_to_char(locator_addr(probed)),
                lisp_addr_to_char(mapping_eid(old_map)));


    if (*(loc->state) == DOWN) {
        *(loc->state) = UP;

        lmlog(DBG_1," Locator %s state changed to UP",
                lisp_addr_to_char(locator_addr(loc)));

        /* [re]Calculate balancing locator vectors if status changed*/
        mapping_compute_balancing_vectors(old_map);
    }

    if (!rmt_ext_inf->probe_timer){
       lmlog(DBG_1," Map-Reply Probe was not requested! Discarding!");
       return (BAD);
    }

    /* Reprogramming timers of rloc probing */
    program_rloc_probing(dev, old_map, probed, 0);

    return (GOOD);

}

static int
update_mcache_entry(lisp_ctrl_dev_t *dev, mapping_t *m, uint64_t nonce)
{

    mcache_entry_t *mce = NULL;
    mapping_t *old_map, *new_map;
    lisp_addr_t *eid;
    locators_list_t *llist[2];
    int ctr;

    eid = mapping_eid(m);

    /* Serch map cache entry exist*/
    mce = map_cache_lookup_exact(eid);
    if (!mce){
        lmlog(DBG_2,"No map cache entry for %s", lisp_addr_to_char(eid));
        return (BAD);
    }
    /* Check if map cache entry contains the nonce*/
    if (nonce_check(mce->nonces, nonce) == BAD) {
        lmlog(DBG_2, " Nonce doesn't match nonce of the Map-Request. "
                "Discarding message ...");
        return(BAD);
    } else {
        mcache_entry_destroy_nonces(mce);
    }

    lmlog(DBG_2, "Mapping with EID %s already exists, replacing!",
            lisp_addr_to_char(eid));
    old_map = mcache_entry_mapping(mce);
    mapping_del(old_map);

    mcache_entry_set_mapping(mce, mapping_clone(m));
    new_map = mcache_entry_mapping(mce);

    mapping_compute_balancing_vectors(new_map);

    /* Reprogramming timers */
    map_cache_entry_start_expiration_timer(mce);

    /* RLOC probing timer */
    program_mapping_rloc_probing(dev, new_map);

    return (GOOD);
}

int
recv_map_reply_msg(lisp_ctrl_dev_t *dev, lbuf_t *buf)
{
    void *mrep_hdr, *mrec_hdr, loc_hdr;
    int i, j, ret;
    glist_t locs;
    locator_t *loc, *probed;
    lisp_addr_t *seid;
    mapping_t *m;
    lbuf_t b;
    mcache_entry_t *mce;
    map_cache_db_t *mcdb;

    /* local copy */
    b = *buf;
    seid = lisp_addr_new();
    mcdb = dev->tr_class->get_map_cache(dev);

    mrep_hdr = lisp_msg_pull_hdr(b);
    lmlog(DBG_1, "%s", lisp_msg_hdr_to_char(mrep_hdr));

    for (i = 0; i <= MREP_REC_COUNT(mrep_hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(b, m, probed) != GOOD) {
            goto err;
        }

        if (!MREP_RLOC_PROBE(mrep_hdr)) {
            /* Check if the map reply corresponds to a not active map cache */
            mce = lookup_nonce_in_no_active_map_caches(mcdb, mapping_eid(m),
                    MREP_NONCE(mrep_hdr));

            if (mce) {
                /* delete placeholder/dummy mapping and install the new one */
                mcache_remove_mapping(mcdb, mapping_eid(mcache_entry_mapping(mce)));

                /* DO NOT free mapping in this case */
                mcache_add_mapping(mcdb, m);
            } else {

                /* the reply might be for an active mapping (SMR)*/
                update_mcache_entry(dev, m, MREP_NONCE(mrep_hdr));
                mapping_del(m);
            }

            map_cache_dump_db(DBG_3);

            /*
            if (is_mrsignaling()) {
                mrsignaling_recv_ack();
                continue;
            } */
        } else {
            if (mapping_locator_count(m) > 0) {
                handle_locator_probe_reply(dev, m, probed, MREP_NONCE(mrep_hdr));
            } else {
                /* If negative probe map-reply, then the probe was for
                 * proxy-ETR (PETR) */
                handle_petr_probe_reply(dev, m, probed, MREP_NONCE(mrep_hdr));
            }
            mapping_del(m);
        }

    }

    return(GOOD);


done:
    lisp_addr_del(seid);
    return(GOOD);
err:
    lisp_addr_del(seid);
    mapping_del(m);
    return(BAD);
}

static void
select_remote_rloc(glist_t *l, int afi, lisp_addr_t *remote) {
    int i;
    glist_entry_t *it;
    lisp_addr_t *rloc;

    glist_for_each_entry(it, l) {
        rloc = glist_entry_data(it);
        if (lisp_addr_ip_afi(rloc) == afi) {
            lisp_addr_copy(remote, rloc);
            break;
        }
    }
}


static int
tr_reply_to_smr(lisp_ctrl_dev_t *dev, lisp_addr_t *eid)
{
    mcache_entry_t *mce;
    nonces_list_t *nonces;

    /* Lookup the map cache entry that match with the source EID prefix
     * of the message */
    if (!(mce = map_cache_lookup(eid))) {
        return(BAD);
    }


    /* Only accept one solicit map request for an EID prefix. If node which
     * generates the message has more than one locator, it probably will
     * generate a solicit map request for each one. Only the first one is
     * considered. If map_cache_entry->nonces is different from null, we have
     * already received a solicit map request  */
    if (!(nonces = mcache_entry_nonces(mce))) {
        mcache_entry_init_nonces_list(mce);
        if (!nonces) {
            return(BAD);
        }

        send_smr_invoked_map_request(dev, mce);
    }

    return(GOOD);
}

int
tr_recv_map_request(lisp_ctrl_dev_t *dev, lbuf_t *buf, uconn_t *uc)
{
    lisp_addr_t *seid, *deid, *tloc;
    mapping_t *map;
    glist_t *itr_rlocs = NULL;
    void *mreq_hdr, *mrep_hdr, *paddr, *per;
    int i;
    lbuf_t *mrep = NULL;
    lbuf_t  b;

    lisp_xtr_t *xtr = CONTAINER_OF(dev, lisp_xtr_t, super);

    /* local copy of the buf that can be modified */
    b = *buf;

    seid = lisp_addr_new();
    deid = lisp_addr_new();

    mreq_hdr = lisp_msg_pull_hdr(&b, sizeof(map_request_hdr_t));

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }

    lmlog(DBG_1, "%s src-eid: %s", lisp_msg_hdr_to_char(mreq_hdr),
            lisp_addr_to_char(seid));

    /* If packet is a Solicit Map Request, process it */
    if (lisp_addr_afi(seid) != LM_AFI_NO_ADDR && MREQ_SMR(mreq_hdr)) {
        if(tr_reply_to_smr(dev, seid) != GOOD) {
            goto err;
        }
        /* Return if RLOC probe bit is not set */
        if (!MREQ_RLOC_PROBE(mreq_hdr)) {
            goto done;
        }
    }

    /* Process additional ITR RLOCs */
    itr_rlocs = lisp_addr_list_new();
    lisp_msg_parse_itr_rlocs(&b, itr_rlocs);


    /* Process records and build Map-Reply */
    mrep = lisp_msg_create(LISP_MAP_REPLY);
    for (i = 0; i < MREQ_REC_COUNT(mreq_hdr); i++) {
        per = lbuf_data(b);
        if (lisp_msg_parse_eid_rec(b, deid, paddr) != GOOD) {
            goto err;
        }

        lmlog(DBG_1, " dst-eid: %s", lisp_addr_to_char(deid));

        if (is_mrsignaling(EID_REC_ADDR(per))) {
            mrsignaling_recv_msg(mrep, seid, deid, mrsignaling_flags(paddr));
            continue;
        }

        /* Check the existence of the requested EID */
        if (!(map = local_map_db_lookup_eid_exact(xtr->local_mdb, deid))) {
            lmlog(DBG_1,"EID %s not locally configured!",
                    lisp_addr_to_char(deid));
            continue;
        }

        lisp_msg_put_mapping(mrep, map, MREQ_RLOC_PROBE(mreq_hdr)
                ? &uc->ra: NULL);
    }

    mrep_hdr = lisp_msg_hdr(mrep);
    MREP_RLOC_PROBE(mrep_hdr) = MREQ_RLOC_PROBE(mreq_hdr);
    MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);

    /* send map-reply */
    select_remote_rloc(itr_rlocs, lisp_addr_ip_afi(&uc->la), &uc.ra);
    if (send_msg(dev, b, uc) != GOOD) {
        lmlog(DBG_1, "Couldn't send Map-Reply!");
    }

done:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_free(deid);
    return(BAD);
}

int
ms_recv_map_request(lisp_ctrl_dev_t *dev, lbuf_t *buf, uconn_t *uc)
{

    lisp_addr_t *seid, *deid, *tloc;
    mapping_t *map;
    glist_t *itr_rlocs = NULL;
    void *mreq_hdr, *mrep_hdr, *paddr, *per;
    int i;
    lbuf_t *mrep = NULL;
    lbuf_t  b;

    lisp_ms_t *ms = CONTAINER_OF(dev, lisp_ms_t, super);

    /* local copy of the buf that can be modified */
    b = *buf;

    seid = lisp_addr_new();
    deid = lisp_addr_new();

    mreq_hdr = lisp_msg_pull_hdr(&b, sizeof(map_request_hdr_t));

    if (lisp_msg_parse_addr(&b, seid) != GOOD) {
        goto err;
    }

    lmlog(DBG_1, "%s src-eid: %s", lisp_msg_hdr_to_char(mreq_hdr),
            lisp_addr_to_char(seid));
    if (MREQ_RLOC_PROBE(mreq_hdr)) {
        lmlog(DBG_3, "Probe bit set. Discarding!");
        return(BAD);
    }

    if (MREQ_SMR(mreq_hdr)) {
        lmlog(DBG_3, "SMR bit set. Discarding!");
        return(BAD);
    }

    /* Process additional ITR RLOCs */
    itr_rlocs = lisp_addr_list_new();
    lisp_msg_parse_itr_rlocs(&b, itr_rlocs);

    /* Process records and build Map-Reply */
    mrep = lisp_msg_create(LISP_MAP_REPLY);
    for (i = 0; i < MREQ_REC_COUNT(mreq_hdr); i++) {
        if (lisp_msg_parse_eid_rec(b, deid, paddr) != GOOD) {
            goto err;
        }

        lmlog(DBG_1, " dst-eid: %s", lisp_addr_to_char(deid));

        /* Check the existence of the requested EID */
        if (!(map = mdb_lookup_entry_exact(ms->reg_sites_db, deid))) {
            lmlog(DBG_1,"Unknown EID %s requested!",
                    lisp_addr_to_char(deid));
            continue;
        }

        lisp_msg_put_mapping(mrep, map, NULL);
    }

    mrep_hdr = lisp_msg_hdr(mrep);
    MREP_RLOC_PROBE(mrep_hdr) = 0;
    MREP_NONCE(mrep_hdr) = MREQ_NONCE(mreq_hdr);

    /* send map-reply */
    select_remote_rloc(itr_rlocs, lisp_addr_ip_afi(&uc->la), &uc.ra);
    if (send_msg(dev, b, uc) != GOOD) {
        lmlog(DBG_1, "Couldn't send Map-Reply!");
    }
done:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_del(seid);
    return(GOOD);
err:
    glist_destroy(itr_rlocs);
    lisp_msg_destroy(mrep);
    lisp_addr_free(deid);
    return(BAD);

}


int
recv_map_notify(lisp_ctrl_dev_t *dev, lbuf_t *b)
{
    lisp_addr_t *eid;
    mapping_t *m, *local_map, *mcache_map;
    mcache_entry_t *mce;
    void *hdr;
    int i;
    locator_t *probed;
    map_cache_db_t *mcdb;
    local_map_db_t *lmdb;

    hdr = lisp_msg_pull_hdr(b);

    mcdb = dev->tr_class->get_map_cache(dev);
    lmdb = dev->tr_class->get_local_mdb(dev);

    /* TODO: compare nonces in all cases not only NAT */
    if (MNTF_XTR_ID_PRESENT(hdr) == TRUE) {
        if (nonce_check(nat_emr_nonce, MNTF_NONCE(hdr)) == GOOD){
            lmlog(DBG_3, "Correct nonce");
            /* Free nonce if authentication is ok */
        } else {
            lmlog(DBG_1, "No Map Register sent with nonce: %s",
                    nonce_to_char(MNTF_NONCE(hdr)));
            return (BAD);
        }
    }

    /* TODO: match eid/nonce to ms-key */
    if (lisp_msg_check_auth_field(b, map_servers->key) != GOOD) {
        lmlog(DBG_1, "Map-Notify message is invalid");
        program_map_register(dev, LISPD_INITIAL_EMR_TIMEOUT);
        return(BAD);
    }

    lisp_msg_pull_auth_field(b);

    for (i = 0; i <= MNTF_REC_COUNT(hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(b, m, probed) != GOOD) {
            mapping_del(m);
            return(BAD);
        }

        eid = mapping_eid(m);

        local_map = local_map_db_lookup_eid_exact(lmdb, eid);
        if (!local_map) {
            lmlog(DBG_1, "Map-Notify confirms registration of UNKNOWN EID %s."
                    " Dropping!", lisp_addr_to_char(mapping_eid(m)));
            continue;
        }

        lmlog(DBG_1, "Map-Notify message confirms correct registration of %s",
                lisp_addr_to_char(eid));

        /* === merge semantics on === */
        if (mapping_cmp(local_map, m) != 0 || lisp_addr_is_mc(eid)) {
            lmlog(DBG_1, "Merge-Semantics on, moving returned mapping to "
                    "map-cache");

            /* Save the mapping returned by the map-notify in the mapping
             * cache */
            mcache_map = mcache_lookup_mapping(mcdb, eid);
            if (mcache_map && mapping_cmp(mcache_map, m) != 0) {
                /* UPDATED rlocs */
                lmlog(DBG_3, "Prefix %s already registered, updating locators",
                        lisp_addr_to_char(eid));
                mapping_update_locators(mcache_map,
                        m->head_v4_locators_list,
                        m->head_v6_locators_list,
                        m->locator_count);

                mapping_compute_balancing_vectors(mcache_map);
                program_mapping_rloc_probing(dev, mcache_map);

                /* cheap hack to avoid cloning */
                m->head_v4_locators_list = NULL;
                m->head_v6_locators_list = NULL;
                mapping_del(m);
            } else if (!mcache_map) {
                /* FIRST registration */
                if (mcache_add_mapping(mcdb, m) != GOOD) {
                    mapping_del(m);
                    return(BAD);
                }

                /* for MC initialize the JIB */
                if (lisp_addr_is_mc(eid)
                    && !mapping_get_re_data(mcache_entry_mapping(mce))) {
                    mapping_init_re_data(mcache_entry_mapping(mce));
                }
            }
        }

        free(nat_emr_nonce);
        nat_emr_nonce = NULL;
        program_map_register(dev, MAP_REGISTER_INTERVAL);

    }

    return(GOOD);
}

static void
mc_add_rlocs_to_rle(mapping_t *cmap, mapping_t *rtrmap) {
    locator_t       *cloc = NULL, *rtrloc = NULL;
    lcaf_addr_t     *crle = NULL, *rtrrle = NULL;
    glist_entry_t   *it = NULL;
    rle_node_t      *rtrnode = NULL, *itnode;
    int             found = 0;

    if (!lisp_addr_is_mc(mapping_eid(rtrmap)))
        return;

    if (rtrmap->head_v4_locators_list)
        rtrloc = rtrmap->head_v4_locators_list->locator;
    else if (rtrmap->head_v6_locators_list)
        rtrloc = rtrmap->head_v6_locators_list->locator;

    if (!rtrloc) {
        lmlog(DBG_1, "mc_add_rlocs_to_rle: NO rloc for mc channel %s. Aborting!",
                lisp_addr_to_char(mapping_eid(rtrmap)));
        return;
    }

    if (cmap->head_v4_locators_list)
        cloc = cmap->head_v4_locators_list->locator;
    else if (cmap->head_v6_locators_list)
        cloc = cmap->head_v6_locators_list->locator;

    if (!cloc) {
        lmlog(DBG_1, "mc_add_rlocs_to_rle: RLOC for mc channel %s is not initialized. Aborting!",
                lisp_addr_to_char(mapping_eid(rtrmap)));
    }

    rtrrle = lisp_addr_get_lcaf(locator_addr(rtrloc));
    crle = lisp_addr_get_lcaf(locator_addr(cloc));
    rtrnode = glist_first_data(lcaf_rle_node_list(rtrrle));

    glist_for_each_entry(it, lcaf_rle_node_list(crle)) {
        itnode = glist_entry_data(it);
        if (lisp_addr_cmp(itnode->addr, rtrnode->addr) == 0
                && itnode->level == rtrnode->level)
            found = 1;
    }

    if (!found)
        glist_add_tail(rle_node_clone(rtrnode), lcaf_rle_node_list(crle));


}

int
ms_recv_map_register(lisp_ctrl_dev_t *dev, lbuf_t *buf, uconn_t *rsk)
{
    mapping_t *mentry = NULL;
    lisp_ms_t *ms = NULL;
    lisp_site_prefix *reg_pref = NULL;
    char *key = NULL;
    lisp_addr_t *eid = NULL;
    lbuf_t b;
    void *hdr, *mntf_hdr;
    int i;
    mapping_t *m;
    locator_t *probed;
    lbuf_t *mntf;
    lisp_key_type_t keyid = HMAC_SHA_1_96; /* TODO configurable */


    b = *buf;

    lisp_ms_t *ms = CONTAINER_OF(dev, lisp_ms_t, super);

    if (MREG_WANT_MAP_NOTIFY(hdr)) {
        mntf = lisp_msg_create(LISP_MAP_NOTIFY);
        lisp_msg_put_empty_auth_record(mntf, keyid);
    }

    hdr = lisp_msg_pull_hdr(&b);
    for (i = 0; i < MREG_REC_COUNT(hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(b, m, probed) != GOOD){
            goto err;
        }

        eid = mapping_eid(m);
        /* find configured prefix */
        reg_pref = mdb_lookup_entry(ms->lisp_sites_db, eid);
        if (!reg_pref) {
            lmlog(DBG_1, "EID %s not in configured lisp-sites DB! "
                    "Discarding mapping!", lisp_addr_to_char(eid));
            mapping_del(m);
            continue;
        }

        /* check auth */
        if (!key) {
            if (!lisp_msg_check_auth_field(b, reg_pref->key)) {
                lmlog(DBG_1, "Message validation failed for EID %s with key %s."
                        " Stopping processing!", lisp_addr_to_char(eid),
                        reg_pref->key);
                goto bad;
            }
            lmlog(DBG_3, "Message validated with key associated to EID %s",
                    lisp_addr_to_char(eid));
            key = reg_pref->key;
        } else if (strncmp(key, reg_pref->key, strlen(key)) !=0 ) {
            lmlog(DBG_1, "EID %s part of multi EID Map-Register has different "
                    "key! Discarding!", lisp_addr_to_char(eid));
            continue;
        }


        /* check if more specific */
        if (!reg_pref->accept_more_specifics
                && lisp_addr_cmp(reg_pref->eid_prefix, eid) !=0) {
            lmlog(DBG_1, "EID %s is a more specific of %s. However more "
                    "specifics not configured! Discarding", lisp_addr_to_char(eid),
                    lisp_addr_to_char(reg_pref->eid_prefix));
            lisp_addr_del(eid);
            continue;
        }

        mentry = mdb_lookup_entry_exact(ms->reg_sites_db, eid);
        if (mentry) {
            if (mapping_cmp(mentry, m) != 0) {
                if (!reg_pref->merge) {
                    lmlog(DBG_3, "Prefix %s already registered, updating locators",
                            lisp_addr_to_char(eid));
                    mapping_update_locators(mentry, m->head_v4_locators_list,
                            m->head_v6_locators_list, m->locator_count);
                    /* cheap hack to avoid cloning */
                    m->head_v4_locators_list = NULL;
                    m->head_v6_locators_list = NULL;
                } else {
                    /* TREAT MERGE SEMANTICS */
                    lmlog(LISP_LOG_WARNING, "Prefix %s has merge semantics",
                            lisp_addr_to_char(eid));
                    /* MCs EIDs have their RLOCs aggregated into an RLE */
                    if (lisp_addr_is_mc(eid)) {
                        mc_add_rlocs_to_rle(mentry, m);
                    } else {
                        lmlog(LISP_LOG_WARNING, "MS: Registered %s requires "
                                "merge semantics but we don't know how to "
                                "handle! Discarding!", lisp_addr_to_char(eid));
                        goto bad;
                    }
                }

                ms_dump_registered_sites(dev, DBG_3);
            }

            mapping_del(m);

        } else if (!mentry) {
            /* save prefix to the registered sites db */
            mdb_add_entry(ms->reg_sites_db, mapping_eid(m), m);
            ms_dump_registered_sites(dev, DBG_3);
            mentry = m;
        }

        if (MREG_WANT_MAP_NOTIFY(hdr)) {
            lisp_msg_put_mapping(mntf, m);
        }

        /* TODO: start timers */

        mapping_del(m);
    }


    if (mntf) {
        mntf_hdr = lisp_msg_hdr(mntf);
        MNTF_NONCE(mntf_hdr) = MREG_NONCE(hdr);
        lisp_msg_fill_auth_data(b, key, keyid);
        core_send_msg(mntf, rsk);//fix
        lisp_msg_destroy(mntf);

    }

    return(GOOD);
err:
    return(BAD);
    if (m) {
        mapping_del(m);
    }
    if (mntf) {
        lisp_msg_destroy(mntf);
    }
bad: /* could return different error */
    if(m) {
        mapping_del(m);
    }
    if (mntf) {
        lisp_msg_destroy(mntf);
    }
    return(BAD);

}

int
send_map_request(lisp_ctrl_dev_t *dev, lbuf_t *b, lisp_addr_t *srloc,
        lisp_addr_t *drloc) {
    uconn_t uc;
    uc.lp = uc.rp = LISP_CONTROL_PORT;
    if (srloc) {
        lisp_addr_copy(&uc.la, srloc);
    } else {
        lisp_addr_set_afi(&uc.la, LM_AFI_NO_ADDR);
    }

    lisp_addr_copy(&uc.ra, drloc);
    if (send_msg(dev, b, &uc) != GOOD) {
        lmlog(DBG_1,"Couldn't send Map-Request!");
    }
    return(GOOD);
}



int
send_map_request_to_mr(lisp_ctrl_dev_t *dev, lbuf_t *b, lisp_addr_t *in_srloc,
        lisp_addr_t *in_drloc)
{
    lisp_addr_t *drloc, *srloc;
    uconn_t in_uc, uc;
    int afi;

    /* udp connection parameters (inner headers) */
    lisp_addr_copy(&in_uc.la, in_srloc);
    lisp_addr_copy(&in_uc.ra, in_drloc);
    in_uc.rp = in_uc.lp = LISP_CONTROL_PORT;

    /* encap */
    lisp_msg_push_ecm_encap(b, in_uc);

    /* prepare outer headers */
    drloc = dev->tr_class->get_map_resolver(dev);
    afi = lisp_addr_ip_afi(drloc);
    srloc = dev->tr_class->get_default_rloc(dev, afi);

    return(send_map_request(dev, b, srloc, drloc));

}

int
handle_map_cache_miss(lisp_ctrl_dev_t *dev, lisp_addr_t *requested_eid,
        lisp_addr_t *src_eid)
{
    mcache_entry_t *mce = NULL;
    mapping_t *m;

    /* install temporary, NOT active, mapping in map_cache
     * TODO: should also build a nonce hash table for faster
     *       nonce lookups*/
    m = mapping_init_remote(requested_eid);
    mce = mcache_entry_init(m);
    if (map_cache_add_entry(mce) != GOOD) {
        lmlog(LWRN, "Couln't install temporary map cache entry for %s!",
                lisp_addr_to_char(requested_eid));
        return(BAD);
    }

    if (src_eid) {
        mcache_entry_set_requester(mce, lisp_addr_clone(src_eid));
    } else {
        mcache_entry_set_requester(mce, NULL);
    }

    return(send_map_request_retry(dev, mce));
}

static glist_t *
build_rloc_list(mapping_t *m) {
    glist_t *rlocs = glist_new();
    locators_list_t *llist[2] = {NULL, NULL};
    int ctr;
    locator_t *loc;

    llist[0] = m->head_v4_locators_list;
    llist[1] = m->head_v6_locators_list;
    for (ctr = 0 ; ctr < 2 ; ctr++){
        while (llist[ctr]) {
            loc = locator_addr(llist[ctr]);
            glist_add(rlocs, loc);
            llist[ctr] = llist[ctr]->next;
        }
    }
    return(rlocs);
}

/* solicit SMRs for 'src_map' to all locators of 'dst_map'*/
static int
build_and_send_smr_mreq(lisp_ctrl_dev_t *dev, mapping_t *src_map,
        mapping_t *dst_map)
{
    lbuf_t *b;
    void *hdr;
    uconn_t uc;
    int ret, j;
    lisp_addr_t *srloc, *seid, *deid, *drloc;
    glist_t *rlocs;
    locators_list_t *llists[2], *lit;
    locator_t *loc;


    seid = mapping_eid(src_map);
    rlocs = build_rloc_list(src_map);
    deid = mapping_eid(dst_map);

    uc->rp = uc->lp = LISP_CONTROL_PORT;

    llists[0] = dst_map->head_v4_locators_list;
    llists[1] = dst_map->head_v6_locators_list;
    for (j = 0; j < 2; j++) {
        if (llists[j]) {
            lit = llists[j];
            while (lit) {
                loc = lit->locator;

                /* build Map-Request */
                b = lisp_msg_create(LISP_MAP_REQUEST);
                lisp_msg_mreq_init(b, seid, rlocs, deid);

                hdr = lisp_msg_hdr(b);
                MREQ_SMR(hdr) = 1;

                srloc = dev->tr_class->get_default_rloc(dev, lisp_addr_ip_afi(drloc));
                if (!srloc) {
                    lmlog(DBG_1, "No compatible RLOC was found to send SMR Map-Request "
                            "for local EID %s", lisp_addr_to_char(seid));
                    lisp_msg_destroy(b);
                    continue;
                }

                lisp_addr_copy(&uc->ra, drloc);
                lisp_addr_copy(&uc->la, srloc);

                ret = send_msg(dev, b, &uc);

                if (ret != GOOD) {
                    lmlog(DBG_1, "FAILED TO SEND \n %s "
                            "EID: %s ->  %s RLOC: %s -> %s",
                            lisp_msg_hdr_to_char(hdr), lisp_addr_to_char(seid),
                            lisp_addr_to_char(srloc), lisp_addr_to_char(drloc));
                } else {
                    lmlog(DBG_1, "%s EID: %s -> %s RLOC: %s -> dst-rloc: %s",
                            lisp_msg_hdr_to_char(hdr), lisp_addr_to_char(seid),
                            lisp_addr_to_char(srloc), lisp_addr_to_char(drloc));
                }

                lisp_msg_destroy(b);
                lit = lit->next;
            }
        }
    }

    glist_destroy(rlocs);

    return(GOOD);
}

static int
send_all_smr_cb(timer *t, void *arg)
{
    timer_arg_t *ta = arg;
    send_all_smr(ta->dev);
    return(GOOD);
}

/* Send a solicit map request for each rloc of all eids in the map cache
 * database */
static void
send_all_smr(lisp_ctrl_dev_t *dev)
{
    locators_list_t *loc_lists[2] = {NULL, NULL};
    mcache_entry_t *mce = NULL;
    locators_list_t *lit = NULL;
    locator_t *loc = NULL;
    mapping_t **mlist = NULL, *mit;
    lisp_addr_list_t *pitr_elt = NULL;
    lisp_addr_t *eid = NULL;
    int mcount = 0;
    int i, j, nb_mappings;
    map_cache_db_t *mcdb;



    lmlog(DBG_2,"*** Init SMR notification ***");

    /* Get a list of mappings that require smrs */
    nb_mappings = local_map_db_n_mappings(dev->tr_class->get_local_mdb(dev));
    if (!(mlist = calloc(1, nb_mappings*sizeof(mapping_t *)))) {
        lmlog(LWRN, "ctrl_dev_send_smr: Unable to allocate memory: %s",
                strerror(errno));
        return;
    }

    mlist = ctrl_get_mappings_to_smr(dev->ctrl, mlist, &mcount);

    /* Send map register and SMR request for each mapping */
    for (i = 0; i < mcount; i++) {
        /* Send map register for all mappings */
        if (nat_aware == FALSE || nat_status == NO_NAT) {
            build_and_send_map_register_msg(mlist[i]);
        }else if (nat_status != UNKNOWN){
            /* TODO : We suppose one EID and one interface.
             * To be modified when multiple elements */
            map_register_process();
        }

        eid = mapping_eid(mlist[i]);

        lmlog(DBG_1, "Start SMR for local EID %s", lisp_addr_to_char(eid));

        /* For each map cache entry with same afi as local EID mapping */

        if (lisp_addr_afi(eid) == LM_AFI_IP ) {
            lmlog(DBG_3, "init_smr: SMR request for %s. Shouldn't receive SMR "
                    "for IP in mapping?!", lisp_addr_to_char(eid));
        } else if (lisp_addr_afi(eid) != LM_AFI_IPPREF) {
            lmlog(DBG_3, "init_smr: SMR request for %s. SMR supported only for "
                    "IP-prefixes for now!",  lisp_addr_to_char(eid));
            continue;
        }

        /* no SMRs for now for multicast */
        if (lisp_addr_is_mc(eid))
            continue;


        /* TODO: spec says SMRs should be sent only to peer ITRs that sent us
         * traffic in the last minute. Should change this in the future*/
        /* XXX: works ONLY with IP */
        mcdb = dev->tr_class->get_map_cache(dev);
        mcache_foreach_active_entry_in_ip_eid_db(mcdb, eid, mce) {
            mit = mcache_entry_mapping(mce);
            build_and_send_smr_mreq(dev, mlist[i], mit);

        } mcache_foreach_active_entry_in_ip_eid_db_end;

        /* SMR proxy-itr */
        pitr_elt = proxy_itrs;

        while (pitr_elt) {
            if (build_and_send_smr_mreq(dev, mlist[i], pitr_elt->address)
                    == GOOD) {
                lmlog(DBG_1, "  SMR'ing Proxy ITR %s for EID %s",
                        lisp_addr_to_char(pitr_elt->address),
                        lisp_addr_to_char(eid));
            } else {
                lmlog(DBG_1, "  Coudn't SMR Proxy ITR %s for EID %s",
                        lisp_addr_to_char(pitr_elt->address),
                        lisp_addr_to_char(eid));
            }
            pitr_elt = pitr_elt->next;
        }

    }

    free (mlist);
    lmlog(DBG_2,"*** Finish SMR notification ***");
}

static int
smr_invoked_map_request_cb(timer *t, void *arg)
{
    timer_arg_t *ta = arg;
    return(send_smr_invoked_map_request(ta->dev, ta->data));
}

int
send_smr_invoked_map_request(lisp_ctrl_dev_t *dev, mcache_entry_t *mce)
{
    struct lbuf *b;
    void *hdr;
    nonces_list_t *nonces;
    mapping_t *m;
    lisp_addr_t *deid, empty, *srloc, *drloc;
    timer_arg_t *arg;
    timer *t;
    glist_t *rlocs;
    int afi;

    m = mcache_entry_mapping(mce);
    deid = mapping_eid(m);
    lisp_addr_set_afi(&empty, LM_AFI_NO_ADDR);

    /* Sanity Check */
    if (!nonces) {
        mcache_entry_init_nonces(mce);
        if (!(nonces = mcache_entry_nonces(mce))) {
            lmlog(LWRN, "send_smr_invoked_map_request: Unable to allocate"
                    " memory for nonces.");
            return (BAD);
        }
    }

    if (nonces->retransmits - 1 < LISPD_MAX_SMR_RETRANSMIT) {
        lmlog(DBG_1,"SMR: Map-Request for EID: %s (%d retries)",
                lisp_addr_to_char(deid), nonces->retransmits);

        /* build Map-Request */
        b = lisp_msg_create(LISP_MAP_REQUEST);

        /* no source EID and mapping, so put default control rlocs */
        rlocs = dev->tr_class->get_default_rlocs(dev);
        lisp_msg_mreq_init(&empty, rlocs, mapping_eid(m));
        glist_destroy(rlocs);

        hdr = lisp_msg_hdr(b);
        MREQ_SMR_INVOKED(hdr) = 1;
        MREQ_NONCE(hdr) = nonces->nonce[nonces->retransmits];

        afi = lisp_addr_afi(deid);
        /* we could put anything here. Still, better put something that
         * makes a bit of sense .. */
        srloc = dev->tr_class->get_main_eid(dev, afi);
        drloc = deid;

        if (send_map_request_to_mr(dev, b, srloc, drloc) != GOOD) {
            return(BAD);
        }

        /* init or delete and init, if needed, the timer */
        t = mcache_entry_init_smr_inv_timer(mce);
        arg = mcache_entry_smr_inv_timer_arg(mce);
        *arg = (timer_arg_t){dev, mce};

        start_timer(t, LISPD_INITIAL_SMR_TIMEOUT,
                smr_invoked_map_request_cb, arg);
        nonces->retransmits ++;

    } else {
        mcache_entry_stop_smr_inv_timer(mce);
        lmlog(DBG_1,"SMR: No Map Reply for EID %s. Stopping ...",
                lisp_addr_to_char(deid));
    }
    return (GOOD);

}


int
program_smr(lisp_ctrl_dev_t *dev, int time) {
    timer *t;
    timer_arg_t *arg;
    t = dev->tr_class->smr_timer(dev);

    arg->dev = dev;
    start_timer(t, LISPD_SMR_TIMEOUT, send_all_smr_cb, arg);
    return(GOOD);
}


static int
send_map_request_retry_cb(timer *t, void *arg) {
    timer_arg_t *ta = arg;
    int ret;

    free(ta);
    ret = send_map_request_retry(ta->dev, ta->data);
    return(ret);
}


/* Sends a Map-Request for EID in 'mce' and sets-up a retry timer */
int
send_map_request_retry(lisp_ctrl_dev_t *dev, mcache_entry_t *mce)
{
    timer *t;
    nonces_list_t *nonces;
    mapping_t *m;
    lisp_addr_t *eid;
    lbuf_t *b;
    void *mr_hdr;
    timer_arg_t *arg;

    nonces = mcache_entry_nonces(mce);
    m = mcache_entry_mapping(mce);
    eid = mapping_eid(m);

    if (!nonces) {
        mcache_entry_init_nonces(mce);
        if (!(nonces = mcache_entry_nonces(mce))) {
            lmlog(LWRN, "Send_map_request_miss: Unable to allocate memory for "
                    "nonces.");
            return (BAD);
        }
    }

    if (nonces->retransmits - 1 < map_request_retries) {
        if (nonces->retransmits > 0) {
            lmlog(DBG_1, "Retransmiting Map Request for EID: %s (%d retries)",
                    lisp_addr_to_char(eid), nonces->retransmits);
        }

        /* build Map-Request */
        b = lisp_msg_create(LISP_MAP_REQUEST);
        lisp_msg_mreq_init(b, dev->tr_class->get_main_eid(),
                dev->tr_class->get_default_rlocs(dev), mapping_eid(m));

        mr_hdr = lisp_msg_hdr(b);
        MREQ_NONCE(mr_hdr) = nonces->nonce[nonces->retransmits];

        send_map_request_to_mr(dev, b, mcache_entry_requester(mce), eid);

        /* prepare callback
         * init or delete and init, if needed, the timer */
        t = mcache_entry_init_req_retry_timer(mce);
        arg = mcache_entry_req_retry_timer_arg(mce);
        *arg = (timer_arg_t){dev, mce};

        start_timer(t, LISPD_INITIAL_SMR_TIMEOUT,
                send_map_request_retry_cb, arg);

        nonces->retransmits++;

        lisp_msg_destroy(b);

    } else {
        lmlog(DBG_1, "No Map-Reply for EID %s after %d retries. Aborting!",
                lisp_addr_to_char(eid), nonces->retransmits - 1);
        mcache_remove_mapping(eid);
    }

    return(GOOD);
}

/* build and send generic map-register with one record */
static int
build_and_send_map_reg(lisp_ctrl_dev_t *dev, mapping_t *m, char *key,
        lisp_key_type_t keyid)
{
    lbuf_t *b;
    void *hdr;

    b = lisp_msg_create(LISP_MAP_REGISTER);

    if (lisp_msg_put_empty_auth_record(*b, keyid) != GOOD) {
        return(BAD);
    }
    if (lisp_msg_put_mapping(b, m) != GOOD) {
        return(BAD);
    }
    if (lisp_msg_fill_auth_data(b, key, keyid) != GOOD) {
        return(BAD);
    }

    hdr = lisp_msg_hdr(b);
    /* XXX Quick hack */
    /* Cisco IOS RTR implementation drops Data-Map-Notify if ECM Map Register
     * nonce = 0 */
    MREG_NONCE(hdr) = nonce_build((unsigned int) time(NULL));

    send_msg(dev, b);
    lisp_msg_destroy(b);
    return(GOOD);
}

static int
map_register_cb(timer *t, void *arg)
{
    return(map_register_process(arg));
}

int
program_map_register(lisp_ctrl_dev_t *dev, int time) {
    timer *t = dev->tr_class->map_register_timer(dev);

    /* Configure timer to send the next map register. */
    start_timer(t, time, map_register_cb, dev);
    lmlog(DBG_1, "(Re)programmed Map-Register process in %d seconds", time);
    return(GOOD);
}



static int
map_register_process_default(lisp_ctrl_dev_t *dev)
{
    mapping_t *m;
    void *it = NULL;
    lbuf_t *mreg;
    lisp_key_type_t keyid = HMAC_SHA_1_96;
    local_map_db_t *lmdb;

    /* TODO
     * - configurable keyid
     * - multiple MSes
     */

    lmdb = dev->tr_class->get_local_mdb(dev);
    local_map_db_foreach_entry(lmdb, it) {
        m = it;
        if (m->locator_count != 0) {
            err = build_and_send_map_reg(dev, &mreg, m,
                    map_servers->key, keyid);
            if (err != GOOD) {
                lmlog(LERR, "Coudn't send Map-Register for EID  %s!",
                        lisp_addr_to_char(mapping_eid(m)));
            }
        }
    } local_map_db_foreach_end;

    program_map_register(dev, MAP_REGISTER_INTERVAL);

    return(GOOD);
}

static int
map_register_process_encap(lisp_ctrl_dev_t *dev)
{
    mapping_t *m = NULL;
    locators_list_t *loc_list[2] = { NULL, NULL };
    locator_t *loc = NULL;
    lisp_addr_t *nat_rtr = NULL;
    int next_timer_time = 0;
    int ctr1 = 0;
    void *it = NULL;
    nonces_list_t *nemrn;
    local_map_db_t *lmdb;

    lmdb = dev->tr_class->get_local_mdb(dev);
    nemrn = dev->tr_class->nat_emr_nonce(dev);
    if (!nemrn) {
        lmlog(LWRN,"map_register_process_encap: nonces unallocated!"
                " Aborting!");
        exit_cleanup();
    }

    if (nemrn->retransmits <= LISPD_MAX_RETRANSMITS) {

        if (nemrn->retransmits > 0) {
            lmlog(DBG_1,"No Map Notify received. Retransmitting encapsulated "
                    "map register.");
        }

        local_map_db_foreach_entry(lmdb, it) {
            m = it;
            if (m->locator_count != 0) {

                /* Find the locator behind NAT */
                loc_list[0] = m->head_v4_locators_list;
                loc_list[1] = m->head_v6_locators_list;
                for (ctr1 = 0 ; ctr1 < 2 ; ctr1++) {
                    while (loc_list[ctr1] != NULL) {
                        loc = loc_list[ctr1]->locator;
                        if ((((lcl_locator_extended_info *)loc->extended_info)->rtr_locators_list) != NULL) {
                            break;
                        }
                        loc = NULL;
                        loc_list[ctr1] = loc_list[ctr1]->next;
                    }
                    if (loc != NULL){
                        break;
                    }
                }
                /* If found a locator behind NAT, send
                 * Encapsulated Map Register */
                if (loc != NULL) {
                    nat_rtr = &(((lcl_locator_extended_info *)loc->extended_info)->rtr_locators_list->locator->address);
                    /* ECM map register only sent to the first Map Server */
                    err = build_and_send_ecm_map_register(m,
                            map_servers,
                            nat_rtr,
                            default_ctrl_iface_v4,
                            &site_ID,
                            &xTR_ID,
                            &(nemrn->nonce[nemrn->retransmits]));
                    if (err != GOOD){
                        lmlog(LERR,"encapsulated_map_register_process: "
                                "Couldn't send encapsulated map register.");
                    }
                    nemrn->retransmits++;
                }else{
                    if (loc == NULL){
                        lmlog(LERR,"encapsulated_map_register_process: "
                                "Couldn't send encapsulated map register. "
                                "No RTR found");
                    }else{
                        lmlog(LERR,"encapsulated_map_register_process: "
                                "Couldn't send encapsulated map register. "
                                "No output interface found");
                    }
                }
                next_timer_time = LISPD_INITIAL_EMR_TIMEOUT;
            }
        } local_map_db_foreach_end;

    }else{
        free (nemrn);
        nemrn = NULL;
        lmlog(LERR,"encapsulated_map_register_process: Communication error "
                "between LISPmob and RTR/MS. Retry after %d seconds",
                MAP_REGISTER_INTERVAL);
        next_timer_time = MAP_REGISTER_INTERVAL;
    }

    program_map_register(dev, next_timer_time);

    return(GOOD);
}


int
map_register_process(lisp_ctrl_dev_t *dev)
{
    int ret = 0;
    lispd_map_server_list_t *ms;
    int nat_aw, nat_stat;

    ms = dev->tr_class->get_map_servers(dev);
    if (!ms) {
        lmlog(LISP_LOG_CRIT, "map_register: No Map Servers configured!");
        exit_cleanup();
    }

    nat_aw = dev->tr_class->nat_aware(dev);
    nat_stat = dev->tr_class->nat_status(dev);

    if (nat_aw == TRUE) {
        /* NAT procedure instead of the standard one */
        /* TODO: if possible move info_request_process out */
        if (nat_stat == UNKNOWN) {
            ret = initial_info_request_process();
        }

        if (nat_stat == FULL_NAT) {
            ret = map_register_process_encap(dev);
        }
    }

    /* Standard Map-Register mechanism */
    if ((nat_aw == FALSE) || ((nat_aw == TRUE) && (nat_stat == NO_NAT))) {
        ret = map_register_process_default(dev);
    }

    return (ret);
}

