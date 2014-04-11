/*
 * lisp_ctrl_device.c
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


#include "lisp_ctrl_device.h"
#include <lispd_external.h>
#include <lispd_sockets.h>
#include <packets.h>
#include <lispd_lib.h>


int process_ctrl_msg(lisp_ctrl_device *dev, lisp_msg *msg, udpsock_t *udpsock) {
    return(dev->vtable->process_msg(dev, msg, udpsock));
}

void lisp_ctrl_dev_start(lisp_ctrl_device *dev) {
    dev->vtable->start(dev);
}

void lisp_ctrl_dev_del(lisp_ctrl_device *dev) {
    dev->vtable->delete(dev);
}

//static uint8_t is_lcaf_mcast_info(address_field *addr) {
//    return( address_field_afi(addr) != LISP_AFI_LCAF
//            && address_field_lcaf_type(addr) != LCAF_MCAST_INFO);
//}





/* Process a record from map-reply probe message */
int process_map_reply_probe(mapping_t *m, locator_t *probed, uint64_t nonce)
{
    lisp_addr_t *src_eid = NULL;
    locator_t *loc = NULL, *aux_loc = NULL;
    mapping_t *old_map = NULL, *pmap = NULL;
    locators_list_t *loc_list[2] = {NULL, NULL};
    rmt_locator_extended_info *rmt_ext_inf = NULL;
    int ctr = 0;

    src_eid = maping_eid(m);
    if (mapping_locator_count(m) > 0) {
        /* Lookup src EID in map cache */
        old_map = mcache_lookup_mapping(src_eid);
        if(!old_map) {
            lmlog(DBG_1, "Source EID %s couldn't be found in the map-cache",
                    lisp_addr_to_char(src_eid));
            return(BAD);
        }

        /* Find probed locator in mapping */
        loc = get_locator_from_mapping(old_map, locator_addr(probed));
        if (!loc){
            lmlog(DBG_2,"Probed locator %s not part of the the mapping %s",
                    lisp_addr_to_char(locator_addr(probed)),
                    lisp_addr_to_char(mapping_eid(old_map)));
            return (ERR_NO_EXIST);
        }

        /* Compare nonces */
        rmt_ext_inf = (rmt_locator_extended_info *)(loc->extended_info);
        if (!rmt_ext_inf || !rmt_ext_inf->rloc_probing_nonces) {
            lmlog(DBG_1, "Locator %s has no nonces!",
                    lisp_addr_to_char(locator_addr(loc)));
            return(BAD);
        }

        /* Check if the nonce of the message match with the one stored in the
         * structure of the locator */
        if ((check_nonce(rmt_ext_inf->rloc_probing_nonces, nonce)) == GOOD){
            free(rmt_ext_inf->rloc_probing_nonces);
            rmt_ext_inf->rloc_probing_nonces = NULL;
        }else{
            lmlog(DBG_1,"Nonce of Map-Reply Probe doesn't match nonce of the "
                    "Map-Request Probe. Discarding message ...");
            return (BAD);
        }

        lmlog(DBG_1," Successfully pobed RLOC %s of cache entry with EID %s",
                    lisp_addr_to_char(locator_addr(probed)),
                    lisp_addr_to_char(mapping_eid(old_map)));

    /* If negative probe map-reply, then the probe was for proxy-ETR (PETR) */
    } else {
        pmap = mcache_entry_mapping(proxy_etrs);
        if (proxy_etrs
            && lisp_addr_cmp(src_eid, mapping_eid(pmap)) == 0) {

            /* find locator */
            old_map = mcache_entry_mapping(proxy_etrs);
            loc_list[0] = pmap->head_v4_locators_list;
            loc_list[1] = pmap->head_v6_locators_list;
            for (ctr=0 ; ctr < 2 ; ctr++) {
                while (loc_list[ctr]!=NULL) {
                    aux_loc = loc_list[ctr]->locator;
                    rmt_ext_inf = (rmt_locator_extended_info *)(aux_loc->extended_info);
                    if ((check_nonce(rmt_ext_inf->rloc_probing_nonces,nonce)) == GOOD){
                        free (rmt_ext_inf->rloc_probing_nonces);
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
            if (!loc) {
                lmlog(DBG_1,"Nonce of Negative Map-Reply Probe doesn't match "
                        "any nonce of Proxy-ETR locators");
                return (BAD);
            }
        } else {
            lmlog(DBG_1,"Map-Reply Probe for %s has not been requested! "
                    "Discarding!", lisp_addr_to_char(src_eid));
            return (BAD);
        }

        lmlog(DBG_1,"Map-Reply probe reachability to the PETR with RLOC %s",
                    lisp_addr_to_char(locator_addr(loc)));
    }

    if (*(loc->state) == DOWN) {
        *(loc->state) = UP;

        lmlog(DBG_1," Locator %s state changed to UP",
                lisp_addr_to_char(locator_addr(loc)));

        /* [re]Calculate balancing locator vectors if status changed*/
        mapping_compute_balancing_vectors(old_map);
    }

    /* Reprogramming timers of rloc probing */
    rmt_ext_inf = (rmt_locator_extended_info *)(loc->extended_info);
    if (!rmt_ext_inf->probe_timer){
       lmlog(DBG_1," Map-Reply Probe was not requested! Discarding!");
       return (BAD);
    }

    start_timer(rmt_ext_inf->probe_timer, RLOC_PROBING_INTERVAL,
            (timer_callback)rloc_probing, rmt_ext_inf->probe_timer->cb_argument);

    if (mapping_locator_count(m) != 0 ){
        lmlog(DBG_2,"Reprogrammed probing of EID's %s locator %s (%d seconds)",
                lisp_addr_to_char(mapping_eid(old_map)),
                lisp_addr_to_char(locator_addr(loc)),
                RLOC_PROBING_INTERVAL);
    } else {
        lmlog(DBG_2,"Reprogrammed RLOC probing of PETR locator %s in %d seconds",
                lisp_addr_to_char(locator_addr(loc)), RLOC_PROBING_INTERVAL);
    }

    return (GOOD);

}


//static int process_map_reply_record(mapping_record *record, uint64_t nonce) {
//
//    lisp_addr_t                     *eid        = NULL;
//    locators_list_t             **locators  = NULL;
//    locator_t                       *loc_elt    = NULL;
//    glist_t                         *locs       = NULL;
//    glist_entry_t                   *it         = NULL;
//
//    if (!(eid = lisp_addr_init_from_field(mapping_record_eid(record))))
//        return(BAD);
//
//    if (lisp_addr_afi(eid) == LM_AFI_IP)
//        lisp_addr_set_plen(eid, mapping_record_hdr(record)->eid_prefix_length);
//
//    lmlog(DBG_1, " EID: %s", lisp_addr_to_char(eid));
//
//    /* I don't like this too much but we need it to be compatible with locators_list */
//    locators = calloc(1, sizeof(locators_list_t*));
//
//    locs = mapping_record_locators(record);
//    glist_for_each_entry(it, locs) {
//        if (!(loc_elt = locator_init_from_field(glist_entry_data(it))))
//            goto err;
//        lmlog(DBG_1, "    RLOC: %s", locator_to_char(loc_elt));
//        if (add_locator_to_list(locators, loc_elt) != GOOD)
//            goto err;
//    }
//
//    /* TODO: mapping should be created here */
//    if (mcache_activate_mapping(eid, *locators, nonce,
//                                mapping_record_hdr(record)->action,
//                                ntohl(mapping_record_hdr(record)->ttl)) != GOOD)
//        goto err;
//
//    lisp_addr_del(eid); /* TODO: eid is copied when mapping is created. Should change ... */
//    return(GOOD);
//err:
//    lmlog(DBG_3, "Error encountered while processing locators!");
//    lisp_addr_del(eid);
//    if (locators)
//        locator_list_del(*locators);
//    return(BAD);
//
//}


int
process_map_reply_msg(map_reply_msg *mrep, lbuf_t *buf)
{
    mapping_record              *record;
    glist_t                     *records;
    glist_entry_t               *it;


    void *mrep_hdr, *mrec_hdr, loc_hdr;
    int i, j, ret;
    glist_t locs;
    locator_t *loc, *probed;
    lisp_addr_t *seid;
    mapping_t *m;
    lbuf_t b;
    map_cache_entry_t *mce;

    /* local copy */
    b = *buf;
    seid = lisp_addr_new();

    mrep_hdr = lisp_msg_pull_hdr(b);
    lmlog(DBG_1, "%s", lisp_msg_hdr_to_char(mrep));

    for (i = 0; i <= MREP_REC_COUNT(mrep_hdr); i++) {
        m = mapping_new();
        if (lisp_msg_parse_mapping_record(b, m, probed) != GOOD) {
            goto err;
        }

        if (!MREP_RLOC_PROBE(mrep_hdr)) {
            /* Check if the map reply corresponds to a not active map cache */
            mce = lookup_nonce_in_no_active_map_caches(mapping_eid(m), MREP_NONCE(mrep_hdr));

            if (mce) {
                /* delete placeholder/dummy mapping and install the new one */
                mcache_del_mapping(mapping_eid(mcache_entry_mapping(mce)));

                /* DO NOT free mapping in this case */
                mcache_add_mapping(m);
            } else {

                /* the reply might be for an active mapping (SMR)*/
                mcache_update_entry(m, MREP_NONCE(mrep_hdr));
                mapping_del(m);
            }

            map_cache_dump_db(DBG_3);

            /*
            if (is_mrsignaling()) {
                mrsignaling_recv_ack();
                continue;
            } */
        } else {
            process_map_reply_probe(m, probed, MREP_NONCE(mrep_hdr));
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


int handle_map_cache_miss(lisp_addr_t *requested_eid, lisp_addr_t *src_eid)
{

    map_cache_entry_t       *entry          = NULL;
    timer_map_request_argument  *arguments      = NULL;

    lmlog(DBG_1, "req %s and src %s", lisp_addr_to_char(requested_eid), lisp_addr_to_char(src_eid));
    if ((arguments = malloc(sizeof(timer_map_request_argument)))==NULL){
        lmlog(LISP_LOG_WARNING,"handle_map_cache_miss: Unable to allocate memory for timer_map_request_argument: %s",
                strerror(errno));
        return (ERR_MALLOC);
    }

    //arnatal TODO: check if this works
    entry = new_map_cache_entry(
            *requested_eid,
            lisp_addr_get_plen(requested_eid),
            DYNAMIC_MAP_CACHE_ENTRY,
            DEFAULT_DATA_CACHE_TTL);

//    if (entry) dump_map_cache_entry(entry, DBG_1);
    if (!entry) {
        lmlog(LISP_LOG_WARNING, "Couln't install the new map cache entry!");
        return(BAD);
    }

    arguments->map_cache_entry = entry;
    if (src_eid)
        /* clone the address not to lose it while waiting for the answer*/
        arguments->src_eid = lisp_addr_clone(src_eid);
    else
        arguments->src_eid = NULL;
    /* need to delete src addr, which may be an lcaf */
    arguments->arg_free_fct = (void (*)(void *))timer_map_request_argument_del;

    if ((err=send_map_request_miss(NULL, (void *)arguments))!=GOOD)
        return (BAD);

    return (GOOD);
}

/*
 *  process Map_Request Message
 *  Receive a Map_request message and process based on control bits
 *
 *  For first phase just accept (encapsulated) SMR. Proxy bit is set to avoid receiving ecm, and all other types are ignored.
 */


int send_map_request_miss(timer *t, void *arg)
{
    timer_map_request_argument *argument = (timer_map_request_argument *)arg;
    map_cache_entry_t *map_cache_entry = argument->map_cache_entry;
    nonces_list *nonces = map_cache_entry->nonces;
    lisp_addr_t *dst_rloc = NULL;
    mapping_t       *mapping    = NULL;

    mapping = mcache_entry_mapping(map_cache_entry);

    if (nonces == NULL){
        nonces = new_nonces_list();
        if (nonces==NULL){
            lmlog(LISP_LOG_WARNING,"Send_map_request_miss: Unable to allocate memory for nonces.");
            return (BAD);
        }
        map_cache_entry->nonces = nonces;
    }

    if (nonces->retransmits - 1 < map_request_retries ){

        if (map_cache_entry->request_retry_timer == NULL){
            map_cache_entry->request_retry_timer = create_timer (MAP_REQUEST_RETRY_TIMER);
        }

        if (nonces->retransmits > 0){
            lmlog(DBG_1,"Retransmiting Map Request for EID: %s (%d retries)",
                    lisp_addr_to_char(mapping_eid(map_cache_entry->mapping)),
                    nonces->retransmits);
        }

        /* Get the RLOC of the Map Resolver to be used */
        dst_rloc = get_map_resolver();

        if ((dst_rloc == NULL) || (build_and_send_map_request_msg(
                map_cache_entry->mapping, argument->src_eid,
                dst_rloc, 1, 0, 0, 0, NULL,
                &nonces->nonce[nonces->retransmits]))==BAD){
            lmlog (DBG_1, "send_map_request_miss: Couldn't send map request for a new map cache entry");

        }

        nonces->retransmits ++;
        start_timer(map_cache_entry->request_retry_timer, LISPD_INITIAL_MRQ_TIMEOUT,
                send_map_request_miss, (void *)argument);

    }else{
        lmlog(DBG_1,"No Map Reply for EID %s after %d retries. Removing map cache entry ...",
                        lisp_addr_to_char(mapping_eid(map_cache_entry->mapping)), nonces->retransmits -1);
        mcache_del_mapping(mapping_eid(mapping));
    }
    return GOOD;
}


/*
 *  get_up_locators_length
 *
 *  Compute the sum of the lengths of the locators that has the status up
 *  so we can allocate  memory for the packet....
 */

static int get_up_locators_length(
        locators_list_t *locators_list,
        int                 *loc_count)
{
    int sum, counter, size;

    sum = 0;
    counter = 0;

    while (locators_list) {
        if (*(locators_list->locator->state)== DOWN){
            locators_list = locators_list->next;
            continue;
        }

//        if (lisp_addr_afi(locator_addr(locators_list->locator)) != LM_AFI_IP)
//            continue;
//
        if ( (size=lisp_addr_get_size_in_field(locators_list->locator->addr))) {
            counter++;
            sum += size;
        } else {
            lmlog(DBG_2, "get_up_locators_length: Uknown addr (%s) - It should never happen",
               lisp_addr_to_char(locators_list->locator->addr));
        }

        locators_list = locators_list->next;
    }

    *loc_count = counter;
    return(sum);
}

/*
 * Calculate Map Request length. Just add locators with status up
 */

int get_map_request_length(lisp_addr_t *dst_eid, lisp_addr_t *src_eid, mapping_t *src_mapping, uint8_t mrsig) {
    int mr_len = 0;
    int locator_count = 0, aux_locator_count = 0;
    mr_len = sizeof(map_request_hdr_t);
    if (src_mapping && !mrsig) {
        mr_len += lisp_addr_get_size_in_field(mapping_eid(src_mapping));

        /* Calculate ITR-RLOC length */
        mr_len += get_up_locators_length(src_mapping->head_v4_locators_list,
                &aux_locator_count);

        locator_count = aux_locator_count;
        mr_len += get_up_locators_length(src_mapping->head_v6_locators_list,
                &aux_locator_count);
        locator_count += aux_locator_count;

    } else {
        if (src_eid && mrsig) {
            /* MR-SIGNALING case */
            mr_len += lisp_addr_get_size_in_field(src_eid);
        } else {
            /* NO SRC ADDR case */
            mr_len += sizeof(uint16_t); /* the src EID AFI */
        }

        if (default_ctrl_iface_v4 != NULL ) {
            mr_len += sizeof(struct in_addr) + sizeof(uint16_t);
            locator_count++;
        }

        if (default_ctrl_iface_v6 != NULL ) {
            mr_len += sizeof(struct in6_addr) + sizeof(uint16_t);
            locator_count++;
        }
    }

    /* Record size */
    mr_len += sizeof(eid_record_hdr_t);
    /* XXX: We supose that the requested EID has the same AFI as the source EID */
    mr_len += lisp_addr_get_size_in_field(dst_eid);

    /* Add the Map-Reply Record */
    if (src_mapping)
        mr_len += mapping_get_size_in_record(src_mapping);

    return mr_len;
}

/* Build a Map Request paquet */

uint8_t *build_map_request_pkt(
        lisp_addr_t     *dst_eid,
        lisp_addr_t     *src_eid,
        uint8_t         encap,
        uint8_t         probe,
        uint8_t         solicit_map_request,/* boolean really */
        uint8_t         smr_invoked,
        mrsignaling_flags_t *mrsig,
        int             *len,               /* return length here */
        uint64_t        *nonce)             /* return nonce here */
{

    uint8_t                                 *packet                 = NULL;
    uint8_t                                 *mr_packet              = NULL;
    map_request_hdr_t                     *mrp                    = NULL;
    mapping_record_hdr_t                    *rec                    = NULL;
    eid_record_hdr_t                   *request_eid_record     = NULL;
    uint8_t                                 *cur_ptr                = NULL;

    int                     map_request_msg_len = 0;
    int                     ctr                 = 0;
    int                     locators_ctr        = 0;
    int                     rlen                = 0;

    mapping_t               *src_mapping        = NULL;
    locators_list_t     *locators_list[2]   = {NULL,NULL};
    locator_t               *locator            = NULL;
    lisp_addr_t             *ih_src_ip          = NULL;

    /*
     * Lookup the local EID prefix from where we generate the message.
     * src_eid is null for RLOC probing and refreshing map_cache -> Source-EID AFI = 0
     */

    if (src_eid != NULL && !mrsig){
        src_mapping = local_map_db_lookup_eid(src_eid);
        if (!src_mapping){
            lmlog(DBG_2,"build_map_request_pkt: Source EID address not found in local data base - %s -",
                    lisp_addr_to_char(src_eid));
            return (NULL);
        }

    }

    /* Calculate the packet size and reserve memory */
    map_request_msg_len = get_map_request_length(dst_eid, src_eid, src_mapping, mrsig ? 1 : 0);
    *len = map_request_msg_len;

    if ((packet = malloc(map_request_msg_len)) == NULL){
        lmlog(LISP_LOG_WARNING,"build_map_request_pkt: Unable to allocate memory for Map Request (packet_len): %s", strerror(errno));
        return (NULL);
    }
    memset(packet, 0, map_request_msg_len);

    cur_ptr = packet;

    mrp = (map_request_hdr_t *)cur_ptr;

    mrp->type                       = LISP_MAP_REQUEST;
    mrp->authoritative              = 0;
    mrp->map_data_present           = (src_eid && !mrsig) ? 1 : 0;
    mrp->rloc_probe                 = (probe) ? 1: 0;
    mrp->solicit_map_request        = (solicit_map_request) ? 1 : 0;
    mrp->smr_invoked                = (smr_invoked) ? 1 : 0;
    mrp->additional_itr_rloc_count  = 0;     /* To be filled later  */
    mrp->record_count               = 1;     /* XXX: assume 1 record */
    mrp->nonce                      = build_nonce((unsigned int) time(NULL));
    *nonce                          = mrp->nonce;

    cur_ptr = CO(cur_ptr, sizeof(map_request_hdr_t));

    if (src_eid && !mrsig) {
        cur_ptr = CO(cur_ptr, lisp_addr_write(cur_ptr, mapping_eid(src_mapping)));

        /* Add itr-rlocs */
        locators_list[0] = src_mapping->head_v4_locators_list;
        locators_list[1] = src_mapping->head_v6_locators_list;

        for (ctr=0 ; ctr < 2 ; ctr++){
            while (locators_list[ctr]){
                locator = locators_list[ctr]->locator;
                if (*(locator->state)==DOWN){
                    locators_list[ctr] = locators_list[ctr]->next;
                    continue;
                }
                /* Remove ITR locators behind NAT: No control message (4342) can be received in these interfaces */
                if (((lcl_locator_extended_info *)locator->extended_info)->rtr_locators_list != NULL){
                    locators_list[ctr] = locators_list[ctr]->next;
                    continue;
                }
                cur_ptr = CO(cur_ptr, lisp_addr_write(cur_ptr, locator->addr));
                locators_ctr ++;
                locators_list[ctr] = locators_list[ctr]->next;
            }
        }

    } else {
        if (src_eid && mrsig) {
            rlen = lisp_addr_write(cur_ptr, src_eid);
            mrsignaling_set_flags_in_pkt(cur_ptr, mrsig);
            cur_ptr = CO(cur_ptr, rlen);
        } else {
            *(uint16_t*)cur_ptr = LISP_AFI_NO_ADDR;
            cur_ptr = CO(cur_ptr, sizeof(uint16_t));
        }

        // XXX If no source EID is used, then we only use one ITR-RLOC for IPv4 and one for IPv6-> Default control RLOC
        if (default_ctrl_iface_v4 != NULL){
            cur_ptr = CO(cur_ptr, lisp_addr_write(cur_ptr, default_ctrl_iface_v4->ipv4_address));
            locators_ctr ++;
        }
        if (default_ctrl_iface_v6 != NULL){
            cur_ptr = CO(cur_ptr, lisp_addr_write(cur_ptr, default_ctrl_iface_v6->ipv6_address));
            locators_ctr ++;
        }
    }

    mrp->additional_itr_rloc_count = locators_ctr - 1; /* IRC = 0 --> 1 ITR-RLOC */
    if (locators_ctr == 0){
        lmlog(DBG_2,"build_map_request_pkt: No ITR RLOCs.");
        free(packet);
        return (NULL);
    }


    /* Requested EID record */
    request_eid_record = (eid_record_hdr_t *)cur_ptr;
    request_eid_record->eid_prefix_length = lisp_addr_get_plen(dst_eid);
    cur_ptr = CO(cur_ptr, sizeof(eid_record_hdr_t));
    rlen = lisp_addr_write(cur_ptr, dst_eid);
    if (mrsig)
        mrsignaling_set_flags_in_pkt(cur_ptr, mrsig);
    cur_ptr = CO(cur_ptr, rlen);

    if (mrp->map_data_present == 1){
        /* Map-Reply Record */
        rec = (mapping_record_hdr_t *)cur_ptr;
        if ((mapping_fill_record_in_pkt(rec, src_mapping, NULL))== NULL) {
            lmlog(DBG_2,"build_map_request_pkt: Couldn't buil map reply record for map request. "
                    "Map Request will not be send");
            free(packet);
            return(NULL);
        }
    }

    /* Add Encapsulated (Inner) control header*/
    if (encap){
        /*
         * If no source EID is included (Source-EID-AFI = 0), The default RLOC address is used for
         * the source address in the inner IP header
         */
        if (src_eid != NULL){
            if (lisp_addr_afi(mapping_eid(src_mapping)) == LM_AFI_IP)
                ih_src_ip = mapping_eid(src_mapping);
            else
                /* avoid lcafs */
                ih_src_ip = local_map_db_get_main_eid(AF_INET);
        }else{
            if (lisp_addr_ip_afi(dst_eid) == AF_INET){
                ih_src_ip = local_map_db_get_main_eid(AF_INET);
                if (!ih_src_ip)
                    ih_src_ip = default_ctrl_iface_v4->ipv4_address;
            }else{
                ih_src_ip = local_map_db_get_main_eid(AF_INET6);
                if (!ih_src_ip)
                    ih_src_ip = default_ctrl_iface_v6->ipv6_address;
            }

        }

        dst_eid = lisp_addr_to_ip_addr(dst_eid);

        mr_packet = packet;
        packet = build_control_encap_pkt(mr_packet, map_request_msg_len, ih_src_ip, dst_eid, LISP_CONTROL_PORT, LISP_CONTROL_PORT, len);

        if (packet == NULL){
            lmlog(DBG_1,"build_map_request_pkt: Couldn't encapsulate the map request");
            free (mr_packet);
            return (NULL);
        }
    }

    return (packet);
}

int build_and_send_map_request_msg(
        mapping_t               *requested_mapping,
        lisp_addr_t             *src_eid,
        lisp_addr_t             *dst_rloc,
        uint8_t                 encap,
        uint8_t                 probe,
        uint8_t                 solicit_map_request,
        uint8_t                 smr_invoked,
        mrsignaling_flags_t     *mrsig,
        uint64_t                *nonce)
{

    uint8_t     *packet         = NULL;
    uint8_t     *map_req_pkt    = NULL;
    lisp_addr_t *src_rloc       = NULL;
    int         out_socket      = 0;
    int         packet_len      = 0;
    int         mrp_len         = 0;               /* return the length here */
    int         result          = 0;

    map_req_pkt = build_map_request_pkt(
            mapping_eid(requested_mapping),
            src_eid,
            encap,
            probe,
            solicit_map_request,
            smr_invoked,
            mrsig,  /* no mr signaling flag */
            &mrp_len,
            nonce);

    if (map_req_pkt == NULL) {
        lmlog(DBG_1, "build_and_send_map_request_msg: Could not build map-request packet for %s:"
                " Encap: %c, Probe: %c, SMR: %c, SMR-inv: %c , MRSIG: %c",
                lisp_addr_to_char(mapping_eid(requested_mapping)),
                (encap == TRUE ? 'Y' : 'N'),
                (probe == TRUE ? 'Y' : 'N'),
                (solicit_map_request == TRUE ? 'Y' : 'N'),
                (smr_invoked == TRUE ? 'Y' : 'N'),
                (mrsig ? 'Y' : 'N'));
        return (BAD);
    }

    /* Get src interface information */

    src_rloc    = get_default_ctrl_address(lisp_addr_ip_afi(dst_rloc));
    out_socket  = get_default_ctrl_socket(lisp_addr_ip_afi(dst_rloc));

    if (src_rloc == NULL){
        lmlog(DBG_1, "build_and_send_map_request_msg: Couden't send Map Request. No output interface with afi %d.",
                dst_rloc->afi);
        free (map_req_pkt);
        return (BAD);
    }

    /*  Add UDP and IP header to the Map Request message */


    packet = build_ip_udp_pcket(map_req_pkt,
                                mrp_len,
                                src_rloc,
                                dst_rloc,
                                LISP_CONTROL_PORT,
                                LISP_CONTROL_PORT,
                                &packet_len);
    free (map_req_pkt);


    if (packet == NULL){
        lmlog(DBG_1,"build_and_send_map_request_msg: Couldn't send Map Request. Error adding IP and UDP header to the message");
        return (BAD);
    }

    /* Send the packet */

    if ((err = send_packet(out_socket,packet,packet_len)) == GOOD){
        lmlog(DBG_1, "Sent Map-Request packet for %s to %s: Encap: %c, Probe: %c, SMR: %c, "
                "SMR-inv: %c MRSIG: %c. Nonce: %s",
                        lisp_addr_to_char(mapping_eid(requested_mapping)),
                        lisp_addr_to_char(dst_rloc),
                        (encap == TRUE ? 'Y' : 'N'),
                        (probe == TRUE ? 'Y' : 'N'),
                        (solicit_map_request == TRUE ? 'Y' : 'N'),
                        (smr_invoked == TRUE ? 'Y' : 'N'),
                        (mrsig ? 'Y' : 'N'),
                        nonce_to_char(*nonce));
        result = GOOD;
    }else{
        lmlog(DBG_1, "Couldn't sent Map-Request packet for %s: Encap: %c, Probe: %c, SMR: %c, "
                "SMR-inv: %c MRSIG: %c",
                lisp_addr_to_char(mapping_eid(requested_mapping)),
                (encap == TRUE ? 'Y' : 'N'),
                (probe == TRUE ? 'Y' : 'N'),
                (solicit_map_request == TRUE ? 'Y' : 'N'),
                (smr_invoked == TRUE ? 'Y' : 'N'),
                (mrsig ? 'Y' : 'N'));
        result = BAD;
    }

    free (packet);
    return (result);
}


/**
 * build_map_reply_pkt - builds a map reply packet
 *
 * TODO README: this should be part of map_reply_pkt.c BUT the way it is written doesn't allow for it. That is,
 * map_reply_pkt.c shouldn't know what mapping_elt, lisp_addr_t, locator_elt are.
 * Normally, a map reply packet should be build from smaller, field chunks (records, eids, locators), that
 * are non-contiguous in memory. When we define such a function we can move this packet
 * building function to map_reply_pkt.c
 */
uint8_t *build_map_reply_pkt(mapping_t *mapping, lisp_addr_t *probed_rloc, map_reply_opts opts, uint64_t nonce,
         int *map_reply_msg_len) {
    uint8_t *packet;
    map_reply_hdr_t *map_reply_msg;
    mapping_record_hdr_t *mapping_record;

    *map_reply_msg_len = sizeof(map_reply_hdr_t) + mapping_get_size_in_record(mapping);

    if ((packet = calloc(1, *map_reply_msg_len)) == NULL ) {
        lmlog(LISP_LOG_WARNING,
                "build_map_reply_pkt: Unable to allocate memory for  Map Reply message(%d) %s",
                *map_reply_msg_len, strerror(errno));
        return (NULL );
    }

//    memset(packet, 0, *map_reply_msg_len);

    map_reply_msg = (map_reply_hdr_t *) packet;

    map_reply_msg->type = 2;
    if (opts.rloc_probe)
        map_reply_msg->rloc_probe = 1;
    if (opts.echo_nonce)
        map_reply_msg->echo_nonce = 1;
    map_reply_msg->record_count = 1;
    map_reply_msg->nonce = nonce;


    if (opts.send_rec) {
        mapping_record = (mapping_record_hdr_t *) CO(map_reply_msg, sizeof(map_reply_hdr_t));

        if (mapping_fill_record_in_pkt(mapping_record, mapping, probed_rloc) == NULL) {
            free(packet);
            return (NULL );
        }

        /* if multicast eid and the mrsignaling options are set, write them to the packet */
        if (lisp_addr_is_mc(mapping_eid(mapping)) && (opts.mrsig.jbit || opts.mrsig.lbit) )
            mrsignaling_set_flags_in_pkt(CO(mapping_record, sizeof(mapping_record_hdr_t)), &opts.mrsig);
    }

    return(packet);
}

/**
 * build_and_send_map_reply_msg - builds and sends a map-reply with one record
 *
 * Description: computes the size of the entire packet, allocates the space and fills in the
 * data. Since the function is not as flexible those associated reading, it's harder to set
 * flags. Should be changed in the future.
 */

int build_and_send_map_reply_msg(
        mapping_t *requested_mapping,
        lisp_addr_t *src_rloc_addr,
        lisp_addr_t *dst_rloc_addr,
        uint16_t dport,
        uint64_t nonce,
        map_reply_opts opts)
{
    uint8_t         *packet             = NULL;
    uint8_t         *map_reply_pkt      = NULL;
    int             map_reply_pkt_len   = 0;
    int             packet_len          = 0;
    int             result              = 0;
    lisp_addr_t     *src_addr           = NULL;
    int             out_socket          = 0;
    lispd_iface_elt *iface              = NULL;



    /* Build the packet */
    if (opts.rloc_probe == TRUE)
        map_reply_pkt = build_map_reply_pkt(requested_mapping, src_rloc_addr, opts, nonce, &map_reply_pkt_len);
    else
        map_reply_pkt = build_map_reply_pkt(requested_mapping, NULL, opts, nonce, &map_reply_pkt_len);

    if (map_reply_pkt == NULL){
        lmlog(DBG_1,"build_and_send_map_reply_msg: Couldn't send Map-Reply for requested EID %s ",
                lisp_addr_to_char(mapping_eid(requested_mapping)));
        return (BAD);
    }

    /* Get src interface information */

    if (src_rloc_addr == NULL){
        src_addr   = get_default_ctrl_address(dst_rloc_addr->afi);
        out_socket = get_default_ctrl_socket (dst_rloc_addr->afi);
    }else{
        iface = get_interface_with_address(src_rloc_addr);
        if (iface != NULL){
            src_addr = src_rloc_addr;
            out_socket = get_iface_socket(iface, dst_rloc_addr->afi);
        }else{
            src_addr   = get_default_ctrl_address(dst_rloc_addr->afi);
            out_socket = get_default_ctrl_socket (dst_rloc_addr->afi);
        }
    }

    if (src_addr == NULL){
        lmlog(DBG_1, "build_and_send_map_reply_msg: Couldn't send Map Reply. No output interface with afi %d.",
                dst_rloc_addr->afi);
        free (map_reply_pkt);
        return (BAD);
    }

    /*  Add UDP and IP header to the Map Request message */

    packet = build_ip_udp_pcket(map_reply_pkt,
            map_reply_pkt_len,
            src_addr,
            dst_rloc_addr,
            LISP_CONTROL_PORT,
            dport,
            &packet_len);
    free (map_reply_pkt);

    if (packet == NULL){
        lmlog(DBG_1,"build_and_send_map_reply_msg: Couldn't send Map Reply. Error adding IP and UDP header to the message");
        return (BAD);
    }


    /* Send the packet */

    if ((err = send_packet(out_socket,packet,packet_len)) == GOOD){
        if (opts.rloc_probe == TRUE){
            lmlog(DBG_1, "Sent Map-Reply packet for %s probing local locator %s to %s",
                    lisp_addr_to_char(mapping_eid(requested_mapping)),
                    lisp_addr_to_char(src_rloc_addr), lisp_addr_to_char(dst_rloc_addr));
        }else{
            lmlog(DBG_1, "Sent Map-Reply for %s from %s to %s",
                    lisp_addr_to_char(mapping_eid(requested_mapping)), lisp_addr_to_char(src_rloc_addr),
                    lisp_addr_to_char(dst_rloc_addr));
        }
        result = GOOD;
    }else{
        if (opts.rloc_probe == TRUE){
            lmlog(DBG_1, "Couldn't build/send Probe Reply!");
        }else{
            lmlog(DBG_1, "Couldn't build/send Map-Reply!");
        }
        result = BAD;
    }

    free(packet);

    return (result);
}

/*
 * The function looks up an entry for which a map-request has been sent and activates it once the
 * locators are obtained
 * TODO:
 * 1. The in flight requests should be kept in a local queue in lispd_control NOT
 * in the map-cache (lookups will be slow once the map cache fills)
 * 2. The logic in the function won't be needed as there will be no need to interact with an existing
 * mapping cache entry. That is, the mapping will be instantiated on receipt and inserted in the map-cache.
 *
 */
int mcache_update_entry(mapping_t *m, uint64_t nonce) {

    map_cache_entry_t *mce = NULL;
    uint8_t new_mapping = FALSE;
    mapping_t *old_map;
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
    if (check_nonce(mce->nonces,nonce) == BAD) {
        lmlog(DBG_2," Nonce doesn't match nonce of the Map-Request. "
                "Discarding message ...");
        return(BAD);
    } else {
        mcache_entry_destroy_nonces(mce);
    }

    mcache_entry_stop_smr_timer(mce);
    old_map = mcache_entry_mapping(mce);

    lmlog(DBG_2, "Mapping with EID %s already exists, replacing locators",
            lisp_addr_to_char(mapping_eid(old_map)));
    mapping_del_locators(old_map);

    mce->actions = mapping_action(m);
    mce->ttl = mapping_ttl(m);
    mce->active_witin_period = 1;
    mce->timestamp = time(NULL);

    /* move locators from new to old mapping */
    old_map->head_v4_locators_list = m->head_v4_locators_list;
    old_map->head_v6_locators_list = m->head_v6_locators_list;

    /* avoid freeing the locators */
    m->head_v4_locators_list = NULL;
    m->head_v6_locators_list = NULL;

    mapping_compute_balancing_vectors(old_map);

    /* Reprogramming timers */
    map_cache_entry_start_expiration_timer(mce);

    /* RLOC probing timer */
    if (new_mapping == TRUE && RLOC_PROBING_INTERVAL != 0)
        mapping_program_rloc_probing(old_map);

    return (GOOD);
}


void timer_map_request_argument_del(void *arg) {
    timer_map_request_argument *targ = arg;
    lisp_addr_del(targ->src_eid);
    free(targ);
}


/* Process Map-Request/Join-Request for @dst_eid that ask that replication be
 * performed to @src_eid. @b is the map reply buffer to be filled in if ACK is
 * sent */
int mrsignaling_recv_msg(struct lbuf *b, lisp_addr_t *src_eid,
        lisp_addr_t *dst_eid, mrsignaling_flags_t mrf)
{
    int                 ret;
    mapping_t           *tmapping;
    locator_t           *tloc;
    void *ploc;
    mrsignaling_flags_t ret_mrsig;

    /* hardwired to re, should change when we support lisp-multicast */
    if (mrf.jbit == 1)
        ret = re_recv_join_request(dst_eid, src_eid);
    else if (mrf.lbit == 1)
        ret = re_recv_leave_request(dst_eid, src_eid);
    else if (mrf.rbit == 1) {
        ret = BAD;
        lmlog(LISP_LOG_WARNING, "re_process_mrsignaling: PIM join received, not implemented!");
    }


    if (ret == GOOD) {
        /* prepare quick ack. Actually mapping between (S,G) and (S-RLOC, D-RLOC)
         * does not exist. Creating one here */
        lisp_msg_put_mapping_hdr(b); /* no plen and 1 RLOC */
        lisp_msg_put_addr(b, dst_eid);

        tloc = locator_init_remote(lisp_addr_clone(src_eid));
        locator_set_state_static(tloc, UP); /* XXX: should check state in the future */
        ploc = lisp_msg_put_locator(tloc, 0);
        mrsignaling_set_flags_in_pkt(LOC_ADDR(ploc), mrf);


//        tmapping = mapping_init_remote(dst_eid);
//        add_locator_to_mapping(tmapping, tloc);
//        ret_mrsig = (mrsignaling_flags_t){.rbit = 0, .jbit = 1, .lbit = 0 };
//        mrsignaling_send_ack(tmapping, local_rloc, remote_rloc, dst_port, nonce, ret_mrsig);
//        mapping_del(tmapping);
    }

    return (err);

}

int mrsignaling_send_ack(
        mapping_t *registered_mapping,
        lisp_addr_t *local_rloc,
        lisp_addr_t *remote_rloc,
        uint16_t dport,
        uint64_t nonce,
        mrsignaling_flags_t mc_flags) {

    map_reply_opts mropts;

    mropts.send_rec   = 1;
    mropts.echo_nonce = 0;
    mropts.rloc_probe = 0;
    mropts.mrsig = mc_flags; //(mrsignaling_flags_t){mc_flags.rbit, mc_flags.jbit, mc_flags.lbit};

    return(build_and_send_map_reply_msg(registered_mapping, local_rloc, remote_rloc, dport, nonce, mropts));
}

int mrsignaling_send_join(mapping_t *ch_mapping, lisp_addr_t *delivery_grp, lisp_addr_t *dst_rloc, uint64_t *nonce) {
    lmlog(DBG_3, "Sending Join-Request to %s for %s requesting that traffic be replicated to %s",
            lisp_addr_to_char(dst_rloc), lisp_addr_to_char(mapping_eid(ch_mapping)), lisp_addr_to_char(delivery_grp));
    mrsignaling_flags_t mrsig = {.rbit = 0, .jbit = 1, .lbit = 0};

    return(build_and_send_map_request_msg(ch_mapping, delivery_grp, dst_rloc, 0, 0, 0, 0, &mrsig, nonce));
}

int mrsignaling_send_leave(mapping_t *ch_mapping, lisp_addr_t *delivery_grp, lisp_addr_t *dst_rloc, uint64_t *nonce) {
    lmlog(DBG_3, "Sending Leave-Request to %s for %s requesting that traffic be replicated to %s",
            lisp_addr_to_char(dst_rloc), lisp_addr_to_char(mapping_eid(ch_mapping)), lisp_addr_to_char(delivery_grp));
    mrsignaling_flags_t mrsig = {.rbit = 0, .jbit = 0, .lbit = 1};
    return(build_and_send_map_request_msg(ch_mapping, delivery_grp, dst_rloc, 0, 0, 0, 0, &mrsig, nonce));
}


int mrsignaling_recv_ack(mapping_record *record, uint64_t nonce) {

    lisp_addr_t                             *eid                    = NULL;
    lcaf_mcinfo_hdr_t                       *mcinfohdr               = NULL;
    address_field                           *addr                   = NULL;

    addr = mapping_record_eid(record);

    mcinfohdr = address_field_get_mc_hdr(addr);
    eid = lisp_addr_init_from_field(addr);
    if (!eid)
        return(BAD);

    if (mcinfohdr->J == 1 && mcinfohdr->L == 1) {
        lmlog(DBG_1, "Both join and leave flags are set!");
        return(BAD);
    }

    /* hardwired to re, should change when we support lisp-multicast */
    if (mcinfohdr->J == 1)
        re_recv_join_ack(eid, nonce);
    else if (mcinfohdr->L == 1)
        re_recv_leave_ack(eid, nonce);
    else if (mcinfohdr->R == 1) {
        lmlog(LISP_LOG_WARNING, "PIM join received, not implemented!");
        return(BAD);
    }

    lisp_addr_del(eid);
    return(GOOD);
}

