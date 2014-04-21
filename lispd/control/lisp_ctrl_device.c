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
#include "lisp_proto.h"


int
ctrl_dev_handle_msg(lisp_ctrl_dev_t *dev, lbuf_t *b, uconn_t *usk) {
    return(dev->ctrl_class->handle_msg(dev, b, usk));
}

void
lisp_ctrl_dev_start(lisp_ctrl_dev_t *dev) {
    dev->ctrl_class->start(dev);
}

void
lisp_ctrl_dev_del(lisp_ctrl_dev_t *dev) {
    dev->ctrl_class->delete(dev);
}

int
recv_msg(lisp_ctrl_dev_t *dev, lbuf_t *b, uconn_t *uc) {
    ctrl_dev_handle_msg(dev, b, uc);

    return(GOOD);
}

int
send_msg(lisp_ctrl_dev_t *dev, lisp_msg *msg, uconn_t *uc) {
    ctrl_send_msg(dev->ctrl, msg, uc);
    return(GOOD);
}


int
ctrl_dev_program_smr(lisp_ctrl_dev_t *dev)
{
    void *arg;
    timer *t;

    /* used only with tunnel routers */
    if (dev->mode != xTR_MODE && dev->mode != RTR_MODE) {
        return(GOOD);
    }

    return(program_smr(dev, LISPD_SMR_TIMEOUT));
}

/* Select the source RLOC according to the priority and weight. */
static int
select_src_locators_from_balancing_locators_vec(mapping_t *src_mapping,
        packet_tuple tuple, locator_t **src_locator)
{
    int                     src_vec_len     = 0;
    uint32_t                pos             = 0;
    uint32_t                hash            = 0;
    balancing_locators_vecs *src_blv        = NULL;
    locator_t       **src_loc_vec   = NULL;

    src_blv = &((lcl_mapping_extended_info *)(src_mapping->extended_info))->outgoing_balancing_locators_vecs;

    if (src_blv->balancing_locators_vec != NULL){
        src_loc_vec = src_blv->balancing_locators_vec;
        src_vec_len = src_blv->locators_vec_length;
    }else if (src_blv->v6_balancing_locators_vec != NULL){
        src_loc_vec = src_blv->v6_balancing_locators_vec;
        src_vec_len = src_blv->v6_locators_vec_length;
    }else {
        src_loc_vec = src_blv->v4_balancing_locators_vec;
        src_vec_len = src_blv->v4_locators_vec_length;
    }
    if (src_vec_len == 0){
        lmlog(DBG_3,"select_src_locators_from_balancing_locators_vec: No source locators availables to send packet");
        return(BAD);
    }
    hash = get_hash_from_tuple (tuple);
    if (hash == 0){
        lmlog(DBG_1,"select_src_locators_from_balancing_locators_vec: Couldn't get the hash of the tuple to select the rloc. Using the default rloc");
    }
    pos = hash%src_vec_len; // if hash = 0 then pos = 0
    *src_locator =  src_loc_vec[pos];

    lmlog(DBG_3,"select_src_locators_from_balancing_locators_vec: src RLOC: %s",
            lisp_addr_to_char(locator_addr(*src_locator)));

    return (GOOD);
}

forwarding_entry *
tr_get_forwarding_entry(lisp_ctrl_dev_t *dev, packet_tuple *tuple)
{
    mapping_t *src_mapping = NULL;
    mapping_t *dst_mapping = NULL;
    locator_t *outer_src_locator = NULL;
    locator_t *outer_dst_locator = NULL;
    forwarding_entry *fwd_entry = NULL;

    /* should be retrieved from a cache in the future */
    fwd_entry = calloc(1, sizeof(forwarding_entry));

    /* If the packet doesn't have an EID source, forward it natively */
    if (!(src_mapping = local_map_db_lookup_eid(&(tuple->src_addr)))) {
        return (fwd_entry);
    }

    /* If we are behind a full nat system, send the message directly to the RTR */
    if (nat_aware && (nat_status == FULL_NAT)) {
        if (select_src_locators_from_balancing_locators_vec(src_mapping, *tuple,
                &outer_src_locator) != GOOD) {
            free(fwd_entry);
            return (NULL);
        }
        if (!outer_src_locator || !outer_src_locator->extended_info
                || !((lcl_locator_extended_info *) outer_src_locator->extended_info)->rtr_locators_list->locator) {
            lmlog(DBG_2,
                    "forward_to_natt_rtr: No RTR for the selected src locator (%s).",
                    lisp_addr_to_char(outer_src_locator->addr));
            free(fwd_entry);
            return (NULL);
        }

        fwd_entry->src_rloc = outer_src_locator->addr;
        fwd_entry->dst_rloc = &((lcl_locator_extended_info *) outer_src_locator->extended_info)->rtr_locators_list->locator->address;
        fwd_entry->out_socket = *(((lcl_locator_extended_info *) (outer_src_locator->extended_info))->out_socket);

        return (fwd_entry);
    }

    //arnatal TODO TODO: Check if local -> Do not encapsulate (can be solved with proper route configuration)
    //arnatal: Do not need to check here if route metrics setted correctly -> local more preferable than default (tun)

    /* fcoras TODO: implement unicast FIB instead of using the map-cache? */
    dst_mapping = mcache_lookup_mapping(&(tuple->dst_addr));

    if (!dst_mapping) { /* There is no entry in the map cache */
        lmlog(DBG_1, "get_forwarding_entry: No map cache retrieved for eid %s."
                " Sending Map-Request!", lisp_addr_to_char(&tuple->dst_addr));
        handle_map_cache_miss(dev, &(tuple->dst_addr), &(tuple->src_addr));
    }

    /* No map-cache entry or no output locators (negative entry) */
    if (!dst_mapping || (mapping_locator_count(dst_mapping) == 0)) {
        /* Try PETRs */
        if (proxy_etrs == NULL) {
            lmlog(DBG_3, "get_forwarding_entry: Trying to forward to PxTR but "
                    "none found ...");
            return (fwd_entry);
        }
        if ((select_src_rmt_locators_from_balancing_locators_vec(src_mapping,
                proxy_etrs->mapping, *tuple, &outer_src_locator,
                &outer_dst_locator)) != GOOD) {
            lmlog(DBG_3, "get_forwarding_entry: No Proxy-etr compatible with local locators afi");
            free(fwd_entry);
            return (NULL);
        }

        /* There is an entry in the map cache
         * Find locators to be used */
    } else {
        if (select_src_rmt_locators_from_balancing_locators_vec(src_mapping,
                dst_mapping, *tuple, &outer_src_locator,  &outer_dst_locator)!=GOOD) {
            /* If no match between afi of source and destinatiion RLOC, try to fordward to petr*/
            return (fwd_entry);
        }
    }

    if (outer_src_locator == NULL) {
        lmlog(DBG_2, "get_forwarding_entry: No output src locator");
        return (fwd_entry);
    }
    if (outer_dst_locator == NULL) {
        lmlog(DBG_2, "get_forwarding_entry: No destination locator selectable");
        return (fwd_entry);
    }

    fwd_entry->dst_rloc = locator_addr(outer_dst_locator);
    fwd_entry->src_rloc = locator_addr(outer_src_locator);

    /* Decide what happens when src or dst are LCAFs */
    if (lisp_addr_afi(locator_addr(outer_dst_locator)) == LM_AFI_LCAF) {
        xtr_get_dst_from_lcaf(locator_addr(outer_dst_locator),
                &fwd_entry->dst_rloc);
    }

    /* if our src rloc is an LCAF, just use the default data address */
    if (lisp_addr_afi(locator_addr(outer_src_locator)) == LM_AFI_LCAF) {
        if (lisp_addr_ip_afi(fwd_entry->dst_rloc) == AF_INET)
            fwd_entry->src_rloc = default_out_iface_v4->ipv4_address;
        else
            fwd_entry->src_rloc = default_out_iface_v6->ipv6_address;
    }

    fwd_entry->out_socket = *(((lcl_locator_extended_info *) (outer_src_locator->extended_info))->out_socket);

    return (fwd_entry);

}

forwarding_entry *
tr_get_reencap_forwarding_entry(lisp_ctrl_dev_t *dev, packet_tuple *tuple)
{
    mapping_t           *dst_mapping        = NULL;
    forwarding_entry    *fwd_entry          = NULL;
    locators_list_t         *locator_iterator_array[2]  = {NULL,NULL};
    locators_list_t         *locator_iterator           = NULL;
    locator_t                   *locator                    = NULL;
    int ctr;

    /* should be retrieved from a cache in the future */
    fwd_entry = calloc(1, sizeof(forwarding_entry));

    dst_mapping = mcache_lookup_mapping(&(tuple->dst_addr));

    if (dst_mapping == NULL){ /* There is no entry in the map cache */
        lmlog(DBG_1, "get_forwarding_entry: No map cache retrieved for eid %s. Sending Map-Request!",
                lisp_addr_to_char(&tuple->dst_addr));
        /* the inner src is not registered by the RTR, so don't use it when doing map-requests */
        handle_map_cache_miss(dev, &(tuple->dst_addr), NULL);
        return(fwd_entry);
    }

    /* just lookup the first LCAF in the dst mapping and obtain the src/dst rlocs */
    locator_iterator_array[0] = dst_mapping->head_v4_locators_list;
    locator_iterator_array[1] = dst_mapping->head_v6_locators_list;
    for (ctr = 0 ; ctr < 2 ; ctr++){
        locator_iterator = locator_iterator_array[ctr];
        while (locator_iterator != NULL) {
            locator = locator_iterator->locator;
            if (lisp_addr_afi(locator_addr(locator)) == LM_AFI_LCAF) {
                rtr_get_src_and_dst_from_lcaf(locator_addr(locator), &fwd_entry->src_rloc, &fwd_entry->dst_rloc);
                break;
            }
            locator_iterator = locator_iterator->next;
        }
    }

    if (!fwd_entry->src_rloc || !fwd_entry->dst_rloc) {
        lmlog(LWRN, "Couldn't find src/dst rloc pair");
        return(NULL);
    }

    if (lisp_addr_afi(fwd_entry->src_rloc))
        fwd_entry->out_socket = default_out_iface_v4->out_socket_v4;
    else
        fwd_entry->out_socket = default_out_iface_v6->out_socket_v6;

    return(fwd_entry);
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
        if ( (size=lisp_addr_size_to_write(locators_list->locator->addr))) {
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
        mr_len += lisp_addr_size_to_write(mapping_eid(src_mapping));

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
            mr_len += lisp_addr_size_to_write(src_eid);
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
    mr_len += lisp_addr_size_to_write(dst_eid);

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
        lmlog(LWRN,"build_map_request_pkt: Unable to allocate memory for Map Request (packet_len): %s", strerror(errno));
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
    mrp->nonce                      = nonce_build((unsigned int) time(NULL));
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
        lmlog(LWRN,
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

    if (src_rloc_addr == NULL) {
        src_addr = get_default_ctrl_address(dst_rloc_addr->afi);
        out_socket = get_default_ctrl_socket(dst_rloc_addr->afi);
    } else {
        iface = get_interface_with_address(src_rloc_addr);
        if (iface != NULL) {
            src_addr = src_rloc_addr;
            out_socket = get_iface_socket(iface, dst_rloc_addr->afi);
        } else {
            src_addr = get_default_ctrl_address(dst_rloc_addr->afi);
            out_socket = get_default_ctrl_socket(dst_rloc_addr->afi);
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






















