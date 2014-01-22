/*
 * lispd_map_request.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send a map request.
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 *    David Meyer       <dmm@cisco.com>
 *    Vina Ermagan      <vermagan@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Pranathi Mamidi   <pranathi.3961@gmail.com>
 *
 */

/*
 *  Send this packet on UDP 4342
 *
 *
 * Encapsulated control message header. This is followed by the IP
 * header of the encapsulated LISP control message.
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Type=8 |                   Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *  Next is the inner IP header, either struct ip6_hdr or struct
 *  iphdr. 
 *
 *  This is follwed by a UDP header, random source port, 4342 
 *  dest port.
 *
 *  Followed by a struct lisp_pkt_map_request_t:
 *
 * Map-Request Message Format
 *   
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=1 |A|M|P|S|      Reserved       |   IRC   | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         Source-EID-AFI        |    Source EID Address  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                        EID-prefix ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                      Mappping Record ...                      |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 *	<source EID address>
 *	IRC = 0 --> one source rloc
 *      lisp_pkt_map_request_eid_prefix_record_t
 *      EID
 *
 */

#include "cksum.h"
#include "lispd_afi.h"
#include "lispd_external.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "lispd_map_cache_db.h"
//#include "lispd_map_reply.h"
//#include "lispd_map_request.h"
#include "lispd_nonce.h"
#include "lispd_pkt_lib.h"
#include "lispd_smr.h"
#include "lispd_sockets.h"
#include "lispd_re.h"
#include <time.h>
#include "lispd_control.c"
//#include "lispd_message_fields.h"


/************** Function declaration ************/
//
//
//int process_smr(lisp_addr_t *addr);
//int process_itr_rlocs(uint8_t **cur_pts, int itr_rloc_count, lisp_addr_t *local_rloc, lisp_addr_t *remote_rloc);
//
///*
// * Process record and send Map Reply
// */
//
//int process_map_request_record(
//        uint8_t **cur_ptr,
//        lisp_addr_t *src_eid,
//        lisp_addr_t *src_rloc,
//        lisp_addr_t *dst_rloc,
//        uint16_t    dport,
//        uint64_t    nonce,
//        map_reply_opts mropts);
//
///* Build a Map Request packet */
//
// uint8_t *build_map_request_pkt(
//         lispd_mapping_elt       *requested_mapping,
//         lisp_addr_t             *src_eid,
//         uint8_t                 encap,
//         uint8_t                 probe,
//         uint8_t                 solicit_map_request,/* boolean really */
//         uint8_t                 smr_invoked,
//         int                     *len,               /* return length here */
//         uint64_t                *nonce);             /* return nonce here */
//
//
// /*
//  * Calculate Map Request length. Just add locators with status up
//  */
//
// int get_map_request_length (lispd_mapping_elt *requested_mapping, lispd_mapping_elt *src_mapping);
//
// /*
//  * Calculate the overhead of the Encapsulated Map Request length.
//  */
//
// int get_emr_overhead_length (int afi);
//
///**************************************************/
//
//
//
//
//int process_itr_rlocs(
//        uint8_t **offset,
//        int itr_rloc_count,
//        lisp_addr_t *local_rloc,
//        lisp_addr_t *remote_rloc) {
//
//    lisp_addr_t                *itr_rloc;
//    uint8_t                    *cur_ptr                = NULL;
//    int                        i                       = 0;
//    int                        len                     = 0;
//
//    cur_ptr = *offset;
//    itr_rloc = lisp_addr_new();
//
//    /* Get the array of ITR-RLOCs */
//    for (i = 0; i < itr_rloc_count; i++) {
//        if ((len = lisp_addr_read_from_pkt(cur_ptr, itr_rloc)) <= 0) {
//            lispd_log_msg(LISP_LOG_DEBUG_3,"process_itr_rlocs: Failed to read RLOC!");
//            return(BAD);
//        }
//        cur_ptr = CO(cur_ptr, len);
//
//        /* Select the first accessible rloc from the ITR-RLOC list */
//        if (lisp_addr_get_afi(remote_rloc) == LM_AFI_NO_ADDR) {
//            if (local_rloc != NULL && lisp_addr_ip_get_afi(itr_rloc) == lisp_addr_ip_get_afi(local_rloc))
//                lisp_addr_copy(remote_rloc, itr_rloc);
//        }
//    }
//    if (lisp_addr_get_afi(remote_rloc) == LM_AFI_NO_ADDR){
//        lispd_log_msg(LISP_LOG_DEBUG_3,"process_itr_rlocs: No supported afi in the list of ITR-RLOCS");
//        return (BAD);
//    }
//
//    *offset = cur_ptr;
//    lisp_addr_del(itr_rloc);
//
//    return(GOOD);
//}
//
//
//
//int process_map_request_record(
//        uint8_t **offset,
//        lisp_addr_t *src_eid,
//        lisp_addr_t *local_rloc,
//        lisp_addr_t *remote_rloc,
//        uint16_t    dport,
//        uint64_t    nonce,
//        map_reply_opts mropts)
//{
//    uint8_t                                    *cur_ptr                = NULL;
//    eid_prefix_record_hdr  *record                 = NULL;
//    lispd_mapping_elt                          *mapping                = NULL;
//    lisp_addr_t                                *dst_eid;
//    int                                         len                     = 0;
//
//    cur_ptr = *offset;
//
//    /* Check if mrsignaling packet and read flags ... */
//    if (is_lcaf_mcast_info(cur_ptr))
//        return(mrsignaling_recv_mrequest(cur_ptr, src_eid, local_rloc, remote_rloc, dport, nonce));
//
//    record = (eid_prefix_record_hdr *)cur_ptr;
//
//    cur_ptr = (uint8_t *)&(record->eid_prefix_afi);
//    dst_eid = lisp_addr_new();
//
//    /* Read destination/requested EID prefix */
//    if((len = lisp_addr_read_from_pkt(cur_ptr, dst_eid)) <= 0) {
//        lisp_addr_del(dst_eid);
//        return(err);
//    }
//
//    cur_ptr = CO(cur_ptr, len);
//    lispd_log_msg(LISP_LOG_DEBUG_3, "process_map_request_msg: Received Map-Request from EID %s for EID %s",
//            lisp_addr_to_char(src_eid), lisp_addr_to_char(dst_eid));
//
//    /* Save prefix length only if the entry is an IP */
//    if (lisp_addr_get_afi(dst_eid) == LM_AFI_IP)
//        ip_prefix_set_plen(lisp_addr_get_ippref(dst_eid), record->eid_prefix_length);
//
//    /* Check the existence of the requested EID */
//    /* We don't use prefix mask and use by default 32 or 128*/
//    /* XXX: Maybe here we should do a strict search in case of RLOC probing */
//    if (!(mapping = lookup_eid_in_db(dst_eid))){
//        lispd_log_msg(LISP_LOG_DEBUG_1,"The requested EID doesn't belong to this node: %s",
//                lisp_addr_to_char(dst_eid));
//        lisp_addr_del(dst_eid);
//        return (BAD);
//    }
//
//    err = build_and_send_map_reply_msg(mapping, local_rloc, remote_rloc, dport, nonce, mropts);
//
//    lisp_addr_del(dst_eid);
//
//    *offset = cur_ptr;
//    return (err);
//}
//
///*
// *  build_and_send_map_request --
// *
// *  Put a wrapper around build_map_request_pkt and send_map_request
// *
// */
//
//
///* Build a Map Request paquet */
//
//uint8_t *build_map_request_pkt(
//        lispd_mapping_elt       *requested_mapping,
//        lisp_addr_t             *src_eid,
//        uint8_t                 encap,
//        uint8_t                 probe,
//        uint8_t                 solicit_map_request,/* boolean really */
//        uint8_t                 smr_invoked,
//        int                     *len,               /* return length here */
//        uint64_t                *nonce)             /* return nonce here */
//{
//
//    uint8_t                                     *packet                 = NULL;
//    uint8_t                                     *mr_packet              = NULL;
//    map_request_msg_hdr                     *mrp                    = NULL;
//    mapping_record_hdr                  *rec                    = NULL;
//    lispd_pkt_map_request_itr_rloc_t            *itr_rloc               = NULL;
//    eid_prefix_record_hdr   *request_eid_record     = NULL;
//    uint8_t                                     *cur_ptr                = NULL;
//
//    int                     map_request_msg_len = 0;
//    int                     ctr                 = 0;
//    int                     cpy_len             = 0;
//    int                     locators_ctr        = 0;
//
//    lispd_mapping_elt       *src_mapping        = NULL;
//    lispd_locators_list     *locators_list[2]   = {NULL,NULL};
//    lispd_locator_elt       *locator            = NULL;
//    lisp_addr_t             *ih_src_ip          = NULL;
//
//    /*
//     * Lookup the local EID prefix from where we generate the message.
//     * src_eid is null for RLOC probing and refreshing map_cache -> Source-EID AFI = 0
//     */
//    if (src_eid != NULL){
//        src_mapping = lookup_eid_in_db(src_eid);
//        if (!src_mapping){
//            lispd_log_msg(LISP_LOG_DEBUG_2,"build_map_request_pkt: Source EID address not found in local data base - %s -",
//                    lisp_addr_to_char(src_eid));
//            return (NULL);
//        }
//
//    }
//
//    /* Calculate the packet size and reserve memory */
//    map_request_msg_len = get_map_request_length(requested_mapping,src_mapping);
//    *len = map_request_msg_len;
//
//    if ((packet = malloc(map_request_msg_len)) == NULL){
//        lispd_log_msg(LISP_LOG_WARNING,"build_map_request_pkt: Unable to allocate memory for Map Request (packet_len): %s", strerror(errno));
//        return (NULL);
//    }
//    memset(packet, 0, map_request_msg_len);
//
//
//    cur_ptr = packet;
//
//    mrp = (map_request_msg_hdr *)cur_ptr;
//
//    mrp->type                      = LISP_MAP_REQUEST;
//    mrp->authoritative             = 0;
//    if (src_eid != NULL)
//        mrp->map_data_present      = 1;
//    else
//        mrp->map_data_present      = 0;
//
//    if (probe)
//        mrp->rloc_probe            = 1;
//    else
//        mrp->rloc_probe            = 0;
//
//    if (solicit_map_request)
//        mrp->solicit_map_request   = 1;
//    else
//        mrp->solicit_map_request   = 0;
//
//    if (smr_invoked)
//        mrp->smr_invoked           = 1;
//    else
//        mrp->smr_invoked           = 0;
//
//    mrp->additional_itr_rloc_count = 0;     /* To be filled later  */
//    mrp->record_count              = 1;     /* XXX: assume 1 record */
//    mrp->nonce = build_nonce((unsigned int) time(NULL));
//    *nonce                         = mrp->nonce;
//
//    if (src_eid != NULL){
////        cur_ptr = pkt_fill_eid(&(mrp->source_eid_afi),src_mapping);
//        cur_ptr = (uint8_t *)&(mrp->source_eid_afi);
//        cur_ptr = CO(cur_ptr, lisp_addr_write_to_pkt(cur_ptr, mapping_get_eid_addr(src_mapping)));
//
//        /* Add itr-rlocs */
//        locators_list[0] = src_mapping->head_v4_locators_list;
//        locators_list[1] = src_mapping->head_v6_locators_list;
//
//        for (ctr=0 ; ctr < 2 ; ctr++){
//            while (locators_list[ctr]){
//                locator = locators_list[ctr]->locator;
//                if (*(locator->state)==DOWN){
//                    locators_list[ctr] = locators_list[ctr]->next;
//                    continue;
//                }
//                /* Remove ITR locators behind NAT: No control message (4342) can be received in these interfaces */
//                if (((lcl_locator_extended_info *)locator->extended_info)->rtr_locators_list != NULL){
//                    locators_list[ctr] = locators_list[ctr]->next;
//                    continue;
//                }
//
//                itr_rloc = (lispd_pkt_map_request_itr_rloc_t *)cur_ptr;
//                cur_ptr = (uint8_t *)&itr_rloc->afi;
//                cpy_len = lisp_addr_write_to_pkt(cur_ptr ,locator->locator_addr);
//                cur_ptr = CO(cur_ptr, cpy_len);
//                locators_ctr ++;
//                locators_list[ctr] = locators_list[ctr]->next;
//            }
//        }
//    }else {
//        // XXX If no source EID is used, then we only use one ITR-RLOC for IPv4 and one for IPv6-> Default control RLOC
//        mrp->source_eid_afi = 0;
//        cur_ptr = CO(mrp, sizeof(map_request_msg_hdr));
//        if (default_ctrl_iface_v4 != NULL){
//            itr_rloc = (lispd_pkt_map_request_itr_rloc_t *)cur_ptr;
//            cur_ptr = (uint8_t *)&itr_rloc->afi;
//            cpy_len = lisp_addr_write_to_pkt(cur_ptr, default_ctrl_iface_v4->ipv4_address);
//            cur_ptr = CO(cur_ptr, cpy_len);
//            locators_ctr ++;
//        }
//        if (default_ctrl_iface_v6 != NULL){
//            itr_rloc = (lispd_pkt_map_request_itr_rloc_t *)cur_ptr;
//            cur_ptr = (uint8_t *)&itr_rloc->afi;
//            cpy_len = lisp_addr_write_to_pkt(cur_ptr, default_ctrl_iface_v6->ipv6_address);
//            cur_ptr = CO(cur_ptr, cpy_len);
//            locators_ctr ++;
//        }
//    }
//    mrp->additional_itr_rloc_count = locators_ctr - 1; /* IRC = 0 --> 1 ITR-RLOC */
//    if (locators_ctr == 0){
//        lispd_log_msg(LISP_LOG_DEBUG_2,"build_map_request_pkt: No ITR RLOCs.");
//        free(packet);
//        return (NULL);
//    }
//
//
//    /* Requested EID record */
//    request_eid_record = (eid_prefix_record_hdr *)cur_ptr;
//    request_eid_record->eid_prefix_length = requested_mapping->eid_prefix_length;
//
////    cur_ptr = pkt_fill_eid(&(request_eid_record->eid_prefix_afi),requested_mapping);
//    cur_ptr = CO(&(request_eid_record->eid_prefix_afi),
//            lisp_addr_write_to_pkt(&(request_eid_record->eid_prefix_afi),mapping_get_eid_addr(requested_mapping)));
//
//
//    if (mrp->map_data_present == 1){
//        /* Map-Reply Record */
//        rec = (mapping_record_hdr *)cur_ptr;
//        if ((mapping_fill_record_in_pkt(rec, src_mapping, NULL))== NULL) {
//            lispd_log_msg(LISP_LOG_DEBUG_2,"build_map_request_pkt: Couldn't buil map reply record for map request. "
//                    "Map Request will not be send");
//            free(packet);
//            return(NULL);
//        }
//    }
//
//    /* Add Encapsulated (Inner) control header*/
//    if (encap){
//
//        /*
//         * If no source EID is included (Source-EID-AFI = 0), The default RLOC address is used for
//         * the source address in the inner IP header
//         */
//        if (src_eid != NULL){
//            ih_src_ip = &(src_mapping->eid_prefix);;
//        }else{
//            if (requested_mapping->eid_prefix.afi == AF_INET){
//                ih_src_ip = get_main_eid (AF_INET);
//            }else{
//                ih_src_ip = get_main_eid (AF_INET6);
//            }
//        }
//
//        mr_packet = packet;
//        packet = build_control_encap_pkt(mr_packet, map_request_msg_len, ih_src_ip, &(requested_mapping->eid_prefix), LISP_CONTROL_PORT, LISP_CONTROL_PORT, len);
//
//        if (packet == NULL){
//            lispd_log_msg(LISP_LOG_DEBUG_1,"build_map_request_pkt: Couldn't encapsulate the map request");
//            free (mr_packet);
//            return (NULL);
//        }
//    }
//
//    return (packet);
//}
//
//
///*
// * Calculate Map Request length. Just add locators with status up
// */
//
//int get_map_request_length(lispd_mapping_elt *requested_mapping,
//        lispd_mapping_elt *src_mapping) {
//    int mr_len = 0;
//    int locator_count = 0, aux_locator_count = 0;
//    mr_len = sizeof(map_request_msg_hdr);
//    if (src_mapping) {
////        mr_len += get_mapping_length(src_mapping);
//        mr_len += lisp_addr_get_size_to_write(
//                mapping_get_eid_addr(src_mapping));
//
//        /* Calculate locators length */
//        mr_len += get_up_locators_length(src_mapping->head_v4_locators_list,
//                &aux_locator_count);
//        locator_count = aux_locator_count;
//        mr_len += get_up_locators_length(src_mapping->head_v6_locators_list,
//                &aux_locator_count);
//        locator_count += aux_locator_count;
//    } else {
//        if (default_ctrl_iface_v4 != NULL ) {
//            mr_len += sizeof(struct in_addr);
//            locator_count++;
//        }
//        if (default_ctrl_iface_v6 != NULL ) {
//            mr_len += sizeof(struct in6_addr);
//            locator_count++;
//        }
//    }
//
//    /* ITR-RLOC-AFI field */
//    mr_len += sizeof(lispd_pkt_map_request_itr_rloc_t) * locator_count;
//
//    /* Record size */
//    mr_len += sizeof(eid_prefix_record_hdr);
//    /* XXX: We supose that the requested EID has the same AFI as the source EID */
////    mr_len += get_mapping_length(requested_mapping);
//    mr_len += lisp_addr_get_size_to_write(
//            mapping_get_eid_addr(requested_mapping));
//
//    /* Add the Map-Reply Record */
//    if (src_mapping)
//        mr_len += pkt_get_mapping_record_length(src_mapping);
//
//    return mr_len;
//}




/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
