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
#include "lispd_map_reply.h"
#include "lispd_map_request.h"
#include "lispd_nonce.h"
#include "lispd_pkt_lib.h"
#include "lispd_smr.h"
#include "lispd_sockets.h"
#include "patricia/patricia.h"
#include <time.h>

/************** Function declaration ************/


/*
 * Process record and send Map Reply
 */

int process_map_request_record(
        uint8_t **cur_ptr,
        lisp_addr_t *src_rloc,
        lisp_addr_t *dst_rloc,
        uint16_t dst_port,
        uint8_t rloc_probe,
        uint64_t nonce);

/* Build a Map Request packet */

 uint8_t *build_map_request_pkt(
         lispd_mapping_elt       *requested_mapping,
         lisp_addr_t             *src_eid,
         uint8_t                 encap,
         uint8_t                 probe,
         uint8_t                 solicit_map_request,/* boolean really */
         uint8_t                 smr_invoked,
         int                     *len,               /* return length here */
         uint64_t                *nonce);             /* return nonce here */


 /*
  * Calculate Map Request length. Just add locators with status up
  */

 int get_map_request_length (lispd_mapping_elt *requested_mapping, lispd_mapping_elt *src_mapping);

 /*
  * Calculate the overhead of the Encapsulated Map Request length.
  */

 int get_emr_overhead_length (int afi);

/**************************************************/


 int process_map_request_msg(
         uint8_t        *packet,
         lisp_addr_t    *local_rloc,
         uint16_t       dst_port) {

     lispd_mapping_elt          *source_mapping          = NULL;
     lispd_map_cache_entry      *map_cache_entry        = NULL;
     lisp_addr_t                itr_rloc[32];
     lisp_addr_t                *remote_rloc            = NULL;
     int                        itr_rloc_count          = 0;
     int                        itr_rloc_afi            = 0;
     uint8_t                    *cur_ptr                = NULL;
     int                        len                     = 0;
     lispd_pkt_map_request_t    *msg                    = NULL;
     lisp_addr_t                aux_eid_prefix;
     int                        aux_eid_prefix_length   = 0;
     int                        aux_iid                 = -1;
     int                        i                       = 0;

     /* If the packet is an Encapsulated Map Request, verify checksum and remove the inner IP header */

     if (((lisp_encap_control_hdr_t *) packet)->type == LISP_ENCAP_CONTROL_TYPE) {
         if ((err = process_encapsulated_map_request_headers(packet,&len,&dst_port)) != GOOD){
             return (BAD);
         }
         msg = (lispd_pkt_map_request_t *) CO(packet, len);
     } else if (((lispd_pkt_map_request_t *) packet)->type == LISP_MAP_REQUEST) {
         msg = (lispd_pkt_map_request_t *) packet;
     } else
         return(BAD); //we should never reach this return()

     /*
      * Source EID is optional in general, but required for SMRs
      */

     /* Auxiliar lispd_mapping_elt created to be filled with pkt_process_eid_afi */
     source_mapping = new_local_mapping(aux_eid_prefix,aux_eid_prefix_length,aux_iid);
     if (source_mapping == NULL){
         return (BAD);
     }
     cur_ptr = (uint8_t *)&(msg->source_eid_afi);
     if (pkt_process_eid_afi(&cur_ptr, source_mapping) != GOOD){
         free_mapping_elt(source_mapping, FALSE);
         return (BAD);
     }
     /* If packet is a Solicit Map Request, process it */

     if (source_mapping->eid_prefix.afi != 0 && msg->solicit_map_request) {
         /*
          * Lookup the map cache entry that match with the source EID prefix of the message
          */
         map_cache_entry = lookup_map_cache(source_mapping->eid_prefix);
         if (map_cache_entry == NULL){
             free_mapping_elt(source_mapping, FALSE);
             return (BAD);
         }

         /*
          * Check IID of the received Solicit Map Request match the IID of the map cache
          */
         if (map_cache_entry->mapping->iid != source_mapping->iid){
             lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_request_msg: The IID of the received Solicit Map Request doesn't match the IID of "
                     "the entry in the map cache");
             free_mapping_elt(source_mapping, FALSE);
             return (BAD);
         }
         /* Free source_mapping once we have a valid map cache entry */
         free_mapping_elt(source_mapping, FALSE);

         /*
          * Only accept a solicit map request for an EID prefix ->If node which generates the message
          * has more than one locator, it probably will generate a solicit map request for each one.
          * Only the first one is considered.
          * If map_cache_entry->nonces is different of null, we have already received a solicit map request
          */
         if (map_cache_entry->nonces == NULL){
             solicit_map_request_reply(NULL,(void *)map_cache_entry);
         }
         /* Return here only if RLOC probe bit is not set */
         if (!msg->rloc_probe){
             return(GOOD);
         }
     }

     /* Get the array of ITR-RLOCs */
     itr_rloc_count = msg->additional_itr_rloc_count + 1;
     for (i = 0; i < itr_rloc_count; i++) {
         itr_rloc_afi = lisp2inetafi(ntohs(*(uint16_t *)cur_ptr));
         cur_ptr = CO(cur_ptr, sizeof(uint16_t));
         memcpy(&(itr_rloc[i].address), cur_ptr, get_addr_len(itr_rloc_afi));
         itr_rloc[i].afi = itr_rloc_afi;
         cur_ptr = CO(cur_ptr, get_addr_len(itr_rloc_afi));
         // Select the first accessible rloc from the ITR-RLOC list
         if (remote_rloc == NULL){
             if (local_rloc != NULL && itr_rloc[i].afi ==  local_rloc->afi){
                 remote_rloc = &itr_rloc[i];
             }
         }
     }
     if (remote_rloc == NULL){
         lispd_log_msg(LISP_LOG_DEBUG_1,"process_map_request_msg: Couldn't generate map replay - "
                 "No supported afi in the list of ITR-RLOCS");
         return (BAD);
     }

     /* Process record and send Map Reply for each one */
     for (i = 0; i < msg->record_count; i++) {
         process_map_request_record(&cur_ptr, local_rloc, remote_rloc, dst_port, msg->rloc_probe, msg->nonce);
     }
     return(GOOD);
 }

 /*
  * Process record and send Map Reply
  */

 int process_map_request_record(
         uint8_t **cur_ptr,
         lisp_addr_t *local_rloc,
         lisp_addr_t *remote_rloc,
         uint16_t dst_port,
         uint8_t rloc_probe,
         uint64_t nonce)
 {
     lispd_pkt_map_request_eid_prefix_record_t  *record                 = NULL;
     lispd_mapping_elt                          *requested_mapping      = NULL;
     lispd_mapping_elt                          *mapping                = NULL;
     map_reply_opts                             opts;
     lisp_addr_t                                aux_eid_prefix;
     int                                        aux_eid_prefix_length   = 0;
     int                                        aux_iid                 = -1;

     /* Get the requested EID prefix */
     record = (lispd_pkt_map_request_eid_prefix_record_t *)*cur_ptr;
     /* Auxiliar lispd_mapping_elt created to be filled with pkt_process_eid_afi */
     requested_mapping = new_local_mapping(aux_eid_prefix, aux_eid_prefix_length, aux_iid);
     if (requested_mapping == NULL){
         return (BAD);
     }
     *cur_ptr = (uint8_t *)&(record->eid_prefix_afi);
     if ((err=pkt_process_eid_afi(cur_ptr, requested_mapping))!=GOOD){
         lispd_log_msg(LISP_LOG_DEBUG_2,"process_map_request_record: Requested EID could not be processed");
         free_mapping_elt (requested_mapping, TRUE);
         return (err);
     }
     requested_mapping->eid_prefix_length = record->eid_prefix_length;

     /* Check the existence of the requested EID */
     /*  We don't use prefix mask and use by default 32 or 128*/
     mapping = lookup_eid_in_db(requested_mapping->eid_prefix);
     if (!mapping){
         lispd_log_msg(LISP_LOG_DEBUG_1,"The requested EID doesn't belong to this node: %s/%d",
                 get_char_from_lisp_addr_t(requested_mapping->eid_prefix),
                 requested_mapping->eid_prefix_length);
         free_mapping_elt (requested_mapping, TRUE);
         return (BAD);
     }
     free_mapping_elt (requested_mapping, TRUE);

     /* Set flags for Map-Reply */
     opts.send_rec   = 1;
     opts.echo_nonce = 0;
     opts.rloc_probe = rloc_probe;

     err = build_and_send_map_reply_msg(mapping, local_rloc, remote_rloc, dst_port, nonce, opts);

     return (err);
 }

/*
 *  build_and_send_map_request --
 *
 *  Put a wrapper around build_map_request_pkt and send_map_request
 *
 */

int build_and_send_map_request_msg(
        lispd_mapping_elt       *requested_mapping,
        lisp_addr_t             *src_eid,
        lisp_addr_t             *dst_rloc_addr,
        uint8_t                 encap,
        uint8_t                 probe,
        uint8_t                 solicit_map_request,
        uint8_t                 smr_invoked,
        uint64_t                *nonce)
{

    uint8_t     *packet         = NULL;
    uint8_t     *map_req_pkt    = NULL;
    lisp_addr_t *src_addr       = NULL;
    int         out_socket      = 0;
    int         packet_len      = 0;
    int         mrp_len         = 0;               /* return the length here */
    int         result          = 0;
    map_req_pkt = build_map_request_pkt(
            requested_mapping,
            src_eid,
            encap,
            probe,
            solicit_map_request,
            smr_invoked,
            &mrp_len,
            nonce);

    if (map_req_pkt == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_map_request_msg: Could not build map-request packet for %s/%d:"
                " Encap: %c, Probe: %c, SMR: %c, SMR-inv: %c ",
                get_char_from_lisp_addr_t(requested_mapping->eid_prefix),
                requested_mapping->eid_prefix_length,
                (encap == TRUE ? 'Y' : 'N'),
                (probe == TRUE ? 'Y' : 'N'),
                (solicit_map_request == TRUE ? 'Y' : 'N'),
                (smr_invoked == TRUE ? 'Y' : 'N'));
        return (BAD);
    }

    /* Get src interface information */

    src_addr    = get_default_ctrl_address(dst_rloc_addr->afi);
    out_socket  = get_default_ctrl_socket(dst_rloc_addr->afi);


    if (src_addr == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_1, "build_and_send_map_request_msg: Couden't send Map Request. No output interface with afi %d.",
                dst_rloc_addr->afi);
        free (map_req_pkt);
        return (BAD);
    }

    /*  Add UDP and IP header to the Map Request message */

    packet = build_ip_udp_pcket(map_req_pkt,
                                mrp_len,
                                src_addr,
                                dst_rloc_addr,
                                LISP_CONTROL_PORT,
                                LISP_CONTROL_PORT,
                                &packet_len);
    free (map_req_pkt);

    if (packet == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_1,"build_and_send_map_request_msg: Couldn't send Map Request. Error adding IP and UDP header to the message");
        return (BAD);
    }

    /* Send the packet */

    if ((err = send_packet(out_socket,packet,packet_len)) == GOOD){
        lispd_log_msg(LISP_LOG_DEBUG_1, "Sent Map-Request packet for %s/%d to %s: Encap: %c, Probe: %c, SMR: %c, SMR-inv: %c . Nonce: %s",
                        get_char_from_lisp_addr_t(requested_mapping->eid_prefix),
                        requested_mapping->eid_prefix_length,
                        get_char_from_lisp_addr_t(*dst_rloc_addr),
                        (encap == TRUE ? 'Y' : 'N'),
                        (probe == TRUE ? 'Y' : 'N'),
                        (solicit_map_request == TRUE ? 'Y' : 'N'),
                        (smr_invoked == TRUE ? 'Y' : 'N'),
                        get_char_from_nonce(*nonce));
        result = GOOD;
    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "Couldn't sent Map-Request packet for %s/%d: Encap: %c, Probe: %c, SMR: %c, SMR-inv: %c ",
                get_char_from_lisp_addr_t(requested_mapping->eid_prefix),
                requested_mapping->eid_prefix_length,
                (encap == TRUE ? 'Y' : 'N'),
                (probe == TRUE ? 'Y' : 'N'),
                (solicit_map_request == TRUE ? 'Y' : 'N'),
                (smr_invoked == TRUE ? 'Y' : 'N'));
        result = BAD;
    }
    free (packet);

    return (result);
}

/* Build a Map Request paquet */

uint8_t *build_map_request_pkt(
        lispd_mapping_elt       *requested_mapping,
        lisp_addr_t             *src_eid,
        uint8_t                 encap,
        uint8_t                 probe,
        uint8_t                 solicit_map_request,/* boolean really */
        uint8_t                 smr_invoked,
        int                     *len,               /* return length here */
        uint64_t                *nonce)             /* return nonce here */
{

    uint8_t                                     *packet                 = NULL;
    uint8_t                                     *mr_packet              = NULL;
    lispd_pkt_map_request_t                     *mrp                    = NULL;
    lispd_pkt_mapping_record_t                  *rec                    = NULL;
    lispd_pkt_map_request_itr_rloc_t            *itr_rloc               = NULL;
    lispd_pkt_map_request_eid_prefix_record_t   *request_eid_record     = NULL;
    uint8_t                                     *cur_ptr                = NULL;

    int                     map_request_msg_len = 0;
    int                     ctr                 = 0;
    int                     cpy_len             = 0;
    int                     locators_ctr        = 0;

    lispd_mapping_elt       *src_mapping        = NULL;
    lispd_locators_list     *locators_list[2]   = {NULL,NULL};
    lispd_locator_elt       *locator            = NULL;
    lisp_addr_t             *ih_src_ip          = NULL;

    /*
     * Lookup the local EID prefix from where we generate the message.
     * src_eid is null for RLOC probing and refreshing map_cache -> Source-EID AFI = 0
     */
    if (src_eid != NULL){
        src_mapping = lookup_eid_in_db(*src_eid);
        if (!src_mapping){
            lispd_log_msg(LISP_LOG_DEBUG_2,"build_map_request_pkt: Source EID address not found in local data base - %s -",
                    get_char_from_lisp_addr_t(*src_eid));
            return (NULL);
        }

    }

    /* Calculate the packet size and reserve memory */
    map_request_msg_len = get_map_request_length(requested_mapping,src_mapping);
    *len = map_request_msg_len;

    if ((packet = malloc(map_request_msg_len)) == NULL){
        lispd_log_msg(LISP_LOG_WARNING,"build_map_request_pkt: Unable to allocate memory for Map Request (packet_len): %s", strerror(errno));
        return (NULL);
    }
    memset(packet, 0, map_request_msg_len);


    cur_ptr = packet;

    mrp = (lispd_pkt_map_request_t *)cur_ptr;

    mrp->type                      = LISP_MAP_REQUEST;
    mrp->authoritative             = 0;
    if (src_eid != NULL)
        mrp->map_data_present      = 1;
    else
        mrp->map_data_present      = 0;

    if (probe)
        mrp->rloc_probe            = 1;
    else
        mrp->rloc_probe            = 0;

    if (solicit_map_request)
        mrp->solicit_map_request   = 1;
    else
        mrp->solicit_map_request   = 0;

    if (smr_invoked)
        mrp->smr_invoked           = 1;
    else
        mrp->smr_invoked           = 0;

    mrp->additional_itr_rloc_count = 0;     /* To be filled later  */
    mrp->record_count              = 1;     /* XXX: assume 1 record */
    mrp->nonce = build_nonce((unsigned int) time(NULL));
    *nonce                         = mrp->nonce;

    if (src_eid != NULL){
        cur_ptr = pkt_fill_eid(&(mrp->source_eid_afi),src_mapping);

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

                itr_rloc = (lispd_pkt_map_request_itr_rloc_t *)cur_ptr;
                itr_rloc->afi = htons(get_lisp_afi(locator->locator_addr->afi,NULL));
                /* Add rloc address */
                cur_ptr = CO(itr_rloc,sizeof(lispd_pkt_map_request_itr_rloc_t));
                cpy_len = copy_addr((void *) cur_ptr ,locator->locator_addr, 0);
                cur_ptr = CO(cur_ptr, cpy_len);
                locators_ctr ++;
                locators_list[ctr] = locators_list[ctr]->next;
            }
        }
    }else {
        // XXX If no source EID is used, then we only use one ITR-RLOC for IPv4 and one for IPv6-> Default control RLOC
        mrp->source_eid_afi = 0;
        cur_ptr = CO(mrp, sizeof(lispd_pkt_map_request_t));
        if (default_ctrl_iface_v4 != NULL){
            itr_rloc = (lispd_pkt_map_request_itr_rloc_t *)cur_ptr;
            itr_rloc->afi = htons((uint16_t)LISP_AFI_IP);
            cur_ptr = CO(itr_rloc,sizeof(lispd_pkt_map_request_itr_rloc_t));
            cpy_len = copy_addr((void *) cur_ptr ,default_ctrl_iface_v4->ipv4_address, 0);
            cur_ptr = CO(cur_ptr, cpy_len);
            locators_ctr ++;
        }
        if (default_ctrl_iface_v6 != NULL){
            itr_rloc = (lispd_pkt_map_request_itr_rloc_t *)cur_ptr;
            itr_rloc->afi = htons(get_lisp_afi(AF_INET6,NULL));
            cur_ptr = CO(itr_rloc,sizeof(lispd_pkt_map_request_itr_rloc_t));
            cpy_len = copy_addr((void *) cur_ptr ,default_ctrl_iface_v6->ipv6_address, 0);
            cur_ptr = CO(cur_ptr, cpy_len);
            locators_ctr ++;
        }
    }
    mrp->additional_itr_rloc_count = locators_ctr - 1; /* IRC = 0 --> 1 ITR-RLOC */
    if (locators_ctr == 0){
        lispd_log_msg(LISP_LOG_DEBUG_2,"build_map_request_pkt: No ITR RLOCs.");
        free(packet);
        return (NULL);
    }


    /* Requested EID record */
    request_eid_record = (lispd_pkt_map_request_eid_prefix_record_t *)cur_ptr;
    request_eid_record->eid_prefix_length = requested_mapping->eid_prefix_length;

    cur_ptr = pkt_fill_eid(&(request_eid_record->eid_prefix_afi),requested_mapping);

    if (mrp->map_data_present == 1){
        /* Map-Reply Record */
        rec = (lispd_pkt_mapping_record_t *)cur_ptr;
        if ((pkt_fill_mapping_record(rec, src_mapping, NULL))== NULL) {
            lispd_log_msg(LISP_LOG_DEBUG_2,"build_map_request_pkt: Couldn't buil map reply record for map request. "
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
            ih_src_ip = &(src_mapping->eid_prefix);;
        }else{
            if (requested_mapping->eid_prefix.afi == AF_INET){
                ih_src_ip = get_main_eid (AF_INET);
            }else{
                ih_src_ip = get_main_eid (AF_INET6);
            }
        }

        mr_packet = packet;
        packet = build_control_encap_pkt(mr_packet, map_request_msg_len, ih_src_ip, &(requested_mapping->eid_prefix), LISP_CONTROL_PORT, LISP_CONTROL_PORT, len);

        if (packet == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_1,"build_map_request_pkt: Couldn't encapsulate the map request");
            free (mr_packet);
            return (NULL);
        }
    }

    return (packet);
}


/*
 * Calculate Map Request length. Just add locators with status up
 */

int get_map_request_length (lispd_mapping_elt *requested_mapping, lispd_mapping_elt *src_mapping)
{
    int mr_len = 0;
    int locator_count = 0, aux_locator_count = 0;
    mr_len = sizeof(lispd_pkt_map_request_t);
    if (src_mapping != NULL){
        mr_len += get_mapping_length(src_mapping);
        /* Calculate locators length */
        mr_len += get_up_locators_length(src_mapping->head_v4_locators_list,&aux_locator_count);
        locator_count = aux_locator_count;
        mr_len += get_up_locators_length(src_mapping->head_v6_locators_list,&aux_locator_count);
        locator_count += aux_locator_count;
    }else{
        if (default_ctrl_iface_v4 != NULL){
            mr_len += sizeof(struct in_addr);
            locator_count ++;
        }
        if (default_ctrl_iface_v6 != NULL){
            mr_len += sizeof(struct in6_addr);
            locator_count ++;
        }
    }
    mr_len += sizeof(lispd_pkt_map_request_itr_rloc_t)*locator_count;  // ITR-RLOC-AFI field
    /* Record size */
    mr_len += sizeof(lispd_pkt_map_request_eid_prefix_record_t);
    // We supose that the requested EID has the same AFI as the source EID
    mr_len += get_mapping_length(requested_mapping);
    /* Add the Map-Reply Record */
    if (src_mapping != NULL)
        mr_len += pkt_get_mapping_record_length(src_mapping);

    return mr_len;
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
    lispd_map_cache_entry *map_cache_entry = argument->map_cache_entry;
    nonces_list *nonces = map_cache_entry->nonces;
    lisp_addr_t *dst_rloc = NULL;

    if (nonces == NULL){
        nonces = new_nonces_list();
        if (nonces==NULL){
            lispd_log_msg(LISP_LOG_WARNING,"Send_map_request_miss: Unable to allocate memory for nonces.");
            return (BAD);
        }
        map_cache_entry->nonces = nonces;
    }

    if (nonces->retransmits - 1 < map_request_retries ){

        if (map_cache_entry->request_retry_timer == NULL){
            map_cache_entry->request_retry_timer = create_timer (MAP_REQUEST_RETRY_TIMER);
        }

        if (nonces->retransmits > 0){
            lispd_log_msg(LISP_LOG_DEBUG_1,"Retransmiting Map Request for EID: %s (%d retries)",
                    get_char_from_lisp_addr_t(map_cache_entry->mapping->eid_prefix),
                    nonces->retransmits);
        }

        /* Get the RLOC of the Map Resolver to be used */
        dst_rloc = get_map_resolver();

        if ((dst_rloc == NULL) || (build_and_send_map_request_msg(
                map_cache_entry->mapping,
                &(argument->src_eid),
                dst_rloc,
                1,
                0,
                0,
                0,
                &nonces->nonce[nonces->retransmits]))==BAD){
            lispd_log_msg (LISP_LOG_DEBUG_1, "send_map_request_miss: Couldn't send map request for a new map cache entry");

        }

        nonces->retransmits ++;
        start_timer(map_cache_entry->request_retry_timer, LISPD_INITIAL_MRQ_TIMEOUT,
                send_map_request_miss, (void *)argument);

    }else{
        lispd_log_msg(LISP_LOG_DEBUG_1,"No Map Reply fot EID %s/%d after %d retries. Removing map cache entry ...",
                        get_char_from_lisp_addr_t(map_cache_entry->mapping->eid_prefix),
                        map_cache_entry->mapping->eid_prefix_length,
                        nonces->retransmits -1);
        del_map_cache_entry_from_db(map_cache_entry->mapping->eid_prefix,
                map_cache_entry->mapping->eid_prefix_length);

    }
    return GOOD;
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
