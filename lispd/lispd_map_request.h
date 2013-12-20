/*
 * lispd_map_request.h
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

#ifndef LISPD_MAP_REQUEST_H_
#define LISPD_MAP_REQUEST_H_


#include "lispd.h"
#include "lispd_map_cache_db.h"


/*
 * Map-Request Message Format
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=1 |A|M|P|S|p|s|    Reserved     |   IRC   | Record Count  |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         Nonce . . .                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                         . . . Nonce                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         Source-EID-AFI        |   Source EID Address  ...     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                              ...                              |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                       EID-prefix  ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                   Map-Reply Record  ...                       |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Mapping Protocol Data                     |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


/*
 * Fixed size portion of the map request. Variable size source EID
 * address, originating ITR RLOC AFIs and addresses and then map
 * request records follow.
 */
typedef struct lispd_pkt_map_request_t_ {
#ifdef LITTLE_ENDIANS
    uint8_t solicit_map_request:1;
    uint8_t rloc_probe:1;
    uint8_t map_data_present:1;
    uint8_t authoritative:1;
    uint8_t type:4;
#else
    uint8_t type:4;
    uint8_t authoritative:1;
    uint8_t map_data_present:1;
    uint8_t rloc_probe:1;
    uint8_t solicit_map_request:1;
#endif
#ifdef LITTLE_ENDIANS
    uint8_t reserved1:6;
    uint8_t smr_invoked:1;
    uint8_t pitr:1;
#else
    uint8_t pitr:1;
    uint8_t smr_invoked:1;
    uint8_t reserved1:6;
#endif
#ifdef LITTLE_ENDIANS
    uint8_t additional_itr_rloc_count:5;
    uint8_t reserved2:3;
#else
    uint8_t reserved2:3;
    uint8_t additional_itr_rloc_count:5;
#endif
    uint8_t record_count;
    uint64_t nonce;
    uint16_t source_eid_afi;
} PACKED lispd_pkt_map_request_t;



/*
 * Fixed size portion of map request ITR RLOC.
 */
typedef struct lispd_pkt_map_request_itr_rloc_t_ {
    uint16_t afi;
    /*    uint8_t address[0]; */
} PACKED lispd_pkt_map_request_itr_rloc_t;




/*
 * Map Request Record
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                       EID-prefix  ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Fixed portion of the request record. EID prefix address follow.
 */

typedef struct lispd_pkt_map_request_eid_prefix_record_t_ {
    uint8_t     reserved;
    uint8_t     eid_prefix_length;
    uint16_t    eid_prefix_afi;
} PACKED lispd_pkt_map_request_eid_prefix_record_t;

/*
 * Structure to set Map Request options
 */
typedef struct {
    uint8_t                 encap;                  // Encapsulated Map Request
    encap_control_opts      encap_opts;             // Encapsulated flags
    uint8_t                 probe;                  // Map Request Probe
    uint8_t                 solicit_map_request;    // Solicit Map Request
    uint8_t                 smr_invoked;            // SMR Invoked
} map_request_opts;

/*
 * Use the nonce to calculate the source port for a map request
 * message.
 */
#define LISP_PKT_MAP_REQUEST_UDP_SPORT(Nonce) (0xf000 | (Nonce & 0xfff))

#define LISP_PKT_MAP_REQUEST_TTL 32


/*
 * The IRC value above is set to one less than the number of ITR-RLOC
 * fields (an IRC of zero means one ITR-RLOC). In 5 bits we can encode
 * the number 15 which means we can have up to 16 ITR-RLOCs.
 */
#define LISP_PKT_MAP_REQUEST_MAX_ITR_RLOCS 16


/*
 * Struct used to pass the arguments to the call_back function of a
 * map request miss
 */

typedef struct _timer_map_request_argument{
    lispd_map_cache_entry   *map_cache_entry;
    lisp_addr_t             src_eid;
} timer_map_request_argument;


/*
 *  Put a wrapper around build_map_request_pkt and send_map_request
 */
int build_and_send_map_request_msg(
        lispd_mapping_elt       *requested_mapping,
        lisp_addr_t             *src_eid,
        lisp_addr_t             *dst_rloc_addr,
        map_request_opts        opts,
        uint64_t                *nonce);


/*
 *  Receive a Map_request message and process based on control bits
 *  For first phase just accept (encapsulated) SMR. Proxy bit is set to avoid receiving ecm, and all other types are ignored.
 */
int process_map_request_msg(uint8_t *packet, lisp_addr_t *local_rloc, uint16_t remote_port);


/**
 *  Timer function to send an Encapsulated Map Request to a Map Resolver of the list with X retries.
 *  When a reply to this message  is processed, then the timer that calls this functions to send the retries is removed.
 *  This function is called for first time when a packet miss is generated. In that case the timer parameter is NULL.
 *  @param t Timer responsible to call this function
 *  @param arg Represents a timer_map_request_argument element
 *  @return GOOD if finish correctly or an error code otherwise
 */
int send_map_request_miss(timer *t, void *arg);

/**
 *  Timer function to send a ddt Encapsulated Map Request to a DDT node with X retries.
 *  When a reply to this message  is processed (map referral), the timer that calls this functions to send the
 *  retries is removed.
 *  This function is called for first time when a packet miss is generated and ddt_client is enabled. In that case the
 *  timer parameter is NULL.
 *  @param t Timer responsible to call this function
 *  @param arg Represents a lispd_pending_referral_cache_entry element
 *  @return GOOD if finish correctly or an error code otherwise
 */
int send_ddt_map_request_miss(timer *t, void *arg);


/**
 * Timer function to send an Encapsulated Map Request to a MS node with X retries when we receive a Map Referral MS-ACK but
 * not a Map Reply.
 * NOTE: In the previous referral parameter of the pending_referral_entry ther is the referral cache entry generated by
 * the Referral MS-ACK.
 * @param t Timer responsible to call this function
 * @param arg Represents a lispd_pending_referral_cache_entry element
 * @return GOOD if finish correctly or an error code otherwise
 */
int send_map_request_ddt_map_reply_miss(timer *t, void *arg);

#endif /*LISPD_MAP_REQUEST_H_*/
