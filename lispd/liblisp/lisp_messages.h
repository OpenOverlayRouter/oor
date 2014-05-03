/*
 * lisp_messages.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2012 Cisco Systems, Inc, 2012. All rights reserved.
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
 */

#ifndef LISP_MESSAGES_H_
#define LISP_MESSAGES_H_

#include <stdlib.h>
#include "lisp_message_fields.h"
#include "lisp_map_reply.h"
#include "lisp_map_request.h"
#include "lisp_map_register.h"
#include "lisp_map_notify.h"
#include <defs.h>

/* LISP Types */
typedef enum {
    LISP_MAP_REQUEST = 1,
    LISP_MAP_REPLY,
    LISP_MAP_REGISTER,
    LISP_MAP_NOTIFY,
    LISP_INFO_NAT = 7,
    LISP_ENCAP_CONTROL_TYPE
} lisp_msg_type_t;

/*
 * ENCAPSULATED CONTROL MESSAGE
 */

/*
*     0                   1                   2                   3
*     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   / |                       IPv4 or IPv6 Header                     |
* OH  |                      (uses RLOC addresses)                    |
*   \ |                                                               |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   / |       Source Port = xxxx      |       Dest Port = 4342        |
* UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   \ |           UDP Length          |        UDP Checksum           |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* LH  |Type=8 |S|                  Reserved                           |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   / |                       IPv4 or IPv6 Header                     |
* IH  |                  (uses RLOC or EID addresses)                 |
*   \ |                                                               |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   / |       Source Port = xxxx      |       Dest Port = yyyy        |
* UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   \ |           UDP Length          |        UDP Checksum           |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* LCM |                      LISP Control Message                     |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct _lisp_encap_data {
    uint8_t         *ecmh;
    uint8_t         *iph;
    uint8_t         ip_afi;
    int             ip_header_len;
    struct udphdr   *udph;
    int             udp_len;
    int             len;
} lisp_encap_data;


typedef struct _lisp_msg {
    uint8_t         encap;
    lisp_encap_data *encapdata;
    lisp_msg_type_t  type;
    void            *msg;
} lisp_msg;



/*
 * Encapsulated control message header. This is followed by the IP
 * header of the encapsulated LISP control message.
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Type=8 |S|                 Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct lisp_encap_control_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t reserved:3;
    uint8_t s_bit:1;
    uint8_t type:4;
#else
    uint8_t type:4;
    uint8_t s_bit:1;
    uint8_t reserved1:3;
#endif
    uint8_t reserved2[3];
} ecm_hdr_t;


char *ecm_hdr_to_char(ecm_hdr_t *h);
void ecm_hdr_init(uint8_t *ptr);

#define ECM_TYPE(h_) ((ecm_hdr_t *)(h_))->type


/*
 * MAP-REQUEST MESSAGE
 */

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
typedef struct _map_request_msg_hdr {
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
} __attribute__ ((__packed__)) map_request_hdr_t;


void map_request_hdr_init(uint8_t *ptr);
char *map_request_hdr_to_char(map_request_hdr_t *h);


#define MREQ_HDR_CAST(h_) ((map_request_hdr_t *)(h_))
#define MREQ_REC_COUNT(h_) (MREQ_HDR_CAST(h_))->record_count
#define MREQ_RLOC_PROBE(h_) (MREQ_HDR_CAST(h_))->rloc_probe
#define MREQ_ITR_RLOC_COUNT(h_) (MREQ_HDR_CAST(h_))->additional_itr_rloc_count
#define MREQ_NONCE(h_) (MREQ_HDR_CAST(h_))->nonce
#define MREQ_SMR(h_) (MREQ_HDR_CAST(h_))->solicit_map_request
#define MREQ_SMR_INVOKED(h_) (MREQ_HDR_CAST(h_))->smr_invoked






/*
 * MAP-REPLY MESSAGE
 */

 /*  Map Reply action codes */
 #define LISP_ACTION_NO_ACTION           0
 #define LISP_ACTION_FORWARD             1
 #define LISP_ACTION_DROP                2
 #define LISP_ACTION_SEND_MAP_REQUEST    3

 /*
  * Map-Reply Message Format
  *
  *       0                   1                   2                   3
  *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *      |Type=2 |P|E|S|         Reserved                | Record Count  |
  *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *      |                         Nonce . . .                           |
  *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *      |                         . . . Nonce                           |
  *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |   |                          Record  TTL                          |
  *  |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
  *  e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
  *  o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  r   |                          EID-prefix                           |
  *  d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
  *  | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  | o |        Unused Flags     |L|p|R|           Loc-AFI             |
  *  | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *  |  \|                            Locator                            |
  *  +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  *      |                     Mapping Protocol Data                     |
  *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */



 /*
  * Fixed size portion of the map reply.
  */
 typedef struct map_reply_hdr_ {
 #ifdef LITTLE_ENDIANS
     uint8_t reserved1:1;
     uint8_t security:1;
     uint8_t echo_nonce:1;
     uint8_t rloc_probe:1;
     uint8_t type:4;
 #else
     uint8_t type:4;
     uint8_t rloc_probe:1;
     uint8_t echo_nonce:1;
     uint8_t reserved1:2;
 #endif
     uint8_t reserved2;
     uint8_t reserved3;
     uint8_t record_count;
     uint64_t nonce;
 } __attribute__ ((__packed__)) map_reply_hdr_t;

 void map_reply_hdr_init(uint8_t *ptr);
 char *map_reply_hdr_to_char(map_reply_hdr_t *h);

#define MREP_HDR_CAST(h) ((map_reply_hdr_t *)(h))
#define MREP_REC_COUNT(h) ((map_reply_hdr_t *)(h))->record_count
#define MREP_RLOC_PROBE(h) ((map_reply_hdr_t *)(h))->rloc_probe
#define MREP_NONCE(h) ((map_reply_hdr_t *)(h))->nonce




/*
 * MAP-NOTIFY MESSAGE
 */


 /*
 * Map-Notify Message Format
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=4 |I|R|          Reserved                 | Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   |                          Record  TTL                          |
 *   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   c   | Rsvd  |  Map-Version Number   |        EID-prefix-AFI         |
 *   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   r   |                          EID-prefix                           |
 *   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  \|                             Locator                           |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct _map_notify_msg_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t  reserved1:2;
    uint8_t  rtr_auth_present:1;
    uint8_t  xtr_id_present:1;
    uint8_t  type:4;
#else
    uint8_t  type:4;
    uint8_t  xtr_id_present:1;
    uint8_t  rtr_auth_present:1;
    uint8_t  reserved1:2;
#endif
    uint16_t reserved2;
    uint8_t  record_count;
    uint64_t nonce;
} __attribute__ ((__packed__)) map_notify_hdr_t;

void map_notify_hdr_init(uint8_t *ptr);
char *map_notify_hdr_to_char(map_notify_hdr_t *h);

#define MNTF_HDR_CAST(h_) ((map_notify_hdr_t *)(h_))
#define MNTF_I_BIT(h_) (MNTF_HDR_CAST((h_)))->xtr_id_present
#define MNTF_XTR_ID_PRESENT(h_) (MNTF_HDR_CAST((h_)))->xtr_id_present
#define MNTF_RTR_AUTH_PRESENT(h_) (MNTF_HDR_CAST((h_)))->rtr_auth_present
#define MNTF_REC_COUNT(h_) MNTF_HDR_CAST((h_))->record_count
#define MNTF_NONCE(h_) MNTF_HDR_CAST((h_))->nonce



/*
 * MAP-REGISTER MESSAGE
 */


/*
 * Map-Registers have an authentication header before the UDP header.
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=3 |P| |I|R|      Reserved               |M| Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                       Mapping Records ...                     |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */



/*
 * Map-Register Message Format
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=3 |P| |I|R|      Reserved               |M| Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   |                          Record  TTL                          |
 *   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   c   | Rsvd  |  Map-Version Number   |        EID-prefix-AFI         |
 *   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   r   |                          EID-prefix                           |
 *   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  \|                             Locator                           |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/* I and R bit are defined on NAT tarversal draft*/

typedef struct _map_register_msg_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t  rbit:1;
    uint8_t  ibit:1;
    uint8_t  reserved1:1;
    uint8_t  proxy_reply:1;
    uint8_t  type:4;
#else
    uint8_t  type:4;
    uint8_t  proxy_reply:1;
    uint8_t  reserved1:1;
    uint8_t  ibit:1;
    uint8_t  rbit:1;
#endif
    uint8_t reserved2;
#ifdef LITTLE_ENDIANS
    uint8_t map_notify:1;
    uint8_t lisp_mn:1;
    uint8_t reserved3:6;
#else
    uint8_t reserved3:6;
    uint8_t lisp_mn:1;
    uint8_t map_notify:1;
#endif
    uint8_t  record_count;
    uint64_t nonce;
} __attribute__ ((__packed__)) map_register_hdr_t;


void map_register_hdr_init(uint8_t *ptr);
char *map_register_hdr_to_char(map_register_hdr_t *h);


#define MREG_HDR_CAST(h_) ((map_register_hdr_t *)(h_))
#define MREG_REC_COUNT(h_) MREG_HDR_CAST((h_))->record_count
#define MREG_WANT_MAP_NOTIFY(h_) (MREG_HDR_CAST(h_))->map_notify
#define MREG_NONCE(h_) (MREG_HDR_CAST(h_))->nonce




uint8_t is_mrsignaling(address_hdr_t *addr);
mrsignaling_flags_t mrsignaling_flags(address_hdr_t *addr);
void mrsignaling_set_flags_in_pkt(uint8_t *offset, mrsignaling_flags_t *mrsig);



#endif /* LISP_MESSAGES_H_ */
