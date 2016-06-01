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

#ifndef LISP_MESSAGES_H_
#define LISP_MESSAGES_H_

#include "lisp_message_fields.h"
#include <stdlib.h>
#include "../lib/mem_util.h"

/* LISP Types */
typedef enum lisp_msg_type_ {
    NOT_LISP_MSG,
    LISP_MAP_REQUEST = 1,
    LISP_MAP_REPLY,
    LISP_MAP_REGISTER,
    LISP_MAP_NOTIFY,
    LISP_INFO_NAT = 7,
    LISP_ENCAP_CONTROL_TYPE = 8
} lisp_msg_type_e;


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


/*
 * Encapsulated control message header. This is followed by the IP
 * header of the encapsulated LISP control message.
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Type=8 |S|D|R|             Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct ecm_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t n_bit:1; // RTR relays the ECM-ed Map-Register to a Map-Server
    uint8_t r_bit:1; // The encapsulated msg is to be processed by an RTR
    uint8_t d_bit:1; // DDT originated
    uint8_t s_bit:1;
    uint8_t type:4;
#else
    uint8_t type:4;
    uint8_t s_bit:1;
    uint8_t d_bit:1;
    uint8_t r_bit:1;
    uint8_t n_bit:1;
#endif
    uint8_t reserved2[3];
} ecm_hdr_t;


char *ecm_hdr_to_char(ecm_hdr_t *h);
void ecm_hdr_init(void *ptr);

#define ECM_HDR_CAST(h_) ((ecm_hdr_t *)(h_))
#define ECM_TYPE(h_) (ECM_HDR_CAST(h_))->type
#define ECM_SECURITY_BIT(h_) (ECM_HDR_CAST(h_))->s_bit
#define ECM_DDT_BIT(h_) (ECM_HDR_CAST(h_))->d_bit
#define ECM_RTR_PROCESS_BIT(h_) (ECM_HDR_CAST(h_))->r_bit


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
typedef struct map_request_hdr {
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


void map_request_hdr_init(void *ptr);
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
 typedef struct map_reply_hdr {
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
     uint8_t security:1;
     uint8_t reserved1:1;
 #endif
     uint8_t reserved2;
     uint8_t reserved3;
     uint8_t record_count;
     uint64_t nonce;
 } __attribute__ ((__packed__)) map_reply_hdr_t;

 void map_reply_hdr_init(void *ptr);
 char *map_reply_hdr_to_char(map_reply_hdr_t *h);

#define MREP_HDR_CAST(h_) ((map_reply_hdr_t *)(h_))
#define MREP_REC_COUNT(h_) MREP_HDR_CAST(h_)->record_count
#define MREP_RLOC_PROBE(h_) MREP_HDR_CAST(h_)->rloc_probe
#define MREP_NONCE(h_) MREP_HDR_CAST(h_)->nonce




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

typedef struct map_notify_hdr {
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

void map_notify_hdr_init(void *ptr);
char *map_notify_hdr_to_char(map_notify_hdr_t *h);

#define MNTF_HDR_CAST(h_) ((map_notify_hdr_t *)(h_))
#define MNTF_I_BIT(h_) (MNTF_HDR_CAST((h_)))->xtr_id_present
#define MNTF_XTR_ID_PRESENT(h_) (MNTF_HDR_CAST((h_)))->xtr_id_present
#define MNTF_R_BIT(h_) (MNTF_HDR_CAST((h_)))->rtr_auth_present
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

typedef struct map_register_hdr {
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


void map_register_hdr_init(void *ptr);
char *map_register_hdr_to_char(map_register_hdr_t *h);


#define MREG_HDR_CAST(h_) ((map_register_hdr_t *)(h_))
#define MREG_REC_COUNT(h_) MREG_HDR_CAST((h_))->record_count
#define MREG_WANT_MAP_NOTIFY(h_) (MREG_HDR_CAST(h_))->map_notify
#define MREG_NONCE(h_) (MREG_HDR_CAST(h_))->nonce
#define MREG_PROXY_REPLY(h_)(MREG_HDR_CAST(h_))->proxy_reply
#define MREG_IBIT(h_)(MREG_HDR_CAST(h_))->ibit
#define MREG_RBIT(h_)(MREG_HDR_CAST(h_))->rbit


/*  Info Request type */

#define INFO_REQUEST           0
#define INFO_REPLY             1

/*
 * Info Request Message Format
 *
 *      0                   1                   2                     3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |Type=7 |R|            Reserved                                 |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Nonce . . .                           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                      . . . Nonce                              |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |              Key ID           |  Authentication Data Length   |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ~                     Authentication Data                       ~
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                              TTL                              |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                          EID-prefix                           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |             AFI = 0           |   <Nothing Follows AFI=0>     |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **/


typedef struct info_nat_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t  reserved1:3;
    uint8_t  r_bit_info_reply:1;
    uint8_t  type:4;
#else
    uint8_t  type:4;
    uint8_t  r_bit_info_reply:1;
    uint8_t  reserved1:3;
#endif
    uint8_t  reserved2[3];
    uint64_t nonce;
} __attribute__ ((__packed__)) info_nat_hdr_t;

typedef struct info_nat_hdr_2 {
    uint32_t ttl;
    uint8_t reserved;
    uint8_t eid_mask_len;
} __attribute__ ((__packed__)) info_nat_hdr_2_t;

char *info_nat_hdr_to_char(info_nat_hdr_t *h);
void info_nat_hdr_init(void *ptr);
void info_nat_hdr_2_init(void *ptr);


#define INF_REQ_HDR_CAST(h_) ((info_nat_hdr_t *)(h_))
#define INF_REQ_R_bit(h_) (INF_REQ_HDR_CAST(h_))->r_bit_info_reply
#define INF_REQ_NONCE(h_) (INF_REQ_HDR_CAST(h_))->nonce
#define INF_REQ_HDR_2_CAST(h_) ((info_nat_hdr_2_t *)(h_))
#define INF_REQ_2_TTL(h_) (INF_REQ_HDR_2_CAST(h_))->ttl
#define INF_REQ_2_EID_MASK(h_) (INF_REQ_HDR_2_CAST(h_))->eid_mask_len



uint8_t is_mrsignaling(address_hdr_t *addr);
mrsignaling_flags_t mrsignaling_flags(address_hdr_t *addr);
void mrsignaling_set_flags_in_pkt(uint8_t *offset, mrsignaling_flags_t *mrsig);



#endif /* LISP_MESSAGES_H_ */
