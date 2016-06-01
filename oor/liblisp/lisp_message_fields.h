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

#ifndef LISP_MESSAGE_FIELDS_H_
#define LISP_MESSAGE_FIELDS_H_

//#include <defs.h>
#include "../lib/generic_list.h"
#include <stdint.h>

#include "../lib/mem_util.h"


/*
 * ADDRESS FIELD
 */

/* LISP AFI codes  */
typedef enum {
    LISP_AFI_NO_ADDR,
    LISP_AFI_IP,
    LISP_AFI_IPV6,
    LISP_AFI_LCAF = 16387
} lisp_afi_e;

/* LCAF types */
typedef enum {
    LCAF_NULL = 0,
    LCAF_AFI_LIST,
    LCAF_IID,
    LCAF_ASN,
    LCAF_APP_DATA,
    LCAF_GEO = 5,
    LCAF_OKEY,
    LCAF_NATT,
    LCAF_NONCE_LOC,
    LCAF_MCAST_INFO,
    LCAF_EXPL_LOC_PATH = 10,
    LCAF_SEC_KEY,
    LCAF_TUPLE,
    LCAF_RLE,
    LCAF_DATA_MODEL,
    LCAF_KEY_VALUE
} lcaf_type_e;

/*
 * LISP Canonical Address Format
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |           AFI = 16387         |    Rsvd1     |     Flags      |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |    Type       |     Rsvd2     |            Length             |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


typedef struct _lcaf_hdr_t {
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    len;
} __attribute__ ((__packed__)) lcaf_hdr_t;

/* AFI-list LCAF type */
typedef struct _lcaf_afi_list_hdr_t {
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    length;
} __attribute__ ((__packed__)) lcaf_afi_list_hdr_t;

#define LCAF_CAST(ptr_) ((lcaf_hdr_t *)(ptr_))
#define LCAF_TYPE(ptr_) LCAF_CAST((ptr_))->type
#define LCAF_AFI(ptr_) LCAF_CAST((ptr_))->afi

/* Instance ID
 * Only the low order 24 bits should be used
 * Using signed integer, negative value means "don't send LCAF/IID field"
 * resulting in a non-explicit default IID value of 0
 */

/*
 * Instance ID
 *
 *         0                   1                   2                   3
 *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |           AFI = 16387         |    Rsvd1      |    Flags      |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |   Type = 2    | IID mask-len  |             4 + n             |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |                         Instance ID                           |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *        |              AFI = x          |         Address  ...          |
 *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct lispd_pkt_lcaf_iid_t_ {
    uint32_t    iid;
    uint16_t    afi;
} __attribute__ ((__packed__)) lispd_pkt_lcaf_iid_t;

typedef struct _lcaf_iid_hdr_t{
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     mlen;
    uint16_t    len;
    uint32_t    iid;
} __attribute__ ((__packed__)) lcaf_iid_hdr_t;



/* Geo Coordinate LISP Canonical Address Format:
 *
 *      0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 5    |     Rsvd2     |            12 + n             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |N|     Latitude Degrees        |    Minutes    |    Seconds    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |E|     Longitude Degrees       |    Minutes    |    Seconds    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                            Altitude                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |         Address  ...          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct _lcaf_geo_hdr_t{
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    length;
#ifdef LITTLE_ENDIANS
    uint16_t    latitude_deg:15;
    uint16_t    latitude_dir:1;
#else
    uint16_t    latitude_dir:1;
    uint16_t    latitude_deg:15;
#endif
    uint8_t     latitude_min;
    uint8_t     latitude_sec;
#ifdef LITTLE_ENDIANS
    uint16_t    longitude_deg:15;
    uint16_t    longitude_dir:1;
#else
    uint16_t    longitude_dir:1;
    uint16_t    longitude_deg:15;
#endif
    uint8_t     longitude_min;
    uint8_t     longitude_sec;
    uint32_t    altitude;
} __attribute__ ((__packed__)) lcaf_geo_hdr_t;


/*
 *
 *  NAT-Traversal Canonical Address Format:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 7    |     Rsvd2     |             4 + n             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |       MS UDP Port Number      |      ETR UDP Port Number      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |  Global ETR RLOC Address  ... |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |       MS RLOC Address  ...    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          | Private ETR RLOC Address  ... |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |      RTR RLOC Address 1 ...   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |      RTR RLOC Address k ...   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct _lcaf_nat_hdr_t{
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    length;
    uint16_t    ms_port;
    uint16_t    etr_port;
} __attribute__ ((__packed__)) lcaf_nat_hdr_t;

#define NAT_CAST(ptr_)((lcaf_nat_hdr_t *)(ptr_))
#define NAT_LEN(ptr_) NAT_CAST((ptr_))->length
#define NAT_MS_PORT(ptr_) NAT_CAST((ptr_))->ms_port
#define NAT_ETR_PORT(ptr_) NAT_CAST((ptr_))->etr_port


/*   Multicast Info Canonical Address Format:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 9    |  Rsvd2  |R|L|J|             8 + n             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Instance-ID                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Reserved           | Source MaskLen| Group MaskLen |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |   Source/Subnet Address  ...  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |       Group Address  ...      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct _lcaf_mcinfo_hdr_t{
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
#ifdef LITTLE_ENDIANS
    uint8_t     J:1;
    uint8_t     L:1;
    uint8_t     R:1;
    uint8_t     rsvd2:5;
#else
    uint8_t     rsvd2:5;
    uint8_t     R:1;
    uint8_t     L:1;
    uint8_t     J:1;
#endif
    uint16_t    len;
    uint32_t    iid;
    uint16_t    reserved;
    uint8_t     src_mlen;
    uint8_t     grp_mlen;
} __attribute__ ((__packed__)) lcaf_mcinfo_hdr_t;

typedef struct mrsignaling_flags_t_ {
    uint8_t rbit;
    uint8_t jbit;
    uint8_t lbit;
} mrsignaling_flags_t;

#define MCINFO_CAST(ptr_)((lcaf_mcinfo_hdr_t *)(ptr_))
#define MCINFO_RBIT(ptr_) MCINFO_CAST((ptr_))->R
#define MCINFO_LBIT(ptr_) MCINFO_CAST((ptr_))->L
#define MCINFO_JBIT(ptr_) MCINFO_CAST((ptr_))->J


/* Explicit Locator Path (ELP)
 *
 *      0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 10   |     Rsvd2     |               n               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Rsvd3         |L|P|S|              AFI = x          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Reencap Hop 1  ...                    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           Rsvd3         |L|P|S|              AFI = x          |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Reencap Hop k  ...                    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */


typedef struct _elp_node_flags {
    uint8_t rsvd1;
#ifdef LITTLE_ENDIANS
    uint8_t S:1;
    uint8_t P:1;
    uint8_t L:1;
    uint8_t rsvd2:5;
#else
    uint8_t rsvd2:5;
    uint8_t L:1;
    uint8_t P:1;
    uint8_t S:1;
#endif
} elp_node_flags;

#define ELP_NODE_CAST(ptr_)((elp_node_flags *)(ptr_))
#define ELP_NODE_LBIT(ptr_) ELP_NODE_CAST((ptr_))->L
#define ELP_NODE_PBIT(ptr_) ELP_NODE_CAST((ptr_))->P
#define ELP_NODE_SBIT(ptr_) ELP_NODE_CAST((ptr_))->S



/* Replication List Entry Address Format:
*
*   0                   1                   2                   3
*   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*  |           AFI = 16387         |     Rsvd1     |     Flags     |
*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*  |   Type = 13   |    Rsvd2      |             4 + n             |
*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*  |              Rsvd3            |     Rsvd4     |  Level Value  |
*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*  |              AFI = x          |           RTR/ETR #1 ...      |
*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*  |              Rsvd3            |     Rsvd4     |  Level Value  |
*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*  |              AFI = x          |           RTR/ETR  #n ...     |
*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct _rle_node_hdr {
    uint8_t rsvd[3];
    uint8_t level;
} rle_node_hdr_t;


typedef struct _address_hdr_t {
    uint16_t afi;
} address_hdr_t;


/*
 * LOCATOR FIELD
 */


/*
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *   c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \|                            Locator                            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Fixed portion of the mapping record locator. Variable length
 * locator address follows.
 */
typedef struct _locator_hdr {
    uint8_t priority;
    uint8_t weight;
    uint8_t mpriority;
    uint8_t mweight;
    uint8_t unused1;
#ifdef LITTLE_ENDIANS
    uint8_t reachable:1;
    uint8_t probed:1;
    uint8_t local:1;
    uint8_t unused2:5;
#else
    uint8_t unused2:5;
    uint8_t local:1;
    uint8_t probed:1;
    uint8_t reachable:1;
#endif
} __attribute__ ((__packed__)) locator_hdr_t;

#define LOC_CAST(h_) ((locator_hdr_t *)(h_))
#define LOC_PROBED(h_) LOC_CAST(h_)->probed
#define LOC_PRIORITY(h_) LOC_CAST(h_)->priority
#define LOC_WEIGHT(h_) LOC_CAST(h_)->weight
#define LOC_MPRIORITY(h_) LOC_CAST(h_)->mpriority
#define LOC_MWEIGHT(h_) LOC_CAST(h_)->mweight
#define LOC_REACHABLE(h_) LOC_CAST(h_)->reachable
#define LOC_LOCAL(h_) LOC_CAST(h_)->local
#define LOC_ADDR(h_) ((uint8_t *)(h_)  + sizeof(locator_hdr_t))


/*
 * MAPPING RECORD
 */


/*
 * Mapping record used in all LISP control messages.
 *
 *  +--->  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      |                          Record  TTL                          |
 *  |      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  R      | Locator Count | EID mask-len  | ACT |A|       Reserved        |
 *  e      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  c      | Rsvd  |  Map-Version Number   |            EID-AFI            |
 *  o      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  r      |                          EID-prefix                           |
 *  d      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *  |    / +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Loc |         Unused Flags    |L|p|R|           Loc-AFI             |
 *  |    \ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     \|                             Locator                           |
 *  +--->  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Fixed portion of the mapping record. EID prefix address and
 * locators follow.
 */

typedef struct _mapping_record_hdr_t {
    uint32_t ttl;
    uint8_t locator_count;
    uint8_t eid_prefix_length;
#ifdef LITTLE_ENDIANS
    uint8_t reserved1:4;
    uint8_t authoritative:1;
    uint8_t action:3;
#else
    uint8_t action:3;
    uint8_t authoritative:1;
    uint8_t reserved1:4;
#endif
    uint8_t reserved2;
#ifdef LITTLE_ENDIANS
    uint8_t version_hi:4;
    uint8_t reserved3:4;
#else
    uint8_t reserved3:4;
    uint8_t version_hi:4;
#endif
    uint8_t version_low;
} __attribute__ ((__packed__)) mapping_record_hdr_t;


void mapping_record_init_hdr(mapping_record_hdr_t *h);
char *mapping_action_to_char(int act);
char *mapping_record_hdr_to_char(mapping_record_hdr_t *h);

#define MAP_REC_EID_PLEN(h) ((mapping_record_hdr_t *)(h))->eid_prefix_length
#define MAP_REC_LOC_COUNT(h) ((mapping_record_hdr_t *)(h))->locator_count
#define MAP_REC_ACTION(h) ((mapping_record_hdr_t *)(h))->action
#define MAP_REC_AUTH(h) ((mapping_record_hdr_t *)(h))->authoritative
#define MAP_REC_TTL(h) ((mapping_record_hdr_t *)(h))->ttl
#define MAP_REC_EID(h) (uint8_t *)(h)+sizeof(mapping_record_hdr_t)
#define MAP_REC_VERSION(h) (h)->version_hi << 8 | (h)->version_low

typedef enum lisp_actions {
    ACT_NO_ACTION = 0,
    ACT_NATIVE_FWD,
    ACT_SEND_MREQ,
    ACT_DROP
} lisp_action_e;

typedef enum lisp_authoritative {
    A_NO_AUTHORITATIVE = 0,
    A_AUTHORITATIVE
} lisp_authoritative_e;

/*
 * EID RECORD FIELD
 */

/*
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    / |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
 *  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    \ |                       EID-prefix  ...                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


typedef struct _eid_prefix_record_hdr {
    uint8_t reserved;
    uint8_t eid_prefix_length;
} __attribute__ ((__packed__)) eid_record_hdr_t;

void eid_rec_hdr_init(eid_record_hdr_t *ptr);

#define EID_REC_CAST(h_) ((eid_record_hdr_t *)(h_))
#define EID_REC_MLEN(h_) EID_REC_CAST((h_))->eid_prefix_length
#define EID_REC_ADDR(h) (uint8_t *)(h) + sizeof(eid_record_hdr_t)


/*
 * AUTHENTICATION FIELD (Map-Register and Map-Notify)
 */

/*
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */


typedef struct auth_field_hdr {
    uint16_t key_id;
    uint16_t auth_data_len;
} __attribute__ ((__packed__)) auth_record_hdr_t;


typedef enum lisp_key_type {
    NO_KEY,
    HMAC_SHA_1_96,
    HMAC_SHA_256_128
} lisp_key_type_e;

#define LISP_SHA1_AUTH_DATA_LEN         20

uint16_t auth_data_get_len_for_type(lisp_key_type_e key_id);

#define AUTH_REC_CAST(h_) ((auth_record_hdr_t *)(h_))
#define AUTH_REC_KEY_ID(h_) AUTH_REC_CAST((h_))->key_id
#define AUTH_REC_DATA_LEN(h_) AUTH_REC_CAST((h_))->auth_data_len
#define AUTH_REC_DATA(h_) ((uint8_t *)(h_))+sizeof(auth_record_hdr_t)




/*
 * RTR AUTHENTICATION FIELD (Map-Register and Map-Notify)
 */

/*
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |AD Type|                   Reserved                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        MS-RTR Key ID          |  MS-RTR Auth. Data Length     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~               MS-RTR Authentication Data                      ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef enum rtr_auth_ad_type_ {
    RTR_AUTH_DATA = 2
} rtr_auth_data_type;


typedef struct _rtr_auth_field_hdr {
#ifdef LITTLE_ENDIANS
    uint16_t    reserved1;
    uint8_t     reserved2;
    uint8_t     reserved3:3;
    uint8_t     ad_type:5;
#else
    uint8_t     ad_type:5;
    uint8_t     reserved3:3;
    uint8_t     reserved2;
    uint16_t    reserved1;
#endif
    uint16_t key_id;
    uint16_t rtr_auth_data_len;
} __attribute__ ((__packed__)) rtr_auth_field_hdr;


/* NAT MAP-REGISTER FIELDS */

typedef struct lispd_xTR_ID_{
    uint8_t byte[16];
} lisp_xtr_id;

typedef uint64_t lisp_site_id;

char *locator_record_hdr_to_char(locator_hdr_t *h);

#endif /* LISP_MESSAGE_FIELDS_H_ */
