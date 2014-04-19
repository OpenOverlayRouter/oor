/*
 * lisp_message_fields.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
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
 * Written or modified by:
 *    Florin Coras  <fcoras@ac.upc.edu>
 *
 */

#ifndef LISP_MESSAGE_FIELDS_H_
#define LISP_MESSAGE_FIELDS_H_

#include <defs.h>
#include <generic_list.h>


/*
 * ADDRESS FIELD
 */


/*
 * LISP AFI codes
 */

typedef enum {
    LISP_AFI_NO_ADDR,
    LISP_AFI_IP,
    LISP_AFI_IPV6,
    LISP_AFI_LCAF = 16387
} lisp_afi_t;

/*
 * LCAF types
 */

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
} lcaf_type;

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

/*
 * AFI-list LCAF type
 */

typedef struct _lcaf_afi_list_hdr_t {
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    length;
} __attribute__ ((__packed__)) lcaf_afi_list_hdr_t;


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

typedef struct _address_field {
    uint16_t                len;
    uint8_t                 *data;
} address_field;

inline address_field *address_field_new();
inline void address_field_del(address_field *addr);
address_field           *address_field_parse(uint8_t *offset);


static inline uint16_t address_field_len(address_field *addr) {
    return(addr->len);
}

static inline uint8_t *address_field_data(address_field *addr) {
    return(addr->data);
}

static inline uint8_t address_field_lcaf_type(address_hdr_t *addr) {
    return(((lcaf_hdr_t *)addr)->type);
}

static inline uint16_t address_field_afi(address_hdr_t *addr) {
    return(ntohs(*(uint16_t *)addr->afi));
}

static inline void address_field_set_len(address_field *addr, int len) {
    addr->len = len;
}








/*
 * locator
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


typedef struct _locator_field {
    address_field           *address;
    uint16_t                len;
    uint8_t                 *data;
} locator_field;

inline locator_field *locator_field_new();
inline void locator_field_del(locator_field *locator);
locator_field *locator_field_parse(uint8_t *offset);

static inline locator_hdr_t *locator_field_hdr(locator_field *locator) {
    return((locator_hdr_t *)locator->data);
}

static inline uint8_t *locator_field_addr_ptr(locator_field *locator) {
    return(CO(locator->data, sizeof(locator_hdr_t)));
}

static inline uint16_t locator_field_len(locator_field *locator) {
    return(sizeof(locator_hdr_t) + address_field_len(locator->address));
}

static inline address_field *locator_field_addr(locator_field *locator) {
    return(locator->address);
}

static inline void locator_field_set_data(locator_field *locator, uint8_t *data) {
    locator->data = data;
}

static inline void locator_field_set_len(locator_field *locator, int len) {
    locator->len = len;
}

/* should be called after a write to update field len*/
static inline void locator_field_update_len(locator_field *locator) {
    locator->len = sizeof(locator_field_hdr)+address_field_len(locator->address);
}

#define LOC_PROBED(h) ((locator_hdr_t *)(h))->probed
#define LOC_PRIORITY(h) ((locator_hdr_t *)(h))->priority
#define LOC_WEIGHT(h) ((locator_hdr_t *)(h))->weight
#define LOC_MPRIORITY(h) ((locator_hdr_t *)(h))->mpriority
#define LOC_MWEIGHT(h) ((locator_hdr_t *)(h))->mweight
#define LOC_REACHABLE(h) ((locator_hdr_t *)(h))->reachable
#define LOC_LOCAL(h) ((locator_hdr_t *)(h))->local
#define LOC_ADDR(h) ((uint8_t *)(h)  + sizeof(locator_hdr_t))

/*
 * mapping record
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


typedef struct _mapping_record {
    address_field           *eid;
    glist_t                 *locators;
    uint16_t                len;
    uint8_t                 *data;
} mapping_record;

inline mapping_record *mapping_record_new();
void mapping_record_del(mapping_record *record);
mapping_record *mapping_record_parse(uint8_t *offset);
locator_field *mapping_record_allocate_locator(mapping_record *record, int size);

static inline mapping_record_hdr_t *mapping_record_hdr(mapping_record *record) {
    return((mapping_record_hdr_t *)record->data);
}

static inline uint8_t *mapping_record_data(mapping_record *record) {
    return(record->data);
}

static inline address_field *mapping_record_eid(mapping_record *record) {
    return(record->eid);
}

static inline uint16_t mapping_record_len(mapping_record *record) {
    return(record->len);
}

static inline glist_t *mapping_record_locators(mapping_record *record) {
    return(record->locators);
}

static inline void mapping_record_create_hdr(mapping_record *record) {
    if (record)
        record->data = calloc(1, sizeof(mapping_record_hdr_t));
}

static inline void mapping_record_add_eid(mapping_record *record, address_field *eid) {
    record->eid = eid;
}

static inline void mapping_record_set_data(mapping_record *record, uint8_t *data) {
    record->data = data;
}

static void mapping_record_init_hdr(mapping_record_hdr_t *h) {
    h->ttl                  = htonl(DEFAULT_MAP_REGISTER_TIMEOUT);
    h->locator_count        = 1;
    h->eid_prefix_length    = 0;
    h->action               = 0;
    h->authoritative        = 1;
    h->version_hi           = 0;
    h->version_low          = 0;

    h->reserved1 = 0;
    h->reserved2 = 0;
    h->reserved3 = 0;
}

#define MAP_REC_EID_PLEN(h) ((mapping_record_hdr_t *)(h))->eid_prefix_length
#define MAP_REC_LOC_COUNT(h) ((mapping_record_hdr_t *)(h))->locator_count
#define MAP_REC_ACTION(h) ((mapping_record_hdr_t *)(h))->action
#define MAP_REC_AUTH(h) ((mapping_record_hdr_t *)(h))->authoritative
#define MAP_REC_TTL(h) ((mapping_record_hdr_t *)(h))->action
#define MAP_REC_EID(h) (uint8_t *)(h)+sizeof(mapping_record_hdr_t)
#define MAP_REC_VERSION(h) (h)->version_hi << 8 | (h)->version_low


/*
 * EID record field
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

typedef struct _eid_prefix_record {
    uint8_t                     *data;
    address_field               *eid;
    uint16_t                    len;
} eid_prefix_record;

inline eid_prefix_record *eid_prefix_record_new();
void eid_prefix_record_del(eid_prefix_record *record);
eid_prefix_record *eid_prefix_record_parse(uint8_t *offset);
void eid_prefix_record_list_del(eid_prefix_record *record);



static inline eid_record_hdr_t *eid_prefix_record_get_hdr(eid_prefix_record *record) {
    return((eid_record_hdr_t*)record->data);
}

static inline uint8_t eid_prefix_record_get_mask_len(eid_prefix_record *record) {
    return(eid_prefix_record_get_hdr(record)->eid_prefix_length);
}

static inline address_field *eid_prefix_record_get_eid(eid_prefix_record *record) {
    return(record->eid);
}

static inline uint16_t eid_prefix_record_get_len(eid_prefix_record *record) {
    return(record->len);
}


#define EID_REC_ADDR(h) (uint8_t *)(h) + sizeof(eid_record_hdr_t)


/*
 * Authentication field (Map-Register and Map-Notify)
 */

/*
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */


typedef struct _auth_field_hdr {
    uint16_t key_id;
    uint16_t auth_data_len;
} auth_record_hdr_t;


typedef struct _auth_field {
    uint8_t     *auth_data;
    uint16_t    len;
    uint8_t     *data;
} auth_field;

typedef enum {
    NO_KEY,
    HMAC_SHA_1_96,
    HMAC_SHA_256_128
} lisp_key_type_t;

#define LISP_SHA1_AUTH_DATA_LEN         20

#define AUTH_REC_KEY_ID(h_) ((auth_record_hdr_t *)(h_))->key_id
#define AUTH_REC_DATA_LEN(h_) ((auth_record_hdr_t *)(h_))->auth_data_len
#define AUTH_REC_DATA(h_) (uint8_t *(h_))+sizeof(auth_record_hdr_t)


auth_field *auth_field_new();
auth_field *auth_field_parse(uint8_t *offset);
void auth_field_del(auth_field *raf);
uint16_t auth_data_get_len_for_type(lisp_key_type_t key_id);
int auth_data_fill(uint8_t *msg, int msg_len, lisp_key_type_t key_id, const char *key, uint8_t *md, uint32_t *md_len);


static inline uint8_t *auth_field_get_data(auth_field *af) {
    return(af->data);
}

static inline auth_record_hdr_t *auth_field_hdr(auth_field *af) {
    return((auth_record_hdr_t *)af->data);
}

static inline uint16_t auth_field_get_len(auth_field *af) {
    if (!af)
        return(0);
    return(af->len);
}

static inline uint8_t *auth_field_auth_data(auth_field *af) {
    return(af->auth_data);
}


static inline int auth_field_get_size_for_type(lisp_key_type_t keyid) {
    return(auth_data_get_len_for_type(keyid)+sizeof(auth_record_hdr_t));
}

static inline void auth_field_init(uint8_t *ptr, lisp_key_type_t keyid) {
    ((auth_record_hdr_t*)ptr)->key_id = htons(keyid);
    ((auth_record_hdr_t*)ptr)->auth_data_len = htons(auth_data_get_len_for_type(keyid));
    memset(CO(ptr, sizeof(auth_record_hdr_t)), 0, auth_data_get_len_for_type(keyid));
}

/*
 * RTR Authentication field (Map-Register and Map-Notify)
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

typedef enum {
    RTR_AUTH_DATA = 2
} rtr_auth_ad_type;


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
    uint16_t    reserved3;
#endif
    uint16_t key_id;
    uint16_t rtr_auth_data_len;
} rtr_auth_field_hdr;

typedef struct _rtr_auth_field {
    uint8_t     *bits;
    uint8_t     *rtr_auth_data;
    uint16_t    len;
} rtr_auth_field;

static inline uint8_t *rtr_auth_field_get_data(rtr_auth_field *raf) {
    return(raf->bits);
}
static inline rtr_auth_field_hdr *rtr_auth_field_get_hdr(rtr_auth_field *raf) {
    return((rtr_auth_field_hdr *)raf->bits);
}

static inline uint16_t rtr_auth_field_get_len(rtr_auth_field *raf) {
    return(raf->len);
}

static inline uint8_t *rtr_auth_field_get_auth_data(rtr_auth_field *raf) {
    return(raf->rtr_auth_data);
}

rtr_auth_field *rtr_auth_field_new();
rtr_auth_field *rtr_auth_field_parse(uint8_t *offset);
void rtr_auth_field_del(rtr_auth_field *raf);

#endif /* LISP_MESSAGE_FIELDS_H_ */
