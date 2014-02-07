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
#include <llist/generic_list.h>

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
 * address
 */

typedef struct _generic_lcaf_hdr {
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    len;
} __attribute__ ((__packed__)) generic_lcaf_hdr;

typedef struct _address_field {
    uint16_t                afi;
    uint16_t                len;
    uint8_t                 *data;
} address_field;

inline address_field *address_field_new();
inline void address_field_del(address_field *addr);
address_field           *address_field_parse(uint8_t *offset);


static inline uint16_t address_field_get_len(address_field *addr) {
    return(addr->len);
}

static inline uint8_t *address_field_get_data(address_field *addr) {
    return(addr->data);
}

static inline uint8_t address_field_get_lcaf_type(address_field *addr) {
    return(((generic_lcaf_hdr *)address_field_get_data(addr))->type);
}

static inline uint16_t address_field_get_afi(address_field *addr) {
    return(ntohs(*(uint16_t *)addr->data));
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
} __attribute__ ((__packed__)) locator_hdr;

typedef struct _locator_field {
    uint16_t                len;
    uint8_t                 *data;
    address_field           *address;
} locator_field;

inline locator_field *locator_field_new();
inline void locator_field_del(locator_field *locator);
locator_field *locator_field_parse(uint8_t *offset);

static inline locator_hdr *locator_field_get_hdr(locator_field *locator) {
    return((locator_hdr *)locator->data);
}

static inline uint8_t *locator_field_get_afi_ptr(locator_field *locator) {
    return(CO(locator->data, sizeof(locator_hdr)));
}

static inline uint16_t locator_field_get_len(locator_field *locator) {
    return(locator->len);
}

static inline address_field *locator_field_get_addr(locator_field *locator) {
    return(locator->address);
}




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

typedef struct _mapping_record_hdr {
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
} __attribute__ ((__packed__)) mapping_record_hdr;


typedef struct _mapping_record {
    uint16_t                len;
    uint8_t                 *data;
    address_field           *eid;
    glist_t                 *locators;
} mapping_record;

inline mapping_record *mapping_record_new();
void mapping_record_del(mapping_record *record);
mapping_record *mapping_record_parse(uint8_t *offset);


static inline mapping_record_hdr *mapping_record_get_hdr(mapping_record *record) {
    return((mapping_record_hdr *)record->data);
}

static inline uint8_t *mapping_record_get_data(mapping_record *record) {
    return(record->data);
}

static inline address_field *mapping_record_get_eid(mapping_record *record) {
    return (record->eid);
}

static inline uint16_t mapping_record_get_len(mapping_record *record) {
    return(record->len);
}

static inline uint8_t mapping_record_get_eid_mask(mapping_record *record) {
    return(mapping_record_get_hdr(record)->eid_prefix_length);
}

static inline glist_t *mapping_record_get_locators(mapping_record *record) {
    return(record->locators);
}



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
} __attribute__ ((__packed__)) eid_prefix_record_hdr;

typedef struct _eid_prefix_record {
    uint8_t                     *data;
    address_field               *eid;
    uint16_t                    len;
} eid_prefix_record;

inline eid_prefix_record *eid_prefix_record_new();
void eid_prefix_record_del(eid_prefix_record *record);
eid_prefix_record *eid_prefix_record_parse(uint8_t *offset);
void eid_prefix_record_list_del(eid_prefix_record *record);



static inline eid_prefix_record_hdr *eid_prefix_record_get_hdr(eid_prefix_record *record) {
    return((eid_prefix_record_hdr*)record->data);
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
} auth_field_hdr;

typedef struct _auth_field {
    uint8_t     *bits;
    uint8_t     *auth_data;
    uint16_t    len;
} auth_field;

static inline uint8_t *auth_field_get_data(auth_field *af) {
    return(af->bits);
}
static inline auth_field_hdr *auth_field_get_hdr(auth_field *af) {
    return((auth_field_hdr *)af->bits);
}

static inline uint16_t auth_field_get_len(auth_field *af) {
    return(af->len);
}

static inline uint8_t *auth_field_get_auth_data(auth_field *af) {
    return(af->auth_data);
}

auth_field *auth_field_new();
auth_field *auth_field_parse(uint8_t *offset);
void auth_field_del(auth_field *raf);


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
