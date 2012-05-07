/*
 * lispd.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Definitions for lispd.
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
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "lisp_ipc.h"
#include "patricia/patricia.h"

/*
 *  Protocols constants related with timeouts
 *
 */

#define LISPD_INITIAL_MRQ_TIMEOUT   1  // Initial expiration timer for the first MRq
#define LISPD_INITIAL_SMR_TIMEOUT   1  // Initial expiration timer for the first MRq SMR
#define LISPD_INITIAL_PROBE_TIMEOUT 1  // Initial expiration timer for the first MRq RLOC probe
#define LISPD_MAX_MRQ_TIMEOUT       32 // Max expiration timer for the subsequent MRq
#define LISPD_EXPIRE_TIMEOUT        1  // Time interval in which events are expired
#define LISPD_MAX_SMR_RETRANSMIT    2  // Maximum amount of SMR MRq retransmissions
#define LISPD_MAX_PROBE_RETRANSMIT  1  // Maximum amount of RLOC probe MRq retransmissions


/*
 *  CO --
 *
 *  Calculate Offset
 *
 *  Try not to make dumb mistakes with
 *  pointer arithmetic
 *
 */

#define CO(addr,len) (((char *) addr + len))


/*
 *  SA_LEN --
 *
 *  sockaddr length
 *
 */

#define SA_LEN(a) ((a == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

/*
 *  names for where the udp checksum goes
 */

#ifdef BSD
#define udpsum(x) x->uh_sum
#else
#define udpsum(x) x->check
#endif

/*
 *  lispd constants
 */

#define EVER            ;;
#define LISPD           "lispd"
#define PID_FILE        "/var/run/lispd.pid"
#define MAX_IP_PACKET   4096

/*
 *  misc parameters
 */

#define IP6VERSION      6   /* what's the symbol? */
#define PACKED          __attribute__ ((__packed__))
#define uchar           u_char

#define GOOD                1
#define BAD                 0
#define MAX_IP_PACKET       4096
#define MIN_EPHEMERAL_PORT  32768
#define MAX_EPHEMERAL_PORT  65535

#define DEFAULT_MAP_REQUEST_RETRIES     3
#define DEFAULT_MAP_REGISTER_TIMEOUT    10  /* PN: expected to be in minutes; however, 
                                             * lisp_mod treats this as seconds instead of
                                             * minutes
                                             */
#define MAP_REGISTER_INTERVAL           60  /* LJ: sets the interval at which periodic
                                             * map register messages are sent (seconds).
                                             * The spec recommends 1 minute
                                             */
#define RLOC_PROBING_INTERVAL           30  /* LJ: sets the interval at which periodic
                                             * RLOC probes are sent (seconds) */
#define DEFAULT_DATA_CACHE_TTL          60  /* seconds */
#define DEFAULT_SELECT_TIMEOUT          1000/* ms */

/*
 * LISP Types
 */

#define LISP_MAP_REQUEST                1
#define LISP_MAP_REPLY                  2
#define LISP_MAP_REGISTER               3
#define LISP_MAP_NOTIFY                 4
#define LISP_ENCAP_CONTROL_TYPE         8
#define LISP_CONTROL_PORT               4342

/*
 *  Map Reply action codes
 */

#define LISP_ACTION_NO_ACTION           0
#define LISP_ACTION_FORWARD             1
#define LISP_ACTION_DROP                2
#define LISP_ACTION_SEND_MAP_REQUEST    3


#define LISP_AFI_IP                     1
#define LISP_AFI_IPV6                   2
#define LISP_IP_MASK_LEN                32

/*
 *  locator_types
 */

#define STATIC_LOCATOR                  0
#define DYNAMIC_LOCATOR                 1
#define FQDN_LOCATOR                    2
#define PETR_LOCATOR                    3

/*
 *  map-cache entry types (how_learned)
 */

#define STATIC_MAP_CACHE_ENTRY          0
#define DYNAMIC_MAP_CACHE_ENTRY         1

/*
 *  for map-register auth data...
 */

#define LISP_SHA1_AUTH_DATA_LEN         20

/*
 * Netlink mcast groups lispd is interested in
 * for interface management
 */
#define LISPD_IFACE_NLMGRPS     (RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE) 
/* #define LISPD_IFACE_NLMGRPS     (RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR \
                                                | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE )
*/

/*
 * LISP-MN EID interface name(s)
 */
#define LISP_MN_EID_IFACE_NAME          "lmn0"

/*
 * Maximum length (in bytes) of an IP address
 */
#define MAX_INET_ADDRSTRLEN INET6_ADDRSTRLEN

//mportoles - have to think wether this is the appropriate place
/*
 *  base RT number to use in multihomed policy routing scenarios
 */
#define RT_TABLE_LISP_MN            5

/*
 *  lispd database entry
 */

typedef struct {
    lisp_addr_t     eid_prefix;
    uint16_t        eid_prefix_length;
    lisp_addr_t     locator;
    uint8_t         locator_type:2;
    uint8_t         reserved:6;
    char *          locator_name;
    uint8_t         priority;
    uint8_t         weight;
    uint8_t         mpriority;
    uint8_t         mweight;
} lispd_db_entry_t;

typedef struct {
    lisp_addr_t     eid_prefix;
    uint8_t         eid_prefix_length;
    lisp_addr_t     locator;
    char *          locator_name;
    uint8_t         locator_type:2;
    uint8_t         reserved:5;
    uint8_t         how_learned:1;  /* 1 --> static */
    uint8_t         priority;
    uint8_t         weight;
    uint8_t         mpriority;
    uint8_t         mweight;
    uint32_t        ttl;    
    uint8_t         actions;
} lispd_map_cache_entry_t;


/*
 *  lispd's local database
 */

typedef struct _lispd_database_t {
    lispd_db_entry_t            db_entry;
    struct _lispd_database_t    *next;
} lispd_database_t;

/*
 *  map-cache, static or otherwise
 */

typedef struct _lispd_map_cache_t {
    lispd_map_cache_entry_t     map_cache_entry;
    struct _lispd_map_cache_t   *next;
} lispd_map_cache_t;

/*
 *  generic list of addresses
 */

typedef struct _lispd_addr_list_t {
    lisp_addr_t                 *address;
    struct _lispd_addr_list_t   *next;
} lispd_addr_list_t;


typedef struct _lispd_map_server_list_t {
    lisp_addr_t                     *address;
    uint8_t                         key_type;
    char                            *key;
    uint8_t                         proxy_reply;
    uint8_t                         verify;
    struct _lispd_map_server_list_t *next;
} lispd_map_server_list_t;



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

typedef struct lispd_pkt_mapping_record_t_ {
    uint32_t ttl;
    uint8_t locator_count;
    uint8_t eid_prefix_length;
#ifdef LITTLE_ENDIAN
    uint8_t reserved1:4;
    uint8_t authoritative:1;
    uint8_t action:3;
#else
    uint8_t action:3;
    uint8_t authoritative:1;
    uint8_t reserved1:4;
#endif
    uint8_t reserved2;
#ifdef LITTLE_ENDIAN
    uint8_t version_hi:4;
    uint8_t reserved3:4;
#else
    uint8_t reserved3:4;
    uint8_t version_hi:4;
#endif
    uint8_t version_low;
    uint16_t eid_prefix_afi;
} PACKED lispd_pkt_mapping_record_t;



/*
 * Fixed portion of the mapping record locator. Variable length
 * locator address follows.
 */
typedef struct lispd_pkt_mapping_record_locator_t_ {
    uint8_t priority;
    uint8_t weight;
    uint8_t mpriority;
    uint8_t mweight;
    uint8_t unused1;
#ifdef LITTLE_ENDIAN
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
    uint16_t locator_afi;
} PACKED lispd_pkt_mapping_record_locator_t;

/*
 * Map-Registers have an authentication header before the UDP header.
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=3 |P|            Reserved               |M| Record Count  |
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
 *       |Type=3 |P|            Reserved               |M| Record Count  |
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

typedef struct lispd_pkt_map_register_t_ {
#ifdef LITTLE_ENDIAN
    uint8_t  reserved1:3;
    uint8_t  proxy_reply:1;
    uint8_t  lisp_type:4;
#else
    uint8_t  lisp_type:4;
    uint8_t  proxy_reply:1;
    uint8_t  reserved1:3;
#endif
    uint8_t reserved2;
#ifdef LITTLE_ENDIAN
    uint8_t map_notify:1;
    uint8_t reserved3:7;
#else
    uint8_t reserved3:7;
    uint8_t notify:1;
#endif
    uint8_t  record_count;
    uint64_t nonce;
    uint16_t key_id;
    uint16_t auth_data_len;
    uint8_t  auth_data[LISP_SHA1_AUTH_DATA_LEN];
} PACKED lispd_pkt_map_register_t;


/*
 * Map-Notify Message Format
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=4 |              Reserved                 | Record Count  |
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

typedef struct lispd_pkt_map_notify_t_ {
#ifdef LITTLE_ENDIAN
    uint8_t  reserved1:4;
    uint8_t  lisp_type:4;
#else
    uint8_t  lisp_type:4;
    uint8_t  reserved1:4;
#endif
    uint16_t reserved2;
    uint8_t  record_count;
    uint64_t nonce;
    uint16_t key_id;
    uint16_t auth_data_len;
    uint8_t  auth_data[LISP_SHA1_AUTH_DATA_LEN];
} PACKED lispd_pkt_map_notify_t;



/*
 *  new lisp database layout
 *
 *
 *  lispd_database {AF4_database,AF6_database}
 *    |
 *    | try_search_exact(AFn_database, AF_n, prefix/len);
 *    |
 *    v  
 * patricia_node_t   patricia_node_t ...   patricia_node_t
 *    |                  |                        |
 *    |  data            | data                   | data  data contains a 
 *    |                  |                        |       locator_chain_t
 *    |                  v                        v       per afi eid/n 
 *    v             tail                            
 * locator_chain_t--------------------------------------+   
 *    |                                                 |
 *    | head                                            |
 *    |                                                 |
 *    v                 next                      next  v
 *  locator_chain_elt_t ----> locator_chain_elt_t ----> .... 
 *    | |                     |                         |
 *    | | locator             |                         |
 *    | |                     |                         |
 *    | +--> locator_t        |                         |
 *    |                       |                         |
 *    | db_entry              | db_entry                | db_entry
 *    |                       |                         |
 *    v                       v                         v
 *  db_entry_t           db_entry_t                db_entry_t
 *
 *
 *
 */

typedef struct lispd_locator_chain_elt_t_ {
    lispd_db_entry_t                    *db_entry;
    char                                *locator_name;
    struct lispd_locator_chain_elt_t_   *next;
} lispd_locator_chain_elt_t;


typedef struct {                        /* chain per eid-prefix/len/afi */
    int         mrp_len;                /* map register packet length */
    uint32_t    timer;                  /* send map_register w timer expires */
    ushort      locator_count;          /* number of mappings, 1 locator/per */
    lisp_addr_t eid_prefix;             /* eid_prefix for this chain */
    uint8_t     eid_prefix_length;      /* eid_prefix_length for this chain */
    char        *eid_name;              /* eid in string format */
    uint8_t     has_dynamic_locators:1; /* append dynamic/fqdn to front */
    uint8_t     has_fqdn_locators:1;
    uint8_t     reserved:6; 
    lispd_locator_chain_elt_t *head;    /* first entry in chain */
    lispd_locator_chain_elt_t *tail;    /* last entry in chain */
} lispd_locator_chain_t;



/*
 * Encapsulated control message header. This is followed by the IP
 * header of the encapsulated LISP control message.
 *
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Type=8 |                   Reserved                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct lispd_pkt_encapsulated_control_t_ {
#ifdef LITTLE_ENDIAN
    uint8_t reserved1:4;
    uint8_t type:4;
#else
    uint8_t type:4;
    uint8_t reserved1:4;
#endif
    uint8_t reserved2[3];
} PACKED lispd_pkt_encapsulated_control_t;

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
 * Use the nonce to calculate the source port for a map request
 * message.
 */
#define LISP_PKT_MAP_REQUEST_UDP_SPORT(Nonce) (0xf000 | (Nonce & 0xfff))

#define LISP_PKT_MAP_REQUEST_TTL 32

/*
 * Fixed size portion of the map request. Variable size source EID
 * address, originating ITR RLOC AFIs and addresses and then map
 * request records follow.
 */
typedef struct lispd_pkt_map_request_t_ {
#ifdef LITTLE_ENDIAN
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
#ifdef LITTLE_ENDIAN
    uint8_t reserved1:6;
    uint8_t smr_invoked:1;
    uint8_t pitr:1;
#else
    uint8_t pitr:1;
    uint8_t smr_invoked:1;
    uint8_t reserved1:6;
#endif
#ifdef LITTLE_ENDIAN
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
 * The IRC value above is set to one less than the number of ITR-RLOC
 * fields (an IRC of zero means one ITR-RLOC). In 5 bits we can encode
 * the number 15 which means we can have up to 16 ITR-RLOCs.
 */
#define LISP_PKT_MAP_REQUEST_MAX_ITR_RLOCS 16

/*
 * Fixed size portion of map request ITR RLOC.
 */
typedef struct lispd_pkt_map_request_itr_rloc_t_ {
    uint16_t afi;
    /*    uint8_t address[0]; */
} PACKED lispd_pkt_map_request_itr_rloc_t;

/*
 * Fixed size portion of the map request record. Variable size EID
 * prefix address follows.
 */
typedef struct lispd_pkt_map_request_eid_prefix_record_t_ {
    uint8_t reserved;
    uint8_t eid_prefix_mask_length;
    uint16_t eid_prefix_afi;
} PACKED lispd_pkt_map_request_eid_prefix_record_t;


/*
 * Map-Reply Message Format
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |Type=2 |P|E|           Reserved                | Record Count  |
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
 * Use the nonce to calculate the source port for a map request
 * message.
 */

/*
 * Fixed size portion of the map reply.
 */
typedef struct lispd_pkt_map_reply_t_ {
#ifdef LITTLE_ENDIAN
    uint8_t reserved1:2;
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
} PACKED lispd_pkt_map_reply_t;


/*
 *  essentially the data cache
 */

// Modified by acabello
typedef struct datacache_elt_t_ {
    uint64_t                nonce;
    lisp_addr_t             dest;
    uint8_t                 local:1;        /* is this a database entry? */
    uint8_t                 ttl:7;
    lisp_addr_t             eid_prefix;
    uint8_t                 eid_prefix_length;
    uint8_t                 probe:1; /* Is RLOC-probe? */
    uint8_t                 smr_invoked:1; /* Is SMR-invoked? */
    uint8_t                 retries; /* Number of retries */
    uint8_t                 encap:1;
    uint16_t                timeout;
    struct timer_rec_t_     *timer;
    struct datacache_elt_t_ *next;
    struct datacache_elt_t_ *prev;
} datacache_elt_t;


/*
 * Ordered list of timers
 */

typedef struct timer_rec_t_ {
    struct timer_rec_t_ *next;
    struct timer_rec_t_ *prev;
    time_t timer;
    datacache_elt_t *elt;
}timer_rec_t;

typedef struct timer_datacache_t_ {
    timer_rec_t *head;
    timer_rec_t *tail;
    void (*callback)(datacache_elt_t*); // Callback function for expired nonces
} timer_datacache_t;

typedef struct datacache_t_ {
    datacache_elt_t *head;
    datacache_elt_t *tail;
    timer_datacache_t *timer_datacache;
} datacache_t;

/*
 * PN:
 * Data structures for interface management
 */

typedef struct _db_entry_list_elt {
    lispd_db_entry_t *db_entry;
    struct _db_entry_list_elt *next;
} db_entry_list_elt;

typedef struct {
    db_entry_list_elt   *head;
    db_entry_list_elt   *tail;
} db_entry_list;

/*
 * lispd tracks the AF4 and AF6 eid prefixes associated with 
 * each physical interface.
 * TODO: 
 * 1. Currently, lispd assumes single AF4/AF6 eid per iface.
 * Multiple EIDs are a possibility in the future.
 * 2. The impact of weight/priority fields (from lispd config file)
 * on multiple interfaces
 */
typedef struct _iface_list_elt {
    char            *iface_name;    // name of the physical interface
    char            *AF4_eid_prefix;// v4 eid associated with the iface
    char            *AF6_eid_prefix;// v6 eid associated with the iface
    db_entry_list   *AF4_locators;  // list of v4 locators
    db_entry_list   *AF6_locators;  // list of v6 locators
    int             ready;          // is the iface up and runing?
    int             weight;         // weight & priority associated with the
    int             priority;       // iface
    int rt_table_num;			// num of the routing table to use for policy routing
#ifdef LISPMOBMH
    int if_index;
#endif
    lisp_addr_t     gateway;        // gateway IP (v4/v6) for this iface
    struct _iface_list_elt *next;
} iface_list_elt;

/* 
 * Structure to track list of physical ifaces
 */
typedef struct {
    iface_list_elt *head;
    iface_list_elt *tail;
} iface_list;

/*
 * Structure to simplify netlink processing
 */
typedef struct nlsock_handle
{
    int         fd;       // netlink socket fd
    uint32_t    seq;      // netlink message seq number
} nlsock_handle;

/*
 * Structure to set Map Reply options
 */
typedef struct {
    uint8_t send_rec;       // send a Map Reply record as well
    uint8_t rloc_probe;     // set RLOC probe bit
    uint8_t echo_nonce;     // set Echo-nonce bit
} map_reply_opts;


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
