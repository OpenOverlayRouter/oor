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

#ifndef DEFS_H_
#define DEFS_H_

#include <stdint.h>

typedef enum {
    ENCP_LISP,
    ENCP_VXLAN_GPE
}oor_encap_t;

typedef enum {
    xTR_MODE ,
    MS_MODE,
    RTR_MODE,
    MN_MODE,
    DDT_MODE,
    DDT_MR_MODE
} oor_dev_type_e;

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

typedef struct oor_ctrl_dev oor_ctrl_dev_t;
typedef struct oor_ctrl oor_ctrl_t;
typedef struct shash shash_t;
typedef struct fwd_info_ fwd_info_t;
typedef struct sockmstr sockmstr_t;
typedef struct htable_ptrs htable_ptrs_t;
typedef struct data_plane_struct data_plane_struct_t;
typedef struct net_mgr_class net_mgr_class_t;

typedef struct htable_nonces_ htable_nonces_t;

/* Protocols constants related with timeouts */
#define OOR_INITIAL_MRQ_TIMEOUT       2  // Initial expiration timer for the first MRq
#define OOR_INITIAL_SMR_TIMEOUT       3  // Initial expiration timer for the first MRq SMR
#define OOR_INITIAL_MREG_TIMEOUT      3  // Initial expiration timer for the first Encapsulated Map Register
#define OOR_INITIAL_INF_REQ_TIMEOUT   3  // Initial expiration timer for the first info request
#define OOR_INF_REQ_HANDOVER_TIMEOUT  2  // Time before sending an info request after a handover
#define OOR_SLEEP_INF_REQ_TIMEOUT     60 // When no info reply received after x retries. Sleep for x seconds
#define OOR_SMR_TIMEOUT               4  // Time since interface status change until balancing arrays and SMR is done
#define OOR_MAX_MRQ_TIMEOUT           32 // Max expiration timer for the subsequent MRq
#define OOR_EXPIRE_TIMEOUT            1  // Time interval in which events are expired
#define OOR_MAX_MR_RETRANSMIT         2  // Maximum amount of Map Request retransmissions
#define OOR_MAX_SMR_RETRANSMIT        2  // Maximum amount of SMR MRq retransmissions
#define OOR_MAX_PROBE_RETRANSMIT      1  // Maximum amount of RLOC probe MRq retransmissions
#define OOR_MAX_RETRANSMITS           5  // Maximum amount of retransmits of a message
#define OOR_MIN_RETRANSMIT_INTERVAL   1  // Minimum time between retransmits of control messages
#define OOR_MS_RTR_TTL                1440 // TTL in minutes of a RTR list learned by an xTR


#define DEFAULT_MAP_REQUEST_RETRIES             3

#define MAP_REGISTER_INTERVAL                   60
#define MS_SITE_EXPIRATION                      180

#define RLOC_PROBING_INTERVAL                   30
#define DEFAULT_RLOC_PROBING_RETRIES            2
#define DEFAULT_RLOC_PROBING_RETRIES_INTERVAL   5   /* Interval in seconds between RLOC probing retries  */

#define DEFAULT_DATA_CACHE_TTL                  10
#define DEFAULT_SELECT_TIMEOUT                  1000/* ms */

#define FIELD_AFI_LEN                    2
#define FIELD_PORT_LEN                   2

/*
 * oor constants
 */

#define EVER            ;;
#define OOR_VERSION   "v1.2.1"
#define OOR           "oor"
#define PID_FILE      "/var/run/oor.pid"
#define DEVICE_ID_FILE "oor-id"


/*
 * ddt constants
 */

#define DEFAULT_DDTNODE_TTL  1440
#define DEFAULT_REGISTERED_TTL  1440
#define DEFAULT_CONFIGURED_NOT_REGISTERED_TTL  1
#define DEFAULT_NEGATIVE_REFERRAL_TTL  15

/*
 * ms constants
 */
#define DEFAULT_NOT_EID_TTL  15
#define DEFAULT_NOT_REG_EID_TTL  1


/*
 *  misc parameters
 */

#define IP6VERSION      6   /* what's the symbol? */
#define PACKED          __attribute__ ((__packed__))
#define uchar           u_char

#define UPDATED             2
#define GOOD                1
#define BAD                 0
#define ERR_SRC_ADDR        -1
#define ERR_AFI             -2
#define ERR_DB              -3
#define ERR_MALLOC          -4
#define ERR_EXIST           -5
#define ERR_NO_EXIST        -6
#define ERR_CTR_IFACE       -7
#define ERR_NOT_ENCAP       -8
#define ERR_SOCKET          -9
#define ERR_NO_ROUTE        -10
#define ERR_NO_REPLY        -99

#define TRUE                1
#define FALSE               0
#define UP                  1
#define DOWN                0
#define UNKNOWN            -1
#define ADD                 1
#define RM                  0

#define NO_AFI_SUPPOT   0
#define IPv4_SUPPORT    1
#define IPv6_SUPPORT    2


#define FULL_IPv4_ADDRESS_SPACE  "0.0.0.0/0"
#define FULL_IPv6_ADDRESS_SPACE  "::/0"

/***** NAT status *******/
//#define UNKNOWN          -1
#define NO_NAT              0
#define PARTIAL_NAT         1
#define FULL_NAT            2


typedef enum {
    NAT_PREV_DRAFT_4,
    NAT_AFTER_DRAFT_4,
}nat_version;

typedef enum {
    SCOPE_GLOBAL,
    SCOPE_SITE_LOCAL,
    SCOPE_LINK_LOCAL
} ipv6_scope_e;




/* Use the nonce to calculate the source port for a map request
 * message. */
#define LISP_PKT_MAP_REQUEST_UDP_SPORT(Nonce) (0xf000 | (Nonce & 0xfff))
#define LISP_PKT_MAP_REQUEST_TTL 32
#define LISP_PKT_MAP_REQUEST_MAX_ITR_RLOCS 31

#endif /* DEFS_H_ */
