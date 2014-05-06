/*
 * lispd_defs.h
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

#ifndef DEFS_H_
#define DEFS_H_

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <endian.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <sys/select.h>

#include "lispd_log.h"
#include "util.h"
//#include "lispd_external.h"



/*
 *  Protocols constants related with timeouts
 *
 */

#define LISPD_INITIAL_MRQ_TIMEOUT       2  // Initial expiration timer for the first MRq
#define LISPD_INITIAL_SMR_TIMEOUT       3  // Initial expiration timer for the first MRq SMR
#define LISPD_INITIAL_PROBE_TIMEOUT     3  // Initial expiration timer for the first MRq RLOC probe
#define LISPD_INITIAL_EMR_TIMEOUT       3  // Initial expiration timer for the first Encapsulated Map Register
#define LISPD_SMR_TIMEOUT               6  // Time since interface status change until balancing arrays and SMR is done
#define LISPD_MAX_MRQ_TIMEOUT           32 // Max expiration timer for the subsequent MRq
#define LISPD_EXPIRE_TIMEOUT            1  // Time interval in which events are expired
#define LISPD_MAX_MR_RETRANSMIT         2  // Maximum amount of Map Request retransmissions
#define LISPD_MAX_SMR_RETRANSMIT        2  // Maximum amount of SMR MRq retransmissions
#define LISPD_MAX_PROBE_RETRANSMIT      1  // Maximum amount of RLOC probe MRq retransmissions
#define LISPD_MAX_RETRANSMITS           5  // Maximum amount of retransmits of a message
#define LISPD_MIN_RETRANSMIT_INTERVAL   1  // Minimum time between retransmits of control messages

/*
 *  Determine endianness
 */

#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
#define BIG_ENDIANS  2
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
#define LITTLE_ENDIANS 1
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN
#define BIG_ENDIANS  2
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN
#define LITTLE_ENDIANS 1
#elif defined(BYTE_ORDR) && BYTE_ORDER == BIG_ENDIAN
#define BIG_ENDIANS  2
#elif defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN
#define LITTLE_ENDIANS 1
#elif defined(__386__)
#define LITTLE_ENDIANS 1
#else
# error "Can't determine endianness"
#endif



#define FIELD_AFI_LEN                    2
#define FIELD_PORT_LEN                   2




/*
 *  lispd constants
 */

#define EVER            ;;
#define LISPD           "lispd"
#define PID_FILE        "/var/run/lispd.pid"

/*
 *  misc parameters
 */

#define IP6VERSION      6   /* what's the symbol? */
#define PACKED          __attribute__ ((__packed__))
#define uchar           u_char

int err;
#define GOOD                1
#define BAD                 0
#define ERR_SRC_ADDR        -1
#define ERR_AFI             -2
#define ERR_DB              -3
#define ERR_MALLOC          -4
#define ERR_EXIST           -5
#define ERR_NO_EXIST        -6
#define ERR_CTR_IFACE       -7
#define ERR_NOT_LISP        -8

/***** Negative Map-Reply actions ***/
#define ACT_NO_ACTION           0
#define ACT_NATIVELY_FORWARD    1
#define ACT_SEND_MAP_REQUEST    2
#define ACT_DROP                3


#define TRUE                1
#define FALSE               0
#define UP                  1
#define DOWN                0
#define UNKNOWN            -1

/***** NAT status *******/
//#define UNKNOWN          -1
#define NO_NAT              0
#define PARTIAL_NAT         1
#define FULL_NAT            2


#define MAX_IP_PKT_LEN          4096
#define MAX_IP_HDR_LEN          40      /* without options or IPv6 hdr extensions */
#define UDP_HDR_LEN             8
#define LISP_DATA_HDR_LEN       8
#define LISP_ECM_HDR_LEN        4
#define MAX_LISP_MSG_ENCAP_LEN  2*(MAX_IP_HDR_LEN + UDP_HDR_LEN)+ LISP_ECM_HDR_LEN
#define MAX_LISP_PKT_ENCAP_LEN  MAX_IP_HDR_LEN + UDP_HDR_LEN + LISP_DATA_HDR_LEN


#define DEFAULT_MAP_REQUEST_RETRIES             3
#define DEFAULT_RLOC_PROBING_RETRIES            1
#define DEFAULT_MAP_REGISTER_TIMEOUT            10  /* PN: expected to be in minutes; however,
                                                     * lisp_mod treats this as seconds instead of
                                                     * minutes
                                                     */
//#define MAP_REGISTER_INTERVAL                   60  /* LJ: sets the interval at which periodic
//                                                     * map register messages are sent (seconds).
//                                                     * The spec recommends 1 minute
//                                                     */
//#define RLOC_PROBING_INTERVAL                   30  /* LJ: sets the interval at which periodic
//                                                     * RLOC probes are sent (seconds) */
#define MAP_REGISTER_INTERVAL                   6000
#define RLOC_PROBING_INTERVAL                   3000

#define DEFAULT_RLOC_PROBING_RETRIES_INTERVAL   5   /* Interval in seconds between RLOC probing retries  */
#define DEFAULT_DATA_CACHE_TTL                  60  /* seconds */
#define DEFAULT_SELECT_TIMEOUT                  1000/* ms */


#define LISP_CONTROL_PORT               4342
#define LISP_DATA_PORT                  4341


///*
// * Map register Key type
// */
//#define NO_KEY               0
//#define HMAC_SHA_1_96        1
//#define HMAC_SHA_256_128     2


#define MAX_PRIORITY 0
#define MIN_PRIORITY 254
#define UNUSED_RLOC_PRIORITY 255
#define MIN_WEIGHT 0
#define MAX_WEIGHT 255


/* LISP data packet header */

typedef struct lisphdr {
    #ifdef __LITTLE_ENDIAN_BITFIELD
    uint8_t rflags:3;
    uint8_t instance_id:1;
    uint8_t map_version:1;
    uint8_t echo_nonce:1;
    uint8_t lsb:1;
    uint8_t nonce_present:1;
    #else
    uint8_t nonce_present:1;
    uint8_t lsb:1;
    uint8_t echo_nonce:1;
    uint8_t map_version:1;
    uint8_t instance_id:1;
    uint8_t rflags:3;
    #endif
    uint8_t nonce[3];
    uint32_t lsb_bits;
} lisphdr_t;



typedef struct lispd_site_ID_
{
    uint8_t byte[8];

} lisp_site_ID;

typedef struct lispd_xTR_ID_
{
    uint8_t byte[16];

} lisp_xTR_ID;

/*
 *  for map-register auth data...
 */



/*
 * Structure to simplify netlink processing
 */
typedef struct nlsock_handle
{
    int         fd;       // netlink socket fd
    uint32_t    seq;      // netlink message seq number
} nlsock_handle;


//modified by arnatal for NATT
/*
 * LISP Data header structure
 */

typedef struct lisp_data_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t rflags:3;
    uint8_t instance_id:1;
    uint8_t map_version:1;
    uint8_t echo_nonce:1;
    uint8_t lsb:1;
    uint8_t nonce_present:1;
#else
    uint8_t nonce_present:1;
    uint8_t lsb:1;
    uint8_t echo_nonce:1;
    uint8_t map_version:1;
    uint8_t instance_id:1;
    uint8_t rflags:3;
#endif
    uint8_t nonce[3];
    uint32_t lsb_bits;
} lisp_data_hdr_t;

/*
 * Homeless (for now) variables and parameters
 */

/*
 * Fixed size portion of map request ITR RLOC.
 */
//typedef struct lispd_pkt_map_request_itr_rloc_t_ {
//    uint16_t afi;
//    /*    uint8_t address[0]; */
//} PACKED lispd_pkt_map_request_itr_rloc_t;


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




extern void exit_cleanup();

#endif /* DEFS_H_ */
