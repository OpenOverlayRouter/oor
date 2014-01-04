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

#include "lispd_log.h"



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
 *  CO --
 *
 *  Calculate Offset
 *
 *  Try not to make dumb mistakes with
 *  pointer arithmetic
 *
 */

#define CO(addr,len) (((uint8_t *) addr + len))


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


#define MAX_IP_PACKET       4096


#define DEFAULT_MAP_REQUEST_RETRIES             3
#define DEFAULT_RLOC_PROBING_RETRIES            1
#define DEFAULT_MAP_REGISTER_TIMEOUT            10  /* PN: expected to be in minutes; however,
                                                     * lisp_mod treats this as seconds instead of
                                                     * minutes
                                                     */
#define MAP_REGISTER_INTERVAL                   60  /* LJ: sets the interval at which periodic
                                                     * map register messages are sent (seconds).
                                                     * The spec recommends 1 minute
                                                     */
#define RLOC_PROBING_INTERVAL                   30  /* LJ: sets the interval at which periodic
                                                     * RLOC probes are sent (seconds) */
#define DEFAULT_RLOC_PROBING_RETRIES_INTERVAL   5   /* Interval in seconds between RLOC probing retries  */
#define DEFAULT_DATA_CACHE_TTL                  60  /* seconds */
#define DEFAULT_SELECT_TIMEOUT                  1000/* ms */


/*
 * LISP Types
 */

#define LISP_MAP_REQUEST                1
#define LISP_MAP_REPLY                  2
#define LISP_MAP_REGISTER               3
#define LISP_MAP_NOTIFY                 4
#define LISP_INFO_NAT                   7
#define LISP_ENCAP_CONTROL_TYPE         8
#define LISP_CONTROL_PORT               4342
#define LISP_DATA_PORT                  4341

/*
 *  locator_types
 */

#define STATIC_LOCATOR                  0
#define DYNAMIC_LOCATOR                 1
#define PETR_LOCATOR                    2
#define LOCAL_LOCATOR                   3




/*
 * Map register Key type
 */
#define NO_KEY               0
#define HMAC_SHA_1_96        1
#define HMAC_SHA_256_128     2


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

} lispd_site_ID;

typedef struct lispd_xTR_ID_
{
    uint8_t byte[16];

} lispd_xTR_ID;

/*
 *  for map-register auth data...
 */

#define LISP_SHA1_AUTH_DATA_LEN         20


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
    uint16_t locator_afi;
} PACKED lispd_pkt_mapping_record_locator_t;



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
} lisp_encap_control_hdr_t;




/*
 * Set/get-ers to various data structures
 */

/*
 * lisp_addr_t functions
 */
//extern inline lisp_addr_t       *lisp_addr_new();
//extern inline lisp_addr_t       *lisp_addr_new_ip();
//extern inline lisp_addr_t       *lisp_addr_new_ippref();
//extern inline lisp_addr_t       *lisp_addr_new_lcaf();
//extern inline lisp_addr_t       *lisp_addr_new_afi(uint8_t afi);
//extern inline void              lisp_addr_del(lisp_addr_t *laddr);
//extern inline lisp_afi_t        lisp_addr_get_afi(lisp_addr_t *addr);
//extern inline ip_addr_t         *lisp_addr_get_ip(lisp_addr_t *addr);
//extern inline ip_addr_t         *lisp_addr_get_ippref(lisp_addr_t *addr);
//extern inline mc_addr_t         *lisp_addr_get_mc(lisp_addr_t *addr);
//extern inline ip_afi_t          lisp_addr_get_ip_afi(lisp_addr_t *addr);
//extern inline lisp_addr_t       *lisp_addr_get_mc_src(lisp_addr_t *addr);
//extern inline lisp_addr_t       *lisp_addr_get_mc_grp(lisp_addr_t *addr);
//extern inline lcaf_addr_t       *lisp_addr_get_lcaf(lisp_addr_t *addr);
//extern inline uint16_t           lisp_addr_get_iana_afi(lisp_addr_t laddr);
//
//extern inline uint16_t          lisp_addr_get_plen(lisp_addr_t *laddr);
//extern inline uint32_t          lisp_addr_get_size_in_pkt(lisp_addr_t *laddr);
//extern char                     *lisp_addr_to_char(lisp_addr_t *addr);
//
//extern inline void              lisp_addr_set_afi(lisp_addr_t *addr, lisp_afi_t afi);
//extern inline void              lisp_addr_set_ip(lisp_addr_t *addr, ip_addr_t *ip);
//extern inline void              lisp_addr_copy(lisp_addr_t *dst, lisp_addr_t *src);
//extern inline uint32_t          lisp_addr_copy_to(void *dst, lisp_addr_t *src);
//extern inline int               lisp_addr_copy_to_pkt(void *offset, lisp_addr_t *laddr, uint8_t convert);
//extern inline int               lisp_addr_is_lcaf(lisp_addr_t *laddr);
//
//
///*
// * ip_addr_t functions
// */
//
//extern inline ip_addr_t         *ip_addr_new();
//inline void                     ip_addr_del(ip_addr_t *ip);
//extern inline ip_afi_t          ip_addr_get_afi(ip_addr_t *ipaddr);
//extern inline uint8_t           *ip_addr_get_addr(ip_addr_t *ipaddr);
//extern inline struct in_addr    *ip_addr_get_v4(ip_addr_t *ipaddr);
//extern inline struct in6_addr   *ip_addr_get_v6(ip_addr_t *ipaddr);
//extern inline uint8_t           ip_addr_get_size(ip_addr_t *ipaddr);
//extern inline uint8_t           ip_addr_get_size_in_pkt(ip_addr_t *ipaddr);
//extern inline uint8_t           ip_addr_afi_to_size(uint8_t afi);
//extern inline uint16_t          ip_addr_get_iana_afi(ip_addr_t *ipaddr);
//extern inline void              ip_addr_set_afi(ip_addr_t *ipaddr, lisp_afi_t afi);
//extern inline void              ip_addr_set_v4(ip_addr_t *ipaddr, void *src);
//extern inline void              ip_addr_set_v6(ip_addr_t *ipaddr, void *src);
//extern inline void              ip_addr_copy(ip_addr_t *dst, ip_addr_t *src);
//extern inline void              ip_addr_copy_to(void *dst, ip_addr_t *src);
//extern inline uint8_t           *ip_addr_copy_to_pkt(void *dst, ip_addr_t *src, uint8_t convert);
//extern inline int               ip_addr_read_from_pkt(void *offset, uint16_t afi, ip_addr_t *dst);
//extern inline int               ip_addr_cmp(ip_addr_t *ip1, ip_addr_t *ip2);
//extern inline uint16_t          ip_afi_to_iana_afi(uint16_t afi);
//extern char                     *ip_addr_to_char (ip_addr_t *addr);
//
//
//
///*
// * ip_prefix_t functions
// */
//extern inline void              ip_prefix_get_plen(ip_prefix_t *pref);
//extern inline ip_addr_t         *ip_prefix_get_addr(ip_prefix_t *pref);
//extern inline uint8_t           ip_prefix_get_afi(ip_prefix_t *pref);
//extern inline void              ip_prefix_set(ip_prefix_t *pref, ip_addr_t *ipaddr, uint8_t plen);
//extern inline void              ip_prefix_set_plen(ip_prefix_t *pref, uint8_t plen);
//
//extern char                     *ip_prefix_to_char(ip_prefix_t *pref);
//
//
//
//
//
///*
// * lispd_map_cache_entry  functions
// */
//
//extern inline void                  mcache_entry_set_eid_addr(lispd_map_cache_entry *mapcache, lisp_addr_t *addr);
//extern inline void                  mcache_entry_set_eid_plen(lispd_map_cache_entry *mapcache, uint8_t plen);
//extern inline lispd_mapping_elt     *mcache_entry_get_mapping(lispd_map_cache_entry* mapcache);
//extern inline lisp_addr_t           *mcache_entry_get_eid_addr(lispd_map_cache_entry* mapcache);
//extern inline nonces_list           *mcache_entry_get_nonces_list(lispd_map_cache_entry *mce);
//
//
//
//
///*
// * other
// */
//extern inline uint8_t               ip_addr_is_multicast(ip_addr_t addr);
//extern inline uint8_t               ipv4_addr_is_multicast(struct in_addr *addr);
//extern inline uint8_t               ipv6_addr_is_multicast(struct in6_addr *addr);
//extern inline uint8_t               tuple_get_dst_lisp_addr(packet_tuple tuple, lisp_addr_t *addr);
//
//
///*
// * mc_addr_t functions
// */
//
//extern inline mc_addr_t         *mc_addr_new();
//extern inline void              mc_addr_del(void *mcaddr);
//extern inline mc_addr_t         *mc_addr_init(ip_addr_t *src, ip_addr_t *grp, uint8_t splen, uint8_t gplen, uint32_t iid);
//extern inline void              mc_addr_set_src(mc_addr_t *mc, ip_addr_t *ip);
//extern inline void              mc_addr_set_grp(mc_addr_t *mc, ip_addr_t *ip);
//extern inline lisp_addr_t       *mc_addr_get_src(mc_addr_t *mc);
//extern inline lisp_addr_t       *mc_addr_get_grp(mc_addr_t *mc);
//extern inline uint32_t          *mc_addr_get_iid(mc_addr_t *mc);
//extern inline uint8_t           mc_addr_get_src_plen(mc_addr_t *mc);
//extern inline uint8_t           mc_addr_get_grp_plen(mc_addr_t *mc);
//extern inline uint16_t          mc_addr_get_src_afi(mc_addr_t *mc);
//extern inline uint16_t          mc_addr_get_src_afi(mc_addr_t *mc);
//extern char                     *mc_addr_to_char (mc_addr_t *mcaddr);
//extern inline uint32_t          mc_addr_get_size_in_pkt(mc_addr_t *mc);
//extern inline uint8_t           *mc_addr_copy_to_pkt(void *offset, mc_addr_t *mc);
//extern inline void              mc_addr_copy(mc_addr_t *dst, mc_addr_t *src);
//extern inline void              mc_addr_set(mc_addr_t *dst, ip_addr_t *src, ip_addr_t *grp);
//extern int                      mc_addr_read_from_pkt(void *offset, mc_addr_t *mc);
//
//
///*
// * iid_addr_t functions
// */
//
//extern inline iid_addr_t        *iid_addr_new();
//extern inline uint8_t           iid_addr_get_mlen(iid_addr_t *addr);
//extern inline inline uint32_t   iid_addr_get_iidaddr(iid_addr_t *addr);
//
//extern inline void              iid_addr_set_iid(iid_addr_t *addr, uint32_t iid);
//extern inline void              iid_addr_set_mlen(iid_addr_t *addr, uint8_t mlen);
//extern inline int               iid_addr_cmp(iid_addr_t *iid1, iid_addr_t *iid2);
//extern inline uint32_t          iid_addr_get_size_in_pkt(iid_addr_t *iid);
//extern inline uint8_t           *iid_addr_copy_to_pkt(void *offset, iid_addr_t *iid);
//extern int                      iid_addr_read_from_pkt(void *offset, iid_addr_t *iid);
//
//
//
//
//
///*
// * geo_addr_t functions
// */
//extern inline void              geo_addr_set_lat(geo_addr_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
//extern inline void              geo_addr_set_long(geo_addr_t *geo, uint8_t dir, uint16_t deg, uint8_t min, uint8_t sec);
//extern inline void              geo_addr_set_altitude(geo_addr_t *geo, uint32_t altitude);
//extern int                      geo_addr_read_from_pkt(void *offset, geo_addr_t *geo);
//
//
///*
// * geo_addr_t functions
// */
//extern inline rle_addr_t        *rle_addr_new();
//extern inline void              rle_addr_del(rle_addr_t *rleaddr);

#endif /* DEFS_H_ */
