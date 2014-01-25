#pragma once

#include <defs.h>
#include <lispd_iface_list.h>
#include <cksum.h>
#include "lispd_info_nat.h"


#define DEFAULT_INFO_REQUEST_TIMEOUT    10 

/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |Type=7 |R|            Reserved                                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Nonce . . .                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      . . . Nonce                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |              Key ID           |  Authentication Data Length   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ~                     Authentication Data                       ~
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                              TTL                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                          EID-prefix                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             AFI = 0           |   <Nothing Follows AFI=0>     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                LISP Info-Request Message Format

 */

/* NAT traversal Info-Request message
 * auth_data may be variable length in the future
 */

/* EID fixed part of an Info-Request message
 * variable length EID address follows
 */


/* LCAF part of an Info-Request message
 *
 */

typedef struct lispd_pkt_info_request_lcaf_t_ {
    uint16_t afi;
/*
    uint16_t lcaf_afi;
    uint8_t reserved1;
    uint8_t flags;
    uint8_t lcaf_type;
    uint8_t reserved2;
    uint16_t length;
*/ 
} PACKED lispd_pkt_info_request_lcaf_t;

int  build_and_send_info_request(
        lispd_map_server_list_t     *map_server,
        uint32_t                    ttl,
        uint8_t                     eid_mask_length,
        lisp_addr_t                 *eid_prefix,
        lispd_iface_elt             *src_iface,
        uint64_t                    *nonce);


/* Send initial Info Request message to know nat status*/
int initial_info_request_process();

/* Send Info Request */
int info_request(
        timer   *ttl_timer,
        void    *arg);


