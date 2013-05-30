#pragma once

#include "lispd.h"

#include "lispd_info_nat.h"
#include "lispd_nat_lib.h"


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

int build_and_send_info_request(uint64_t nonce,
                                uint16_t key_type,
                                char *key,
                                uint32_t ttl,
                                uint8_t eid_mask_length,
                                lisp_addr_t *eid_prefix,
                                lisp_addr_t *src_addr,
                                unsigned int src_port,
                                lisp_addr_t *dst_addr,
                                unsigned int dst_port);
