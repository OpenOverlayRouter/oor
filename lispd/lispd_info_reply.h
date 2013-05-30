#pragma once

#include "lispd.h"

#include "lispd_info_nat.h"
#include "lispd_nat_lib.h"


#define DEFAULT_INFO_REPLY_TIMEOUT      10


/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |Type=8 |              Reserved                                 |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Nonce . . .                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      . . . Nonce                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |            Key ID             |  Authentication Data Length   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       ~                     Authentication Data                       ~
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                              TTL                              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                          EID-prefix                           |
    +->+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  |           AFI = 16387         |    Rsvd1      |     Flags     |
    |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  |    Type = 7     |     Rsvd2   |             4 + n             |
    |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    N  |        MS UDP Port Number     |      ETR UDP Port Number      |
    A  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    T  |              AFI = x          | Global ETR RLOC Address  ...  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    L  |              AFI = x          |       MS RLOC Address  ...    |
    C  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    A  |              AFI = x          | Private ETR RLOC Address ...  |
    F  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  |              AFI = x          |      RTR RLOC Address 1 ...   |
    |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  |              AFI = x          |       RTR RLOC Address n ...  |
    +->+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                      LISP Info-Reply Message Format
 */

/* NAT traversal Info-Reply message
 * auth_data may be variable length in the future
 *
 * We use the same lispd_pkt_info_nat_t defined in the previous packet
 */

/* EID fixed part of a Info-Request message
 * variable length EID address follows
 *
 * We use the same lispd_pkt_eid_nat_t defined in the previous packet
 */

/* Fixed part of NAT LCAF.
 * Variable in number and length adresses follows
 */

typedef struct lispd_pkt_info_reply_lcaf_t_ {
    uint16_t lcaf_afi;
    uint8_t reserved1;
    uint8_t flags;
    uint8_t lcaf_type;
    uint8_t reserved2;
    uint16_t length;
    uint16_t ms_udp_port;
    uint16_t etr_udp_port;
} PACKED lispd_pkt_info_reply_lcaf_t;


int process_info_reply_msg(uint8_t *packet);