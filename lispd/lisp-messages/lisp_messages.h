/*
 * lisp_messages.h
 *
 * This file is part of LISP Mobile Node Implementation.
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
 */

#ifndef LISP_MESSAGES_H_
#define LISP_MESSAGES_H_

#include <stdlib.h>
#include "lisp_message_fields.h"
#include "lisp_map_reply.h"
#include "lisp_map_request.h"
#include "lisp_map_register.h"
#include "lisp_map_notify.h"
#include <defs.h>

/*
 * LISP Types
 */

//#define LISP_MAP_REQUEST                1
//#define LISP_MAP_REPLY                  2
//#define LISP_MAP_REGISTER               3
//#define LISP_MAP_NOTIFY                 4
//#define LISP_INFO_NAT                   7
//#define LISP_ENCAP_CONTROL_TYPE         8


typedef enum {
    LISP_MAP_REQUEST = 1,
    LISP_MAP_REPLY,
    LISP_MAP_REGISTER,
    LISP_MAP_NOTIFY,
    LISP_INFO_NAT = 7,
    LISP_ENCAP_CONTROL_TYPE
} lisp_msg_types;

/*
 * Encapsulated Control Message Format
 */

/*
*     0                   1                   2                   3
*     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   / |                       IPv4 or IPv6 Header                     |
* OH  |                      (uses RLOC addresses)                    |
*   \ |                                                               |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   / |       Source Port = xxxx      |       Dest Port = 4342        |
* UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   \ |           UDP Length          |        UDP Checksum           |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* LH  |Type=8 |S|                  Reserved                           |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   / |                       IPv4 or IPv6 Header                     |
* IH  |                  (uses RLOC or EID addresses)                 |
*   \ |                                                               |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   / |       Source Port = xxxx      |       Dest Port = yyyy        |
* UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*   \ |           UDP Length          |        UDP Checksum           |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* LCM |                      LISP Control Message                     |
*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct _lisp_encap_data {
    uint8_t         *data;
    uint8_t         *iph;
    uint8_t         ip_afi;
    int             ip_header_len;
    struct udphdr   *udph;
    int             udp_len;
    int             len;
} lisp_encap_data;


typedef struct _lisp_msg {
    uint8_t         encap;
    lisp_encap_data *encapdata;
    lisp_msg_types  type;
    void            *msg;
} lisp_msg;



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



lisp_msg *lisp_msg_parse(uint8_t *offset);
void lisp_msg_del(lisp_msg *msg);
lisp_encap_data *lisp_encap_hdr_parse(uint8_t *packet);
void lisp_encap_hdr_del(lisp_encap_data *data);

static inline int lisp_encap_data_get_len(lisp_encap_data *data) {
    return(data->len);
}

#endif /* LISP_MESSAGES_H_ */
