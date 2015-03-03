/*
 * defs.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
 * All rights reserved.
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

#include <stdint.h>

typedef struct lisp_ctrl_dev lisp_ctrl_dev_t;
typedef struct lisp_ctrl lisp_ctrl_t;
typedef struct htable shash_t;
typedef struct fwd_entry fwd_entry_t;
typedef struct sockmstr sockmstr_t;

/* Protocols constants related with timeouts */
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


#define DEFAULT_MAP_REQUEST_RETRIES             3
#define DEFAULT_MAP_REGISTER_TIMEOUT            10

//#define MAP_REGISTER_INTERVAL                   60  /* LJ: sets the interval at which periodic
//                                                     * map register messages are sent (seconds).
//                                                     * The spec recommends 1 minute
//                                                     */
//#define RLOC_PROBING_INTERVAL                   30  /* LJ: sets the interval at which periodic
//                                                     * RLOC probes are sent (seconds) */
#define MAP_REGISTER_INTERVAL                   60
#define MS_SITE_EXPIRATION                      180

#define RLOC_PROBING_INTERVAL                   30
#define DEFAULT_RLOC_PROBING_RETRIES            2
#define DEFAULT_RLOC_PROBING_RETRIES_INTERVAL   5   /* Interval in seconds between RLOC probing retries  */

#define DEFAULT_DATA_CACHE_TTL                  60  /* seconds */
#define DEFAULT_SELECT_TIMEOUT                  1000/* ms */

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


/*
 * Structure to simplify netlink processing
 */
typedef struct nlsock_handle
{
    int         fd;       // netlink socket fd
    uint32_t    seq;      // netlink message seq number
} nlsock_handle;




/* Use the nonce to calculate the source port for a map request
 * message. */
#define LISP_PKT_MAP_REQUEST_UDP_SPORT(Nonce) (0xf000 | (Nonce & 0xfff))
#define LISP_PKT_MAP_REQUEST_TTL 32
#define LISP_PKT_MAP_REQUEST_MAX_ITR_RLOCS 31

#endif /* DEFS_H_ */
