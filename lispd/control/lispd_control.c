/*
 * lispd_control.c
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
 * Written or modified by:
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#include "lispd_control.h"
#include <lispd_external.h>
#include "lispd_info_nat.h"
#include <lbuf.h>
#include <cksum.h>

/*
 *  Process a LISP protocol message sitting on
 *  socket s with address family afi
 */
int process_lisp_ctr_msg(struct sock *sl) {

//    uint8_t             packet[MAX_IP_PACKET];
//    lisp_addr_t         local_rloc;
//    uint16_t            remote_port;
    lisp_msg *msg;
    udpsock_t udpsock;
    struct lbuf *packet;
    uint8_t type;

    udpsock.dst_port = LISP_CONTROL_PORT;

    packet = lbuf_new(MAX_IP_PKT_LEN);
    if (get_packet_and_socket_inf(sl->fd, packet, &udpsock) != GOOD) {
        lmlog(LISP_LOG_DEBUG_1, "Couldn't retrieve socket information"
                "for control message! Discarding packet!");
        return (BAD);
    }

    type = lisp_msg_parse_type(packet);

    /* ==================================================== */
    /* FC: should be moved in xtr once process_info_nat_msg is updated to work with lisp_msg */
    if (type == LISP_INFO_NAT) {
        lmlog(LISP_LOG_DEBUG_1,
                "Received a LISP Info-Request/Info-Reply message");
        if (!process_info_nat_msg(packet->data, udpsock.dst)) {
            return (BAD);
        }
        return (GOOD);
    }
    /* ===================================================  */

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (lisp_msg_ecm_decap(packet, &(udpsock.src_port)) != GOOD)
            return (BAD);
    }

//    msg = lisp_msg_parse(packet);
//    if (!msg || !msg->msg) {
//        lispd_log_msg(LISP_LOG_DEBUG_2,
//                "Couldn't parse control message. Discarding ...");
//        return (BAD);
//    }
//
//    if (msg->encapdata)
//        if (lisp_msg_ecm_decap(msg->encapdata,
//                &(udpsock.src_port)) != GOOD)
//            return (BAD);

    process_ctrl_msg(ctrl_dev, packet, &udpsock);
//    (*ctrl_dev->process_lisp_ctrl_msg)(msg, &local_rloc, remote_port);

//    lisp_msg_del(msg);
    lbuf_del(packet);

    return (GOOD);
}

/*
 * Multicast Interface to end-hosts
 */

void multicast_join_channel(lisp_addr_t *src, lisp_addr_t *grp) {
    lisp_addr_t *mceid = lisp_addr_build_mc(src, grp);
    re_join_channel(mceid);
    lisp_addr_del(mceid);
}

void multicast_leave_channel(lisp_addr_t *src, lisp_addr_t *grp) {
    lisp_addr_t *mceid = lisp_addr_build_mc(src, grp);
    re_leave_channel(mceid);
    lisp_addr_del(mceid);
}

