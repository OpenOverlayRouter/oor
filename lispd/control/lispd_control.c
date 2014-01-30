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
#include <lispd_sockets.h>
#include <lispd_external.h>

/*
 * Process encapsulated map request header:  lisp header and the interal IP and UDP header
 */

int process_lisp_msg_encapsulated_data(lisp_encap_data *data, uint16_t *dst_port){
    uint16_t    ipsum   = 0;
    uint16_t    udpsum  = 0;
    int         udp_len  = 0;

    lispd_log_msg(LISP_LOG_DEBUG_2, "Processing the encapsulation header");
    /* This should overwrite the external port (dst_port in map-reply = inner src_port in encap map-request) */
    *dst_port = ntohs(data->udph->source);

#ifdef BSD
    udp_len = ntohs(data->udph->uh_ulen);
    // sport   = ntohs(udph->uh_sport);
#else
    udp_len = ntohs(data->udph->len);
    // sport   = ntohs(udph->source);
#endif

    /*
     * Verify the checksums.
     */
    if (data->ip_afi == AF_INET) {
        ipsum = ip_checksum((uint16_t *)data->iph, data->ip_header_len);
        if (ipsum != 0) {
            lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_request_msg: Map-Request: IP checksum failed.");
        }
        if ((udpsum = udp_checksum(data->udph, udp_len, data->iph, data->ip_afi)) == -1) {
            return(BAD);
        }
        if (udpsum != 0) {
            lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_request_msg: Map-Request: UDP checksum failed.");
            return(BAD);
        }
    }

    //Pranathi: Added this
    if (data->ip_afi== AF_INET6) {

        if ((udpsum = udp_checksum(data->udph, udp_len, data->iph, data->ip_afi)) == -1) {
            return(BAD);
        }
        if (udpsum != 0) {
            lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_request_msg: Map-Request:v6 UDP checksum failed.");
            return(BAD);
        }
    }


    return (GOOD);
}

/*
 *  Process a LISP protocol message sitting on
 *  socket s with address family afi
 */
int process_lisp_ctr_msg(int sock, int afi)
{

    uint8_t             packet[MAX_IP_PACKET];
    lisp_addr_t         local_rloc;
    uint16_t            remote_port;
    lisp_msg            *msg;


    lispd_log_msg(LISP_LOG_DEBUG_2, "Received a LISP control message");

    if  (get_packet_and_socket_inf (sock, afi, packet, &local_rloc, &remote_port) != GOOD )
        return BAD;

    msg = lisp_msg_parse(packet);
    if (!msg || !msg->msg) {
        return(BAD);
        lispd_log_msg(LISP_LOG_DEBUG_2, "Couldn't parse control message");
    }

    if (msg->encapdata)
        if (process_lisp_msg_encapsulated_data(msg->encapdata, &remote_port) != GOOD)
            return(BAD);

    /* ====================== */
    /* FC: should be moved in xtr once process_info_nat_msg is updated to work with lisp_msg */
    if (msg->type == LISP_INFO_NAT) {
          lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Info-Request/Info-Reply message");
          if(!process_info_nat_msg(packet, local_rloc)){
              return (BAD);
          }
          return(GOOD);
    }
    /* ======================  */

    active_dev->process_lisp_ctrl_msg(msg, &local_rloc, remote_port);

//    switch(msg->type) {
//    case LISP_MAP_REPLY:
//        process_map_reply_msg(msg->msg);
//        break;
//    case LISP_MAP_REQUEST:
//        process_map_request_msg(msg->msg, &local_rloc, remote_port);
//        break;
//    case LISP_MAP_REGISTER:
//        break;
//    case LISP_MAP_NOTIFY:
//        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Map-Notify message");
//        if(process_map_notify(msg->msg) != GOOD)
//            return(BAD);
//        break;
//    case LISP_INFO_NAT:
//        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Info-Request/Info-Reply message");
//        if(!process_info_nat_msg(packet, local_rloc)){
//            return (BAD);
//        }
//        break;
//    default:
//        lispd_log_msg(LISP_LOG_DEBUG_1, "Unidentified type (%d) control message received", msg->type);
//        break;
//    }

    lispd_log_msg(LISP_LOG_DEBUG_2, "Completed processing of LISP control message");
    lisp_msg_del(msg);
    return(GOOD);
}



/*
 * Multicast Interface to end-hosts
 */

void multicast_join_channel(ip_addr_t *src, ip_addr_t *grp) {
    re_join_channel(src, grp);
}

void multicast_leave_channel(ip_addr_t *src, ip_addr_t *grp) {
    re_leave_channel(src, grp);
}


