/*
 * lisp_messages.c
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

#include "lisp_messages.h"

inline lisp_msg *lisp_msg_new() {
    lisp_msg *msg;
    msg = calloc(1, sizeof(lisp_msg));
    return(msg);
}

lisp_msg *lisp_msg_parse(uint8_t *packet) {

    lisp_msg            *msg        = NULL;

    msg = lisp_msg_new();
    if (((lisp_encap_control_hdr_t *) packet)->type == LISP_ENCAP_CONTROL_TYPE) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "LISP control message is encapsulated. Parsing encapsulation data");
        msg->encap = 1;
        msg->encapdata = lisp_encap_hdr_parse(packet);
        packet = CO(packet, lisp_encap_data_get_len(msg->encapdata));
    } else {
        msg->encap = 0;
    }

    msg->type = ((lisp_encap_control_hdr_t *) packet)->type;
    switch (msg->type) {
    case LISP_MAP_REPLY:    //Got Map Reply
        lispd_log_msg(LISP_LOG_DEBUG_2, "Parsing LISP Map-Reply message");
        msg->msg = map_reply_msg_parse(packet);
        break;
    case LISP_MAP_REQUEST:      //Got Map-Request
        lispd_log_msg(LISP_LOG_DEBUG_2, "Parsing LISP Map-Request message");
        msg->msg = map_request_msg_parse(packet);
        break;
    case LISP_MAP_REGISTER:     //Got Map-Register, silently ignore
        break;
    case LISP_MAP_NOTIFY:
        lispd_log_msg(LISP_LOG_DEBUG_2, "Parsing LISP Map-Notify message");
        break;
    case LISP_INFO_NAT:      //Got Info-Request/Info-Replay
        lispd_log_msg(LISP_LOG_DEBUG_2, "Parsing LISP Info-Request/Info-Reply message");
        break;
    case LISP_ENCAP_CONTROL_TYPE:   //Got Encapsulated Control Message
        lispd_log_msg(LISP_LOG_DEBUG_2, "Parsing LISP double Encapsulated Map-Request message! Discarding!");
        return(NULL);
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "Unidentified type (%d) control message received", msg->type);
        break;
    }
    lispd_log_msg(LISP_LOG_DEBUG_2, "Completed parsing of LISP control message");

    return(msg);
}

void lisp_msg_del(lisp_msg *msg) {
    switch (msg->type) {
    case LISP_MAP_REPLY:
        map_reply_msg_del(msg->msg);
        break;
    case LISP_MAP_REQUEST:
        map_request_msg_del(msg->msg);
        break;
    case LISP_MAP_REGISTER:
    case LISP_MAP_NOTIFY:
    case LISP_INFO_NAT:
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_1, "Unidentified type (%d) control message received", msg->type);
        break;

    }
    if (msg->encap)
        lisp_encap_hdr_del(msg->encapdata);
    free(msg);
}

lisp_encap_data *lisp_encap_hdr_parse(uint8_t *packet) {

    lisp_encap_data *data;
    data = calloc(1, sizeof(lisp_encap_data));

    data->iph = CO(packet, sizeof(lisp_encap_control_hdr_t));
    switch (((struct ip *)data->iph)->ip_v) {
    case IPVERSION:
        data->ip_header_len = sizeof(struct ip);
        data->udph = (struct udphdr *) CO(data->iph, data->ip_header_len);
        data->ip_afi = AF_INET;
        break;
    case IP6VERSION:
        data->ip_header_len = sizeof(struct ip6_hdr);
        data->udph = (struct udphdr *) CO(data->iph, data->ip_header_len);
        data->ip_afi = AF_INET6;
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_map_request_msg: couldn't read incoming Encapsulated Map-Request: IP header corrupted.");
        return(NULL);
    }

    data->len = sizeof(lisp_encap_control_hdr_t)+data->ip_header_len + sizeof(struct udphdr);
    lispd_log_msg(LISP_LOG_DEBUG_2, "********* len is  = %d ", data->len);

    return(data);
}

void lisp_encap_hdr_del(lisp_encap_data *data) {
    free(data);
}


inline map_reply_msg *map_reply_msg_new() {
    map_reply_msg     *mrp        = NULL;
    mrp = calloc(1, sizeof(map_reply_msg));
    return(mrp);
}

map_reply_msg *map_reply_msg_parse(uint8_t *offset) {
    map_reply_msg *mrp  = NULL;
    int i;

    mrp = map_reply_msg_new();
    mrp->data = offset;

    offset = CO(mrp->data, sizeof(map_reply_hdr));

    mrp->records = calloc(mrep_get_hdr(mrp)->record_count, sizeof(mapping_record *));
    for (i=0; i < mrep_get_hdr(mrp)->record_count; i++) {
         mrp->records[i] = mapping_record_parse(offset);
         if (!mrp->records[i])
             goto err;
         offset = CO(offset, mapping_record_get_len(mrp->records[i]));
    }

    return(mrp);
err:
    if (mrp->records) {
        for (i = 0; i < mrep_get_hdr(mrp)->record_count; i++)
            if (mrp->records[i])
                mapping_record_del(mrp->records[i]);
        free(mrp->records);
    }
    free(mrp);
    return(NULL);
}

void map_reply_msg_del(map_reply_msg *mrp) {
    int i;
    if (mrp->records) {
        for (i=0; i < mrep_get_hdr(mrp)->record_count; i++)
            mapping_record_del(mrp->records[i]);
    }
    free(mrp);
}


map_request_msg *map_request_msg_new() {
    map_request_msg     *mrp        = NULL;
    mrp = calloc(1, sizeof(map_request_msg));
    return(mrp);
}


map_request_msg *map_request_msg_parse(uint8_t *offset) {
    map_request_msg     *mrp            = NULL;
    int i;

    mrp = map_request_msg_new();

    mrp->data = offset;
    offset = CO(mrp->data, sizeof(map_request_msg_hdr));
    mrp->src_eid = address_field_parse(offset);
    if (!mrp->src_eid)
        goto err;
    offset = CO(offset, address_field_get_len(mrp->src_eid));

    /* parse ITR RLOCs */
    mrp->itr_rlocs = calloc(mreq_get_hdr(mrp)->additional_itr_rloc_count + 1, sizeof(address_field*));
    for (i=0; i < mreq_get_hdr(mrp)->additional_itr_rloc_count + 1; i++) {
        mrp->itr_rlocs[i] = address_field_parse(offset);
        if (!mrp->itr_rlocs[i])
            goto err;
        offset = CO(offset, address_field_get_len(mrp->itr_rlocs[i]));
    }

    /* parse EIDs */
    mrp->eids = calloc(mreq_get_hdr(mrp)->record_count, sizeof(eid_prefix_record*));
    for (i=0; i< mreq_get_hdr(mrp)->record_count; i++) {
        mrp->eids[i] = eid_prefix_record_parse(offset);
        if (!mrp->eids[i])
            goto err;
        offset = CO(offset, eid_prefix_record_get_len(mrp->eids[i]));
    }

    /* TODO read mapping record */

    return(mrp);

err:
    if (mrp->src_eid)
        address_field_del(mrp->src_eid);
    if (mrp->itr_rlocs) {
        for(i=0;i<mreq_get_hdr(mrp)->additional_itr_rloc_count+1; i++)
            if (mrp->itr_rlocs[i])
                address_field_del(mrp->itr_rlocs[i]);
        free(mrp->itr_rlocs);
    }

    if (mrp->eids) {
        for (i=0;i<mreq_get_hdr(mrp)->record_count; i++)
            if (mrp->eids[i])
                eid_prefix_record_del(mrp->eids[i]);
        free(mrp->eids);
    }
    free(mrp);
    return(NULL);
}

void map_request_msg_del(map_request_msg *msg) {
    int i;

    if (msg->src_eid)
        address_field_del(msg->src_eid);
    if (msg->itr_rlocs)
        for(i=0;i<mreq_get_hdr(msg)->additional_itr_rloc_count + 1; i++)
            address_field_del(msg->itr_rlocs[i]);
    free(msg->itr_rlocs);
    if (msg->eids)
        for(i=0;i<mreq_get_hdr(msg)->record_count; i++)
            eid_prefix_record_del(msg->eids[i]);
    free(msg->eids);
    free(msg);
}


