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

inline char *msg_type_to_char(int type) {
    static char buf[40];
    switch(type) {
    case LISP_MAP_REPLY:
        sprintf(buf, "Type: Map-Reply");
        break;
    case LISP_MAP_REQUEST:
        sprintf(buf, "Type: Map-Request");
        break;
    case LISP_MAP_NOTIFY:
        sprintf(buf, "Type: Map-Notify");
        break;
    case LISP_MAP_REGISTER:
        sprintf(buf, "Type: Map-Register");
        break;
    case LISP_ENCAP_CONTROL_TYPE:
        sprintf(buf, "Type: Encapsulated Control Message");
        break;
    default:
        sprintf(buf, "Type: unkown (%d)", type);
    }
    return(buf);
}

inline lisp_msg *lisp_msg_new() {
    lisp_msg *msg;
    msg = calloc(1, sizeof(lisp_msg));
    return(msg);
}

lisp_msg *lisp_msg_parse(uint8_t *packet) {

    lisp_msg            *msg        = NULL;

    msg = lisp_msg_new();
    if (((lisp_encap_control_hdr_t *) packet)->type == LISP_ENCAP_CONTROL_TYPE) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "Parsing encapsulated control message data");
        msg->encap = 1;
        msg->encapdata = lisp_encap_hdr_parse(packet);
        packet = CO(packet, lisp_encap_data_get_len(msg->encapdata));
    } else {
        lispd_log_msg(LISP_LOG_DEBUG_3, "Parsing control message");
        msg->encap = 0;
    }

    msg->type = ((lisp_encap_control_hdr_t *) packet)->type;
    switch (msg->type) {
    case LISP_MAP_REPLY:    //Got Map Reply
        msg->msg = map_reply_msg_parse(packet);
        break;
    case LISP_MAP_REQUEST:      //Got Map-Request
        msg->msg = map_request_msg_parse(packet);
        break;
    case LISP_MAP_REGISTER:     //Got Map-Register, silently ignore
        break;
    case LISP_MAP_NOTIFY:
        msg->msg = map_notify_msg_parse(packet);
        break;
    case LISP_INFO_NAT:      //Got Info-Request/Info-Replay
        break;
    case LISP_ENCAP_CONTROL_TYPE:   //Got Encapsulated Control Message
        return(NULL);
    default:
        break;
    }

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

    data->ecmh = packet;
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
    map_reply_msg   *mrp  = NULL;
    mapping_record  *record = NULL;
    int i;

    mrp = map_reply_msg_new();
    mrp->data = offset;

    offset = CO(mrp->data, sizeof(map_reply_hdr));
    mrp->records = glist_new(NO_CMP, (void (*)(void *))mapping_record_del);
    if (!mrp->records)
        goto err;

    for (i=0; i < mrep_get_hdr(mrp)->record_count; i++) {
        record = mapping_record_parse(offset);
        if (!record)
            goto err;
        glist_add_tail(record, mrp->records);
        offset = CO(offset, mapping_record_get_len(record));
    }

    return(mrp);
err:
    if (mrp->records)
        glist_destroy(mrp->records);
    free(mrp);
    return(NULL);
}

void map_reply_msg_del(map_reply_msg *mrp) {
    if (mrp->records)
        glist_destroy(mrp->records);
    free(mrp);
}


inline map_request_msg *map_request_msg_new() {
    map_request_msg     *mrp        = NULL;
    mrp = calloc(1, sizeof(map_request_msg));
    return(mrp);
}


map_request_msg *map_request_msg_parse(uint8_t *offset) {
    map_request_msg     *mrp            = NULL;
    eid_prefix_record   *record         = NULL;
    address_field       *afield         = NULL;
    int i;

    mrp = map_request_msg_new();

    mrp->data = offset;
    offset = CO(mrp->data, sizeof(map_request_msg_hdr));
    mrp->src_eid = address_field_parse(offset);
    if (!mrp->src_eid)
        goto err;
    offset = CO(offset, address_field_get_len(mrp->src_eid));

    /* parse ITR RLOCs */
    mrp->itr_rlocs = glist_new(NO_CMP, (void (*)(void *))address_field_del);
    for (i=0; i < mreq_msg_get_hdr(mrp)->additional_itr_rloc_count + 1; i++) {
        afield = address_field_parse(offset);
        if (!afield)
            goto err;
        glist_add_tail(afield, mrp->itr_rlocs);
        offset = CO(offset, address_field_get_len(afield));
    }

    /* parse EIDs */
    mrp->eids = glist_new(NO_CMP, (glist_del_fct)eid_prefix_record_del);
    for (i=0; i< mreq_msg_get_hdr(mrp)->record_count; i++) {
        record = eid_prefix_record_parse(offset);
        if (!record)
            goto err;
        glist_add_tail(record, mrp->eids);
        offset = CO(offset, eid_prefix_record_get_len(record));
    }

    /* TODO read mapping record */

    return(mrp);

err:
    map_request_msg_del(mrp);
    return(NULL);
}

void map_request_msg_del(map_request_msg *msg) {

    if (msg->src_eid)
        address_field_del(msg->src_eid);
    if (msg->itr_rlocs)
        glist_destroy(msg->itr_rlocs);
    if (msg->eids)
        glist_destroy(msg->eids);
    free(msg);
}



/*
 * Map-Register
 */

inline map_register_msg *map_register_msg_new() {
    return(calloc(1, sizeof(map_register_msg)));
}

void map_register_msg_del(map_register_msg *mreg) {

    if (!mreg)
        return;
    if (mreg->auth_data)
        auth_field_del(mreg->auth_data);
    if (mreg->records) {
        glist_destroy(mreg->records);
    }

    free(mreg);
}

map_register_msg *map_register_msg_parse(uint8_t *offset) {
    map_register_msg    *mreg  = NULL;
    mapping_record      *record = NULL;
    int i;

    mreg = map_register_msg_new();
    mreg->bits = offset;
    offset = CO(mreg->bits, sizeof(map_register_msg_hdr));
    mreg->auth_data = auth_field_parse(offset);
    if (!mreg->auth_data)
        goto err;
    offset = CO(offset, auth_field_get_len(mreg->auth_data));
    mreg->records = glist_new(NO_CMP, (void (*)(void *))mapping_record_del);
    if (!mreg->records)
        goto err;
    for (i = 0; i < mreg_msg_get_hdr(mreg)->record_count; i++) {
        record = mapping_record_parse(offset);
        if (!record)
            goto err;
        glist_add_tail(record, mreg->records);
        offset = CO(offset, mapping_record_get_len(record));
    }

    return(mreg);
err:
    map_register_msg_del(mreg);
    return(NULL);
}


/*
 * Map-Notify
 */

inline map_notify_msg *map_notify_msg_new() {
    return(calloc(1, sizeof(map_notify_msg)));
}

void map_notify_msg_del(map_notify_msg *mnotify) {

    if (!mnotify)
        return;
    if (mnotify->auth_data)
        auth_field_del(mnotify->auth_data);
    if (mnotify->records)
        glist_destroy(mnotify->records);
    if (mnotify->rtr_auth)
        rtr_auth_field_del(mnotify->rtr_auth);

    free(mnotify);
}

map_notify_msg *map_notify_msg_parse(uint8_t *offset) {
    map_notify_msg  *mnotify  = NULL;
    mapping_record  *record   = NULL;
    int i;

    mnotify = map_notify_msg_new();
    mnotify->bits = offset;
    offset = CO(mnotify->bits, sizeof(map_notify_msg_hdr));
    mnotify->auth_data = auth_field_parse(offset);
    if (!mnotify->auth_data)
        goto err;
    offset = CO(offset, auth_field_get_len(mnotify->auth_data));
    mnotify->records = glist_new(NO_CMP, (glist_del_fct)mapping_record_del);
    if (!mnotify->records)
        goto err;

    for (i = 0; i < mnotify_msg_get_hdr(mnotify)->record_count; i++) {
        record = mapping_record_parse(offset);
        if (!record)
            goto err;
        glist_add_tail(record, mnotify->records);
        offset = CO(offset, mapping_record_get_len(record));
    }

    /* xtr-id and site-id*/
    if (mnotify_msg_get_hdr(mnotify)->xtr_id_present) {
        mnotify->xtr_id = offset;
        offset = CO(offset, 128*sizeof(uint8_t));
        mnotify->site_id = offset;
        offset = CO(offset, 64*sizeof(uint8_t));
    }

    /* rtr auth data */
    if (mnotify_msg_get_hdr(mnotify)->rtr_auth_present)
        mnotify->rtr_auth = rtr_auth_field_parse(offset);
    if (!mnotify->rtr_auth)
        goto err;

    return(mnotify);
err:
    map_notify_msg_del(mnotify);
    return(NULL);
}

uint16_t mnotify_msg_get_len(map_notify_msg *msg) {
    uint16_t len = 0;
    glist_t             *records    = NULL;
    glist_entry_t       *it         = NULL;

    len = sizeof(map_notify_msg_hdr) + auth_field_get_len(msg->auth_data);

    records = mnotify_msg_get_records(msg);
    glist_for_each_entry(it, records) {
        len += mapping_record_get_len(glist_entry_data(it));
    }
    if (mnotify_msg_get_hdr(msg)->xtr_id_present)
        len += 128*sizeof(uint8_t) + 64*sizeof(uint8_t);
    if (mnotify_msg_get_hdr(msg)->rtr_auth_present)
        len += rtr_auth_field_get_len(msg->rtr_auth);

    return(len);
}

static char *mnotify_msg_flags_to_char(map_notify_msg *msg) {
    static char buf[20];

    if(!msg)
        return(NULL);
    sprintf(buf, "Flags: ");
    mnotify_msg_get_hdr(msg)->xtr_id_present ? sprintf(buf+strlen(buf), "I") : sprintf(buf+strlen(buf), "i");
    mnotify_msg_get_hdr(msg)->rtr_auth_present ? sprintf(buf+strlen(buf), "R") : sprintf(buf+strlen(buf), "r");
    return(buf);
}

char *mnotify_hdr_to_char(map_notify_msg *msg) {
    static char buf[100];

    if (!msg)
        return(NULL);

    sprintf(buf, "%s, %s", msg_type_to_char(mnotify_msg_get_hdr(msg)->lisp_type),
            mnotify_msg_flags_to_char(msg));

//    printf("THE BUF: %s\n", mnotify_msg_flags_to_char(msg));
    return(buf);
}
