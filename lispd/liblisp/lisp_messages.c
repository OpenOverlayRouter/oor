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
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>

/* buffer used for filling in and sending messages */
static uint8_t msg_send_buf[2000];

/* The maximum length of the headers, when we have IPv6 encapsulated control messages
 * is 100 bytes. Allocate 150 for safety
 */
#define MAX_HEADERS_LEN 150

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
    if (((ecm_hdr_t *) packet)->type == LISP_ENCAP_CONTROL_TYPE) {
        lmlog(LISP_LOG_DEBUG_3, "Parsing encapsulated control message data");
        msg->encap = 1;
        msg->encapdata = lisp_encap_hdr_parse(packet);
        packet = CO(packet, lisp_encap_data_get_len(msg->encapdata));
    } else {
        msg->encap = 0;
    }
    msg->type = ((ecm_hdr_t *) packet)->type;
    switch (msg->type) {
    case LISP_MAP_REPLY:    //Got Map Reply
        msg->msg = map_reply_msg_parse(packet);
        break;
    case LISP_MAP_REQUEST:      //Got Map-Request
        msg->msg = map_request_msg_parse(packet);
        break;
    case LISP_MAP_REGISTER:     //Got Map-Register, silently ignore
        msg->msg = map_register_msg_parse(packet);
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
        lmlog(LISP_LOG_DEBUG_1, "Unidentified type (%d) control message received", msg->type);
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
    data->iph = CO(packet, sizeof(ecm_hdr_t));
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
        lmlog(LISP_LOG_DEBUG_2, "process_map_request_msg: couldn't read incoming Encapsulated Map-Request: IP header corrupted.");
        return(NULL);
    }

    data->len = sizeof(ecm_hdr_t)+data->ip_header_len + sizeof(struct udphdr);

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

    offset = CO(mrp->data, sizeof(map_reply_hdr_t));
    mrp->records = glist_new_managed((void (*)(void *))mapping_record_del);
    if (!mrp->records)
        goto err;

    for (i=0; i < mrep_get_hdr(mrp)->record_count; i++) {
        record = mapping_record_parse(offset);
        if (!record)
            goto err;
        glist_add_tail(record, mrp->records);
        offset = CO(offset, mapping_record_len(record));
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
    offset = CO(mrp->data, sizeof(map_request_hdr_t));
    mrp->src_eid = address_field_parse(offset);
    if (!mrp->src_eid)
        goto err;
    offset = CO(offset, address_field_len(mrp->src_eid));

    /* parse ITR RLOCs */
    mrp->itr_rlocs = glist_new_managed((glist_del_fct)address_field_del);
    for (i=0; i < mreq_msg_get_hdr(mrp)->additional_itr_rloc_count + 1; i++) {
        afield = address_field_parse(offset);
        if (!afield)
            goto err;
        glist_add_tail(afield, mrp->itr_rlocs);
        offset = CO(offset, address_field_len(afield));
    }

    /* parse EIDs */
    mrp->eids = glist_new_complete(NO_CMP, (glist_del_fct)eid_prefix_record_del);
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
    offset = CO(mreg->bits, sizeof(map_register_hdr_t));
    mreg->auth_data = auth_field_parse(offset);
    if (!mreg->auth_data)
        goto err;
    offset = CO(offset, auth_field_get_len(mreg->auth_data));
    mreg->records = glist_new_managed((glist_del_fct)mapping_record_del);
    if (!mreg->records)
        goto err;
    for (i = 0; i < mreg_msg_get_hdr(mreg)->record_count; i++) {
        record = mapping_record_parse(offset);
        if (!record)
            goto err;
        glist_add_tail(record, mreg->records);
        offset = CO(offset, mapping_record_len(record));
    }

    return(mreg);
err:
    map_register_msg_del(mreg);
    return(NULL);
}

int mreg_msg_check_auth(map_register_msg *msg, const char *key) {
    return(lisp_msg_check_auth_field(mreg_msg_data(msg), mreg_msg_get_len(msg), mreg_msg_get_auth_data(msg), key));
}

int mreg_msg_get_len(map_register_msg *msg) {
    uint16_t len = 0;
    glist_t             *records    = NULL;
    glist_entry_t       *it         = NULL;

    len = sizeof(map_notify_hdr_t) + auth_field_get_len(msg->auth_data);

    records = mreg_msg_get_records(msg);
    glist_for_each_entry(it, records) {
        len += mapping_record_len(glist_entry_data(it));
    }
//    if (mreg_msg_get_hdr(msg)->xtr_id_present)
//        len += 128*sizeof(uint8_t) + 64*sizeof(uint8_t);
//    if (mreg_msg_get_hdr(msg)->rtr_auth_present)
//        len += rtr_auth_field_get_len(msg->rtr_auth);

    records = mreg_msg_get_records(msg);

    return(len);
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
    lmlog(LISP_LOG_DEBUG_3, "Parsing map notify!");

    mnotify = map_notify_msg_new();
    mnotify->data = offset;
    offset = CO(mnotify->data, sizeof(map_notify_hdr_t));
    mnotify->auth_data = auth_field_parse(offset);
    if (!mnotify->auth_data)
        goto err;
    offset = CO(offset, auth_field_get_len(mnotify->auth_data));
    mnotify->records = glist_new_managed((glist_del_fct)mapping_record_del);
    if (!mnotify->records)
        goto err;

    for (i = 0; i < mnotify_msg_hdr(mnotify)->record_count; i++) {
        record = mapping_record_parse(offset);
        if (!record)
            goto err;
        glist_add_tail(record, mnotify->records);
        offset = CO(offset, mapping_record_len(record));
    }

    /* xtr-id and site-id*/
    if (mnotify_msg_hdr(mnotify)->xtr_id_present) {
        mnotify->xtr_id = offset;
        offset = CO(offset, 128*sizeof(uint8_t));
        mnotify->site_id = offset;
        offset = CO(offset, 64*sizeof(uint8_t));
    }

    /* rtr auth data */
    if (mnotify_msg_hdr(mnotify)->rtr_auth_present) {
        mnotify->rtr_auth = rtr_auth_field_parse(offset);
        if (!mnotify->rtr_auth)
            goto err;
    }

    return(mnotify);
err:
    map_notify_msg_del(mnotify);
    return(NULL);
}

uint16_t mnotify_msg_get_len(map_notify_msg *msg) {
    uint16_t len = 0;
    glist_t             *records    = NULL;
    glist_entry_t       *it         = NULL;

    len = sizeof(map_notify_hdr_t) + auth_field_get_len(msg->auth_data);

    records = mnotify_msg_records(msg);
    glist_for_each_entry(it, records) {
        len += mapping_record_len(glist_entry_data(it));
    }
    if (mnotify_msg_hdr(msg)->xtr_id_present)
        len += 128*sizeof(uint8_t) + 64*sizeof(uint8_t);
    if (mnotify_msg_hdr(msg)->rtr_auth_present)
        len += rtr_auth_field_get_len(msg->rtr_auth);

    records = mnotify_msg_records(msg);

    return(len);
}

static char *mnotify_msg_flags_to_char(map_notify_msg *msg) {
    static char buf[20];

    if(!msg)
        return(NULL);
    sprintf(buf, "Flags: ");
    mnotify_msg_hdr(msg)->xtr_id_present ? sprintf(buf+strlen(buf), "I") : sprintf(buf+strlen(buf), "i");
    mnotify_msg_hdr(msg)->rtr_auth_present ? sprintf(buf+strlen(buf), "R") : sprintf(buf+strlen(buf), "r");
    return(buf);
}

char *mnotify_hdr_to_char(map_notify_msg *msg) {
    static char buf[100];

    if (!msg)
        return(NULL);

    sprintf(buf, "%s, %s", msg_type_to_char(mnotify_msg_hdr(msg)->lisp_type),
            mnotify_msg_flags_to_char(msg));

//    printf("THE BUF: %s\n", mnotify_msg_flags_to_char(msg));
    return(buf);
}


/* FC TODO: this should be generalized into a msgbuf  */

/* Allocates a chunk of memory where to write the message
 * For starters, we use a static buffer*/
int mnotify_msg_alloc(map_notify_msg *msg) {
    msg->data = CO(msg_send_buf, MAX_HEADERS_LEN);
    msg->head = msg_send_buf;

    /* clear hdr*/
    memset(msg->data, 0, sizeof(map_notify_hdr_t));

    mnotify_msg_hdr(msg)->type = LISP_MAP_NOTIFY;
    msg->len = sizeof(map_notify_hdr_t);
    return(GOOD);
}

/*
 * allocate some header space
 */
void mnotify_msg_reserve(map_notify_msg *msg, int len) {
    msg->data = CO(msg->data, len);
}


//mapping_record *mnotify_msg_push_record(map_notify_msg *msg, int size) {
//    mapping_record *record  = NULL;
//    if (!msg->data)
//        goto err;
//    if (!msg->records) {
//        msg->records = glist_new(NO_CMP, (glist_del_fct)mapping_record_del);
//        if (!msg->records)
//            goto err;
//    }
//    if (!(record = mapping_record_new()))
//        goto err;
//    mapping_record_set_data(record, CO(msg->data, msg->len));
//    glist_add(record, msg->records);
//    msg->len += size;
//    return(record);
//err:
//    return(NULL);
//}

uint8_t *mnotify_msg_put(map_notify_msg *msg, int len) {
    msg->len += len;
    return(CO(msg->data, msg->len - len));
}

uint8_t *mnotify_msg_push(map_notify_msg *msg, int len) {
    msg->data -= len;
    msg->len += len;
    return(msg->data);
}

int mnotify_msg_check_auth(map_notify_msg *msg, const char *key) {
    return(lisp_msg_check_auth_field(mnotify_msg_data(msg), mnotify_msg_get_len(msg), mnotify_msg_auth_data(msg), key));
}












void map_request_hdr_init(uint8_t *ptr) {
    map_request_hdr_t *mrp = ptr;

    mrp->type                       = LISP_MAP_REQUEST;
    mrp->authoritative              = 0;
    mrp->map_data_present           = 1;    /* default not mrsig */
    mrp->rloc_probe                 = 0;    /* default not rloc probe */
    mrp->solicit_map_request        = 0;    /* default not smr */
    mrp->smr_invoked                = 0;    /* default not smr-invoked */
    mrp->additional_itr_rloc_count  = 0;    /* to be filled in later  */
    mrp->record_count               = 0;    /* to be filled in later */
    mrp->nonce                      = 0;    /* to be filled in later */
    mrp->pitr                       = 0;    /* default not sent by PITR */
    mrp->reserved1 = 0;
    mrp->reserved2 = 0;
}

void map_reply_hdr_init(uint8_t *ptr) {
    map_reply_hdr_t *mrp = ptr;

    mrp->type = LISP_MAP_REPLY;
    mrp->rloc_probe = 0;        /* default not rloc-probe */
    mrp->record_count = 0;      /* to be filled in later */
    mrp->echo_nonce  = 0;       /* default not reply to echo nonce req */
    mrp->security = 0;          /* default no security */
    mrp->nonce = 0;             /* to be filled in later */

    mrp->reserved1 = 0;
    mrp->reserved2 = 0;
    mrp->reserved3 = 0;

}

void map_register_hdr_init(uint8_t *ptr) {
    map_register_hdr_t *mrp = ptr;

    mrp->type = LISP_MAP_REGISTER;
    mrp->proxy_reply = 0;               /* default no proxy-map-reply */
    mrp->map_notify = 1;                /* default want map-notify */
    mrp->nonce = 0;                     /* to be filled in later */
    mrp->record_count = 0;              /* to be filled in later */
    mrp->rbit = 0;                      /* default not NATT */
    mrp->ibit = 0;                      /* default not NATT */

    mrp->reserved1 = 0;
    mrp->reserved2 = 0;
    mrp->reserved3 = 0;
}

void map_notify_hdr_init(uint8_t *ptr) {
    map_notify_hdr_t *mrp = ptr;

    mrp->type = LISP_MAP_NOTIFY;
    mrp->record_count = 0;              /* to be filled in later */
    mrp->rtr_auth_present = 0;          /* to be filled in later */
    mrp->xtr_id_present = 0;            /* to be filled in later */
    mrp->nonce = 0;                     /* to be filled in later */

    mrp->reserved1 = 0;
    mrp->reserved2 = 0;
}

void
ecm_hdr_init(uint8_t *ptr)
    ecm_hdr_t *ecm = ptr;
    ecm->type = LISP_ENCAP_CONTROL_TYPE;
    ecm->s_bit = 0;
    ecm->reserved = 0;
    ecm->reserved2 = 0;
}





/* Given the start of an address field, @addr, checks if the address is an
 * MCAST_INFO LCAF that carries mrsignaling flags */
uint8_t is_mrsignaling(address_hdr_t *addr) {
    return( address_field_afi(addr) == LISP_AFI_LCAF
            && address_field_lcaf_type(addr) == LCAF_MCAST_INFO
            && (address_field_get_mc_hdr(addr)->J || address_field_get_mc_hdr(addr)->L));
}

/* Given the start of an address field, @addr, checks if the address is used
 * for mrsignaling, in which case it returns the mrsignaling flags */
mrsignaling_flags_t
mrsignaling_flags(address_hdr_t *addr) {
    lcaf_mcinfo_hdr_t   *hdr;
    mrsignaling_flags_t mc_flags = {.rbit = 0, .jbit = 0, .lbit = 0};

    if (!is_mrsignaling(addr)) {
        return(mc_flags);
    }

    hdr = addr;

    if (hdr->J == 1 && hdr->L == 1) {
        lmlog(LISP_LOG_DEBUG_1, "Both join and leave flags are set in "
                "mrsignaling msg. Discarding!");
        return(mc_flags);
    }

    mc_flags = (mrsignaling_flags_t){.rbit = hdr->R, .jbit = hdr->J, .lbit = hdr->L};
    return(mc_flags);
}


/**
 * @offset: pointer to start of the mapping record
 */
void
mrsignaling_set_flags_in_pkt(uint8_t *offset, mrsignaling_flags_t *mrsig) {

    lcaf_mcinfo_hdr_t *mc_ptr;

//    offset = CO(offset, sizeof(mapping_record_hdr_t) + sizeof(uint16_t));
    mc_ptr = (lcaf_mcinfo_hdr_t *) offset;
    mc_ptr->J = mrsig->jbit;
    mc_ptr->L = mrsig->lbit;
    mc_ptr->R = mrsig->rbit;

}



char *
locator_record_flags_to_char(locator_hdr_t *h) {
    static char buf[5];
    h->local ? sprintf(buf+strlen(buf), "L") : sprintf(buf+stlen(buf), "l");
    h->probed ? sprintf(buf+strlen(buf), "p") : sprintf(buf+stlen(buf), "P");
    h->reachable ? sprintf(buf+strlen(buf), "R") : sprintf(buf+stlen(buf), "r");
    return(buf);
}

char *
locator_record_hdr_to_char(locator_hdr_t *h) {
   static char buf[100];
   if (!h) {
       return(NULL);
   }

   sprintf(buf, "Locator-record -> flags: %s p/w: %d/%d %d/%d",
           locator_record_flags_to_char(h), h->priority, h->weight,
           h->mpriority, h->mweight);
   return(buf);
}

static char *
action_to_char(int act) {
    static char buf[10];
    switch(act) {
    case 0:
        sprintf(buf, "no-action");
        break;
    case 1:
        sprintf(buf, "native-forward");
        break;
    case 2:
        sprintf(buf, "send-map-request");
        break;
    case 3:
        sprintf(buf, "drop");
        break;
    default:
        sprintf(buf, "unknown-action");
    }
    return(buf);
}

char *
mapping_record_hdr_to_char(mapping_record_hdr_t *h) {
    static char buf[100];
    if (!h) {
        return(NULL);
    }

    sprintf(buf, "Mapping-record -> ttl: %d loc-count: %d action: %s auth: %d "
            "map-version: %d", ntohl(h->ttl), h->locator_count,
            action_to_char(h->action), h->authoritative, MAP_REC_VERSION(h));
    return(buf);
}

char *
mreq_flags_to_char(map_request_hdr_t *h) {
    static char buf[10];
    h->authoritative ? sprintf(buf+strlen(buf), "A") : sprintf(buf+strlen(buf), "a") ;
    h->map_data_present ?  sprintf(buf+strlen(buf), "M") : sprintf(buf+strlen(buf), "m");
    h->rloc_probe ? sprintf(buf+strlen(buf), "P") : sprintf(buf+strlen(buf), "p");
    h->solicit_map_request ? sprintf(buf+strlen(buf), "S") : sprintf(buf+strlen(buf), "s");
    h->pitr ? sprintf(buf+strlen(buf), "p") : sprintf(buf+strlen(buf), "P");
    h->smr_invoked ? sprintf(buf+strlen(buf), "s") : sprintf(buf+strlen(buf), "S");
    return(buf);
}


char *
map_request_hdr_to_char(map_request_hdr_t *h) {
    static char buf[100];

    if (!h) {
        return(NULL);
    }

    sprintf(buf, "Map-Request -> flags:%s irc: %d (+1) record-count: %d nonce %s",
            mreq_flags_to_char(h), h->additional_itr_rloc_count, h->record_count,
            nonce_to_char(h->nonce));
    return(buf);
}

char *
mrep_flags_to_char(map_reply_hdr_t *h) {
    static char buf[10];
    h->rloc_probe ? sprintf(buf+strlen(buf), "P") : sprintf(buf+strlen(buf), "p");
    h->echo_nonce ? sprintf(buf+strlen(buf), "E") : sprintf(buf+strlen(buf), "e");
    h->security ? sprintf(buf+strlen(buf), "S") : sprintf(buf+strlen(buf), "s");
    return(buf);
}

char *
map_reply_hdr_to_char(map_reply_hdr_t *h) {
    static char buf[100];

    if (!h) {
        return(NULL);
    }

    sprintf(buf, "Map-Reply -> flags:%s record-count: %d nonce %s",
            mreq_flags_to_char(h), h->record_count, nonce_to_char(h->nonce));
    return(buf);
}

char *
mreg_flags_to_char(map_register_hdr_t *h) {
    static char buf[10];
    h->proxy_reply ? sprintf(buf+strlen(buf), "P") : sprintf(buf+strlen(buf), "p");
    h->ibit ? sprintf(buf+strlen(buf), "I") : sprintf(buf+strlen(buf), "i");
    h->rbit ? sprintf(buf+strlen(buf), "R") : sprintf(buf+strlen(buf), "r");
    h->map_notify ? sprintf(buf+strlen(buf), "M") : sprintf(buf+strlen(buf), "m");
    return(buf);
}

char *
map_register_hdr_to_char(map_reply_hdr_t *h) {
    static char buf[100];

    if (!h) {
        return(NULL);
    }

    sprintf(buf, "Map-Register -> flags:%s record-count: %d nonce %s",
            mreq_flags_to_char(h), h->record_count, nonce_to_char(h->nonce));
    return(buf);
}

char *
mntf_flags_to_char(map_notify_hdr_t *h) {
    static char buf[5];
    h->xtr_id_present ? sprintf(buf+strlen(buf), "I") : sprintf(buf+strlen(buf), "i");
    h->rtr_auth_present ? sprintf(buf+strlen(buf), "R") : sprintf(buf+strlen(buf), "r");
    return(buf);
}

char *
map_notify_hdr_to_char(map_notify_hdr_t *h) {
    static char buf[100];

    if (!h) {
        return(NULL);
    }

    sprintf(buf, "Map-Notify -> flags:%s record-count: %d nonce %s",
            mreq_flags_to_char(h), h->record_count, nonce_to_char(h->nonce));
    return(buf);
}


char *
ecm_flags_to_char(ecm_hdr_t *h) {
    static char buf[10];
    if (!h) {
        return(NULL);
    }
    h->s_bit ? sprintf(buf+strlen(buf), "S") : sprintf(buf+strlen(buf), "s");
    return(buf);
}

char *
ecm_hdr_to_char(ecm_hdr_t *h) {
    static char buf[50];

    if (!h) {
        return(NULL);
    }

    sprintf(buf, "ECM -> flags:%s", mreq_flags_to_char(h));
    return(buf);
}
