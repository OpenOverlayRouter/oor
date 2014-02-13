

#ifndef LISP_MAP_NOTIFY_H_
#define LISP_MAP_NOTIFY_H_

#include <stdint.h>

/*
 * Map-Notify Message Format
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |Type=4 |I|R|          Reserved                 | Record Count  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         Nonce . . .                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                         . . . Nonce                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            Key ID             |  Authentication Data Length   |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       ~                     Authentication Data                       ~
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   |                          Record  TTL                          |
 *   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
 *   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   c   | Rsvd  |  Map-Version Number   |        EID-prefix-AFI         |
 *   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   r   |                          EID-prefix                           |
 *   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
 *   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
 *   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  \|                             Locator                           |
 *   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct _map_notify_msg_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t  reserved1:2;
    uint8_t  rtr_auth_present:1;
    uint8_t  xtr_id_present:1;
    uint8_t  lisp_type:4;
#else
    uint8_t  lisp_type:4;
    uint8_t  xtr_id_present:1;
    uint8_t  rtr_auth_present:1;
    uint8_t  reserved1:2;
#endif
    uint16_t reserved2;
    uint8_t  record_count;
    uint64_t nonce;
//    uint16_t key_id;
//    uint16_t auth_data_len
//    uint8_t  auth_data[LISP_SHA1_AUTH_DATA_LEN];
} __attribute__ ((__packed__)) map_notify_msg_hdr_t;


typedef struct _map_notify_msg {
    auth_field      *auth_data;
    glist_t         *records;
    uint8_t         *xtr_id;
    uint8_t         *site_id;
    rtr_auth_field  *rtr_auth;

    /* should be at the end*/
    uint16_t        len;    /* also offset to end of data */
    uint8_t         *data;
} map_notify_msg;

inline map_notify_msg *map_notify_msg_new();
void                map_notify_msg_del(map_notify_msg *msg);
map_notify_msg      *map_notify_msg_parse(uint8_t *offset);
uint16_t            mnotify_msg_get_len(map_notify_msg *msg);
char                *mnotify_hdr_to_char(map_notify_msg *msg);
int                 mnotify_msg_check_auth(map_notify_msg *msg, const char *key);

int                 mnotify_msg_alloc(map_notify_msg *msg);
uint8_t             *mnotify_msg_push(map_notify_msg *msg, int len);
mapping_record      *mnotify_msg_push_record(map_notify_msg *msg, int size);

int                 mnotify_msg_write_auth_field(map_notify_msg *msg, auth_field *afield);

int                 mnotify_msg_write_records(map_notify_msg *msg, glist_t *rec);
int                 mnotify_msg_create_hdr(map_notify_msg *msg);
int                 mnotify_msg_add_record(map_notify_msg *msg, mapping_record *record);
int                 mnotify_msg_add_auth_field(map_notify_msg *msg, auth_field *afield);
int                 mnotify_msg_serialize(map_notify_msg *msg, uint8_t *pkt, int *pkt_len);

static inline map_notify_msg_hdr_t *mnotify_msg_hdr(map_notify_msg *msg) {
    return((map_notify_msg_hdr_t *)msg->data);
}

static inline glist_t *mnotify_msg_records(map_notify_msg *msg) {
    return(msg->records);
}

static inline auth_field *mnotify_msg_auth_data(map_notify_msg *msg) {
    return(msg->auth_data);
}

static inline uint8_t *mnotify_msg_data(map_notify_msg *msg) {
    return(msg->data);
}

/* easily confused with mnotify_msg_get_len, will change */
static inline int mnotify_msg_len(map_notify_msg *msg) {
    return(msg->len);
}


#endif /* LISP_MAP_NOTIFY_H_ */
