/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef LIBLISP_H_
#define LIBLISP_H_

#include "lisp_address.h"
#include "lisp_locator.h"
#include "lisp_mapping.h"
#include "lisp_messages.h"
#include "lisp_data.h"
#include "../lib/generic_list.h"
#include "../lib/lbuf.h"


#define LISP_DATA_HDR_LEN       8
#define LISP_ECM_HDR_LEN        4
#define MAX_LISP_MSG_ENCAP_LEN  2*(MAX_IP_HDR_LEN + UDP_HDR_LEN)+ LISP_ECM_HDR_LEN
#define MAX_LISP_PKT_ENCAP_LEN  MAX_IP_HDR_LEN + UDP_HDR_LEN + LISP_DATA_HDR_LEN

#define LISP_CONTROL_PORT               4342
#define LISP_DATA_PORT                  4341


lisp_msg_type_e lisp_msg_type(lbuf_t *);
int lisp_msg_parse_addr(lbuf_t *, lisp_addr_t *);
int lisp_msg_parse_eid_rec(lbuf_t *, lisp_addr_t *);
int lisp_msg_parse_itr_rlocs(lbuf_t *, glist_t *);
int lisp_msg_parse_loc(lbuf_t *, locator_t *);
int lisp_msg_parse_mapping_record_split(lbuf_t *, lisp_addr_t *, glist_t *,
                                        locator_t **);
int lisp_msg_parse_mapping_record(lbuf_t *, mapping_t *, locator_t **);

int lisp_msg_ecm_decap(struct lbuf *, uint16_t *);

void *lisp_msg_put_addr(lbuf_t *, lisp_addr_t *);
void *lisp_msg_put_locator(lbuf_t *, locator_t *);
void *lisp_msg_put_mapping_hdr(lbuf_t *) ;
void *lisp_msg_put_mapping(lbuf_t *, mapping_t *, lisp_addr_t *);
void *lisp_msg_put_neg_mapping(lbuf_t *, lisp_addr_t *, int, lisp_action_e,
        lisp_authoritative_e a);
void *lisp_msg_put_itr_rlocs(lbuf_t *, glist_t *);
void *lisp_msg_put_eid_rec(lbuf_t *, lisp_addr_t *);
void *lisp_msg_encap(lbuf_t *, int, int, lisp_addr_t *, lisp_addr_t *);

lbuf_t *lisp_msg_create_buf();
lbuf_t* lisp_msg_create();
static inline void lisp_msg_destroy(lbuf_t *);
static inline void *lisp_msg_hdr(lbuf_t *b);

lbuf_t *lisp_msg_mreq_create(lisp_addr_t *, glist_t *, lisp_addr_t *);
lbuf_t *lisp_msg_neg_mrep_create(lisp_addr_t *, int, lisp_action_e,
        lisp_authoritative_e, uint64_t);
lbuf_t *lisp_msg_inf_req_create(mapping_t *m, lisp_key_type_e keyid);
lbuf_t *lisp_msg_mreg_create(mapping_t *, lisp_key_type_e);
lbuf_t *lisp_msg_nat_mreg_create(mapping_t *, lisp_site_id ,
        lisp_xtr_id *, lisp_key_type_e );

char *lisp_msg_hdr_to_char(lbuf_t *b);
char *lisp_msg_ecm_hdr_to_char(lbuf_t *b);

int lisp_msg_fill_auth_data(lbuf_t *, lisp_key_type_e , const char *);
int lisp_msg_check_auth_field(lbuf_t *, const char *);
void *lisp_msg_put_empty_auth_record(lbuf_t *, lisp_key_type_e);
void *lisp_msg_put_inf_req_hdr_2(lbuf_t *b, lisp_addr_t *eid_pref, uint8_t ttl);
static inline void *lisp_msg_auth_record(lbuf_t *);

void *lisp_msg_pull_hdr(lbuf_t *b);
void *lisp_msg_pull_auth_field(lbuf_t *b);

void *lisp_data_push_hdr(lbuf_t *b, uint32_t iid);
void *lisp_data_pull_hdr(lbuf_t *b);
void *lisp_data_encap(lbuf_t *, int, int, lisp_addr_t *, lisp_addr_t *, uint32_t);

static inline glist_t *laddr_list_new();
static inline void laddr_list_init(glist_t *);
static inline glist_t *laddr_sorted_list_new();
static inline void laddr_list_del(glist_t *);
int laddr_list_get_addr(glist_t *, int, lisp_addr_t *);
char *laddr_list_to_char(glist_t *l);

static inline void
lisp_msg_destroy(lbuf_t *b)
{
    if (b) {
        lbuf_del(b);
    }
}

static inline void *
lisp_msg_hdr(lbuf_t *b)
{
    return(lbuf_lisp(b));
}

static inline void *
lisp_msg_ecm_hdr(lbuf_t *b)
{
    return(lbuf_lisp_hdr(b));
}

/* get pointer of auth field in a message */
static inline void *
lisp_msg_auth_record(lbuf_t *b)
{
    /* assumption here is that auth field in all messages is at
     * sizeof(map_notify_hdr_t) from the beginning of the lisp
     * message */
    return((uint8_t *)lbuf_lisp(b) + sizeof(map_notify_hdr_t));
}



static inline glist_t *
laddr_list_new()
{
    return(glist_new_managed((glist_del_fct)lisp_addr_del));
}

static inline void
laddr_list_del(glist_t *lst)
{
    glist_destroy(lst);
}

static inline void
laddr_list_init(glist_t *lst)
{
    glist_init_managed(lst, (glist_del_fct)lisp_addr_del);
}

static inline glist_t *
laddr_sorted_list_new()
{
    return(glist_new_complete((glist_cmp_fct)lisp_addr_cmp,
            (glist_del_fct)lisp_addr_del));
}


#endif /* LIBLISP_H_ */
