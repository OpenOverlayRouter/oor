/*
 * liblisp.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
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

#ifndef LIBLISP_H_
#define LIBLISP_H_

#include "lisp_address.h"
#include "lispd_locator.h"
#include "lispd_mapping.h"
#include "lisp_messages.h"
#include "generic_list.h"
#include "lbuf.h"

typedef struct fwd_entry {
    lisp_addr_t *srloc;
    lisp_addr_t *drloc;
//    int         out_socket;
    /* fill in other stuff */
    int natt_flag;
} fwd_entry_t;

lisp_msg_type_t lisp_msg_type(lbuf_t *);
int lisp_msg_parse_type(lbuf_t *b, lisp_msg_type_t *);
int lisp_msg_parse_addr(lbuf_t *, lisp_addr_t *);
int lisp_msg_parse_eid_rec(lbuf_t *, lisp_addr_t *);
int lisp_msg_parse_itr_rlocs(lbuf_t *, glist_t *);
int lisp_msg_parse_loc(lbuf_t *, locator_t *);
int lisp_msg_parse_mapping_record_split(lbuf_t *, lisp_addr_t *, glist_t *,
                                        locator_t **);
int lisp_msg_parse_mapping_record(lbuf_t *, mapping_t *, locator_t **);

int lisp_msg_ecm_decap(struct lbuf *, uint16_t *);

void *lisp_msg_put_addr(lbuf_t *, lisp_addr_t *addr);
void *lisp_msg_put_locator(lbuf_t *, locator_t *locator);
void *lisp_msg_put_mapping_hdr(lbuf_t *b, int plen) ;
void *lisp_msg_put_mapping(lbuf_t *, mapping_t *, lisp_addr_t *);
void *lisp_msg_put_neg_mapping(lbuf_t *, lisp_addr_t *, int, lisp_action_e);
void *lisp_msg_put_itr_rlocs(lbuf_t *, glist_t *);
void *lisp_msg_put_eid_rec(lbuf_t *, lisp_addr_t *);
void *lisp_msg_encap(lbuf_t *, int, int, lisp_addr_t *, lisp_addr_t *);

lbuf_t* lisp_msg_create();
static inline void lisp_msg_destroy(lbuf_t *);
static inline void *lisp_msg_hdr(lbuf_t *b);

lbuf_t *lisp_msg_mreq_create(lisp_addr_t *, glist_t *, lisp_addr_t *);
lbuf_t *lisp_msg_neg_mrep_create(lisp_addr_t *, int, lisp_action_e);
lbuf_t *lisp_msg_mreg_create(mapping_t *, char *, lisp_key_type);
lbuf_t *lisp_msg_nat_mreg_create(mapping_t *, char *, lisp_site_id *,
        lisp_xtr_id *, lisp_key_type );

char *lisp_msg_hdr_to_char(lbuf_t *b);

int lisp_msg_fill_auth_data(lbuf_t *, lisp_key_type , const char *);
int lisp_msg_check_auth_field(lbuf_t *, const char *);
void *lisp_msg_put_empty_auth_record(lbuf_t *, lisp_key_type);
static inline void *lisp_msg_auth_record(lbuf_t *);

void *lisp_msg_pull_hdr(lbuf_t *b);
void *lisp_msg_pull_auth_field(lbuf_t *b);

static inline glist_t *lisp_addr_list_new();
static inline void lisp_addr_list_init(glist_t *);
static inline glist_t *list_addr_sorted_list_new();
static inline void lisp_addr_list_del(glist_t *);
int lisp_addr_list_get_addr(glist_t *, int, lisp_addr_t *);

static inline void lisp_msg_destroy(lbuf_t *b)
{
    if (b) {
        lbuf_del(b);
    }
}

static inline void *lisp_msg_hdr(lbuf_t *b)
{
    return(lbuf_lisp(b));
}

/* get pointer of auth field in a message */
static inline void *lisp_msg_auth_record(lbuf_t *b)
{
    /* assumption here is that auth field in all messages is at
     * sizeof(map_notify_hdr_t) from the beginning of the lisp
     * message */
    return((uint8_t *)lbuf_lisp(b) + sizeof(map_notify_hdr_t));
}



static inline glist_t *lisp_addr_list_new()
{
    return(glist_new_managed((glist_del_fct)lisp_addr_del));
}

static inline void lisp_addr_list_del(glist_t *lst)
{
    glist_destroy(lst);
}

static inline void lisp_addr_list_init(glist_t *lst)
{
    glist_init_managed(lst, (glist_del_fct)lisp_addr_del);
}

static inline glist_t *list_addr_sorted_list_new()
{
    return(glist_new_complete((glist_cmp_fct)lisp_addr_cmp,
            (glist_del_fct)lisp_addr_del));
}


#endif /* LIBLISP_H_ */
