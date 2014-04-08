/*
 * lbuf.h
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
 * Inspired by ofpbuf from the OpenVSwitch project and sk_buff from the Linux Kernel
 *
 * Written or modified by:
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#ifndef LBUF_H_
#define LBUF_H_

#include <llist/list.h>
#include <defs.h>

struct lbuf {
    struct list_head list;      /* for queueing*/

    uint32_t allocated;         /* allocated size */
    uint32_t size;              /* size in-use */

//    uint16_t ip_hdr;            /* IP hdr offset*/
//    uint16_t udp_hdr;           /* UDP hdr offset*/
//
//    uint16_t lh;                /* lisp hdr offset*/
//    uint16_t ip_ihdr;           /* inner IP hdr offset */
//    uint16_t udp_ihdr;          /* inner UDP hdr offset */
//
    uint16_t lisp;              /* lisp payload (msg or pkt) offset */

    void *base;                 /* start of allocated space */
    void *data;                 /* start of in-use space */
};

void lbuf_init(struct lbuf *, uint32_t);
void lbuf_uninit(struct lbuf *);
struct lbuf *lbuf_new(uint32_t);
struct lbuf *lbuf_new_with_headroom(uint32_t, uint32_t);
struct lbuf *lbuf_clone(struct lbuf *);
static void lbuf_del(struct lbuf *);


static void *lbuf_at(const struct lbuf *, uint32_t, uint32_t);
static void *lbuf_tail(const struct lbuf *);
static uint32_t lbuf_end(const struct lbuf *);
static void *lbuf_data(const struct lbuf *b);

void lbuf_prealloc_tailroom(struct lbuf *b, uint32_t);
void lbuf_prealloc_headroom(struct lbuf *b, uint32_t);

void *lbuf_put_uninit(struct lbuf *, uint32_t);
void *lbuf_put(struct lbuf *, void *, uint32_t);
void *lbuf_push_uninit(struct lbuf *, uint32_t);
void *lbuf_push(struct lbuf *, void *, uint32_t);
static void *lbuf_pull(struct lbuf *b, uint32_t);


void lbuf_reserve(struct lbuf *b, uint32_t size);
struct lbuf *lbuf_clone(struct lbuf *b);

static void *lbuf_lisp(struct lbuf*);


static void *lbuf_at(const struct lbuf *buf, uint32_t offset, uint32_t size) {
    return offset+size <= buf->size ? (uint8_t *) buf->data + offset : NULL;
}


static void *lbuf_tail(const struct lbuf *b) {
    return (uint8_t *) b->data + b->size;
}

static void *lbuf_end(const struct lbuf *b) {
    return (uint8_t *) b->base + b->allocated;
}

static uint32_t lbuf_headroom(const struct lbuf *b) {
    return (uint8_t *)b->base - (uint8_t *)b->data;
}

static uint32_t lbuf_tailroom(const struct lbuf *b) {
    return lbuf_end(b)-lbuf_tail(b);
}

static void lbuf_del(struct lbuf *b) {
    if (b) {
        lbuf_uninit(b);
        free(b);
    }
}

static void *lbuf_data(const struct lbuf *b) {
    return b->data;
}

/* moves 'data' pointer by 'size'. Returns first byte
 * of data removed */
static void *lbuf_pull(struct lbuf *b, uint32_t size) {
    if (size > b->size)
        return NULL;
    void *data = b->data;
    b->data = (uint8_t *)b->data + size;
    b->size -= size;
    return data;
}

static void lbuf_reset_lisp(struct lbuf *b) {
    b->lisp = (uint8_t *)b->data - (uint8_t *)b->base;
}

static void *lbuf_lisp(struct lbuf *b) {
    return(b->lisp ? (uint8_t *)b->allocated + b->lisp : NULL);
}

#endif /* LBUF_H_ */
