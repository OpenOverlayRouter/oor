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

#include <list.h>
#include <defs.h>
#include <stdint.h>

struct lbuf {
    struct list_head list;      /* for queueing, to be implemented*/

    uint32_t allocated;         /* allocated size */
    uint32_t size;              /* size in-use */

    uint16_t ip;                /* IP hdr offset */
    uint16_t udp;               /* UDP hdr offset */

    uint16_t lhdr;              /* lisp hdr offset */
    uint16_t in_ip;             /* inner IP hdr offset */
    uint16_t in_udp;            /* inner UDP hdr offset */

    uint16_t lisp;              /* lisp payload offset */

    void *base;                 /* start of allocated space */
    void *data;                 /* start of in-use space */
};

typedef struct lbuf lbuf_t;


void lbuf_init(lbuf_t *, uint32_t);
void lbuf_uninit(lbuf_t *);
lbuf_t *lbuf_new(uint32_t);
lbuf_t *lbuf_new_with_headroom(uint32_t, uint32_t);
lbuf_t *lbuf_clone(lbuf_t *);
static inline void lbuf_del(lbuf_t *);


static inline void *lbuf_at(const lbuf_t *, uint32_t, uint32_t);
static inline void *lbuf_tail(const lbuf_t *);
static inline void *lbuf_end(const lbuf_t *);
static inline void *lbuf_data(const lbuf_t *);
static inline void *lbuf_base(const lbuf_t *);
static inline uint32_t lbuf_size(const lbuf_t *);
static inline void lbuf_set_size(lbuf_t *, uint32_t);

void *lbuf_put_uninit(lbuf_t *, uint32_t);
void *lbuf_put(lbuf_t *, void *, uint32_t);
void *lbuf_push_uninit(lbuf_t *, uint32_t);
void *lbuf_push(lbuf_t *, void *, uint32_t);
static inline void *lbuf_pull(lbuf_t *b, uint32_t);

void lbuf_reserve(lbuf_t *b, uint32_t size);
lbuf_t *lbuf_clone(lbuf_t *b);

void lbuf_prealloc_tailroom(lbuf_t *b, uint32_t);
void lbuf_prealloc_headroom(lbuf_t *b, uint32_t);

static inline void lbuf_reset_ip(lbuf_t *b);
static inline void *lbuf_ip(lbuf_t *b);
static inline void lbuf_reset_udp(lbuf_t *b);
static inline void *lbuf_udp(lbuf_t *b);
static inline void lbuf_reset_lisp(lbuf_t *b);
static inline void *lbuf_lisp(lbuf_t*);
static inline void lbuf_reset_lisp_hdr(lbuf_t *b);
static inline void *lbuf_lisp_hdr(lbuf_t*);

static inline void *lbuf_at(const lbuf_t *b, uint32_t offset, uint32_t size)
{
    return offset + size <= lbuf_size(b) ? (char *)lbuf_data(b) + offset : NULL;
}

static inline void *lbuf_tail(const lbuf_t *b)
{
    return (char *)lbuf_data(b) + lbuf_size(b);
}

static inline void *lbuf_end(const lbuf_t *b)
{
    return (char *)lbuf_base(b) + b->allocated;
}

static inline uint32_t lbuf_headroom(const lbuf_t *b)
{
    return (char *)lbuf_base(b) - (char *)lbuf_data(b);
}

static inline uint32_t lbuf_tailroom(const lbuf_t *b)
{
    return (char *)lbuf_end(b) - (char *)lbuf_tail(b);
}

static inline void lbuf_del(lbuf_t *b)
{
    if (b) {
        lbuf_uninit(b);
        free(b);
    }
}

static inline void *lbuf_data(const lbuf_t *b)
{
    return b->data;
}

static inline void *lbuf_base(const lbuf_t *b)
{
    return b->base;
}

static inline uint32_t lbuf_size(const lbuf_t *b)
{
    return b->size;
}

static inline void lbuf_set_size(lbuf_t *b, uint32_t sz)
{
    b->size = sz;
}

/* moves 'data' pointer by 'size'. Returns first byte
 * of data removed */
static inline void *lbuf_pull(lbuf_t *b, uint32_t size)
{
    if (size > b->size) {
        return NULL;
    }

    void *data = b->data;
    b->data = (uint8_t *) b->data + size;
    b->size -= size;
    return data;
}

static inline void lbuf_reset_ip(lbuf_t *b)
{
    b->ip = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *lbuf_ip(lbuf_t *b)
{
    return b->ip != UINT16_MAX ? (char *)lbuf_base(b) + b->ip : NULL;
}

static inline void lbuf_reset_udp(lbuf_t *b)
{
    b->udp = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *lbuf_udp(lbuf_t *b)
{
    return b->udp != UINT16_MAX ? (char *)lbuf_base(b) + b->udp : NULL;
}

static inline void lbuf_reset_lisp(lbuf_t *b)
{
    b->lisp = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *lbuf_lisp(lbuf_t *b)
{
    return b->lisp != UINT16_MAX ? (char *)lbuf_base(b) + b->lisp : NULL;
}

static inline void lbuf_reset_lisp_hdr(lbuf_t *b)
{
    b->lhdr = (char *)lbuf_data(b) - (char *)lbuf_base(b);
}

static inline void *lbuf_lisp_hdr(lbuf_t *b)
{
    return b->lhdr != UINT16_MAX ? (char *)lbuf_base(b) + b->lhdr : NULL;
}



#endif /* LBUF_H_ */
