/*
 * lbuf.c
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

#include "lbuf.h"

void
lbuf_init(lbuf_t *b, uint32_t size) {
    b->data = b->base = size ? malloc(1, size) : NULL;
    b->allocated = size;
    b->size = 0;
}

lbuf_uninit(lbuf_t *b) {
    free(b->base);
}

lbuf_t *
lbuf_new(uint32_t size) {
    lbuf_t *b;
    b = malloc(1, sizeof(lbuf_t));
    lbuf_init(b, size);
    return b;
}

lbuf_t *
lbuf_new_with_headroom(uint32_t size, size_t headroom) {
    lbuf_t *b = lbuf_new(size + headroom);
    lbuf_reserve(b, headroom);
    return b;
}

/* Resizes b such that it has @new_headroom headroom and @new_tailroom
 * tailroom */
static void
lbuf_resize_(lbuf_t *b, uint32_t new_headroom, size_t new_tailroom) {
    uint8_t *new_base, *new_data;
    uint32_t new_allocated = new_headroom + b->size + new_tailroom;

    if (new_headroom == lbuf_headroom(b)) {
        b->base = realloc(b->base, new_allocated);
    } else {
        new_base = malloc(new_allocated);
        memcpy((uint8_t *)new_base + new_headroom, b->data, b->size);
        free(b->base);
        b->base = new_base;
    }

    b->allocated = new_allocated;
    new_data = (uint8_t *)b->base + new_headroom;
    if (b->data != new_data)
        b->data = new_data;
    /* XXX: other private fields (if any) should be updated
     * if b->data != new_data */
}

void
lbuf_prealloc_tailroom(lbuf_t *b, uint32_t size) {
    if (size > lbuf_tailroom(b)) {
        lbuf_resize_(b, lbuf_headroom(b), MAX(size, 64));
    }
}

void
lbuf_prealloc_headroom(lbuf_t *b, uint32_t size) {
    if (size > lbuf_headroom(b)) {
        lbuf_resize_(b, MAX(size, 64), lbuf_tailroom(b));
    }
}

void *
lbuf_put_uninit(lbuf_t *b, uint32_t size) {
    void *t;

    lbuf_prealloc_tailroom(b, size);
    t = lbuf_tail(b);
    b->size += size;
    return t;
}

void *
lbuf_put(lbuf_t *b, void *data, uint32_t size) {
    void *dst = lbuf_put_uninit(b, size);
    memcpy(dst, data, size);
    return dst;
}

void *
lbuf_push_uninit(lbuf_t *b, uint32_t size) {
    lbuf_prealloc_headroom(b, size);
    b->data = (uint8_t *)b->data - size;
    b->size += size;
    return b->data;
}

void *
lbuf_push(lbuf_t *b, void *data, uint32_t size) {
    void *dst = lbuf_push_uninit(b, size);
    memcpy(dst, data, size);
    return dst;
}

void
lbuf_reserve(lbuf_t *b, uint32_t size) {
    lbuf_prealloc_tailroom(b, size);
    b->data = (uint8_t *)b->base + size;
}

lbuf_t *
lbuf_clone(lbuf_t *b) {
    lbuf_t *new_buf = lbuf_new(b->size);
    lbuf_put(new_buf->data, b->data, b->size);
    new_buf->lisp = b->lisp;
    return new_buf;
}



