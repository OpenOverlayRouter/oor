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

#include <stdint.h>
#include <stdlib.h>

#include "lbuf.h"
#include "oor_log.h"
#include "mem_util.h"


static void
lbuf_init__(lbuf_t *b, uint32_t allocated, lbuf_source_e source)
{
    b->allocated = allocated;
    b->source = source;
    b->size = 0;
    b->lisp = b->ip = b->udp = b->lhdr = b->l3 = b->l4 = UINT16_MAX;
}

static void
lbuf_use__(lbuf_t *b, void *data, uint32_t allocated, lbuf_source_e source)
{
    lbuf_set_base(b, data);
    lbuf_set_data(b, data);

    lbuf_init__(b, allocated, source);
}

/* Initializes 'b' as an empty lbuf that contains the 'allocated' bytes of
 * memory starting at 'base'. 'base' should be obtained with malloc(). It
 * will be freed on resized or freed */
void
lbuf_use(lbuf_t *b, void *base, uint32_t allocated)
{
    lbuf_use__(b, base, allocated, LBUF_MALLOC);
}

/* Initializes 'b' as an empty lbuf that contains the 'allocated' bytes of
 * memory starting at 'base'. 'base' should point to a buffer allocated on
 * the stack. There's no need to uninit the buffer */
void
lbuf_use_stack(lbuf_t *b, void *base, uint32_t allocated)
{
    lbuf_use__(b, base, allocated, LBUF_STACK);
}

void
lbuf_init(lbuf_t *b, uint32_t size)
{
    lbuf_use(b, size ? xzalloc(size) : NULL, size);
}

void
lbuf_uninit(lbuf_t *b)
{
    if (b) {
        if (b->source == LBUF_MALLOC) {
            free(b->base);
        }
    }
}

lbuf_t *
lbuf_new(uint32_t size)
{
    lbuf_t *b;
    b = xzalloc(sizeof(lbuf_t));
    lbuf_init(b, size);
    return b;
}

inline void
lbuf_del(lbuf_t *b)
{
    if (b) {
        lbuf_uninit(b);
        free(b);
    }
}

lbuf_t *
lbuf_new_with_headroom(uint32_t size, uint32_t headroom)
{
    lbuf_t *b = lbuf_new(size + headroom);
    lbuf_reserve(b, headroom);
    return b;
}

/* Resizes b such that it has @new_headroom headroom and @new_tailroom
 * tailroom */
static void
lbuf_resize_(lbuf_t *b, uint32_t new_headroom, size_t new_tailroom)
{
    uint8_t *new_base;
    uint32_t new_allocated = new_headroom + b->size + new_tailroom;
    uint32_t diff_offset = new_headroom - lbuf_headroom(b);

    if (new_headroom == lbuf_headroom(b)) {
        b->base = xrealloc(b->base, new_allocated);
    } else {
        new_base = xmalloc(new_allocated);
        memcpy((uint8_t *)new_base + new_headroom, b->data, b->size);
        free(b->base);
        b->base = new_base;
        if (b->ip != UINT16_MAX){
            b->ip = b->ip + diff_offset;
        }
        if (b->udp != UINT16_MAX){
            b->udp = b->udp + diff_offset;
        }
        if (b->lhdr != UINT16_MAX){
            b->lhdr = b->lhdr + diff_offset;
        }
        if (b->l3 != UINT16_MAX){
            b->l3 = b->l3 + diff_offset;
        }
        if (b->l4 != UINT16_MAX){
            b->l4 = b->l4 + diff_offset;
        }
        if (b->lisp != UINT16_MAX){
            b->lisp = b->lisp + diff_offset;
        }
    }

    b->allocated = new_allocated;
    b->data = (uint8_t *)b->base + new_headroom;

}

void
lbuf_prealloc_tailroom(lbuf_t *b, uint32_t size)
{
    if (size > lbuf_tailroom(b)) {
        lbuf_resize_(b, lbuf_headroom(b), MAX(size, 64));
    }
}

void
lbuf_prealloc_headroom(lbuf_t *b, uint32_t size)
{
    if (size > lbuf_headroom(b)) {
        lbuf_resize_(b, MAX(size, 64), lbuf_tailroom(b));
    }
}

void *
lbuf_put_uninit(lbuf_t *b, uint32_t size)
{
    void *t;

    lbuf_prealloc_tailroom(b, size);
    t = lbuf_tail(b);
    b->size += size;
    return t;
}

void *
lbuf_put(lbuf_t *b, void *data, uint32_t size)
{
    void *dst = lbuf_put_uninit(b, size);
    memcpy(dst, data, size);
    return dst;
}

void *
lbuf_push_uninit(lbuf_t *b, uint32_t size)
{
    lbuf_prealloc_headroom(b, size);
    b->data = (char *)b->data - size;
    b->size += size;
    return b->data;
}

void *
lbuf_push(lbuf_t *b, void *data, uint32_t size)
{
    void *dst = lbuf_push_uninit(b, size);
    memcpy(dst, data, size);
    return dst;
}

void
lbuf_reserve(lbuf_t *b, uint32_t size)
{
    lbuf_prealloc_tailroom(b, size);
    b->data = (char *)b->base + size;
}

lbuf_t *
lbuf_clone(lbuf_t *b)
{
    lbuf_t *new_buf = lbuf_new(b->size);
    lbuf_put(new_buf->data, b->data, b->size);
    new_buf->lisp = b->lisp;
    return new_buf;
}

inline int lbuf_point_to_ip(lbuf_t *b)
{
    if (b->ip == UINT16_MAX){
        OOR_LOG(LDBG_2,"lbuf_data_to_ip: IP header not specified in buffer");
        return (BAD);
    }
    b->size = lbuf_tail(b) - lbuf_ip(b);
    b->data = lbuf_ip(b);

    return (GOOD);
}

inline int lbuf_point_to_udp(lbuf_t *b)
{
    if (b->udp == UINT16_MAX){
        OOR_LOG(LDBG_2,"lbuf_data_to_udp: UDP header not specified in buffer");
        return (BAD);
    }
    b->size = lbuf_tail(b) - lbuf_udp(b);
    b->data = lbuf_udp(b);

    return (GOOD);
}

inline int lbuf_point_to_lisp_hdr(lbuf_t *b)
{
    if (b->lhdr == UINT16_MAX){
        OOR_LOG(LDBG_2,"lbuf_data_to_lisp_hdr: LISP Encap header not specified in buffer");
        return (BAD);
    }
    b->size = lbuf_tail(b) - lbuf_lisp_hdr(b);
    b->data = lbuf_lisp_hdr(b);

    return (GOOD);
}

inline int lbuf_point_to_l3(lbuf_t *b)
{
    if (b->l3 == UINT16_MAX){
        OOR_LOG(LDBG_2,"lbuf_data_to_l3: Inner IP header not specified in buffer");
        return (BAD);
    }
    b->size = lbuf_tail(b) - lbuf_l3(b);
    b->data = lbuf_l3(b);

    return (GOOD);
}

inline int lbuf_point_to_l4(lbuf_t *b)
{
    if (b->l4 == UINT16_MAX){
        OOR_LOG(LDBG_2,"lbuf_data_to_l4: Inner UDP header not specified in buffer");
        return (BAD);
    }
    b->size = lbuf_tail(b) - lbuf_l4(b);
    b->data = lbuf_l4(b);

    return (GOOD);
}

inline int lbuf_point_to_lisp(lbuf_t *b)
{
    if (b->lisp == UINT16_MAX){
        OOR_LOG(LDBG_2,"lbuf_data_to_lisp: LISP header not specified in buffer");
        return (BAD);
    }
    b->size = lbuf_tail(b) - lbuf_lisp(b);
    b->data = lbuf_lisp(b);

    return (GOOD);
}
