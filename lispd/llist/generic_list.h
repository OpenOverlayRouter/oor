/*
 * lispd_generic_list.h
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

#ifndef LISPD_GENERIC_LIST_H_
#define LISPD_GENERIC_LIST_H_

#include "list.h"

typedef struct {
    struct list_head    list;
    void                *data;
} glist_entry_t;

typedef struct {
    glist_entry_t       *head;
    int                 size;
    int                 (*cmp_fct)(void *, void *);
    void                (*del_fct)(void *);
} glist_t;

/**
 * generic_list_for_each_entry  - iterates over list in generic_list_t
 * @ iter:  * of lispd_generic_list_t to use as loop counter
 * @ lst:   * to the list over which to iterate
 */
#define glist_for_each_entry(iter, lst) \
    list_for_each_entry(iter, &((lst)->head->list), list)

glist_t                 *glist_new(int (*cmp_fct)(void *, void *), void (*del_fct)(void *));
int                     glist_add(void *data, glist_t *list);
void                    glist_del(glist_entry_t *entry, glist_t *list);
void                    glist_destroy(glist_t *lst);
inline int              glist_size(glist_t *list);
inline void             *glist_entry_get_data(glist_entry_t *entry);

#endif /* LISPD_GENERIC_LIST_H_ */
