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

#include "llist/list.h"

typedef struct {
    struct list_head    list;
    void                *data;
} lispd_generic_list_entry_t;

typedef struct {
    lispd_generic_list_entry_t       *head;
    uint32_t                        size;
    int                             (*cmp_fct)(void *, void *);
    void                            (*del_fct)(void *);
} lispd_generic_list_t;


#define generic_list_for_each_entry(iter, lst) list_for_each_entry(iter, &((lst)->head.list), list)

lispd_generic_list_t    *generic_list_new( int (*cmp_fct)(void *, void *), void (*del_fct)(void *));
int                     generic_list_add(void *data, lispd_generic_list_t *list);
void                    generic_list_del(lispd_generic_list_entry_t *entry, lispd_generic_list_t *list);
void                    generic_list_destroy(lispd_generic_list_t *lst);
inline uint32_t         generic_list_size(lispd_generic_list_t *list);
inline void             *generic_list_entry_get_data(lispd_generic_list_entry_t *entry);

#endif /* LISPD_GENERIC_LIST_H_ */
