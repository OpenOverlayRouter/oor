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

#define NO_CMP NULL
#define NO_DEL NULL

typedef void (*glist_del_fct)(void *);
typedef int  (*glist_cmp_fct)(void *, void *);

typedef struct {
    struct list_head    list;
    void                *data;
} glist_entry_t;

typedef struct {
    glist_entry_t       head;
    int                 size;
    glist_cmp_fct       cmp_fct;
    glist_del_fct       del_fct;
} glist_t;


glist_t                 *glist_new();
glist_t                 *glist_new_managed(glist_del_fct);
glist_t                 *glist_new_full(glist_cmp_fct, glist_del_fct);
void                    glist_init_full(glist_t *, glist_cmp_fct, glist_del_fct);
void                    glist_init(glist_t *);
void                    glist_init_managed(glist_t *lst, glist_del_fct del_fct);
int                     glist_add(void *data, glist_t *list);
int                     glist_add_tail(void *data, glist_t *glist);
void                    glist_remove(glist_entry_t *entry, glist_t *list);
void                    glist_destroy(glist_t *lst);
void                    glist_remove_all(glist_t *lst);
//inline int              glist_size(glist_t *list);
//inline void             *glist_entry_data(glist_entry_t *entry);


inline static int glist_size(glist_t *list) {
    return(list->size);
}

inline static void *glist_entry_data(glist_entry_t *entry) {
    return(entry->data);
}

inline static glist_entry_t *glist_head(glist_t *lst) {
    return(lst->head);
}

inline static glist_entry_t *glist_first(glist_t *lst) {
    return(list_entry(lst->head.list.next, glist_entry_t, list));
}

inline static void *glist_first_data(glist_t *lst) {
    return(glist_entry_data(glist_first(lst)));
}

inline static glist_entry_t *glist_last(glist_t *lst) {
    return(list_entry(lst->head.list.prev, glist_entry_t, list));
}

inline static void *glist_last_data(glist_t *lst) {
    return(glist_entry_data(glist_last(lst)));
}

inline static glist_entry_t *glist_next(glist_entry_t *entry) {
    return(list_entry(entry->list.next, glist_entry_t, list));
}

/**
 * generic_list_for_each_entry  - iterates over list in generic_list_t
 * @ iter:  * of glist_entry_t type, to use as loop iterator
 * @ lst:   * the list of glist_t type, over whose elements to iterate
 */
#define glist_for_each_entry(iter, lst) \
    list_for_each_entry(iter, &((lst)->head.list), list)

/*
#define glist_for_each(pos, lst)              \
    for (pos = list_entry((lst->head)->next, glist_entry_t, list);  \
         &pos->list != (lst->head);                    \
         pos = list_entry(pos->member.next, glist_entry_t, list))
 *
 */

#endif /* LISPD_GENERIC_LIST_H_ */
