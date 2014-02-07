/*
 * lispd_generic_list.c
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

#include "generic_list.h"
#include <stdlib.h>


/**
 * lispd_list_gen_new - initializes the list
 * @cmp_fct: function to compare to data entries
 * @del_fct: function to deallocate a data entry
 */

glist_t *glist_new(
        int (*cmp_fct)(void *, void *),
        glist_del_fct del_fct) {
    glist_t    *glist  = NULL;

    if (!(glist = calloc(1, sizeof(glist_t))))
        return(NULL);
    if (!(glist->head = calloc(1, sizeof(glist_entry_t))))
        return(NULL);
    INIT_LIST_HEAD(&(glist->head->list));
    glist->size = 0;

    glist->cmp_fct = cmp_fct;
    glist->del_fct = del_fct;

    return(glist);
}

/**
 * lispd_list_gen_insert - insert new value to the list
 * @data: new value to be added
 * @head: list where data is to be inserted
 * @cmp_fct: function that compares two list entries
 *
 * Append a new entry to the list.
 * If cmp_fct is defined, it seeks incrementally, starting
 * at the head head, the position where cmp_fct fails and
 * inserts the new element there.
 */
int glist_add(void *data, glist_t *glist) {
    glist_entry_t    *new    = NULL;
    glist_entry_t    *tmp    = NULL;

    if (!(new = calloc(1, sizeof(glist_entry_t))))
        return(-1);

    new->data = data;
    INIT_LIST_HEAD(&new->list);

    if (!glist->cmp_fct) {
        list_add(&(new->list), &(glist->head->list));
    } else {
        list_for_each_entry(tmp, &(glist->head->list), list) {
            /* insert where cmp fails */
            if((*glist->cmp_fct)(data, tmp->data) <= 0)
                break;
        }
        list_add(&(new->list), &(tmp->list));
    }
    glist->size++;

    return(0);
}

/**
 * lispd_list_gen_insert - insert new value to the list
 * @data: new value to be added
 * @head: list where data is to be inserted
 *
 * Append a new entry to the end of the list.
 * If cmp_fct is defined, the element is not added
 */
int glist_add_tail(void *data, glist_t *glist) {
    glist_entry_t    *new    = NULL;

    if (glist->cmp_fct)
        return(-1);
    if (!(new = calloc(1, sizeof(glist_entry_t))))
        return(-1);

    new->data = data;
    INIT_LIST_HEAD(&new->list);
    list_add_tail(&(new->list), &(glist->head->list));
    glist->size++;

    return(0);
}

/**
 * lispd_generic_list_del - remove entry from list
 * @entry: entry to be removed
 * @list: list from which the entry is to be removed
 *
 * If del_fct is defined, entry->data will be freed using it
 *
 */
void glist_del(glist_entry_t *entry, glist_t *list) {
    list_del(&(entry->list));
    if(list->del_fct)
        (*list->del_fct)(entry->data);
//    else
//        free(entry->data);

    free(entry);
    list->size--;
}

void glist_destroy(glist_t *lst) {
    struct list_head *buf, *it;
    glist_entry_t *tmp;

    list_for_each_safe(it, buf, &(lst->head->list)) {
        tmp = list_entry(it, glist_entry_t, list);
        glist_del(tmp, lst);
    }

    free(lst->head);
    free(lst);
}

inline int glist_size(glist_t *list) {
    return(list->size);
}

inline void *glist_entry_data(glist_entry_t *entry) {
    return(entry->data);
}
