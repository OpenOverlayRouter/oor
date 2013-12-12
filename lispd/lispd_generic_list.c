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

#include "lispd_generic_list.h"
#include "defs.h"


/**
 * lispd_list_gen_new - initializes the list
 * @cmp_fct: function to compare to data entries
 * @del_fct: function to deallocate a data entry
 */
lispd_generic_list_t *generic_list_new(
        int (*cmp_fct)(void *, void *),
        void (*del_fct)(void *)) {
    lispd_generic_list_t    *glist  = NULL;

    glist = calloc(1, sizeof(lispd_generic_list_t));
    glist->size = 0;
    glist->head = NULL;

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
int generic_list_add(void *data, lispd_generic_list_t *list) {
    lispd_generic_list_entry_t    *new    = NULL;
    lispd_generic_list_entry_t    *tmp    = NULL;

    if (!(new = calloc(1, sizeof(lispd_generic_list_t))))
        return(ERR_MALLOC);

    new->data = data;

    if (!list->cmp_fct) {
        list_add(new->list, list->head);
    } else {
        list_for_each_entry(tmp, list->head, list) {
            /* insert where cmp fails */
            if(cmp_fct(data, tmp->data) <= 0)
                break;
        }
        list_add(new->list, tmp->list);
    }
    list->size++;

    return(GOOD);
}

/**
 * lispd_generic_list_del - remove entry from list
 * @entry: entry to be removed
 * @list: list from which the entry is to be removed
 *
 * If del_fct is defined, entry->data will be freed using it,
 * otherwise free is used
 */
void lispd_generic_list_del(lispd_generic_list_entry_t *entry, lispd_generic_list_t *list) {
    list_del(entry->list);
    if(list->del_fct)
        list->del_fct(entry->data);
    else
        free(entry->data);

    free(entry);
    list->size--;
}

void generic_list_destroy(lispd_generic_list_t *lst) {
    struct list_head *buf, *it;
    lispd_generic_list_entry_t *tmp;

    list_for_each_safe(it, buf, lst->head) {
        tmp = list_entry(it, lispd_generic_list_entry_t, list);
        lispd_generic_list_del(tmp, lst);
    }

    free(lst);
}

inline uint32_t generic_list_size(lispd_generic_list_t *list) {
    return(list->size);
}

void *generic_list_entry_get_data(lispd_generic_list_entry_t *entry) {
    assert(entry);
    return(entry->data);
}
