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

#include <stdlib.h>
#include "generic_list.h"
#include "oor_log.h"
#include "mem_util.h"

void
glist_init_complete(glist_t *lst, glist_cmp_fct cmp_fct, glist_del_fct del_fct)
{
    lst->cmp_fct = cmp_fct;
    lst->del_fct = del_fct;
    lst->size = 0;
    list_init(&(lst->head.list));
}

void
glist_init(glist_t *lst)
{
    glist_init_complete(lst, NULL, NULL);
}

void
glist_init_managed(glist_t *lst, glist_del_fct del_fct)
{
    glist_init_complete(lst, NULL, del_fct);
}


/**
 * glist_new_complete - initializes the list
 * @cmp_fct: function to compare to data entries
 * @del_fct: function to deallocate a data entry
 */

glist_t *
glist_new_complete(glist_cmp_fct cmp_fct, glist_del_fct del_fct)
{
    glist_t *glist = NULL;
    glist = xzalloc(sizeof(glist_t));

    glist_init_complete(glist, cmp_fct, del_fct);
    return(glist);
}

glist_t *
glist_new(void)
{
    return(glist_new_complete(NO_CMP, NO_DEL));
}

/* memory managed. when destroy is called all inner data is freed*/
glist_t *
glist_new_managed(glist_del_fct del)
{
    return(glist_new_complete(NO_CMP, del));
}


inline
glist_cmp_fct glist_get_cmp_fct(glist_t *lst)
{
    return (lst->cmp_fct);
}

inline
glist_del_fct glist_get_del_fct(glist_t *lst)
{
    return (lst->del_fct);
}

inline
void glist_set_cmp_fct(glist_t *lst, glist_cmp_fct cmp_fct)
{
    lst->cmp_fct = cmp_fct;
}

inline
void glist_set_del_fct(glist_t *lst, glist_del_fct del_fct)
{
    lst->del_fct = del_fct;
}

/* Use the indicated clone function to obtain a clone of the list */
glist_t *
glist_clone(glist_t *src_list, glist_clone_obj clone_obj)
{
    glist_t *list;
    glist_entry_t *it;
    void *obj;

    list = glist_new_complete(src_list->cmp_fct,src_list->del_fct);
    glist_for_each_entry(it, src_list){
            obj = glist_entry_data(it);
            glist_add(clone_obj(obj),list);
    }
    return (list);
}

/**
 * glist_add - insert new value to the list
 * @data: new value to be added
 * @glist: list where data is to be inserteds
 *
 * Append a new entry to the list.
 * If cmp_fct is defined, it seeks incrementally, starting
 * at the head head.
 */
int
glist_add(void *data, glist_t *glist)
{
    glist_entry_t *new = NULL;
    glist_entry_t *tmp = NULL;
    int ctr = 0;
    int cmp = 0;

    new = xzalloc(sizeof(glist_entry_t));
    new->data = data;
    list_init(&new->list);

    if (!glist->cmp_fct) {
        list_push_front(&glist->head.list, &new->list);
    } else {
        if (glist->size != 0) {
            glist_for_each_entry(tmp,glist){
                /* insert where new element is bigger than current one */
                cmp = (*glist->cmp_fct)(data, tmp->data);
                if( cmp == 2){
                    break;
                }else if (cmp < 0){
                    free(new);
                    return (BAD);
                }
                ctr++;
            }
            if (ctr != glist->size){
                list_push_front(tmp->list.prev, &new->list);
            }else{
                // Add at the end of the list
                list_push_back(&(glist->head.list), &(new->list));
            }
        }else{
            list_push_front( &glist->head.list, &new->list);
        }
    }
    glist->size++;
    return(GOOD);
}

/**
 * glist_add_tail - insert new value to the list
 * @data: new value to be added
 * @glist: list where data is to be inserted
 *
 * Append a new entry to the end of the list.
 * If cmp_fct is defined, the element is not added
 */
int
glist_add_tail(void *data, glist_t *glist)
{
    glist_entry_t *new = NULL;

    if (glist->cmp_fct) {
        return(BAD);
    }

    new = xzalloc(sizeof(glist_entry_t));
    new->data = data;
    list_init(&(new->list));

    list_push_back(&(glist->head.list), &(new->list));
    glist->size++;

    return(GOOD);
}

uint8_t
glist_contain(void *data, glist_t *list)
{
    glist_entry_t *entry = NULL;
    if (list->size == 0){
        return (FALSE);
    }
    glist_for_each_entry(entry,list){
        if(list->cmp_fct) {
            if((*list->cmp_fct)(data, entry->data) == 0){
                return(TRUE);
            }
        }else{
            if(entry->data == data){
                return(TRUE);
            }
        }
    }
    return(FALSE);
}

uint8_t
glist_contain_using_cmp_fct(void *data, glist_t *list,glist_cmp_fct  cmp_fct)
{
    glist_entry_t *entry = NULL;
    if (list->size == 0){
        return (FALSE);
    }
    glist_for_each_entry(entry,list){
        if(cmp_fct) {
            if((*cmp_fct)(data, entry->data) == 0){
                return(TRUE);
            }
        }else{
            if(entry->data == data){
                return(TRUE);
            }
        }
    }
    return(FALSE);
}

void
glist_dump(glist_t *list, glist_to_char_fct dump_fct, int log_level)
{
    glist_entry_t *     it          = NULL;
    void *              data        = NULL;
    int                 ctr         = 0;

    glist_for_each_entry(it,list){
        ctr++;
        data = glist_entry_data (it);
        OOR_LOG(log_level,"[%d] =>  %s",ctr,dump_fct(data));
    }
}


/**
 * glist_extract - remove entry from list without deleting object
 * @entry: entry to be removed
 * @list: list from which the entry is to be removed
 */
void
glist_extract(glist_entry_t *entry, glist_t *list)
{
    if (!entry || !list) {
        return;
    }

    list_remove(&(entry->list));

    free(entry);
    list->size--;
}

/**
 * glist_remove - remove entry from list
 * @entry: entry to be removed
 * @list: list from which the entry is to be removed
 *
 * If del_fct is defined, entry->data will be freed using it
 *
 */
void
glist_remove(glist_entry_t *entry, glist_t *list)
{
    if (!entry || !list) {
        return;
    }

    list_remove(&(entry->list));
    if(list->del_fct) {
        (*list->del_fct)(entry->data);
    }

    free(entry);
    list->size--;
}

/**
 * glist_remove_obj - remove object from list. The comparison function is used to get the entry to
 * be removed. If comparition function is not deffined, the value of the pointer is used to get the
 * elemnt to be removed
 * @data: object to be removed
 * @list: list from which the entry is to be removed
 */
void
glist_remove_obj(void *data, glist_t *list)
{
    glist_entry_t *remove_entry = NULL;
    glist_entry_t *entry;

    if (!list || list->size == 0) {
        return;
    }
    if(list->cmp_fct) {
        glist_for_each_entry(entry,list){
            if((*list->cmp_fct)(data, entry->data) == 0){
                remove_entry = entry;
                break;
            }
        }
    }else{
        glist_for_each_entry(entry,list){
            if(entry->data == data){
                remove_entry = entry;
                break;
            }
        }
    }
    if (remove_entry != NULL){
        glist_remove(remove_entry,list);
    }
}

/**
 * glist_remove_obj_with_ptr - remove object from list. The comparison function is
 * used to get the entry to be removed. IThe value of the pointer is used to get the
 * elemnt to be removed
 * @data: object to be removed
 * @list: list from which the entry is to be removed
 */
void
glist_remove_obj_with_ptr(void *data, glist_t *list)
{
    glist_entry_t *remove_entry = NULL;
    glist_entry_t *entry;

    if (!list || list->size == 0) {
        return;
    }

    glist_for_each_entry(entry,list){
        if(entry->data == data){
            remove_entry = entry;
            break;
        }
    }
    if (remove_entry != NULL){
        glist_remove(remove_entry,list);
    }
}


void
glist_remove_all(glist_t *lst)
{
    glist_entry_t *tmp, *aux_tmp;

    if (!lst || lst->size == 0) {
        return;
    }

    glist_for_each_entry_safe(tmp, aux_tmp, lst) {
        glist_remove(tmp, lst);
    }
}

void
glist_destroy(glist_t *lst)
{
    if (!lst) {
        return;
    }

    glist_remove_all(lst);
    free(lst);
}



