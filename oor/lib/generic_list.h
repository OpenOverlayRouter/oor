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

#ifndef GENERIC_LIST_H_
#define GENERIC_LIST_H_

#include <stdint.h>
#include "../elibs/ovs/list.h"

#define NO_CMP NULL
#define NO_DEL NULL

typedef void (*glist_del_fct)(void *);
/*
 * Return:
 *      -1 if error in the comparison
 *       0 if both elements are equal
 *       1 if first element is bigger than the second one
 *       2 if second element is bigger than the first one
 */
typedef int  (*glist_cmp_fct)(void *, void *);
typedef char *(*glist_to_char_fct)(void *);
typedef void *(*glist_clone_obj)(void *);

typedef struct glist_entry_t_ {
    struct ovs_list    list;
    void                *data;
} glist_entry_t;

typedef struct {
    glist_entry_t       head;
    int                 size;
    glist_cmp_fct       cmp_fct;
    glist_del_fct       del_fct;
} glist_t;


glist_t *glist_new(void);
glist_t *glist_new_managed(glist_del_fct);
glist_t *glist_new_complete(glist_cmp_fct, glist_del_fct);
void glist_init_complete(glist_t *, glist_cmp_fct, glist_del_fct);
void glist_init(glist_t *);
void glist_init_managed(glist_t *lst, glist_del_fct del_fct);
inline glist_cmp_fct glist_get_cmp_fct(glist_t *lst);
inline glist_del_fct glist_get_del_fct(glist_t *lst);
inline void glist_set_cmp_fct(glist_t *lst, glist_cmp_fct cmp_fct);
inline void glist_set_del_fct(glist_t *lst, glist_del_fct del_fct);
glist_t *glist_clone(glist_t *, glist_clone_obj clone_obj);
int glist_add(void *data, glist_t *list);
int glist_add_tail(void *data, glist_t *glist);
uint8_t glist_contain(void *data, glist_t *list);
uint8_t glist_contain_using_cmp_fct(void *data, glist_t *list,
        glist_cmp_fct  cmp_fct);
void glist_extract(glist_entry_t *entry, glist_t *list);
void glist_remove(glist_entry_t *entry, glist_t *list);
void glist_remove_obj(void * data,glist_t * list);
void glist_remove_obj_with_ptr(void * data, glist_t * list);
void glist_dump(glist_t *list, glist_to_char_fct dump_fct, int log_level);
void glist_destroy(glist_t *lst);
void glist_remove_all(glist_t *lst);

static inline int glist_size(glist_t *list);
static inline void *glist_entry_data(glist_entry_t *entry);
static inline glist_entry_t *glist_head(glist_t *lst);
static inline glist_entry_t *glist_first(glist_t *lst);
static inline void *glist_first_data(glist_t *lst);
static inline glist_entry_t *glist_last(glist_t *lst);
static inline void *glist_last_data(glist_t *lst);
static inline glist_entry_t *glist_next(glist_entry_t *entry);
static inline glist_entry_t *glist_prev(glist_entry_t *entry);

static inline int
glist_size(glist_t *list)
{
    return(list->size);
}

static inline void *
glist_entry_data(glist_entry_t *entry)
{
    return(entry->data);
}

static inline glist_entry_t *
glist_head(glist_t *lst)
{
    return(&lst->head);
}

static inline glist_entry_t *
glist_first(glist_t *lst)
{
    if (lst->size == 0){
        return (NULL);
    }
    return (CONTAINER_OF(glist_next(&lst->head), glist_entry_t, list));
}

static inline void *
glist_first_data(glist_t *lst)
{
    if (lst->size == 0){
        return (NULL);
    }
    return(glist_entry_data(glist_first(lst)));
}

static inline glist_entry_t *
glist_last(glist_t *lst)
{
    return (CONTAINER_OF(glist_prev(&lst->head), glist_entry_t, list));
}

static inline void *
glist_last_data(glist_t *lst)
{
    return(glist_entry_data(glist_last(lst)));
}

static inline glist_entry_t *
glist_next(glist_entry_t *entry)
{
    return(CONTAINER_OF(entry->list.next, glist_entry_t, list));
}

static inline glist_entry_t *
glist_prev(glist_entry_t *entry)
{
    return(CONTAINER_OF(entry->list.prev, glist_entry_t, list));
}

/**
 * generic_list_for_each_entry  - iterates over list in generic_list_t
 * @ iter:  * of glist_entry_t type, to use as loop iterator
 * @ lst:   * the list of glist_t type, over whose elements to iterate
 */
#define glist_for_each_entry(iter_, lst_) \
        LIST_FOR_EACH(iter_,list,&((lst_)->head.list))

/**
 * generic_list_for_each_entry  - iterates over list in generic_list_t
 * safe against removal of list entry
 * @ iter:  * of glist_entry_t type, to use as loop iterator
 * @ aux_iter: * of glist_entry_t type, to use as temporary storage
 * @ lst:   * the list of glist_t type, over whose elements to iterate
 */
#define glist_for_each_entry_safe(iter_, aux_iter_, lst_) \
        LIST_FOR_EACH_SAFE(iter_, aux_iter_, list,&((lst_)->head.list))

#endif /* GENERIC_LIST_H_ */
