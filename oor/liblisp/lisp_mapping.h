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

#ifndef MAPPING_H_
#define MAPPING_H_

#include "lisp_address.h"
#include "lisp_locator.h"


typedef enum {
    MAPPING_LOCAL,
    MAPPING_REMOTE,
    MAPPING_RE,
} mapping_type;

typedef void (*extended_info_del_fct)(void *);

typedef struct mapping {
    lisp_addr_t                     eid_prefix;
    uint16_t                        locator_count;

    glist_t                         *locators_lists; //<glist_t *>

    uint32_t                        ttl;
    uint8_t                         action;
    uint8_t                         authoritative;

    uint32_t                        iid;                /*to remove in future*/
} mapping_t;

inline mapping_t *mapping_new();
inline mapping_t *mapping_new_init(lisp_addr_t *);
void mapping_del(mapping_t *);
int mapping_cmp(mapping_t *, mapping_t *);
mapping_t *mapping_clone(mapping_t *);
char *mapping_to_char(mapping_t *m);

int mapping_add_locator(mapping_t *, locator_t *);
/* This function extract the locator from the list of locators of the mapping */
int mapping_remove_locator(mapping_t *mapping,locator_t *loct);
void mapping_remove_locators(mapping_t *mapping);
void mapping_update_locators(mapping_t *, glist_t *);
locator_t *mapping_get_loct_with_addr(mapping_t *, lisp_addr_t *);
glist_t *mapping_get_loct_lst_with_afi(mapping_t *mapping, lm_afi_t lafi, int afi);
glist_t *mapping_get_loct_lst_with_addr_type(mapping_t * mapping,lisp_addr_t *addr);
uint8_t mapping_has_locator(mapping_t *mapping, locator_t *loct);
int mapping_sort_locators(mapping_t *, lisp_addr_t *);
int mapping_activate_locator(mapping_t *map,locator_t *loct, lisp_addr_t *new_addr);

static inline lisp_addr_t *mapping_eid(mapping_t *m);
static inline void mapping_set_eid(mapping_t *m, lisp_addr_t *addr);
static inline void mapping_set_iid(mapping_t *m, uint32_t iid);
static inline glist_t *mapping_locators_lists(mapping_t *m);
static inline uint16_t mapping_locator_count(mapping_t *);
static inline uint32_t mapping_ttl(mapping_t *);
static inline void mapping_set_ttl(mapping_t *, uint32_t);
static inline uint8_t mapping_action(mapping_t *);
static inline void mapping_set_action(mapping_t *, uint8_t);
static inline uint8_t mapping_auth(const mapping_t *);
static inline void mapping_set_auth(mapping_t *, uint8_t);

/*****************************************************************************/

static inline lisp_addr_t *mapping_eid(mapping_t *m)
{
    return (&m->eid_prefix);
}

static inline void mapping_set_eid(mapping_t *m, lisp_addr_t *addr)
{
    lisp_addr_copy(mapping_eid(m), addr);
}

static inline void mapping_set_iid(mapping_t *m, uint32_t iid)
{
    m->iid = iid;
}


static inline glist_t *mapping_locators_lists(mapping_t *m)
{
    return (m->locators_lists);
}

static inline uint16_t mapping_locator_count(mapping_t *m)
{
    return(m->locator_count);
}


static inline uint32_t mapping_ttl(mapping_t *m)
{
    return(m->ttl);
}

static inline void mapping_set_ttl(mapping_t *m, uint32_t t)
{
    m->ttl = t;
}

static inline uint8_t mapping_action(mapping_t *m)
{
    return(m->action);
}

static inline void mapping_set_action(mapping_t *m, uint8_t a)
{
    m->action = a;
}

static inline uint8_t mapping_auth(const mapping_t *m)
{
    return(m->authoritative);
}

static inline void mapping_set_auth(mapping_t *m, uint8_t a)
{
    m->authoritative = a;
}

/* For all locators */
#define mapping_foreach_locator(_map, _loct) \
        do { \
            glist_t *_loct_list_; \
            glist_entry_t *_it_list_; \
            glist_entry_t *_it_loct_; \
            \
            glist_for_each_entry(_it_list_,_map->locators_lists){ \
                _loct_list_ = (glist_t *)glist_entry_data(_it_list_); \
                if (glist_size(_loct_list_) == 0){ \
                    continue; \
                } \
                glist_for_each_entry(_it_loct_,_loct_list_){ \
                    _loct = (locator_t *)glist_entry_data(_it_loct_); \

#define mapping_foreach_locator_end \
                } \
            } \
       }while(0)



/* For each locator that has an active address. If the locator status is down it will
 * also be returned */
#define mapping_foreach_active_locator(_map, _loct) \
        do { \
            glist_t *_loct_list_; \
            glist_entry_t *_it_list_; \
            glist_entry_t *_it_loct_; \
            locator_t *_locator_; \
            \
            glist_for_each_entry(_it_list_,_map->locators_lists){ \
                _loct_list_ = (glist_t *)glist_entry_data(_it_list_); \
                if (glist_size(_loct_list_) == 0){ \
                    continue; \
                } \
                _locator_ = (locator_t *)glist_first_data(_loct_list_); \
                if (lisp_addr_is_no_addr(locator_addr(_locator_)) == TRUE){ \
                    continue; \
                } \
                glist_for_each_entry(_it_loct_,_loct_list_){ \
                    _loct = (locator_t *)glist_entry_data(_it_loct_); \

#define mapping_foreach_active_locator_end \
                } \
            } \
       }while(0)



#endif /* MAPPING_H_ */
