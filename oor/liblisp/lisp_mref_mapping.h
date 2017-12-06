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

#ifndef MREF_MAPPING_H_
#define MREF_MAPPING_H_

#include "lisp_address.h"
#include "lisp_locator.h"

/*
typedef enum {
    MAPPING_LOCAL,
    MAPPING_REMOTE,
    MAPPING_RE,
} mapping_type;
*/

typedef void (*extended_info_del_fct)(void *);

typedef struct mref_mapping {
    lisp_addr_t                     eid_prefix;
    uint16_t                        referral_count;
    uint16_t                        signature_count;

    glist_t                         *referral_lists; //<glist_t *>
    glist_t                         *signature_list;

    uint32_t                        ttl;
    uint8_t                         action;
    uint8_t                         authoritative;
    uint8_t                         incomplete;

    uint32_t                        iid;                /*to remove in future*/
} mref_mapping_t;

mref_mapping_t *mref_mapping_new();
mref_mapping_t *mref_mapping_new_init(lisp_addr_t *);
mref_mapping_t *mref_mapping_new_init_full(lisp_addr_t *, int, lisp_ref_action_e, lisp_authoritative_e, int,
        glist_t *, glist_t *, lisp_addr_t *);
void mref_mapping_del(mref_mapping_t *);
int mref_mapping_cmp(mref_mapping_t *, mref_mapping_t *);
mref_mapping_t *mref_mapping_clone(mref_mapping_t *);
char *mref_mapping_to_char(mref_mapping_t *m);

int mref_mapping_add_referral(mref_mapping_t *, locator_t *);
/* This function extract the referral from the list of referrals of the mapping */
int mref_mapping_remove_referral(mref_mapping_t *mref_mapping,locator_t *referral);
void mref_mapping_remove_referrals(mref_mapping_t *mref_mapping);
void mref_mapping_update_referrals(mref_mapping_t *, glist_t *);
locator_t *mref_mapping_get_ref_with_addr(mref_mapping_t *, lisp_addr_t *);
glist_t *mref_mapping_get_ref_lst_with_afi(mref_mapping_t *mref_mapping, lm_afi_t lafi, int afi);
glist_t *mref_mapping_get_ref_lst_with_addr_type(mref_mapping_t * mref_mapping,lisp_addr_t *addr);
uint8_t mref_mapping_has_referral(mref_mapping_t *mref_mapping, locator_t *ref);
int mref_mapping_sort_referrals(mref_mapping_t *, lisp_addr_t *);
int mref_mapping_activate_referral(mref_mapping_t *map,locator_t *ref, lisp_addr_t *new_addr);
glist_t *mref_mapping_get_ref_addrs(mref_mapping_t *mref_mapping);

static inline lisp_addr_t *mref_mapping_eid(mref_mapping_t *m);
static inline void mref_mapping_set_eid(mref_mapping_t *m, lisp_addr_t *addr);
static inline void mref_mapping_set_iid(mref_mapping_t *m, uint32_t iid);
static inline glist_t *mref_mapping_referral_lists(mref_mapping_t *m);
static inline uint16_t mref_mapping_referral_count(mref_mapping_t *);
static inline uint32_t mref_mapping_ttl(mref_mapping_t *);
static inline void mref_mapping_set_ttl(mref_mapping_t *, uint32_t);
static inline uint8_t mref_mapping_action(mref_mapping_t *);
static inline void mref_mapping_set_action(mref_mapping_t *, uint8_t);
static inline uint8_t mref_mapping_auth(const mref_mapping_t *);
static inline void mref_mapping_set_auth(mref_mapping_t *, uint8_t);
static inline uint8_t mref_mapping_incomplete(const mref_mapping_t *);
static inline void mref_mapping_set_incomplete(mref_mapping_t *, uint8_t);

/*****************************************************************************/

static inline lisp_addr_t *mref_mapping_eid(mref_mapping_t *m)
{
    return (&m->eid_prefix);
}

static inline void mref_mapping_set_eid(mref_mapping_t *m, lisp_addr_t *addr)
{
    lisp_addr_copy(mref_mapping_eid(m), addr);
}

static inline void mref_mapping_set_iid(mref_mapping_t *m, uint32_t iid)
{
    m->iid = iid;
}


static inline glist_t *mref_mapping_referral_lists(mref_mapping_t *m)
{
    return (m->referral_lists);
}

static inline uint16_t mref_mapping_referral_count(mref_mapping_t *m)
{
    return(m->referral_count);
}


static inline uint32_t mref_mapping_ttl(mref_mapping_t *m)
{
    return(m->ttl);
}

static inline void mref_mapping_set_ttl(mref_mapping_t *m, uint32_t t)
{
    m->ttl = t;
}

static inline uint8_t mref_mapping_action(mref_mapping_t *m)
{
    return(m->action);
}

static inline void mref_mapping_set_action(mref_mapping_t *m, uint8_t a)
{
    m->action = a;
}

static inline uint8_t mref_mapping_auth(const mref_mapping_t *m)
{
    return(m->authoritative);
}

static inline void mref_mapping_set_auth(mref_mapping_t *m, uint8_t a)
{
    m->authoritative = a;
}

static inline uint8_t mref_mapping_incomplete(const mref_mapping_t *m)
{
    return(m->incomplete);
}

static inline void mref_mapping_set_incomplete(mref_mapping_t *m, uint8_t i)
{
    m->incomplete = i;
}

/* For all referrals */
#define mref_mapping_foreach_referral(_map, _loct) \
        do { \
            glist_t *_loct_list_; \
            glist_entry_t *_it_list_; \
            glist_entry_t *_it_loct_; \
            \
            glist_for_each_entry(_it_list_,_map->referral_lists){ \
                _loct_list_ = (glist_t *)glist_entry_data(_it_list_); \
                if (glist_size(_loct_list_) == 0){ \
                    continue; \
                } \
                glist_for_each_entry(_it_loct_,_loct_list_){ \
                    _loct = (locator_t *)glist_entry_data(_it_loct_); \

#define mref_mapping_foreach_referral_end \
                } \
            } \
       }while(0)


#endif /* MREF_MAPPING_H_ */
