/*
 * lisp_mapping.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send registration messages for each database mapping to
 * configured map-servers.
 *
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 *    Albert Lopez      <alopez@ac.upc.edu>
 *    Florin Coras      <fcoras@ac.upc.edu>
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
void mapping_update_locators(mapping_t *, glist_t *);
locator_t *mapping_get_loct_with_addr(mapping_t *, lisp_addr_t *);
glist_t *mapping_get_loct_lst_with_afi(mapping_t *mapping, lm_afi_t lafi, int afi);
glist_t *mapping_get_loct_lst_with_addr_type(mapping_t * mapping,lisp_addr_t *addr);
uint8_t mapping_has_locator(mapping_t *mapping, locator_t *loct);
int mapping_sort_locators(mapping_t *, lisp_addr_t *);
int mapping_activate_locator(mapping_t *map,locator_t *loct);

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


#endif /* MAPPING_H_ */
