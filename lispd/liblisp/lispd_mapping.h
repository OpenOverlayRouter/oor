/*
 * lispd_mapping.h
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
 */

#ifndef LISPD_MAPPING_H_
#define LISPD_MAPPING_H_

//#include "lispd_locator.h"
//#include "lispd_address.h"
#include "lispd_types.h"
//#include "lispd_remdb.h"
#include <liblisp.h>



typedef enum {
    MAPPING_LOCAL,
    MAPPING_REMOTE,
    MAPPING_RE,
} mapping_type;

typedef void (*extended_info_del_fct)(void *);

typedef struct lispd_mapping_elt_ {
    lisp_addr_t                     eid_prefix;
    uint16_t                        locator_count;
    locators_list_t                 *head_v4_locators_list;
    locators_list_t                 *head_v6_locators_list;

    uint32_t                        ttl;
    uint8_t                         action;
    uint8_t                         authoritative;

    uint8_t                         eid_prefix_length;  /*to remove in future*/
    uint32_t                        iid;                /*to remove in future*/
    mapping_type                    type;               /*to remove in future*/
    void                            *extended_info;     /*to remove in future*/
    extended_info_del_fct           extended_info_del;  /*to remove in future*/
} mapping_t;


/*
 * Used to select the locator to be used for an identifier according to locators' priority and weight.
 *  v4_balancing_locators_vec: If we just have IPv4 RLOCs
 *  v6_balancing_locators_vec: If we just hace IPv6 RLOCs
 *  balancing_locators_vec: If we have IPv4 & IPv6 RLOCs
 *  For each packet, a hash of its tuppla is calculaed. The result of this hash is one position of the array.
 */

typedef struct balancing_locators_vecs_ {
    locator_t **v4_balancing_locators_vec;
    locator_t **v6_balancing_locators_vec;
    locator_t **balancing_locators_vec;
    int v4_locators_vec_length;
    int v6_locators_vec_length;
    int locators_vec_length;
} balancing_locators_vecs;


/* Structure to expand the lispd_mapping_elt used in lispd_map_cache_entry */
typedef struct lcl_mapping_extended_info_ {
    balancing_locators_vecs outgoing_balancing_locators_vecs;
    /* List of locators not initialized: interface without ip */
    locators_list_t *head_not_init_locators_list;
} lcl_mapping_extended_info;

/* Structure to expand the lispd_mapping_elt used in lispd_map_cache_entry */
typedef struct rmt_mapping_extended_info_ {
    balancing_locators_vecs rmt_balancing_locators_vecs;
} rmt_mapping_extended_info;



mapping_t *new_local_mapping(lisp_addr_t eid_prefix, uint8_t eid_prefix_length,
        int iid);

mapping_t *new_map_cache_mapping(lisp_addr_t eid_prefix,
        uint8_t eid_prefix_length, int iid);



inline mapping_t *mapping_new();
mapping_t *mapping_init_local(lisp_addr_t *);
mapping_t *mapping_init_static(lisp_addr_t *);
mapping_t *mapping_init_remote(lisp_addr_t *);
mapping_t *mapping_clone(mapping_t *);
void mapping_del(mapping_t *);
int mapping_cmp(mapping_t *, mapping_t *);

int mapping_add_locator(mapping_t *, locator_t *);
int mapping_add_locators(mapping_t *, locators_list_t *);
void mapping_update_locators(mapping_t *, locators_list_t *,
        locators_list_t *, int);
locator_t *mapping_get_locator(mapping_t *, lisp_addr_t *);
void mapping_sort_locators(mapping_t *, lisp_addr_t *);
void mapping_del_locators(mapping_t *);

int mapping_compute_balancing_vectors(mapping_t *);
void mapping_extended_info_del(mapping_t *);
int balancing_vectors_calculate(mapping_t *, balancing_locators_vecs *);
void balancing_vectors_to_char(balancing_locators_vecs, mapping_t *, int );

void mapping_to_char(mapping_t *m, int log_level);

static inline void *mapping_extended_info(mapping_t *m);
static inline void mapping_set_extended_info(mapping_t *, void *,
        extended_info_del_fct);
static inline void mapping_set_iid(mapping_t *m, uint32_t iid);
static inline void mapping_set_eid_addr(mapping_t *m, lisp_addr_t *addr);
static inline void mapping_set_eid_plen(mapping_t *m, uint8_t plen);
static inline uint16_t mapping_locator_count(mapping_t *);
static inline uint32_t mapping_ttl(mapping_t *);
static inline void mapping_set_ttl(mapping_t *, uint32_t);
static inline uint8_t mapping_action(mapping_t *);
static inline void mapping_set_action(mapping_t *, uint8_t);
static inline void mapping_set_auth(mapping_t *, uint8_t);
static inline uint16_t mapping_locator_count(mapping_t *);



static inline void *mapping_extended_info(mapping_t *m)
{
    if (m)
        return (m->extended_info);
    else
        return (NULL);
}

static inline void mapping_set_extended_info(mapping_t *m, void *ei,
        extended_info_del_fct ei_del_fct)
{
    m->extended_info = ei;
    m->extended_info_del = ei_del_fct;
}

static inline void mapping_set_iid(mapping_t *m, uint32_t iid)
{
    m->iid = iid;
}

static inline void mapping_set_eid_addr(mapping_t *m, lisp_addr_t *addr)
{
    lisp_addr_copy(mapping_eid(m), addr);
}

static inline void mapping_set_eid_plen(mapping_t *m, uint8_t plen)
{
    m->eid_prefix_length = plen;
}

static inline lisp_addr_t *mapping_eid(mapping_t *m)
{
    return (&(m->eid_prefix));
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

static inline void mapping_set_auth(mapping_t *m, uint8_t a)
{
    m->authoritative = a;
}




#endif /* LISPD_MAPPING_H_ */
