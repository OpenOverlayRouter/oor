/*
 * lisp_xtr.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
 * All rights reserved.
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


#ifndef LISP_XTR_H_
#define LISP_XTR_H_

#include "defs.h"
#include "lisp_ctrl_device.h"

typedef enum tr_type {
    xTR_TYPE,
    RTR_TYPE,
    PITR_TYPE,
    PETR_TYPE
} tr_type_e;

typedef struct lisp_xtr {
    lisp_ctrl_dev_t super; /* base "class" */

    tr_type_e tr_type;

    /* xtr interface */
    mapping_t *(*lookup_eid_map_cache)(lisp_addr_t *eid);
    mapping_t *(*lookup_eid_local_map_db)(lisp_addr_t *eid);
    int (*add_mapping_to_map_cache)(mapping_t *mapping);
    int (*add_mapping_to_local_map_db)(mapping_t *mapping);

    int map_request_retries;
    int probe_interval;
    int probe_retries;
    int probe_retries_interval;

    mcache_entry_t *petrs;
    lisp_addr_list_t *pitrs;

    /* DATABASES */
    map_cache_db_t *map_cache;
    local_map_db_t *local_mdb;

    /* MAP RESOLVERS */
    lisp_addr_list_t *map_resolvers;

    /* MAP SERVERs */
    map_server_list_t *map_servers;
    char *map_server_key;
    int map_server_key_type;

    /* NAT */
    int nat_aware;
    int nat_status;
    lisp_site_id site_id;
    lisp_xtr_id xtr_id;

    nonces_list_t *nat_emr_nonces;
    nonces_list_t *nat_ir_nonces;

    /* TIMERS */
    timer *map_register_timer;
    timer *smr_timer;

    /* LOCAL IFACE MAPPING */
    /* in case of RTR can be used for outgoing load balancing */
    mapping_t *all_locs_map;

} lisp_xtr_t;

typedef struct _timer_rloc_prob_argument {
    mapping_t   *mapping;
    locator_t   *locator;
} timer_rloc_probe_argument;

typedef struct map_server_list {
    lisp_addr_t *address;
    uint8_t key_type;
    char *key;
    uint8_t proxy_reply;
    struct map_server_list *next;
} map_server_list_t;


int tr_mcache_add_mapping(lisp_xtr_t *, mapping_t *);
int tr_mcache_add_static_mapping(lisp_xtr_t *, mapping_t *);
int tr_mcache_remove_mapping(lisp_xtr_t *, lisp_addr_t *);
mapping_t *tr_mcache_lookup_mapping(lisp_xtr_t *, lisp_addr_t *);
mapping_t *tr_mcache_lookup_mapping_exact(lisp_xtr_t *, lisp_addr_t *);

#endif /* LISP_XTR_H_ */
