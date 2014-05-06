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

#include <defs.h>
#include "lisp_ctrl_device.h"

typedef struct _lisp_xtr {
    lisp_ctrl_dev_t super; /* base "class" */

    /* xtr interface */
    mapping_t *(*lookup_eid_map_cache)(lisp_addr_t *eid);
    mapping_t *(*lookup_eid_local_map_db)(lisp_addr_t *eid);
    int (*add_mapping_to_map_cache)(mapping_t *mapping);
    int (*add_mapping_to_local_map_db)(mapping_t *mapping);

    int map_request_retries;
    int probe_interval;
    int probe_retries;
    int probe_retries_interval;

    lisp_site_ID site_ID;
    lisp_xTR_ID xTR_ID;
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
    char *nat_site_ID;
    char *nat_xTR_ID;
    nonces_list_t *nat_emr_nonces;
    nonces_list_t *nat_ir_nonces;

    /* TIMERS */
    timer *map_register_timer;
    timer *smr_timer;

} lisp_xtr_t;

typedef struct _timer_rloc_prob_argument{
    mapping_t   *mapping;
    locator_t   *locator;
} timer_rloc_probe_argument;


int tr_mcache_add_mapping(map_cache_db_t *, mapping_t *);
int tr_mcache_add_static_mapping(map_cache_db_t *, mapping_t *);
int tr_mcache_remove_mapping(map_cache_db_t *, lisp_addr_t *);
mapping_t *tr_mcache_lookup_mapping(map_cache_db_t *, lisp_addr_t *);
mapping_t *tr_mcache_lookup_mapping_exact(map_cache_db_t *, lisp_addr_t *);

#endif /* LISP_XTR_H_ */
