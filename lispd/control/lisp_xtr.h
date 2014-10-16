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
#include "shash.h"

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
    glist_t *pitrs; // <lisp_addr_t *>

    /* DATABASES */
    map_cache_db_t *map_cache;
    local_map_db_t *local_mdb;

    /* MAP RESOLVERS */
    glist_t *map_resolvers; // <lisp_addr_t *>

    /* MAP SERVERs */
    glist_t *map_servers; // <map_server_elt *>

    /* NAT */
    int nat_aware;
    int nat_status;
    lisp_site_id site_id;
    lisp_xtr_id xtr_id;

    nonces_list_t *nat_emr_nonces;
    nonces_list_t *nat_ir_nonces;

    /* TIMERS */
    lmtimer_t *map_register_timer;
    lmtimer_t *smr_timer;

    /* MAPPING IFACE TO LOCATORS */
    shash_t *iface_locators_table; /* Key: Iface name, Value: iface_locators */

    /* LOCAL IFACE MAPPING */
    /* in case of RTR can be used for outgoing load balancing */
    mapping_t *all_locs_map;

} lisp_xtr_t;

typedef struct _timer_rloc_prob_argument {
    mapping_t   *mapping;
    locator_t   *locator;
} timer_rloc_probe_argument;

typedef struct map_server_elt_t {
    lisp_addr_t *   address;
    uint8_t         key_type;
    char *          key;
    uint8_t         proxy_reply;
} map_server_elt;

typedef struct iface_locators_{
    char        *iface_name;
    glist_t     *mappings;          /*Mappings associated to this iface*/
    glist_t     *ipv4_locators;     /*IPv4 locators associated with this iface*/
    glist_t     *ipv6_locators;     /*IPv6 locators associated with this iface*/
    uint8_t     status_changed:1;   /*Iface change status --> Used to avioid transitions*/
    lisp_addr_t *ipv4_prev_addr;    /*Previous IPv4 address of the iface --> Used to avoid transitions A->B->A*/
    lisp_addr_t *ipv6_prev_addr;    /*Previous IPv6 address of the iface --> Used to avoid transitions A->B->A*/
}iface_locators;



int tr_mcache_add_mapping(lisp_xtr_t *, mapping_t *);
int tr_mcache_add_static_mapping(lisp_xtr_t *, mapping_t *);
int tr_mcache_remove_mapping(lisp_xtr_t *, lisp_addr_t *);
mapping_t *tr_mcache_lookup_mapping(lisp_xtr_t *, lisp_addr_t *);
mapping_t *tr_mcache_lookup_mapping_exact(lisp_xtr_t *, lisp_addr_t *);

iface_locators *iface_locators_new(char *iface_name);
void iface_locators_del(iface_locators *if_loct);
#endif /* LISP_XTR_H_ */
