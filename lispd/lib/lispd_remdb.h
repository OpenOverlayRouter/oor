/*
 * lispd_remdb.h
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


#ifndef LISPD_REMDB_H_
#define LISPD_REMDB_H_

#include <generic_list.h>
#include "lisp_locator.h"

/* simple member database backend for starters */
typedef glist_t        remdb_t;

typedef struct {
    /* actual data */
    lisp_addr_t         *addr;
    locators_list_t *locators;

    /* status fields */
    lmtimer_t               *rt_timer;
    nonces_list_t         *nonces;
    uint8_t             join_pending;
    uint8_t             leave_pending;
} remdb_member_t;


remdb_t                 *remdb_new();
void                    remdb_del(remdb_t *db);
void                    remdb_add_member(lisp_addr_t *addr, lisp_addr_t *rloc_pair, remdb_t *jib);
void                    remdb_del_member(lisp_addr_t *addr, remdb_t *jib);
remdb_member_t          *remdb_find_member(lisp_addr_t *peer, remdb_t *jib);
void                    remdb_update_member(lisp_addr_t *addr, locators_list_t *loc_list);
inline uint32_t         remdb_size(remdb_t *jib);
remdb_member_t          *remdb_member_init(lisp_addr_t *src, lisp_addr_t *rloc_pair);
void                    remdb_dump(remdb_t *remdb, int log_level);

/* builds a forwarding database for mc */
glist_t    *remdb_get_orlist(remdb_t *jib);



#endif /* LISPD_REMDB_H_ */
