/*
 * lispd_re_jib.c
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

/*
 * This defines the LISP-RE downstream join information base (jib)
 */

#ifndef LISPD_RE_JIB_H_
#define LISPD_RE_JIB_H_

#include "lispd_generic_list.h"

typedef lispd_generic_list_t        lispd_jib_t;
typedef struct {
    lispd_locators_list *locators;
    timer timer;
}lispd_jib_entry_t;

typedef struct {
    lisp_addr_t     *locator;
    nonces_list     *nonces;
    timer           *probe_timer;
    int             join_pending;
    int             leave_pending;
} lispd_upstream_t;

lispd_jib_t             *lispd_new_jib();
lispd_generic_list_t    *jib_get_orlist(lispd_jib_t *jib);
void                    jib_add_locator_list(lispd_locators_list *loc_list, lispd_jib_t *jib);
void                    jib_del_locator_list(lispd_locators_list *loc_list, lispd_jib_t *jib);
inline uint32_t         jib_size(lispd_jib_t *jib);


#endif /* LISPD_RE_JIB_H_ */
