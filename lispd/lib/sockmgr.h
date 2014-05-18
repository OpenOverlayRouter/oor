/*
 * sockmgr.h
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

#ifndef SOCKMGR_H_
#define SOCKMGR_H_

#include <shash.h>
#include <lisp_address.h>

typedef struct sockmgr_t_ {
    shash_t *if_socks;
    sock_t *ctrl_sock;
} sockmgr_t;


sockmgr_t *sockmgr_create();
void sockmgr_destroy(sockmgr_t *);
sock_t *sockmgr_get_if_sock(sockmgr_t *, lisp_addr_t *);

#endif /* SOCKMGR_H_ */
