/*
 * lisp_ms.h
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

#ifndef LISP_MS_H_
#define LISP_MS_H_

#include "lisp_ctrl_device.h"
#include <lisp_site.h>

#define REQ_MAP_NOTIFY 1
#define MORE_SPECIFICS 1


typedef struct _lisp_ms {
    lisp_ctrl_device super;    /* base "class" */

    /* ms members */
    mdb_t *lisp_sites_db;
    mdb_t *registered_sites_db;
} lisp_ms;

lisp_ctrl_device *ms_ctrl_init();

/* ms interface */
int ms_add_lisp_site_prefix(lisp_ctrl_device *ms, lisp_site_prefix *site);

#endif /* LISP_MS_H_ */
