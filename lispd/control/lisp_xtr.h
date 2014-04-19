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

    /* xtr members */
    map_cache_db *map_cache;
    local_map_db *local_mdb;
} lisp_xtr_t;

//extern ctrl_device_vtable xtr_vtable;

lisp_ctrl_dev_t *xtr_ctrl_init();
int xtr_process_ctrl_msg(lisp_ctrl_dev_t *dev, lisp_msg *msg, uconn_t *udpsock);

#endif /* LISP_XTR_H_ */
