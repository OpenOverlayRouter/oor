/*
 * lisp_rtr.c
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

#include "lisp_rtr.h"
#include "lisp_xtr.h"
#include "../lib/lmlog.h"

void rtr_ctrl_start(lisp_ctrl_dev_t *dev) {
    LMLOG(LISP_LOG_DEBUG_1, "Starting RTR...");
    program_map_register(dev, 0);
}

void rtr_ctrl_delete(lisp_ctrl_dev_t *dev) {

}

/* implementation of base functions */
ctrl_dev_class_t rtr_vtable = {
        .process_msg = xtr_process_ctrl_msg,
        .start = rtr_ctrl_start,
        .delete = rtr_ctrl_delete
};

lisp_ctrl_dev_t *rtr_ctrl_init() {
    lisp_rtr *rtr;
    rtr = calloc(1, sizeof(lisp_rtr));
    rtr->super.ctrl_class = &rtr_vtable;
    rtr->super.mode = RTR_MODE;
    LMLOG(DBG_1, "Finished Initializing xTR");

    /* set up databases */

    rtr->local_mdb = local_map_db_new();
    rtr->map_cache = mcache_new();

    return((lisp_ctrl_dev_t *)rtr);
}
