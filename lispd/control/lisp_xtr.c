/*
 * lisp_xtr.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
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

#include "lisp_xtr.h"
#include "lispd_sockets.h"


int
xtr_handle_msg(lisp_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *usk) {
    int ret = 0;
    lisp_msg_type_t type;

    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (lisp_msg_ecm_decap(msg, &(usk.lp)) != GOOD)
            return (BAD);
    }

    switch (type) {
    case LISP_MAP_REPLY:
        ret = recv_map_reply_msg(dev, msg);
        break;
    case LISP_MAP_REQUEST:
        ret = tr_recv_map_request(dev, msg, usk);
        break;
    case LISP_MAP_REGISTER:
        break;
    case LISP_MAP_NOTIFY:
        ret = recv_map_notify(dev, msg);
        break;
    case LISP_INFO_NAT:
        /*FC: temporary fix until info_nat uses liblisp */
        lmlog(LISP_LOG_DEBUG_1, "Info-Request/Info-Reply message");
        if (!process_info_nat_msg(lbuf_data(msg), usk.ra)) {
            return (BAD);
        }
        return (GOOD);
        break;
    default:
        lmlog(DBG_1, "xTR: Unidentified type (%d) control message received",
                type);
        ret = BAD;
        break;
    }

    if (ret != GOOD) {
        lmlog(DBG_1,"xTR: Failed to process LISP control message");
        return (BAD);
    } else {
        lmlog(DBG_3, "xTR: Completed processing of LISP control message");
        return (ret);
    }
}

void
xtr_ctrl_start(lisp_ctrl_dev_t *dev) {

    lmlog(DBG_1, "Starting xTR ...");

    /*  Register to the Map-Server(s) */
    program_map_register(dev, 0);

    /* SMR proxy-ITRs list to be updated with new mappings */
    program_smr(dev, 0);

    /* RLOC Probing proxy ETRs */
    programming_petr_rloc_probing(dev, 0);

}

void
xtr_delete(lisp_ctrl_dev_t *dev) {
//    lisp_xtr *xtr;
//    xtr = (lisp_xtr *)dev;
//    mdb_del(xtr->local_mdb, (glist_del_fct)mapping_del_local);
//    mdb_del(xtr->map_cache, (glist_del_fct)mapping_del_remote);

}

/* implementation of ctrl base functions */
ctrl_dev_class_t xtr_vtable = {
        .process_msg = xtr_handle_msg,
        .start = xtr_ctrl_start,
        .delete = xtr_delete
};

lisp_ctrl_dev_t *
xtr_ctrl_init() {
    lisp_xtr_t *xtr;
    xtr = calloc(1, sizeof(lisp_xtr_t));
    xtr->super.ctrl_class = &xtr_vtable;
    xtr->super.mode = xTR_MODE;
    lmlog(DBG_1, "Finished Initializing xTR");

    /* set up databases */

    xtr->local_mdb = local_map_db_new();
    xtr->map_cache = mcache_new();

    return((lisp_ctrl_dev_t *)xtr);
}


