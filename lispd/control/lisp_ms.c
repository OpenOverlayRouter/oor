/*
 * lisp_ms.c
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

#include "lisp_ms.h"
#include <cksum.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>


/* for testing, should move them out */
#include <lispd_lib.h>
#include <packets.h>
#include <lispd_sockets.h>

void
ms_ctrl_start(lisp_ctrl_dev_t *dev) {
//    lisp_ms *ms = NULL;
//    ms = (lisp_ms *)dev;
    lmlog(DBG_1, "Starting Map-Server ...");
}

void
ms_ctrl_delete(lisp_ctrl_dev_t *dev) {
    lisp_ms_t *ms;
    ms = (lisp_ms_t *)dev;
    lmlog(DBG_1, "Freeing Map-Server ...");
    mdb_del(ms->lisp_sites_db, (mdb_del_fct)mapping_del);
    mdb_del(ms->reg_sites_db, (mdb_del_fct)lisp_site_prefix_del);
}


int ms_handle_msg(lisp_ctrl_dev_t *dev, lbuf_t *msg, uconn_t *usk) {
    int ret = BAD;
    lisp_msg_type_t type;

    type = lisp_msg_type(msg);

    if (type == LISP_ENCAP_CONTROL_TYPE) {
        if (lisp_msg_ecm_decap(msg, &(usk.lp)) != GOOD)
            return (BAD);
    }

     switch(type) {
     case LISP_MAP_REQUEST:
         ret = ms_recv_map_request(dev, msg, usk);
         break;
     case LISP_MAP_REGISTER:
         ret = ms_recv_map_register(dev, msg, usk);
         break;
     case LISP_MAP_REPLY:
     case LISP_MAP_NOTIFY:
     case LISP_INFO_NAT:
         lmlog(DBG_3, "Map-Server: Received control message with type %d."
                 " Discarding!", type);
         break;
     default:
         lmlog(DBG_3, "Map-Server: Received unidentified type (%d) control "
                 "message", type);
         ret = BAD;
         break;
     }

     if (ret != GOOD) {
         lmlog(DBG_1, "Map-Server: Failed to process  control message");
         return(BAD);
     } else {
         lmlog(DBG_3, "Map-Server: Completed processing of control message");
         return(ret);
     }
}

ctrl_dev_class_t ms_ctrl_class = {
        .process_msg = ms_handle_msg,
        .start = ms_ctrl_start,
        .delete = ms_ctrl_delete
};

lisp_ctrl_dev_t *ms_ctrl_init() {
    lisp_ms_t *ms;
    ms = calloc(1, sizeof(lisp_ms_t));
    ms->super.mode = MS_MODE;
    ms->super.ctrl_class = &ms_ctrl_class;
    lmlog(DBG_1, "Finished Initializing Map-Server");

    ms->reg_sites_db = mdb_new();
    ms->lisp_sites_db = mdb_new();

    return((lisp_ctrl_dev_t *)ms);
}

int ms_add_lisp_site_prefix(lisp_ctrl_dev_t *dev, lisp_site_prefix *sp) {
    lisp_ms_t *ms = NULL;
    ms = (lisp_ms_t *)dev;

    if (!sp)
        return(BAD);

    if(!mdb_add_entry(ms->lisp_sites_db, lsite_prefix(sp), sp))
        return(BAD);
    return(GOOD);
}

int ms_add_registered_site_prefix(lisp_ctrl_dev_t *dev, mapping_t *sp) {
    lisp_ms_t *ms = (lisp_ms_t *)dev;

    if (!sp)
        return(BAD);
    if (!mdb_add_entry(ms->reg_sites_db, mapping_eid(sp), sp))
        return(BAD);
    return(GOOD);
}

void ms_dump_configured_sites(lisp_ctrl_dev_t *dev, int log_level)
{
    lisp_ms_t *ms = (lisp_ms_t *) dev;
    void *it = NULL;
    lisp_site_prefix *site = NULL;

    lmlog(log_level,"****************** MS configured prefixes **************\n");

    mdb_foreach_entry(ms->lisp_sites_db, it) {
        site = it;
        lmlog(log_level, "Prefix: %s, accept specifics: %s merge: %s, proxy: %s",
                lisp_addr_to_char(site->eid_prefix),
                (site->accept_more_specifics) ? "on" : "off",
                (site->merge) ? "on" : "off",
                (site->proxy_reply) ? "on" : "off");
    } mdb_foreach_entry_end;
    lmlog(log_level,"*******************************************************\n");
}

void ms_dump_registered_sites(lisp_ctrl_dev_t *dev, int log_level) {
    lisp_ms_t     *ms = (lisp_ms_t *)dev;
    void        *it     = NULL;
    mapping_t   *mapping = NULL;

    lmlog(log_level,"**************** MS registered sites ******************\n");
    mdb_foreach_entry(ms->reg_sites_db, it) {
        mapping = it;
        mapping_to_char(mapping, log_level);
    } mdb_foreach_entry_end;
    lmlog(log_level,"*******************************************************\n");

}


