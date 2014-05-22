/*
 * lisp_site.c
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


#include "lisp_site.h"
#include "defs.h"

lisp_site_prefix *lisp_site_prefix_init(lisp_addr_t *eid, uint32_t iid,
        int key_type, char *key, uint8_t more_specifics, uint8_t proxy_reply,
        uint8_t merge)
{

    lisp_site_prefix *sp = NULL;
    sp = xzalloc(sizeof(lisp_site_prefix));

    sp->eid_prefix = lisp_addr_clone(eid);
    sp->iid = iid;
    sp->key_type = key_type;
    sp->key = strdup(key);
    sp->accept_more_specifics = more_specifics;
    sp->proxy_reply = proxy_reply;
    sp->merge = merge;

    return(sp);
}

void lisp_site_prefix_del(lisp_site_prefix *sp) {
    if (!sp)
        return;
    if (sp->eid_prefix)
        lisp_addr_del(sp->eid_prefix);
    if (sp->key)
        free(sp->key);
    free(sp);
}
