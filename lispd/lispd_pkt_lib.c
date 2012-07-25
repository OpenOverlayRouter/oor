/*
 * lispd_pkt_lib.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
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
 *    Lorand Jakab	<ljakab@ac.upc.edu>
 *
 */


#include "lispd_external.h"

extern void *pkt_fill_eid(offset, loc_chain)
    void                    *offset;
    lispd_locator_chain_t   *loc_chain;
{
    uint16_t                *afi_ptr;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    lispd_pkt_lcaf_iid_t    *iid_ptr;
    void                    *eid_ptr;
    uint16_t                 eid_afi;

    afi_ptr = (uint16_t *)offset;
    eid_afi = get_lisp_afi(loc_chain->eid_prefix.afi, NULL);

    /* For negative IID values, we skip LCAF/IID field */
    if (loc_chain->iid < 0) {
        *afi_ptr = htons(eid_afi);
        eid_ptr  = CO(offset, sizeof(uint16_t));
    } else {
        *afi_ptr = htons(LISP_AFI_LCAF);

        lcaf_ptr = (lispd_pkt_lcaf_t *) CO(offset, sizeof(uint16_t));
        iid_ptr  = (lispd_pkt_lcaf_iid_t *) CO(lcaf_ptr, sizeof(lispd_pkt_lcaf_t));
        eid_ptr  = (void *) CO(iid_ptr, sizeof(lispd_pkt_lcaf_iid_t));

        lcaf_ptr->rsvd1 = 0;
        lcaf_ptr->flags = 0;
        lcaf_ptr->type  = 2;
        lcaf_ptr->rsvd2 = 0;    /* This can be IID mask-len, not yet supported */
        lcaf_ptr->len   = htons(sizeof(lispd_pkt_lcaf_iid_t) +
                          get_addr_len(loc_chain->eid_prefix.afi));

        iid_ptr->iid = htonl(loc_chain->iid);
        iid_ptr->afi = htons(eid_afi);
    }

    if ((copy_addr(eid_ptr, &(loc_chain->eid_prefix), 0)) == 0) {
        syslog(LOG_DAEMON, "pkt_fill_eid: copy_addr failed");
        return NULL;
    }

    return CO(eid_ptr, get_addr_len(loc_chain->eid_prefix.afi));
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
