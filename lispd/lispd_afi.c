/*
 * lispd_afi.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
 *
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 *    Albert López      <alopez@ac.upc.edu>
 *
 */

#include "lispd_afi.h"

int pkt_process_eid_afi(char  **offset,
        lispd_identifier_elt *identifier);

int pkt_process_rloc_afi(char  **offset,
        lispd_locator_elt *locator);

int pkt_process_eid_afi(char  **offset,
        lispd_identifier_elt *identifier)
{

    char                    *cur_ptr;
    lispd_pkt_lcaf_t        *lcaf_ptr;
    uint16_t                 lisp_afi;


    cur_ptr  = *offset;
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));
    switch(lisp_afi) {
    case LISP_AFI_IP:
        identifier->eid_prefix.address.ip.s_addr = ntohs(*(uint32_t *)cur_ptr);
        identifier->eid_prefix.afi = AF_INET;
        cur_ptr  = CO(cur_ptr, sizeof(struct in_addr));
        break;
    case LISP_AFI_IPV6:
        memcpy(&(identifier->eid_prefix.address.ipv6),cur_ptr,sizeof(struct in6_addr));
        identifier->eid_prefix.afi = AF_INET6;
        cur_ptr  = CO(cur_ptr, sizeof(struct in6_addr));
        break;
    case LISP_AFI_LCAF:
        lcaf_ptr = (lispd_pkt_lcaf_t *)cur_ptr;
        cur_ptr  = CO(lcaf_ptr, sizeof(lispd_pkt_lcaf_t));
        switch(lcaf_ptr->type) {
        case LCAF_IID:
            identifier->iid = ntohs(*(uint32_t *)cur_ptr);
            cur_ptr = CO(lcaf_ptr, sizeof(identifier->iid));
            if (!pkt_process_eid_afi (&cur_ptr, identifier))
                return BAD;
            break;
        default:
            identifier->eid_prefix.afi = -1;
            syslog(LOG_ERR,"  unknown LCAF type %d in EID", lcaf_ptr->type);
            return BAD;
        }
        break;
    case 0:
        identifier->eid_prefix.afi = 0;
        return BAD;
    default:
        identifier->eid_prefix.afi = -1;
        syslog(LOG_ERR,"  unknown AFI type %d in EID", lisp_afi);
        return BAD;
    }
    *offset = cur_ptr;
    return GOOD;
}



int pkt_process_rloc_afi(char  **offset,
        lispd_locator_elt *locator)
{
    char                    *cur_ptr;
    uint16_t                 lisp_afi;

    cur_ptr  = *offset;
    lisp_afi = ntohs(*(uint16_t *)cur_ptr);
    cur_ptr  = CO(cur_ptr, sizeof(lisp_afi));
    switch(lisp_afi) {
    case LISP_AFI_IP:
        locator->locator_addr->address.ip.s_addr = ntohs(*(uint32_t *)cur_ptr);
        locator->locator_addr->afi = AF_INET;
        cur_ptr  = CO(cur_ptr, sizeof(struct in_addr));
        break;
    case LISP_AFI_IPV6:
        memcpy(&(locator->locator_addr->address.ipv6),cur_ptr,sizeof(struct in6_addr));
        locator->locator_addr->afi = AF_INET6;
        cur_ptr  = CO(cur_ptr, sizeof(struct in6_addr));
        break;
    case LISP_AFI_LCAF:
        syslog(LOG_ERR,"  LCAF address is not supported in locators");
        return BAD;
    default:
        syslog(LOG_ERR,"  unknown AFI type %d in locator", lisp_afi);
        return BAD;
    }
    *offset = cur_ptr;
    return GOOD;
}
