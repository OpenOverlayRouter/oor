/*
 * lispd_patricia.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Patrica tree manipulation functions
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
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

#include "lispd_external.h"

/*
 *  make_and_lookup for network format prefix
 */

patricia_node_t *make_and_lookup_network(afi,addr,mask_len)
     int    afi;
     void   *addr;
     int    mask_len;
{
    struct in_addr  *sin;
    struct in6_addr *sin6;
    prefix_t        *prefix = NULL;
    patricia_node_t *node;

    if ((node = malloc(sizeof(patricia_node_t))) == NULL) {
        syslog(LOG_DAEMON, "can't allocate patrica_node_t");
        return(NULL);
    }

    switch (afi) {
    case AF_INET:
        sin = (struct in_addr *) addr;
        if ((prefix = New_Prefix(AF_INET, sin, mask_len)) == NULL) {
            syslog(LOG_DAEMON, "couldn't alocate prefix_t for AF_INET");
            free(node);
            return(NULL);
        }
        node = patricia_lookup(AF4_database, prefix);
        break;
    case AF_INET6:
        sin6   = (struct in6_addr *) addr;
        if ((prefix = New_Prefix(AF_INET6, sin6, mask_len)) == NULL) {
            syslog(LOG_DAEMON, "couldn't alocate prefix_t for AF_INET6");
            free(node);
            return(NULL);
        }
        node   = patricia_lookup(AF6_database, prefix);
        break;
    default:
        free(node);
        free(prefix);
        syslog(LOG_DAEMON, "Unknown afi (%d) when allocating prefix_t", afi);
        return (NULL);
    }
    Deref_Prefix (prefix);
    return(node);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
