/*
 * lispd_routing_tables_lib.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Various routines to manage the list of interfaces.
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
 *    Preethi Natarajan         <prenatar@cisco.com>
 *    Lorand Jakab              <ljakab@ac.upc.edu>
 *    Albert López              <alopez@ac.upc.edu>
 *    Alberto Rodriguez Natal   <arnatal@ac.upc.edu>
 *
 */

#ifndef LISPD_ROUTING_TABLES_LIB_H_
#define LISPD_ROUTING_TABLES_LIB_H_


#define RULE_AVOID_LISP_TABLE_PRIORITY 99
#define RULE_TO_LISP_TABLE_PRIORITY 100
#define LISP_TABLE 100

/*
 * This function adds a specific ip rule to
 * kernel's rule list
 */
int add_rule(
        int         afi,
        int         if_index,
        uint8_t     table,
        uint32_t    priority,
        uint8_t     type,
        lisp_addr_t *src_addr,
        int         src_plen,
        lisp_addr_t *dst_addr,
        int         dst_plen,
        int         flags);

/*
 * This function deletes a specific ip rule to
 * kernel's rule list
 */
int del_rule(
        int         afi,
        int         if_index,
        uint8_t     table,
        uint32_t    priority,
        uint8_t     type,
        lisp_addr_t *src_addr,
        int         src_plen,
        lisp_addr_t *dst_addr,
        int         dst_plen,
        int         flags);
/*
 * Remove all the created rules to the source routing tables
 */
void remove_created_rules();

/*
 * Request to the kernel the routing table with the selected afi
 */
int request_route_table(uint32_t table, int afi);


/*
 * Creates a routing entry in the specified table
 * ifindex:     Output interface
 * dest:        Destination address
 * gw:          Gateway
 * prefix_len:  Destination address mask (/n)
 * metric:      Route metric
 * table:       Routing table. 0 = main table
 */

int add_route(
        int                 afi,
        uint32_t            ifindex,
        lisp_addr_t         *dest,
        lisp_addr_t         *src,
        lisp_addr_t         *gw,
        uint32_t            prefix_len,
        uint32_t            metric,
        uint32_t            table);

/*
 * Deletes a routing entry in the specified table
 * ifindex:     Output interface
 * dest:        Destination address
 * gw:          Gateway
 * prefix_len:  Destination address mask (/n)
 * metric:      Route metric
 * table:       Routing table. 0 = main table
 */

int del_route(
        int                 afi,
        uint32_t            ifindex,
        lisp_addr_t         *dest,
        lisp_addr_t         *src,
        lisp_addr_t         *gw,
        uint32_t            prefix_len,
        uint32_t            metric,
        uint32_t            table);

#endif /* LISPD_ROUTING_TABLES_LIB_H_ */
