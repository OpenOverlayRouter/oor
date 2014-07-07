/*
 * lispd_iface_mgmt.h
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
 *    Albert López   <alopez@ac.upc.edu>
 *
 */

#ifndef LISPD_IFACE_MGMT_H_
#define LISPD_IFACE_MGMT_H_

#include "lispd_iface_list.h"


int opent_netlink_socket();

void process_netlink_msg(int netlink_fd);

int lispd_get_iface_address_nl(
        char                *ifacename,
        lisp_addr_t         *addr,
        int                 afi);

/*
 * Get MAC address of an interface
 */
void iface_mac_address(
		char 	*iface_name,
		uint8_t *mac);

/*
 * Return a list of ifaces names
 */
int get_all_ifaces_name_list(
        char ***ifaces,
        int *count);

#endif /* LISPD_IFACE_MGMT_H_ */
