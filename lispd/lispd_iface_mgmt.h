/*
 * lispd_iface_mgmt.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Netlink support and related routines for interface management.
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
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Vijay Subramanian <vijaynsu@cisco.com>
 *    Pere Monclus      <pmonclus@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Pranathi Mamidi   <pranathi.3961@gmail.com>
 *
 */

#ifndef LISPD_IFACE_MGMT_H_
#define LISPD_IFACE_MGMT_H_

#include "lispd.h"


#define BUF_SIZE                    512
#define RT_TABLE_LISP_MN            5
#define LISP_MN_EID_IFACE_MTU       1300
#define LISP_MN_IP_RULE_PRIORITY    1
#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *)(((void * )(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

typedef struct _reqaddr_t {
    struct nlmsghdr n;
    struct ifaddrmsg r;
    char buf [BUF_SIZE];
} reqaddr_t;

typedef     struct _reqinfo_t {
    struct nlmsghdr     n;
    struct ifinfomsg    r;
    char            buf[BUF_SIZE];
} reqinfo_t;

typedef struct _reqmsg_t {
    struct nlmsghdr     n;
    struct rtmsg        r;
    char            buf[BUF_SIZE];
} reqmsg_t;

/*
 * As a result of this function, the kernel will send a RTM_NEWROUTE
 * message for each of its routing entries
 */
int dump_routing_table(uint16_t afi, int table);

int setup_netlink_iface ();

int process_netlink_iface ();

/*
 * This function configures the lisp eid interface (ex: lmn0)
 * 1. Configures the iface with eid addr
 * 2. Brings up the interface and sets the mtu
 * 3. Configures the interface as the default gw
 */
int setup_lisp_eid_iface(char *eid_iface_name, lisp_addr_t *eid_addr, int eid_prefix_len);

/*
 *  remove lisp modules (and restore network settings)
 */
void exit_cleanup(void);

#endif /*LISPD_IFACE_MGMT_H_*/




