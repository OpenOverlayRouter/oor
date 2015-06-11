/*
 * iface_list.h
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
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Albert López      <alopez@ac.upc.edu>
 *
 */

#ifndef IFACE_LIST_H_
#define IFACE_LIST_H_

#include "liblisp/lisp_mapping.h"
#include "defs.h"
#include "lib/timers.h"
#ifdef ANDROID
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

/* Interface structure
 * ===================
 * Locator address (rloc) is linked to the interface address. If the address
 * of the interface changes, the locator address changes automatically */
typedef struct iface {
    char *iface_name;
    uint32_t iface_index;
    uint8_t status;
    lisp_addr_t *ipv4_address;
    lisp_addr_t *ipv6_address;
    lisp_addr_t *ipv4_gateway;
    lisp_addr_t *ipv6_gateway;

    int out_socket_v4;
    int out_socket_v6;
} iface_t;


#ifdef ANDROID

/*
 * Different from lispd_if_t to maintain
 * linux system call compatibility.
 */
typedef struct ifaddrs {
    struct ifaddrs      *ifa_next;
    char                *ifa_name;
    unsigned int         ifa_flags;
    struct sockaddr      *ifa_addr;
    int                  ifa_index;
} ifaddrs;


typedef struct {
    struct nlmsghdr nlh;
    struct rtgenmsg  rtmsg;
} request_struct;

#endif

extern glist_t *interface_list;  //<iface_t *>

extern iface_t *default_out_iface_v4;
extern iface_t *default_out_iface_v6;

extern iface_t *default_ctrl_iface_v4;
extern iface_t *default_ctrl_iface_v6;

extern shash_t *iface_addr_ht;


int ifaces_init();
inline void ifaces_destroy();


void iface_destroy(iface_t *iface);
void iface_remove_routing_rules(iface_t *iface);

/*  Fill the parameter addr with the lisp_addr_t of the interface with afi.
 *  Return BAD if no address is present in the interface. */
int get_iface_address(char *ifacename, lisp_addr_t *addr, int afi);
iface_t *add_interface(char *iface_name);
iface_t *get_interface(char *iface_name);
iface_t *get_interface_from_index(int iface_index);
iface_t *get_interface_with_address(lisp_addr_t *address);


/* Print the interfaces and locators of the lisp node */
void iface_list_to_char(int log_level);


iface_t *get_default_ctrl_iface(int afi);
lisp_addr_t *get_default_ctrl_address(int afi);
int get_default_ctrl_socket(int afi);
void set_default_ctrl_ifaces();


iface_t *get_any_output_iface(int);
lisp_addr_t *get_default_output_address(int);
int get_default_output_socket(int);
void set_default_output_ifaces();


lisp_addr_t *iface_address(iface_t *iface, int afi);
int iface_socket(iface_t *iface, int afi);
static uint8_t iface_status(iface_t *iface);

static inline uint8_t iface_status(iface_t *iface)
{
    return (iface->status);
}

char *
get_interface_name_from_address(lisp_addr_t *addr);

#endif /*IFACE_LIST_H_*/
