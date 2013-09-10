/*
 * lispd_iface_list.h
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

#ifndef LISPD_IFACE_LIST_H_
#define LISPD_IFACE_LIST_H_

#include "lispd.h"
#include "lispd_mapping.h"
#include "lispd_timers.h"

/*
 * list of mappings associated to the interface containin this structure.
 */
typedef struct lispd_iface_mappings_list_ {
    lispd_mapping_elt                       *mapping;
    uint8_t                                 use_ipv4_address:1;// The mapping has a locator that use the IPv4 address of iface
    uint8_t                                 use_ipv6_address:1;// The mapping has a locator that use the IPv6 address of iface
    struct lispd_iface_mappings_list_       *next;
} lispd_iface_mappings_list;


/*
 * Interface structure
 * locator address (rloc) is linked to the interface address. If changes the address of the interface
 * , the locator address change automatically
 */
typedef struct lispd_iface_elt_ {
    char                        *iface_name;
    uint32_t                    iface_index;
    uint8_t                     status;
    lisp_addr_t                 *ipv4_address;
    lisp_addr_t                 *ipv6_address;
    lisp_addr_t                 *ipv4_gateway;
    lisp_addr_t                 *ipv6_gateway;
    /* List of mappings that have a locator associated with this interface. Used to do SMR  when interface changes*/
    lispd_iface_mappings_list   *head_mappings_list;
    uint8_t                     status_changed:1;
    uint8_t                     ipv4_changed:1;
    uint8_t                     ipv6_changed:1;
    int                         out_socket_v4;
    int                         out_socket_v6;
}lispd_iface_elt;

/*
 * List of interfaces
 */
typedef struct lispd_iface_list_elt_ {
    lispd_iface_elt                  *iface;
    struct lispd_iface_list_elt_     *next;
}lispd_iface_list_elt;



/*
 * Return the interface if it already exists. If it doesn't exist,
 * create and add an interface element to the list of interfaces.
 */

lispd_iface_elt *add_interface(char *iface_name);




/*
 * Look up an interface based in the iface_name.
 * Return the iface element if it is found or NULL if not.
 */

lispd_iface_elt *get_interface(char *iface_name);

/*
 * Look up an interface based in the index of the iface.
 * Return the iface element if it is found or NULL if not.
 */

lispd_iface_elt *get_interface_from_index(int iface_index);

/*
 * Return the interface belonging the address passed as a parameter
 */

lispd_iface_elt *get_interface_with_address(lisp_addr_t *address);

/*
 * Add the mapping to the list of mappings of the interface according to the afi.
 * The mapping is added just one time
 */

int add_mapping_to_interface (lispd_iface_elt *interface, lispd_mapping_elt *mapping, int afi);



/*
 * Print the interfaces and locators of the lisp node
 */

void dump_iface_list(int log_level);


void open_iface_binded_sockets();

lispd_iface_elt *get_any_output_iface(int afi);

lispd_iface_elt *get_default_ctrl_iface(int afi);

lisp_addr_t *get_default_ctrl_address(int afi);

int get_default_ctrl_socket(int afi);

int get_default_output_socket(int afi);

void set_default_output_ifaces();

/*
 * Init the default interfaces to send control packets
 */
void set_default_ctrl_ifaces();

lisp_addr_t *get_iface_address(lispd_iface_elt *iface, int afi);

int get_iface_socket(lispd_iface_elt *iface, int afi);

/*
 * Return the list of interfaces
 */

lispd_iface_list_elt *get_head_interface_list();

/*
 * Recalculate balancing vector of the mappings assorciated to iface
 */

void iface_balancing_vectors_calc(lispd_iface_elt  *iface);

/*
 * Close all the open output sockets associated to interfaces
 */

void close_output_sockets();

#endif /*LISPD_IFACE_LIST_H_*/
