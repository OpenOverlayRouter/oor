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
#include "lispd_local_db.h"
#include "lispd_sockets.h"

/*
 * Interface structure
 * locator address (rloc) is linked to the interface address. If changes the address of the interface
 * , the locator address change automatically
 */
typedef struct lispd_iface_elt_ {
    char                        *iface_name;
    uint8_t                     status;
    lisp_addr_t                 *ipv4_address;
    lisp_addr_t                 *ipv6_address;
    lispd_identifiers_list      *head_v4_identifiers_list;
    lispd_identifiers_list      *head_v6_identifiers_list;
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
 * Add the identifier to the list of identifiers of the interface according to the afi.
 * The identifier is added just one time
 */

int add_identifier_to_interface (lispd_iface_elt *interface, lispd_identifier_elt *identifier, int afi);









/*
 * Add a new db_entry_list_elt to the head of a db_entry_list
 */
void add_item_to_db_entry_list (db_entry_list *list, db_entry_list_elt  *item);

/*
 * Delete db_entry_list_elt from db_entry_list
 */
int del_item_from_db_entry_list (db_entry_list *list, lispd_db_entry_t  *item);

/*
 * Search iface_list for an iface_list_elt with a particular interface name
 */
iface_list_elt *search_iface_list (char *iface_name);


/*
 * Function that allows iterating through interfaces from elsewhere
 */
iface_list_elt *get_first_iface_elt();

/*
 * Function returns an active (up and running) physical interface
 * with a v4 or v6 locator
 */
lispd_iface_elt *find_active_ctrl_iface();


/*
 * Print the interfaces and locators of the lisp node
 */

void dump_iface_list();


void open_iface_binded_sockets();

lispd_iface_elt *get_any_output_iface();

lispd_iface_elt *get_default_output_iface(int afi);

void set_default_output_ifaces();

lisp_addr_t *get_iface_address(lispd_iface_elt *iface, int afi);

#endif /*LISPD_IFACE_LIST_H_*/
