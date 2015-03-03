/*
 * iface_locators.h
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
 *    Albert López <alopez@ac.upc.edu>
 */

#ifndef IFACE_LOCATORS_H_
#define IFACE_LOCATORS_H_

#include "../liblisp/liblisp.h"
#include "map_local_entry.h"
#include "shash.h"


typedef struct iface_locators_{
    char        *iface_name;
    glist_t     *map_loc_entries;   /*Mappings associated to this iface <map_local_entry_t>*/
    glist_t     *ipv4_locators;     /*IPv4 locators associated with this iface <lisp_addr_t>*/
    glist_t     *ipv6_locators;     /*IPv6 locators associated with this iface <lisp_addr_t>*/
    uint8_t     status_changed:1;   /*Iface change status --> Used to avioid transitions*/
    lisp_addr_t *ipv4_prev_addr;    /*Previous IPv4 address of the iface --> Used to avoid transitions A->B->A*/
    lisp_addr_t *ipv6_prev_addr;    /*Previous IPv6 address of the iface --> Used to avoid transitions A->B->A*/
}iface_locators;

iface_locators *iface_locators_new(char *iface_name);
void iface_locators_del(iface_locators *if_loct);

void
iface_locators_attach_map_local_entry(
        shash_t *   iface_locators_table,
        map_local_entry_t * map_loc_e);

void
iface_locators_unattach_mapping_and_loct(
        shash_t *   iface_locators_table,
        map_local_entry_t * map_loc_e);

void
iface_locators_unattach_locator(
        shash_t *       iface_locators_table,
        locator_t *     locator);

#endif /* IFACE_LOCATORS_H_ */
