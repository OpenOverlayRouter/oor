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
 *
 */

#pragma once

#include "lispd.h"

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
 * Add/update iface_list_elt with the input parameters
 */
int update_iface_list (
    char *iface_name, char *eid_prefix,
    lispd_db_entry_t  *db_entry,
    int is_up,
    int weight,
    int priority);

/*
 * Function that allows iterating through interfaces from elsewhere
 */
iface_list_elt *get_first_iface_elt();

/*
 * Function returns an active (up and running) physical interface
 * with a v4 or v6 locator
 */
iface_list_elt *find_active_ctrl_iface();
