/* 
 * lispd_iface_list.c
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

#include "lispd.h"

iface_list  *avail_phy_ifaces = NULL;

/*
 * Add a new iface_list_elt to the 
 * tail of an iface_list
 */
static void add_item_to_iface_list (list, item) 
    iface_list      *list;
    iface_list_elt  *item;
{
    if (list->head == NULL) { 
        list->head = item; 
        list->tail = item; 
    } 
    else { 
        list->tail->next = item; 
        list->tail = item; 
    }
}

/*
 * Add a new db_entry_list_elt to the
 * head of a db_entry_list
 */
void add_item_to_db_entry_list (list, item) 
    db_entry_list      *list;
    db_entry_list_elt  *item;
{
    db_entry_list_elt   *prev_head = NULL;
    if (list->head == NULL) { 
        list->head = item; 
        list->tail = item; 
    } 
    else { 
        /* 
         * Add new locators to the head of the list
         * such that head of list is most likely the best
         * source rloc to use for control/data msgs.
         */
        prev_head = list->head;
        list->head = item;
        item->next = prev_head;
    }
}

/*
 * Delete db_entry_list_elt from db_entry_list
 */
int del_item_from_db_entry_list (list, item)
    db_entry_list      *list;
    lispd_db_entry_t         *item;
{
    db_entry_list_elt   *prev = list->head;
    db_entry_list_elt   *curr = list->head;

    if ((list->head->db_entry == item) && 
            (list->tail->db_entry == item)) {
        free (list->head);
        list->head = NULL;
        list->tail = NULL;
        return (1);
    }
    while (curr) {
         if (curr->db_entry == item) {
             prev->next = curr->next;
             if(curr == list->head) {
                /* set new head */
                list->head = curr->next;
             }
             if (curr == list->tail) {
                /* set new tail */
                list->tail = prev;
             }

             free (curr);
             return (1);
         }
         prev = curr;
         curr = curr->next;
    } 
    return (0);
}

/*
 * Search iface_list for an iface_list_elt
 * with a particular interface name
 */
iface_list_elt *search_iface_list (iface_name) 
    char            *iface_name;
{
    iface_list_elt  *item = avail_phy_ifaces->head;
    while (item) {
        if (!strcmp((item)->iface_name, iface_name)) 
            return item;
        item = item->next;
    } 
    return (NULL);
}


static void dump_iface_list (item)
    iface_list_elt *item;
{
    syslog(LOG_DAEMON, "Interface list:");
    while (item) {
        syslog(LOG_DAEMON, "  %s %s %s %p %p %d\n",
                item->iface_name, 
                item->AF4_eid_prefix, item->AF6_eid_prefix,
                item->AF4_locators, item->AF6_locators, item->ready); 
        item = item->next; 
    }
}


/* get_rt_number
 * Selects an appropriate routing table number.
 * As of now is quite naive it goes to the last element in the table
 * and picks rt_number+1.
 */

int get_rt_number()
{
	iface_list_elt *item=avail_phy_ifaces->tail;
	if(item)
		return item->rt_table_num+1;
	return RT_TABLE_LISP_MN;
}


/*
 * Add/update iface_list_elt with the input parameters
 */
int update_iface_list (iface_name, eid_prefix, 
        db_entry, is_up, priority, weight)
    char *iface_name;
    char *eid_prefix;
    lispd_db_entry_t  *db_entry;
    int is_up;
    int weight;
    int priority;
{
    iface_list_elt *elt = NULL;
    db_entry_list_elt *db_elt   = NULL;
    int afi;

    if (!avail_phy_ifaces) {
        /* first iface_list_elt */
        if((avail_phy_ifaces = malloc (sizeof(iface_list))) == NULL) {
            syslog(LOG_DAEMON, "Can't malloc(sizeof(iface_list))\n");
            return (0);
        }
        memset (avail_phy_ifaces, 0, sizeof(iface_list));
    }

    elt = search_iface_list (iface_name);

    if (elt == NULL) {
        /* should create a new iface_list_elt */
        if ((elt = malloc (sizeof(iface_list_elt))) == NULL) {
            syslog(LOG_DAEMON, "Can't malloc(sizeof(iface_list_elt))\n");
            return (0);
        }
        memset (elt, 0, sizeof(iface_list_elt));
        if (((elt->AF4_locators = malloc (sizeof(db_entry_list))) == NULL) ||
            ((elt->AF6_locators = malloc (sizeof(db_entry_list))) == NULL)) {

            syslog(LOG_DAEMON, "Can't malloc(sizeof(db_entry_list)\n");
            free(elt->AF4_locators);
            free(elt->AF6_locators);
            free(elt);
            return (0);
        }
        memset (elt->AF4_locators, 0, sizeof(db_entry_list));
        memset (elt->AF6_locators, 0, sizeof(db_entry_list));
        elt->iface_name     = strdup(iface_name);
        //get a table number that we can use
        elt->rt_table_num	= get_rt_number();
#ifdef LISPMOBMH
		elt->if_index = if_nametoindex(iface_name);
#endif

        add_item_to_iface_list (avail_phy_ifaces,elt);
    }

    if (eid_prefix) {
        afi = get_afi(eid_prefix);
        switch (afi) {
            case AF_INET6:
                if (!elt->AF6_eid_prefix) 
                    elt->AF6_eid_prefix = strdup(eid_prefix);
                break;
            default:
                if (!elt->AF4_eid_prefix) 
                    elt->AF4_eid_prefix = strdup(eid_prefix);
                break;
        }
    }

    elt->ready          = is_up;
    elt->weight         = weight;
    elt->priority       = priority;

    if (db_entry == NULL)
        /* No rloc available to add */
        return (1);

    if ((db_elt = malloc (sizeof(db_entry_list_elt))) == NULL) {
            syslog(LOG_DAEMON, "Can't malloc(sizeof(db_entry_list_elt))\n");
            return (0);
    }
    memset (db_elt, 0, sizeof(db_entry_list_elt));
    db_elt->db_entry    = db_entry;
    db_elt->next        = NULL;

    switch (db_entry->locator.afi) {
        case AF_INET:
            add_item_to_db_entry_list(elt->AF4_locators, db_elt);
            break;
        case AF_INET6:
            add_item_to_db_entry_list(elt->AF6_locators, db_elt);
            break;
        default:
            syslog (LOG_DAEMON, "Unknown AFI; db_entry not added\n");
            break;
    }

    dump_iface_list(avail_phy_ifaces->head);

    return (1);
}


/* 
 * Function that allows iterating through interfaces from elsewhere
 */
iface_list_elt *get_first_iface_elt(){
	iface_list_elt  *elt = avail_phy_ifaces->head;
	return elt;
}

/*
 * Function returns an active (up and running) physical interface
 * with a v4 or v6 locator
 */
iface_list_elt *find_active_ctrl_iface()
{
    iface_list_elt  *temp = avail_phy_ifaces->head;
    char x[128];

    while (temp) {
        if (temp->ready) {
            if (temp->AF4_locators->head) {
                if (temp->AF4_locators->head->db_entry) {
                    syslog(LOG_DAEMON, "Interface for ctrl msgs: %s, v4 rloc: %s\n", 
                        temp->iface_name,
                        inet_ntop(AF_INET, 
                            &(temp->AF4_locators->head->db_entry->locator), 
                            x, 128));
                    return temp;
                }
            }
            if (temp->AF6_locators->head) {
                if (temp->AF6_locators->head->db_entry) {
                    syslog(LOG_DAEMON, "Interface for ctrl msgs: %s, v6 rloc: %s\n", 
                        temp->iface_name,
                        inet_ntop(AF_INET6, 
                            &(temp->AF6_locators->head->db_entry->locator), 
                            x, 128));
                    return temp;
                }
            }
        }
        temp = temp->next;

    }
    syslog(LOG_DAEMON, "Cannot find interface for control messages\n");
    return NULL;
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
