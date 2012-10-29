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

#include "lispd_iface_list.h"
#include <string.h>


iface_list  *avail_phy_ifaces = NULL;

lispd_iface_list_elt *head_interface_list = NULL;


lispd_iface_elt *add_interface(char *iface_name,
        int priority_v4,
        int weight_v4,
        int priority_v6,
        int weight_v6)
{
    lispd_iface_list_elt *iface_list, *aux_iface_list;
    lispd_iface_elt *iface;
    lisp_addr_t *rloc_addr_v4 = NULL;
    lisp_addr_t *rloc_addr_v6 = NULL;

    /* Search if the interface already exist and return it */
    if ((iface = get_interface(iface_name))!=NULL)
        return iface;
    /* Creating the new interface*/
    if ((iface_list = malloc(sizeof(lispd_iface_list_elt)))==NULL){
        syslog(LOG_CRIT,"Unable to allocate memory for iface_list_elt: %s", strerror(errno));
        return(NULL);
    }
    if ((iface = malloc(sizeof(lispd_iface_elt)))==NULL){
        syslog(LOG_CRIT,"Unable to allocate memory for iface_elt: %s", strerror(errno));
        free(iface_list);
        return(NULL);
    }
    iface->iface_name = iface_name;
    iface->status = UP;
    iface->head_locator_list = NULL;
    iface_list->iface = iface;
    iface_list->next = NULL;

    /* Add iface to the list */
    if (!head_interface_list){
        head_interface_list = iface_list;
    }else {
        aux_iface_list = head_interface_list;
        while (aux_iface_list->next)
           aux_iface_list = aux_iface_list->next;
        aux_iface_list->next = iface_list;
    }
    /* Get address and create locators */
    if (priority_v4 != -1 && weight_v4 != -1)
        rloc_addr_v4 = lispd_get_iface_address(iface_name, rloc_addr_v4, AF_INET);
    if (priority_v6 != -1 && weight_v6 != -1)
        rloc_addr_v4 = lispd_get_iface_address(iface_name, rloc_addr_v4, AF_INET);


    return iface;
}

/*
 * Look up an interface based in the iface_name.
 * Return the iface element if it is found or NULL if not.
 */

lispd_iface_elt *get_interface(char *iface_name)
{
    lispd_iface_list_elt *iface_list;
    lispd_iface_elt *iface;
    if (!head_interface_list)
        return NULL;
    iface_list = head_interface_list;
    while (!iface_list){
        if (strcmp (iface_list->iface->iface_name , iface_name) == 0)
            return iface_list->iface;
        iface_list = iface_list->next;
    }
    return NULL;
}




























































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

/* TODO alopez : It will probably disapear */
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
