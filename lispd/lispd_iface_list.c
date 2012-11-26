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
#include "lispd_lib.h"
#include <string.h>


iface_list  *avail_phy_ifaces = NULL;

lispd_iface_list_elt *head_interface_list = NULL;

lispd_iface_elt *default_out_iface_v4;
lispd_iface_elt *default_out_iface_v6;


lispd_iface_elt *add_interface(char *iface_name)
{
    lispd_iface_list_elt *iface_list, *aux_iface_list;
    lispd_iface_elt *iface;

    /* Creating the new interface*/
    if ((iface_list = malloc(sizeof(lispd_iface_list_elt)))==NULL){
        syslog(LOG_CRIT,"add_interface: Unable to allocate memory for iface_list_elt: %s", strerror(errno));
        return(NULL);
    }
    if ((iface = malloc(sizeof(lispd_iface_elt)))==NULL){
        syslog(LOG_CRIT,"add_interface: Unable to allocate memory for iface_elt: %s", strerror(errno));
        free(iface_list);
        return(NULL);
    }
    if ((iface->ipv4_address = malloc(sizeof(lisp_addr_t)))==NULL){
    	syslog(LOG_CRIT,"add_interface: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
    	free(iface_list);
    	free(iface);
    	return(NULL);
    }
    if ((iface->ipv6_address = malloc(sizeof(lisp_addr_t)))==NULL){
    	syslog(LOG_CRIT,"add_interface: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
    	free(iface_list);
    	free(iface->ipv4_address);
    	free(iface);
    	return(NULL);
    }
    iface->iface_name = malloc(strlen(iface_name) + 1);   // XXX Must free elsewhere
    strcpy(iface->iface_name, iface_name);
    iface->status = UP;
    iface->ipv4_address = lispd_get_iface_address(iface_name, iface->ipv4_address, AF_INET);
    iface->ipv6_address = lispd_get_iface_address(iface_name, iface->ipv6_address, AF_INET6);
    iface->head_v4_identifiers_list = NULL;
    iface->head_v6_identifiers_list = NULL;
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
    return iface;
}

/*
 * Add the identifier to the list of identifiers of the interface according to the afi.
 * The identifier is added just one time
 */

int add_identifier_to_interface (lispd_iface_elt *interface, lispd_identifier_elt *identifier, int afi)
{
	lispd_identifiers_list *identifiers_list, *aux_identifiers_list;


	if ((identifiers_list = malloc(sizeof(lispd_identifiers_list)))==NULL){
		syslog(LOG_ERR,"add_identifier_to_interface: couldn't allocate memory for lispd_identifiers_list");
		return (ERR_MALLOC);
	}
	identifiers_list->identifier=identifier;
	identifiers_list->next = NULL;

	if ( afi == AF_INET ){
		if (interface->head_v4_identifiers_list == NULL){
			interface->head_v4_identifiers_list = identifiers_list;
			return (GOOD);
		}
		aux_identifiers_list = interface->head_v4_identifiers_list;
	}
	else{
		if (interface->head_v6_identifiers_list == NULL){
			interface->head_v6_identifiers_list = identifiers_list;
			return (GOOD);
		}
		aux_identifiers_list = interface->head_v6_identifiers_list;
	}
	while (aux_identifiers_list->next && aux_identifiers_list->identifier != identifier){
		aux_identifiers_list = aux_identifiers_list->next;
	}
	if (aux_identifiers_list->identifier == identifier)
		return (ERR_EXIST);
	aux_identifiers_list->next = identifiers_list;
	return (GOOD);
}

/*
 * Look up an interface based in the iface_name.
 * Return the iface element if it is found or NULL if not.
 */

lispd_iface_elt *get_interface(char *iface_name)
{
    lispd_iface_list_elt *iface_list;
    if (!head_interface_list)
        return NULL;
    iface_list = head_interface_list;
    while (iface_list){
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
void add_item_to_iface_list (list, item)
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
lispd_iface_elt *find_active_ctrl_iface()
{
    lispd_iface_list_elt    *iface_list = head_interface_list;
    lispd_iface_elt         *iface;

    while (iface_list) {
        iface = iface_list->iface;
        if (iface->status) {
            if (iface->ipv4_address){
                syslog(LOG_INFO, "Interface for ctrl msgs: %s, v4 rloc: %s\n",
                        iface->iface_name,
                        get_char_from_lisp_addr_t(*(iface->ipv4_address)));
            }
            if (iface->ipv6_address){
                syslog(LOG_INFO, "Interface for ctrl msgs: %s, v6 rloc: %s\n",
                        iface->iface_name,
                        get_char_from_lisp_addr_t(*(iface->ipv6_address)));
            }
            return iface;
        }
        iface_list = iface_list->next;

    }
    syslog(LOG_DAEMON, "Cannot find interface for control messages\n");
    return NULL;
}

/*
 * Print the interfaces and locators of the lisp node
 */

void dump_iface_list()
{

    lispd_iface_list_elt     *interface_list = head_interface_list;
    lispd_identifiers_list   *identifier_list;

    if (head_interface_list == NULL)
        return;

    printf("LISP Interfaces List\n\n");

    while (interface_list){
        printf ("== %s   (%s)==\n",interface_list->iface->iface_name, interface_list->iface->status ? "Up" : "Down");
        if (interface_list->iface->ipv4_address){
            printf ("  IPv4 RLOC: %s \n",get_char_from_lisp_addr_t(*(interface_list->iface->ipv4_address)));
            printf ("    -- LIST identifiers -- \n");
            identifier_list = interface_list->iface->head_v4_identifiers_list;
            while (identifier_list){
                printf("    %s/%d\n",get_char_from_lisp_addr_t(identifier_list->identifier->eid_prefix),
                        identifier_list->identifier->eid_prefix_length);
                identifier_list = identifier_list->next;
            }
        }
        if (interface_list->iface->ipv6_address){
            printf ("  IPv6 RLOC: %s \n",get_char_from_lisp_addr_t(*(interface_list->iface->ipv6_address)));
            printf ("    -- LIST identifiers -- \n");
            identifier_list = interface_list->iface->head_v6_identifiers_list;
            while (identifier_list){
                printf("    %s/%d\n",get_char_from_lisp_addr_t(identifier_list->identifier->eid_prefix),
                        identifier_list->identifier->eid_prefix_length);
                identifier_list = identifier_list->next;
            }
        }
        interface_list = interface_list->next;
    }
}





void open_iface_binded_sockets(){

    lispd_iface_elt *iface;
    
    lispd_iface_list_elt *iface_list_elt;

    
    iface_list_elt = head_interface_list;
    
    do {
        
        iface = iface_list_elt->iface;

        iface->out_socket_v4 = open_device_binded_raw_socket(iface->iface_name,AF_INET);
        iface->out_socket_v6 = open_device_binded_raw_socket(iface->iface_name,AF_INET6);
        
        iface_list_elt = iface_list_elt->next;
        
    }while (iface_list_elt != NULL);
    
}

/* Search the iface list for the first UP iface that has an 'afi' address*/

lispd_iface_elt *get_any_output_iface(int afi){

    lispd_iface_elt *iface;
    lispd_iface_list_elt *iface_list_elt;

    iface_list_elt = head_interface_list;

    iface = NULL;
    
    switch (afi){
        case AF_INET:
            while ((iface_list_elt!=NULL)
                && (iface_list_elt->iface->ipv4_address!=NULL)
                && (iface_list_elt->iface->status == UP)) {

                iface = iface_list_elt->iface;
                iface_list_elt = iface_list_elt->next;
            }
            break;
        case AF_INET6:
            while ((iface_list_elt!=NULL)
                && (iface_list_elt->iface->ipv6_address!=NULL)
                && (iface_list_elt->iface->status == UP)) {

                iface = iface_list_elt->iface;
                iface_list_elt = iface_list_elt->next;
            }
            break;
        default:
            syslog(LOG_ERR, "get_output_iface: unknown afi %d",afi);
    }

    return iface;
}

lispd_iface_elt *get_default_output_iface(int afi){

    lispd_iface_elt *iface;

    switch (afi){
        case AF_INET:
            iface = default_out_iface_v4;
            break;
        case AF_INET6:
            iface = default_out_iface_v6;
            break;
        default:
            //arnatal TODO: syslog
            iface = NULL;
    }

    return iface;
}

void set_default_output_ifaces(){

    default_out_iface_v4 = get_any_output_iface(AF_INET);
    printf("Default IPv4 iface %s\n",default_out_iface_v4->iface_name);
    default_out_iface_v6 = get_any_output_iface(AF_INET6);
    printf("Default IPv6 iface %s\n",default_out_iface_v6->iface_name);

}


lisp_addr_t *get_iface_address(lispd_iface_elt *iface, int afi){
    
    lisp_addr_t *addr;
    
    switch(afi){
        case AF_INET:
            addr = iface->ipv4_address;
            break;
        case AF_INET6:
            addr = iface->ipv6_address;
            break;
    }
    
    return addr;
    
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
