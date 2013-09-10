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

#include "lispd_external.h"
#include "lispd_info_request.h"
#include "lispd_lib.h"
#include "lispd_routing_tables_lib.h"
#include "lispd_sockets.h"
#include "lispd_tun.h"
#include <string.h>


lispd_iface_list_elt    *head_interface_list    = NULL;

lispd_iface_elt         *default_out_iface_v4   = NULL;
lispd_iface_elt         *default_out_iface_v6   = NULL;

lispd_iface_elt         *default_ctrl_iface_v4  = NULL;
lispd_iface_elt         *default_ctrl_iface_v6  = NULL;


lispd_iface_elt *add_interface(char *iface_name)
{
    lispd_iface_list_elt    *iface_list         = NULL;
    lispd_iface_list_elt    *aux_iface_list     = NULL;
    lispd_iface_elt         *iface              = NULL;

    /* Creating the new interface*/
    if ((iface_list = malloc(sizeof(lispd_iface_list_elt)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"add_interface: Unable to allocate memory for iface_list_elt: %s", strerror(errno));
        return(NULL);
    }
    if ((iface = malloc(sizeof(lispd_iface_elt)))==NULL){
        lispd_log_msg(LISP_LOG_WARNING,"add_interface: Unable to allocate memory for iface_elt: %s", strerror(errno));
        free(iface_list);
        return(NULL);
    }
    if ((iface->ipv4_address = (lisp_addr_t *)malloc(sizeof(lisp_addr_t)))==NULL){
    	lispd_log_msg(LISP_LOG_WARNING,"add_interface: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
    	free(iface_list);
    	free(iface);
    	return(NULL);
    }
    if ((iface->ipv6_address = (lisp_addr_t *)malloc(sizeof(lisp_addr_t)))==NULL){
    	lispd_log_msg(LISP_LOG_WARNING,"add_interface: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
    	free(iface_list);
    	free(iface->ipv4_address);
    	free(iface);
    	return(NULL);
    }
    memset(iface->ipv4_address,0,sizeof(lisp_addr_t));
    memset(iface->ipv6_address,0,sizeof(lisp_addr_t));

    iface->iface_name = malloc(strlen(iface_name) + 1);   // XXX Must free elsewhere
    strcpy(iface->iface_name, iface_name);

    iface->iface_index = if_nametoindex(iface_name);


    if (iface->iface_index != 0){
        if (default_rloc_afi != AF_INET6){
            err = lispd_get_iface_address(iface_name, iface->ipv4_address, AF_INET);
            if (err == GOOD){
                iface->out_socket_v4 = open_device_binded_raw_socket(iface->iface_name,AF_INET);
                bind_socket_src_address(iface->out_socket_v4,iface->ipv4_address);
                add_rule(AF_INET,
                        0,                      //iface
                        iface->iface_index,     //table
                        iface->iface_index,     //priority
                        RTN_UNICAST,
                        iface->ipv4_address,
                        32,NULL,0,0);
            }else {
                iface->ipv4_address->afi = AF_UNSPEC;
                iface->out_socket_v4 = -1;
            }
        }else{
            iface->ipv4_address->afi = AF_UNSPEC;
            iface->out_socket_v4 = -1;
        }
        // XXX To be modified when full NAT implemented
        if (nat_aware != TRUE){
            if (default_rloc_afi != AF_INET){
                err = lispd_get_iface_address(iface_name, iface->ipv6_address, AF_INET6);
                if (err == GOOD){
                    iface->out_socket_v6 = open_device_binded_raw_socket(iface->iface_name,AF_INET6);
                    bind_socket_src_address(iface->out_socket_v6,iface->ipv6_address);
                    add_rule(AF_INET6,
                            0,                      //iface
                            iface->iface_index,     //table
                            iface->iface_index,     //priority
                            RTN_UNICAST,
                            iface->ipv6_address,
                            128,NULL,0,0);
                }else {
                    iface->ipv6_address->afi = AF_UNSPEC;
                    iface->out_socket_v6 = -1;
                }
            }else {
                iface->ipv6_address->afi = AF_UNSPEC;
                iface->out_socket_v6 = -1;
            }
        }else{
            iface->ipv6_address->afi = AF_UNSPEC;
            iface->out_socket_v6 = -1;
        }

    }else{
        iface->ipv4_address->afi = AF_UNSPEC;
        iface->out_socket_v4 = -1;
        iface->ipv6_address->afi = AF_UNSPEC;
        iface->out_socket_v6 = -1;
    }

    if ( iface->ipv4_address->afi == AF_UNSPEC &&  iface->ipv6_address->afi == AF_UNSPEC){
        iface->status = DOWN;
    }else{
        iface->status = UP;
    }

    iface->head_mappings_list = NULL;
    iface->status_changed = TRUE;
    iface->ipv4_changed = TRUE;
    iface->ipv6_changed = TRUE;
    iface->ipv4_gateway = NULL;
    iface->ipv6_gateway = NULL;
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
    lispd_log_msg(LISP_LOG_DEBUG_2,"add_interface: Interface %s with interface index %d added to interfaces lists",
            iface_name, iface->iface_index);
    return (iface);
}

/*
 * Add the mapping to the list of mappings of the interface according to the afi.
 * The mapping is added just one time
 */

int add_mapping_to_interface (
        lispd_iface_elt         *interface,
        lispd_mapping_elt       *mapping,
        int                     afi)
{
    lispd_iface_mappings_list       *mappings_list       = NULL;
    lispd_iface_mappings_list       *prev_mappings_list  = NULL;


    mappings_list = interface->head_mappings_list;
    while (mappings_list != NULL){
        // Check if the mapping is already installed in the list
        if ( mappings_list->mapping == mapping ){
            switch(afi){
            case AF_INET:
                mappings_list->use_ipv4_address = TRUE;
                break;
            case AF_INET6:
                mappings_list->use_ipv6_address = TRUE;
                break;
            }
            lispd_log_msg(LISP_LOG_DEBUG_2,"The EID %s/%d has been assigned to the RLOCs of the interface %s",
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length,
                    interface->iface_name);
            return (GOOD);
        }
        prev_mappings_list = mappings_list;
        mappings_list = mappings_list->next;
    }


    if ((mappings_list = malloc(sizeof(lispd_iface_mappings_list)))==NULL){
        lispd_log_msg(LISP_LOG_ERR,"add_mapping_to_interface: couldn't allocate memory for lispd_mappings_list: %s",strerror(errno));
        return (ERR_MALLOC);
    }

    mappings_list->mapping=mapping;
    mappings_list->next = NULL;

    switch(afi){
    case AF_INET:
        mappings_list->use_ipv4_address = TRUE;
        mappings_list->use_ipv6_address = FALSE;
        break;
    case AF_INET6:
        mappings_list->use_ipv4_address = FALSE;
        mappings_list->use_ipv6_address = TRUE;
        break;
    }

    if (prev_mappings_list != NULL){
        prev_mappings_list->next =  mappings_list;
    }else{
        interface->head_mappings_list = mappings_list;
    }

    lispd_log_msg(LISP_LOG_DEBUG_2,"The EID %s/%d has been assigned to the RLOCs of the interface %s",
            get_char_from_lisp_addr_t(mapping->eid_prefix),
            mapping->eid_prefix_length,
            interface->iface_name);

    return (GOOD);
}

/*
 * Look up an interface based in the iface_name.
 * Return the iface element if it is found or NULL if not.
 */

lispd_iface_elt *get_interface(char *iface_name)
{
    lispd_iface_list_elt *iface_list = head_interface_list;
    lispd_iface_elt      *iface      = NULL;

    while (iface_list != NULL){
        if (strcmp (iface_list->iface->iface_name , iface_name) == 0){
            iface = iface_list->iface;
            break;
        }
        iface_list = iface_list->next;
    }

    return (iface);
}

/*
 * Look up an interface based in the index of the iface.
 * Return the iface element if it is found or NULL if not.
 */

lispd_iface_elt *get_interface_from_index(int iface_index)
{

    lispd_iface_elt         *iface          = NULL;
    lispd_iface_list_elt    *iface_lst_elt  = NULL;

    iface_lst_elt = head_interface_list;
    while (iface_lst_elt != NULL){
        if (iface_lst_elt->iface->iface_index == 0){
            iface_lst_elt->iface->iface_index = if_nametoindex (iface_lst_elt->iface->iface_name);
        }

        if (iface_lst_elt->iface->iface_index == iface_index){
            iface = iface_lst_elt->iface;
            break;
        }
        iface_lst_elt = iface_lst_elt->next;
    }

    return iface;
}
/*
 * Return the interface belonging the address passed as a parameter
 */

lispd_iface_elt *get_interface_with_address(lisp_addr_t *address)
{
    lispd_iface_elt         *iface          = NULL;
    lispd_iface_list_elt    *iface_lst_elt  = NULL;

    iface_lst_elt = head_interface_list;
    while (iface_lst_elt != NULL){
        iface = iface_lst_elt->iface;
        switch(address->afi)
        {
        case AF_INET:
            if (compare_lisp_addr_t (address,iface->ipv4_address) == 0){
                return (iface);
            }
            break;
        case AF_INET6:
            if (compare_lisp_addr_t (address,iface->ipv6_address) == 0){
                return (iface);
            }
            break;
        }
        iface_lst_elt = iface_lst_elt->next;
    }

    return (NULL);
}


/*
 * Print the interfaces and locators of the lisp node
 */

void dump_iface_list(int log_level)
{

    lispd_iface_list_elt        *interface_list    = head_interface_list;
    lispd_iface_mappings_list   *mapping_list      = NULL;
    char                        str[4000];

    if (head_interface_list == NULL || is_loggable(log_level) == FALSE){
        return;
    }

    sprintf(str,"*** LISP RLOC Interfaces List ***\n\n");

    while (interface_list){
        sprintf(str + strlen(str),"== %s   (%s)==\n",interface_list->iface->iface_name, interface_list->iface->status ? "Up" : "Down");
        if (interface_list->iface->ipv4_address){
            sprintf(str + strlen(str),"  IPv4 RLOC: %s \n",get_char_from_lisp_addr_t(*(interface_list->iface->ipv4_address)));
            sprintf(str + strlen(str),"    -- LIST mappings -- \n");
            mapping_list = interface_list->iface->head_mappings_list;
            while (mapping_list){
                if (mapping_list->use_ipv4_address == TRUE){
                    sprintf(str + strlen(str),"    %s/%d\n",get_char_from_lisp_addr_t(mapping_list->mapping->eid_prefix),
                            mapping_list->mapping->eid_prefix_length);
                }
                mapping_list = mapping_list->next;
            }
        }
        if (interface_list->iface->ipv6_address){
            sprintf(str + strlen(str),"  IPv6 RLOC: %s \n",get_char_from_lisp_addr_t(*(interface_list->iface->ipv6_address)));
            sprintf(str + strlen(str),"    -- LIST mappings -- \n");
            mapping_list = interface_list->iface->head_mappings_list;
            while (mapping_list){
                if (mapping_list->use_ipv6_address == TRUE){
                    sprintf(str + strlen(str),"    %s/%d\n",get_char_from_lisp_addr_t(mapping_list->mapping->eid_prefix),
                            mapping_list->mapping->eid_prefix_length);
                }
                mapping_list = mapping_list->next;
            }
        }
        interface_list = interface_list->next;
    }
    lispd_log_msg(log_level,"%s",str);
}


/* Search the iface list for the first UP iface that has an 'afi' address*/

lispd_iface_elt *get_any_output_iface(int afi)
{
    lispd_iface_elt         *iface              = NULL;
    lispd_iface_list_elt    *iface_list_elt     = head_interface_list;
    
    switch (afi){
        case AF_INET:
            while (iface_list_elt!=NULL){
                if ((iface_list_elt->iface->ipv4_address->afi != AF_UNSPEC)
                        && (iface_list_elt->iface->status == UP)) {
                    iface = iface_list_elt->iface;
                    break;
                }
                iface_list_elt = iface_list_elt->next;
            }
            break;
        case AF_INET6:
            while (iface_list_elt!=NULL){
                if ((iface_list_elt->iface->ipv6_address->afi != AF_UNSPEC)
                        && (iface_list_elt->iface->status == UP)) {
                    iface = iface_list_elt->iface;
                    break;
                }
                iface_list_elt = iface_list_elt->next;
            }
            break;
        default:
            lispd_log_msg(LISP_LOG_DEBUG_2, "get_output_iface: unknown afi %d",afi);
            break;
    }

    return (iface);
}

lispd_iface_elt *get_default_ctrl_iface(int afi)
{

    lispd_iface_elt *iface = NULL;

    switch (afi){
        case AF_INET:
            iface = default_ctrl_iface_v4;
            break;
        case AF_INET6:
            iface = default_ctrl_iface_v6;
            break;
        default:
            //arnatal TODO: syslog
            iface = NULL;
            break;
    }

    return (iface);
}


lisp_addr_t *get_default_ctrl_address(int afi)
{

    lisp_addr_t *address = NULL;


    switch (afi){
        case AF_INET:
            if (default_ctrl_iface_v4 != NULL){
                address = default_ctrl_iface_v4->ipv4_address;
            }
            break;
        case AF_INET6:
            if (default_ctrl_iface_v6 != NULL){
                address = default_ctrl_iface_v6->ipv6_address;
            }
            break;
        default:
            break;
    }

    return (address);
}

int get_default_ctrl_socket(int afi)
{

    int socket = 0;


    switch (afi){
        case AF_INET:
            if (default_ctrl_iface_v4 != NULL){
                socket = default_ctrl_iface_v4->out_socket_v4;
            }
            break;
        case AF_INET6:
            if (default_ctrl_iface_v6 != NULL){
                socket = default_ctrl_iface_v6->out_socket_v6;
            }
            break;
        default:
            socket = ERR_SRC_ADDR;
            break;
    }

    return (socket);
}

int get_default_output_socket(int afi)
{
    int out_socket = -1;

    switch (afi){
    case AF_INET:
        if (default_out_iface_v4 != NULL){
            out_socket = default_out_iface_v4->out_socket_v4;
        }
        break;
    case AF_INET6:
        if (default_out_iface_v6 != NULL){
            out_socket = default_out_iface_v6->out_socket_v6;
        }
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "get_default_output_socket: Packet with not valid AFI: %d",afi);
        break;
    }

    return (out_socket);
}

void set_default_output_ifaces()
{

    default_out_iface_v4 = get_any_output_iface(AF_INET);

    if (default_out_iface_v4 != NULL) {
       lispd_log_msg(LISP_LOG_DEBUG_2,"Default IPv4 iface %s\n",default_out_iface_v4->iface_name);
#ifdef ROUTER
       set_tun_default_route_v4();
#endif
    }
    
    default_out_iface_v6 = get_any_output_iface(AF_INET6);
    if (default_out_iface_v6 != NULL) {
       lispd_log_msg(LISP_LOG_DEBUG_2,"Default IPv6 iface %s\n",default_out_iface_v6->iface_name);
#ifdef ROUTER
       // For IPv6, the route is not updated and should be removed before adding the new one
       del_tun_default_route_v6();
       set_tun_default_route_v6();
#endif
    }

    if (!default_out_iface_v4 && !default_out_iface_v6){
        lispd_log_msg(LISP_LOG_CRIT,"NO OUTPUT IFACE: all the locators are down");
    }
}

void set_default_ctrl_ifaces()
{

    default_ctrl_iface_v4 = get_any_output_iface(AF_INET);

    if (default_ctrl_iface_v4 != NULL) {
       lispd_log_msg(LISP_LOG_DEBUG_2,"Default IPv4 control iface %s: %s\n",
               default_ctrl_iface_v4->iface_name, get_char_from_lisp_addr_t(*(default_ctrl_iface_v4->ipv4_address)));
    }

    default_ctrl_iface_v6 = get_any_output_iface(AF_INET6);

    if (default_ctrl_iface_v6 != NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2,"Default IPv6 control iface %s: %s\n",
                default_ctrl_iface_v6->iface_name, get_char_from_lisp_addr_t(*(default_ctrl_iface_v6->ipv6_address)));
    }

    /* Check NAT status */
    if (nat_aware == TRUE && ( (default_ctrl_iface_v4 != NULL) || (default_ctrl_iface_v6 != NULL))){
              // TODO : To be modified when implementing NAT per multiple interfaces
              nat_status = UNKNOWN;
              initial_info_request_process();
    }

    if (!default_ctrl_iface_v4 && !default_ctrl_iface_v6){
        lispd_log_msg(LISP_LOG_ERR,"NO CONTROL IFACE: all the locators are down");
    }
}


lisp_addr_t *get_iface_address(
        lispd_iface_elt     *iface,
        int                 afi)
{
    
    lisp_addr_t     *addr   = NULL;
    
    switch(afi){
        case AF_INET:
            addr = iface->ipv4_address;
            break;
        case AF_INET6:
            addr = iface->ipv6_address;
            break;
    }
    
    return (addr);
}

int get_iface_socket(
        lispd_iface_elt     *iface,
        int                 afi)
{
    int out_socket   = 0;

    switch(afi){
    case AF_INET:
        out_socket = iface->out_socket_v4;
        break;
    case AF_INET6:
        out_socket = iface->out_socket_v6;
        break;
    default:
        out_socket = ERR_SRC_ADDR;
        break;
    }
    
    return (out_socket);
}

/*
 * Return the list of interfaces
 */

lispd_iface_list_elt *get_head_interface_list()
{
    return head_interface_list;
}


/*
 * Recalculate balancing vector of the mappings assorciated to iface
 */

void iface_balancing_vectors_calc(lispd_iface_elt  *iface)
{
    lispd_iface_mappings_list   *mapping_list       = NULL;
    lcl_mapping_extended_info   *lcl_extended_info  = NULL;

    mapping_list = iface->head_mappings_list;
    while (mapping_list != NULL){
        lcl_extended_info = (lcl_mapping_extended_info *)(mapping_list->mapping->extended_info);
        calculate_balancing_vectors (
                mapping_list->mapping,
                &(lcl_extended_info->outgoing_balancing_locators_vecs));
        mapping_list = mapping_list->next;
    }
}

/*
 * Close all the open output sockets associated to interfaces
 */

void close_output_sockets()
{
    lispd_iface_list_elt    *interface_list_elt = NULL;
    lispd_iface_elt         *iface              = NULL;

    interface_list_elt = head_interface_list;
    while (interface_list_elt != NULL){
        iface = interface_list_elt->iface;
        if (iface->out_socket_v4 != -1){
            close (iface->out_socket_v4);
        }
        if (iface->out_socket_v6 != -1){
            close (iface->out_socket_v6);
        }

        interface_list_elt = interface_list_elt->next;
    }

    return;
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
