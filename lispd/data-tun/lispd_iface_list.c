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
#include <elibs/htable/hash_table.h>
#include <string.h>


iface_list_elt *head_interface_list = NULL;

iface_t *default_out_iface_v4 = NULL;
iface_t *default_out_iface_v6 = NULL;

iface_t *default_ctrl_iface_v4 = NULL;
iface_t *default_ctrl_iface_v6 = NULL;

shash_t *iface_addr_ht = NULL;

int
build_iface_addr_hash_table()
{
    struct  ifaddrs *ifaddr, *ifa;
    int     family, s;
    char    host[NI_MAXHOST];

    lmlog(LINF, "Building address to interface hash table");
    if (getifaddrs(&ifaddr) == -1) {
        lmlog(LCRIT, "Can't read the interfaces of the system. Exiting .. ");
        exit_cleanup();
    }

    iface_addr_ht = shash_new_managed(free);

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                          sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                lmlog(LWRN, "getnameinfo() failed: %s. Skipping interface. ",
                        gai_strerror(s));
                continue;
            }

            shash_insert(iface_addr_ht, host, strdup(ifa->ifa_name));

            lmlog(LINF, "Found interface %s with address %s", ifa->ifa_name,
                    host);
        }
    }

    freeifaddrs(ifaddr);
    return(GOOD);
}

int
init_ifaces() {
    build_iface_addr_hash_table();
    return(GOOD);
}

/* set address, open socket, insert rule */
static int
iface_setup(iface_t *iface, char* iface_name,
        int afi)
{
    lisp_addr_t *addr;
    int *sock;

    switch (afi) {
    case AF_INET:
        addr = iface->ipv4_address;
        sock = &iface->out_socket_v4;
        break;
    case AF_INET6:
        addr = iface->ipv6_address;
        sock = &iface->out_socket_v6;
        break;
    }

    err = get_iface_address(iface_name, addr, afi);
    if (err != BAD) {
        sock = open_device_bound_raw_socket(iface_name, afi);
        bind_socket_address(sock, addr);
        add_rule(afi, 0, iface->iface_index, iface->iface_index, RTN_UNICAST,
                addr, ip_afi_to_default_mask(afi), NULL, 0, 0);
    } else {
        sock = -1;
        lisp_addr_ip_set_afi(addr, AF_UNSPEC);
        lisp_addr_set_afi(addr, LM_AFI_NO_ADDR);
        return(BAD);
    }

    return(GOOD);
}

/* Return the interface if it already exists. If it doesn't exist,
 * create and add an interface element to the list of interfaces. */
iface_t *
add_interface(char *iface_name)
{
    iface_list_elt *iface_list = NULL;
    iface_list_elt *aux_iface_list = NULL;
    iface_t *iface = NULL;

    /* Creating the new interface*/
    iface_list = xzalloc(sizeof(iface_list_elt));
    iface = xzalloc(sizeof(iface_t));
    iface->ipv4_address = lisp_addr_new_afi(LM_AFI_IP);
    iface->ipv6_address = lisp_addr_new_afi(LM_AFI_IP);

    iface->iface_name = strdup(iface_name); /* MUST FREE */
    iface->iface_index = if_nametoindex(iface_name);

    lisp_addr_set_ip_afi(iface->ipv4_address, AF_UNSPEC);
    iface->out_socket_v4 = -1;
    lisp_addr_set_ip_afi(iface->ipv6_address, AF_UNSPEC);
    iface->out_socket_v6 = -1;

    if (iface->iface_index != 0) {
        if (default_rloc_afi != AF_INET6) {
            iface_setup(iface, iface_name, AF_INET);
        }

        if (default_rloc_afi != AF_INET) {
            iface_setup(iface, iface_name, AF_INET6);
        }
    }

    if (lisp_addr_ip_afi(iface->ipv4_address) == AF_UNSPEC
            && lisp_addr_ip_afi(iface->ipv6_address) == AF_UNSPEC) {
        iface->status = DOWN;
    } else {
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
    if (!head_interface_list) {
        head_interface_list = iface_list;
    } else {
        aux_iface_list = head_interface_list;
        while (aux_iface_list->next)
            aux_iface_list = aux_iface_list->next;
        aux_iface_list->next = iface_list;
    }
    lmlog(DBG_2, "add_interface: Interface %s with interface index %d added to"
            " interfaces lists", iface_name, iface->iface_index);
    return (iface);
}


/* Add the mapping to the list of mappings of the interface according to the
 * afi. The mapping is added just one time */
int
add_mapping_to_interface(iface_t *iface, mapping_t *m, int afi)
{
    iface_mappings_list *map_list = NULL;
    iface_mappings_list *prev_map_list = NULL;

    map_list = iface->head_mappings_list;
    while (map_list != NULL) {
        // Check if the mapping is already installed in the list
        // XXX: this is risky stuff
        if (map_list->mapping == m) {
            switch (afi) {
            case AF_INET:
                map_list->use_ipv4_address = TRUE;
                break;
            case AF_INET6:
                map_list->use_ipv6_address = TRUE;
                break;
            }
            lmlog(DBG_2, "The EID %s has been previously assigned to the RLOCs"
                    " of the iface %s", lisp_addr_to_char(mapping_eid(m)),
                    iface->iface_name);
            return (GOOD);
        }
        prev_map_list = map_list;
        map_list = map_list->next;
    }

    map_list = xmalloc(1, sizeof(iface_mappings_list));
    map_list->mapping = m;
    map_list->next = NULL;

    switch (afi) {
    case AF_INET:
        map_list->use_ipv4_address = TRUE;
        map_list->use_ipv6_address = FALSE;
        break;
    case AF_INET6:
        map_list->use_ipv4_address = FALSE;
        map_list->use_ipv6_address = TRUE;
        break;
    }

    if (prev_map_list != NULL) {
        prev_map_list->next = map_list;
    } else {
        iface->head_mappings_list = map_list;
    }

    lmlog(DBG_2, "The EID %s has been assigned to the RLOCs of the interface "
            "%s", lisp_addr_to_char(mapping_eid(m)), iface->iface_name);

    return (GOOD);
}


/* Look up an interface based in the iface_name.
 * Return the iface element if it is found or NULL if not. */
iface_t *get_interface(char *iface_name)
{
    iface_list_elt *iface_list = head_interface_list;
    iface_t *iface = NULL;

    while (iface_list != NULL) {
        if (strcmp(iface_list->iface->iface_name, iface_name) == 0) {
            iface = iface_list->iface;
            break;
        }
        iface_list = iface_list->next;
    }

    return (iface);
}

/* Look up an interface based in the index of the iface.
 * Return the iface element if it is found or NULL if not. */
iface_t *get_interface_from_index(int iface_index)
{
    iface_t *iface = NULL;
    iface_list_elt *iface_lst_elt = NULL;

    iface_lst_elt = head_interface_list;
    while (iface_lst_elt != NULL) {
        if (iface_lst_elt->iface->iface_index == 0) {
            iface_lst_elt->iface->iface_index = if_nametoindex(
                    iface_lst_elt->iface->iface_name);
        }

        if (iface_lst_elt->iface->iface_index == iface_index) {
            iface = iface_lst_elt->iface;
            break;
        }
        iface_lst_elt = iface_lst_elt->next;
    }

    return iface;
}

/* Return the interface having assigned the address passed as a parameter  */
iface_t *
get_interface_with_address(lisp_addr_t *address)
{
    iface_t *iface = NULL;
    iface_list_elt *iface_lst_elt = NULL;

    iface_lst_elt = head_interface_list;
    while (iface_lst_elt != NULL){
        iface = iface_lst_elt->iface;
        switch (lisp_addr_ip_afi(address)) {
        case AF_INET:
            if (compare_lisp_addr_t(address, iface->ipv4_address) == 0) {
                return (iface);
            }
            break;
        case AF_INET6:
            if (compare_lisp_addr_t(address, iface->ipv6_address) == 0) {
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
    iface_list_elt *interface_list = head_interface_list;
    iface_mappings_list *mapping_list = NULL;
    char str[4000];

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
    lmlog(log_level,"%s",str);
}


iface_t *
get_default_ctrl_iface(int afi)
{
    iface_t *iface = NULL;

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


lisp_addr_t *
get_default_ctrl_address(int afi)
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

int
get_default_ctrl_socket(int afi)
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

/* Search the iface list for the first UP iface that has an 'afi' address*/
iface_t *
get_any_output_iface(int afi)
{
    iface_t *iface = NULL, *tif;
    iface_list_elt *iface_list_elt = head_interface_list;

    switch (afi) {
    case AF_INET:
        while (iface_list_elt != NULL) {
            tif = iface_list_elt->iface;
            if ((lisp_addr_ip_afi(tif->ipv4_address) != AF_UNSPEC)
                    && (tif->status == UP)) {
                iface = tif;
                break;
            }
            iface_list_elt = iface_list_elt->next;
        }
        break;
    case AF_INET6:
        while (iface_list_elt != NULL) {
            tif = iface_list_elt->iface;
            if ((lisp_addr_ip_afi(tif->ipv6_address) != AF_UNSPEC)
                    && (tif->status == UP)) {
                iface = tif;
                break;
            }
            iface_list_elt = iface_list_elt->next;
        }
        break;
    default:
        lmlog(DBG_2, "get_output_iface: unknown afi %d", afi);
        break;
    }

    return (iface);
}

lisp_addr_t *
get_default_output_address(int afi) {
    lisp_addr_t *addr = NULL;

    switch (afi) {
    case AF_INET:
        if (default_out_iface_v4 != NULL) {
            addr = default_out_iface_v4->ipv4_address;
        }
        break;
    case AF_INET6:
        if (default_out_iface_v6 != NULL) {
            addr = default_out_iface_v6->ipv6_address;
        }
        break;
    default:
        lmlog(DBG_2, "get_default_output_address: AFI %s not valid", afi);
        return(NULL);
    }

    return(addr);
}

int
get_default_output_socket(int afi)
{
    int out_socket = -1;

    switch (afi) {
    case AF_INET:
        if (default_out_iface_v4 != NULL) {
            out_socket = default_out_iface_v4->out_socket_v4;
        }
        break;
    case AF_INET6:
        if (default_out_iface_v6 != NULL) {
            out_socket = default_out_iface_v6->out_socket_v6;
        }
        break;
    default:
        lmlog(DBG_2, "get_default_output_socket: AFI %s not valid", afi);
        break;
    }

    return (out_socket);
}

void
set_default_output_ifaces()
{

    default_out_iface_v4 = get_any_output_iface(AF_INET);

    if (default_out_iface_v4 != NULL) {
       lmlog(DBG_2,"Default IPv4 iface %s\n",default_out_iface_v4->iface_name);
#ifdef ROUTER
       set_tun_default_route_v4();
#endif
    }
    
    default_out_iface_v6 = get_any_output_iface(AF_INET6);
    if (default_out_iface_v6 != NULL) {
       lmlog(DBG_2,"Default IPv6 iface %s\n", default_out_iface_v6->iface_name);
#ifdef ROUTER
       /* For IPv6, the route is not updated and should be removed before
        * adding the new one */
       del_tun_default_route_v6();
       set_tun_default_route_v6();
#endif
    }

    if (!default_out_iface_v4 && !default_out_iface_v6){
        lmlog(LCRIT,"NO OUTPUT IFACE: all the locators are down");
    }
}

void
set_default_ctrl_ifaces()
{
    default_ctrl_iface_v4 = get_any_output_iface(AF_INET);

    if (default_ctrl_iface_v4 != NULL) {
       lmlog(DBG_2,"Default IPv4 control iface %s: %s\n",
               default_ctrl_iface_v4->iface_name,
               lisp_addr_to_char(default_ctrl_iface_v4->ipv4_address));
    }

    default_ctrl_iface_v6 = get_any_output_iface(AF_INET6);

    if (default_ctrl_iface_v6 != NULL) {
        lmlog(DBG_2,"Default IPv6 control iface %s: %s\n",
                default_ctrl_iface_v6->iface_name,
                lisp_addr_to_char(default_ctrl_iface_v6->ipv6_address));
    }

    if (!default_ctrl_iface_v4 && !default_ctrl_iface_v6) {
        lmlog(LERR, "NO CONTROL IFACE: all the locators are down");
    }
}


lisp_addr_t *
iface_address(iface_t *iface, int afi)
{
    lisp_addr_t *addr = NULL;

    switch (afi) {
    case AF_INET:
        addr = iface->ipv4_address;
        break;
    case AF_INET6:
        addr = iface->ipv6_address;
        break;
    }

    return (addr);
}

int
iface_socket(iface_t *iface, int afi)
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

iface_list_elt *get_head_interface_list()
{
    return head_interface_list;
}


/* Recalculate balancing vector of the mappings associated to iface */
void
iface_balancing_vectors_calc(iface_t *iface) {
    iface_mappings_list *mapping_list = NULL;
    lcl_mapping_extended_info *lcl_extended_info = NULL;

    mapping_list = iface->head_mappings_list;
    while (mapping_list != NULL) {
        lcl_extended_info = mapping_list->mapping->extended_info;
        balancing_vectors_calculate(mapping_list->mapping,
                &(lcl_extended_info->outgoing_balancing_locators_vecs));
        mapping_list = mapping_list->next;
    }
}

/* Close all the open output sockets associated to interfaces */
void
close_output_sockets() {
    iface_list_elt *interface_list_elt = NULL;
    iface_t *iface = NULL;

    interface_list_elt = head_interface_list;
    while (interface_list_elt != NULL) {
        iface = interface_list_elt->iface;
        if (iface->out_socket_v4 != -1) {
            close(iface->out_socket_v4);
        }
        if (iface->out_socket_v6 != -1) {
            close(iface->out_socket_v6);
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
