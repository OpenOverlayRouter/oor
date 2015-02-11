/* 
 * iface_list.c
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
 *    Florin Coras      <fcoras@ac.upc.edu>
 *
 */
#include <string.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <errno.h>
#include <linux/rtnetlink.h>

#include "iface_list.h"
#include "lispd_external.h"
#include "routing_tables_lib.h"
#include "sockets.h"
#include "lispd_tun.h"
#include "shash.h"
#include "sockets-util.h"
#include "lmlog.h"


iface_list_elt_t *head_interface_list = NULL;

iface_t *default_out_iface_v4 = NULL;
iface_t *default_out_iface_v6 = NULL;

iface_t *default_ctrl_iface_v4 = NULL;
iface_t *default_ctrl_iface_v6 = NULL;

shash_t *iface_addr_ht = NULL;

int
build_iface_addr_hash_table()
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    LMLOG(LINF, "Building address to interface hash table");
    if (getifaddrs(&ifaddr) == -1) {
        LMLOG(LCRIT, "Can't read the interfaces of the system. Exiting .. ");
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
                LMLOG(LWRN, "getnameinfo() failed: %s. Skipping interface. ",
                        gai_strerror(s));
                continue;
            }

            shash_insert(iface_addr_ht, host, strdup(ifa->ifa_name));

            LMLOG(DBG_2, "Found interface %s with address %s", ifa->ifa_name,
                    host);
        }
    }

    freeifaddrs(ifaddr);
    return(GOOD);
}

int
ifaces_init()
{
    build_iface_addr_hash_table();
    return(GOOD);
}


void
iface_remove_routing_rules(iface_t *iface)
{
    if (!lisp_addr_is_no_addr(iface->ipv4_address)) {
        if (iface->ipv4_gateway != NULL) {
            del_route(AF_INET, iface->iface_index, NULL, NULL,
                    iface->ipv4_gateway, 0, iface->iface_index);
        }

        del_rule(AF_INET, 0, iface->iface_index, iface->iface_index,
                RTN_UNICAST, iface->ipv4_address, NULL, 0);
    }
    if (!lisp_addr_is_no_addr(iface->ipv6_address)) {
        if (iface->ipv6_gateway != NULL) {
            del_route(AF_INET6, iface->iface_index, NULL, NULL,
                    iface->ipv6_gateway, 0, iface->iface_index);
        }
        del_rule(AF_INET6, 0, iface->iface_index, iface->iface_index,
                RTN_UNICAST, iface->ipv6_address, NULL, 0);
    }
}

void
iface_destroy(iface_t *iface)
{
    /* Remove routing rules */
    iface_remove_routing_rules(iface);

    /* Close sockets */
    if (iface->out_socket_v4 != -1) {
        close(iface->out_socket_v4);
    }
    if (iface->out_socket_v6 != -1) {
        close(iface->out_socket_v6);
    }

    /* Free data structure */
    free(iface->iface_name);

    lisp_addr_del(iface->ipv4_address);
    lisp_addr_del(iface->ipv6_address);
    lisp_addr_del(iface->ipv4_gateway);
    lisp_addr_del(iface->ipv6_gateway);

    free(iface);
}


void
ifaces_destroy()
{
    iface_list_elt_t *elt, *next;
    elt = head_interface_list;
    while(elt) {
        next = elt->next;
        iface_destroy(elt->iface);
        free(elt);
        elt = next;
    }

    shash_destroy(iface_addr_ht);
}


/*
 *  lispd_get_iface_address
 *
 *  fill the parameter addr with the lisp_addr_t of the interface with afi.
 *  Return BAD if no address is present in the interface.
 */

int
get_iface_address(char *ifacename, lisp_addr_t *addr, int afi)
{
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;
    struct sockaddr_in *s4;
    struct sockaddr_in6 *s6;
    ip_addr_t ip;

    /* search for the interface */
    if (getifaddrs(&ifaddr) !=0) {
        LMLOG(DBG_2, "lispd_get_iface_address: getifaddrs error: %s",
                strerror(errno));
        return(BAD);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr == NULL)
             || ((ifa->ifa_flags & IFF_UP) == 0)
             || (ifa->ifa_addr->sa_family != afi)
             || strcmp(ifa->ifa_name, ifacename) != 0) {
            continue;
        }

        switch (ifa->ifa_addr->sa_family) {
        case AF_INET:
            s4 = (struct sockaddr_in *) ifa->ifa_addr;
            ip_addr_init(&ip, &s4->sin_addr, AF_INET);

            if (ip_addr_is_link_local(&ip) == TRUE) {
                LMLOG(DBG_2, "lispd_get_iface_address: interface address from "
                        "%s discarded (%s)", ifacename, ip_addr_to_char(&ip));
                continue;
            }

            lisp_addr_init_from_ip(addr, &ip);
            freeifaddrs(ifaddr);
            return(GOOD);
        case AF_INET6:
            s6 = (struct sockaddr_in6 *) ifa->ifa_addr;
            ip_addr_init(&ip, &s6->sin6_addr, AF_INET6);

            /* XXX sin6_scope_id is an ID depending on the scope of the
             * address.  Linux only supports it for link-local addresses, in
             * that case sin6_scope_id contains the interface index.
             * --> If sin6_scope_id is not zero, is a link-local address */
            if (s6->sin6_scope_id != 0) {
                LMLOG(DBG_2, "lispd_get_iface_address: interface address from "
                        "%s discarded (%s)", ifacename, ip_addr_to_char(&ip));
                continue;
            }

            lisp_addr_init_from_ip(addr, &ip);
            freeifaddrs(ifaddr);
            return(GOOD);

        default:
            continue;                   /* XXX */
        }
    }
    freeifaddrs(ifaddr);
    LMLOG(DBG_3, "lispd_get_iface_address: No %s RLOC configured for interface "
            "%s\n", (afi == AF_INET) ? "IPv4" : "IPv6", ifacename);
    return(BAD);
}

/* set address, open socket, insert rule */
static int
iface_setup(iface_t *iface, char* iface_name, int afi)
{
    lisp_addr_t *addr;
    int *sock, ret;

    switch (afi) {
    case AF_INET:
        addr = iface->ipv4_address;
        sock = &iface->out_socket_v4;
        break;
    case AF_INET6:
        addr = iface->ipv6_address;
        sock = &iface->out_socket_v6;
        break;
    default:
        LMLOG(DBG_2,"iface_setup: Unknown afi: %d", afi);
        return (BAD);
    }

    ret = get_iface_address(iface_name, addr, afi);
    if (ret == GOOD) {
        *sock = open_device_bound_raw_socket(iface_name, afi);
        bind_socket_address(*sock, addr);
        add_rule(afi, 0, iface->iface_index, iface->iface_index, RTN_UNICAST,
                addr, NULL, 0);
    } else {
        *sock = -1;
        lisp_addr_set_lafi(addr, LM_AFI_NO_ADDR);
        return(BAD);
    }

    return(GOOD);
}

/* Return the interface if it already exists. If it doesn't exist,
 * create and add an interface element to the list of interfaces. */
iface_t *
add_interface(char *iface_name)
{
    iface_list_elt_t *iface_list = NULL;
    iface_list_elt_t *aux_iface_list = NULL;
    iface_t *iface = NULL;

    if (if_nametoindex(iface_name) == 0) {
        LMLOG(LERR, "Configuration file: INVALID INTERFACE or not initialized "
                "virtual interface: %s ", iface_name);
        return(NULL);
    }

    /* Creating the new interface*/
    iface_list = xzalloc(sizeof(iface_list_elt_t));
    iface = xzalloc(sizeof(iface_t));

    iface->iface_name = strdup(iface_name); /* MUST FREE */
    iface->iface_index = if_nametoindex(iface_name);

    /* set up all fields to default, null values */
    iface->ipv4_address = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
    iface->ipv6_address = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
    iface->out_socket_v4 = -1;
    iface->out_socket_v6 = -1;


    LMLOG(DBG_2, "Adding interface %s with index %d to iface list",
            iface_name, iface->iface_index);


    if (iface->iface_index != 0) {
        if (default_rloc_afi != AF_INET6) {
            iface_setup(iface, iface_name, AF_INET);
        }

        if (default_rloc_afi != AF_INET) {
            iface_setup(iface, iface_name, AF_INET6);
        }
    }

    if (lisp_addr_lafi(iface->ipv4_address) == LM_AFI_NO_ADDR
        && lisp_addr_lafi(iface->ipv6_address) == LM_AFI_NO_ADDR) {
        iface->status = DOWN;
    } else {
        iface->status = UP;
    }

    iface->ipv4_gateway = NULL;
    iface->ipv6_gateway = NULL;
    iface_list->iface = iface;
    iface_list->next = NULL;

    /* Add iface to the list */
    if (!head_interface_list) {
        head_interface_list = iface_list;
    } else {
        aux_iface_list = head_interface_list;
        while (aux_iface_list->next) {
            aux_iface_list = aux_iface_list->next;
        }
        aux_iface_list->next = iface_list;
    }
    LMLOG(DBG_2, "Interface %s with index %d added to interfaces lists\n",
            iface_name, iface->iface_index);
    return (iface);
}


/* Look up an interface based in the iface_name.
 * Return the iface element if it is found or NULL if not. */
iface_t *get_interface(char *iface_name)
{
    iface_list_elt_t *iface_list = head_interface_list;
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
    iface_list_elt_t *iface_lst_elt = NULL;

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
    iface_list_elt_t *iface_lst_elt = NULL;

    iface_lst_elt = head_interface_list;
    while (iface_lst_elt != NULL){
        iface = iface_lst_elt->iface;
        switch (lisp_addr_ip_afi(address)) {
        case AF_INET:
            if (lisp_addr_cmp(address, iface->ipv4_address) == 0) {
                return (iface);
            }
            break;
        case AF_INET6:
            if (lisp_addr_cmp(address, iface->ipv6_address) == 0) {
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

void
iface_list_to_char(int log_level)
{
    iface_t *iface;
    iface_list_elt_t *interface_list = head_interface_list;
    char str[4000];

    if (head_interface_list == NULL || is_loggable(log_level) == FALSE) {
        return;
    }

    sprintf(str, "*** LISP RLOC Interfaces List ***\n\n");

    while (interface_list) {
        iface = interface_list->iface;
        sprintf(str + strlen(str), "== %s   (%s)==\n", iface->iface_name,
                iface->status ? "Up" : "Down");
        if (iface->ipv4_address) {
            sprintf(str + strlen(str), "  IPv4 RLOC: %s \n",
                    lisp_addr_to_char(iface->ipv4_address));
        }
        if (iface->ipv6_address) {
            sprintf(str + strlen(str), "  IPv6 RLOC: %s \n",
                    lisp_addr_to_char(iface->ipv6_address));
        }
        interface_list = interface_list->next;
    }
    LMLOG(log_level, "%s", str);
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
    iface_list_elt_t *iface_list_elt = head_interface_list;

    switch (afi) {
    case AF_INET:
        while (iface_list_elt != NULL) {
            tif = iface_list_elt->iface;
            if ((lisp_addr_lafi(tif->ipv4_address) != LM_AFI_NO_ADDR)
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
            if ((lisp_addr_lafi(tif->ipv6_address) != LM_AFI_NO_ADDR)
                    && (tif->status == UP)) {
                iface = tif;
                break;
            }
            iface_list_elt = iface_list_elt->next;
        }
        break;
    default:
        LMLOG(DBG_2, "get_output_iface: unknown afi %d", afi);
        break;
    }

    return (iface);
}

lisp_addr_t *
get_default_output_address(int afi)
{
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
        LMLOG(DBG_2, "get_default_output_address: AFI %s not valid", afi);
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
        LMLOG(DBG_2, "get_default_output_socket: AFI %s not valid", afi);
        break;
    }

    return (out_socket);
}

void
set_default_output_ifaces()
{

    default_out_iface_v4 = get_any_output_iface(AF_INET);

    if (default_out_iface_v4 != NULL) {
       LMLOG(DBG_2,"Default IPv4 iface %s\n",default_out_iface_v4->iface_name);
    }
    
    default_out_iface_v6 = get_any_output_iface(AF_INET6);
    if (default_out_iface_v6 != NULL) {
       LMLOG(DBG_2,"Default IPv6 iface %s\n", default_out_iface_v6->iface_name);
    }

    if (!default_out_iface_v4 && !default_out_iface_v6){
        LMLOG(LCRIT,"NO OUTPUT IFACE: all the locators are down");
    }
}

void
set_default_ctrl_ifaces()
{
    default_ctrl_iface_v4 = get_any_output_iface(AF_INET);
    if (default_ctrl_iface_v4 != NULL) {
       LMLOG(DBG_2,"Default IPv4 control iface %s: %s\n",
               default_ctrl_iface_v4->iface_name,
               lisp_addr_to_char(default_ctrl_iface_v4->ipv4_address));
    }

    default_ctrl_iface_v6 = get_any_output_iface(AF_INET6);
    if (default_ctrl_iface_v6 != NULL) {
        LMLOG(DBG_2,"Default IPv6 control iface %s: %s\n",
                default_ctrl_iface_v6->iface_name,
                lisp_addr_to_char(default_ctrl_iface_v6->ipv6_address));
    }

    if (!default_ctrl_iface_v4 && !default_ctrl_iface_v6) {
        LMLOG(LERR, "NO CONTROL IFACE: all the locators are down");
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

iface_list_elt_t *ifaces_list_head()
{
    return head_interface_list;
}


char *
get_interface_name_from_address(lisp_addr_t *addr)
{
    char *iface  = NULL;

    if (lisp_addr_lafi(addr) != LM_AFI_IP) {
        LMLOG(DBG_1, "get_interface_name_from_address: failed for %s. Function"
                " only supports IP syntax addresses!", lisp_addr_to_char(addr));
        return(NULL);
    }

    iface = shash_lookup(iface_addr_ht, lisp_addr_to_char(addr));
    if (iface) {
        return(iface);
    } else {
        return(NULL);
    }
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
