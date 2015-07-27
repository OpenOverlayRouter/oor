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
#ifndef ANDROID
  #include <ifaddrs.h>
#endif
#include <errno.h>
#include <linux/rtnetlink.h>

#include "iface_list.h"
#include "iface_mgmt.h"
#include "lispd_external.h"
#include "lib/routing_tables_lib.h"
#include "lib/sockets.h"
#include "data-tun/lispd_tun.h"
#include "lib/shash.h"
#include "lib/sockets-util.h"
#include "lib/lmlog.h"

#ifdef ANDROID
  int getifaddrs(ifaddrs **addrlist);
#endif

glist_t *interface_list = NULL;

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

            LMLOG(LDBG_2, "Found interface %s with address %s", ifa->ifa_name,
                    host);
        }
    }

    freeifaddrs(ifaddr);
    return(GOOD);
}

int
ifaces_init()
{
    interface_list = glist_new_managed((glist_del_fct)iface_destroy);
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


inline void
ifaces_destroy()
{
    glist_destroy(interface_list);

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
        LMLOG(LDBG_2, "lispd_get_iface_address: getifaddrs error: %s",
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
                LMLOG(LDBG_2, "lispd_get_iface_address: interface address from "
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
                LMLOG(LDBG_2, "lispd_get_iface_address: interface address from "
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
    LMLOG(LDBG_3, "lispd_get_iface_address: No %s RLOC configured for interface "
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
        LMLOG(LDBG_2,"iface_setup: Unknown afi: %d", afi);
        return (ERR_AFI);
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
    iface_t *iface = NULL;

    if (if_nametoindex(iface_name) == 0) {
        LMLOG(LERR, "Configuration file: INVALID INTERFACE or not initialized "
                "virtual interface: %s ", iface_name);
        return(NULL);
    }

    /* Creating the new interface*/
    iface = xzalloc(sizeof(iface_t));

    iface->iface_name = strdup(iface_name); /* MUST FREE */
    iface->iface_index = if_nametoindex(iface_name);

    /* set up all fields to default, null values */
    iface->ipv4_address = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
    iface->ipv6_address = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
    iface->out_socket_v4 = -1;
    iface->out_socket_v6 = -1;


    LMLOG(LDBG_2, "Adding interface %s with index %d to iface list",
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

    /* Add iface to the list */
    glist_add(iface,interface_list);

    LMLOG(LDBG_2, "Interface %s with index %d added to interfaces lists\n",
            iface_name, iface->iface_index);

    if (default_ctrl_iface_v4 == NULL || default_ctrl_iface_v6 == NULL){
        set_default_ctrl_ifaces();
    }

    return (iface);
}


/* Look up an interface based in the iface_name.
 * Return the iface element if it is found or NULL if not. */
iface_t *get_interface(char *iface_name)
{
    glist_entry_t *     iface_it    = NULL;
    iface_t *           iface       = NULL;
    iface_t *           find_iface  = NULL;

    glist_for_each_entry(iface_it,interface_list){
        iface = (iface_t *)glist_entry_data(iface_it);
        if (strcmp(iface->iface_name, iface_name) == 0) {
            find_iface = iface;
            break;
        }
    }

    return (find_iface);
}

/* Look up an interface based in the index of the iface.
 * Return the iface element if it is found or NULL if not. */
iface_t *get_interface_from_index(int iface_index)
{
    glist_entry_t *     iface_it    = NULL;
    iface_t *           iface       = NULL;
    iface_t *           find_iface  = NULL;

    glist_for_each_entry(iface_it,interface_list){
        iface = (iface_t *)glist_entry_data(iface_it);
        if (iface->iface_index == 0) {
            iface->iface_index = if_nametoindex(iface->iface_name);
        }

        if (iface->iface_index == iface_index) {
            find_iface = iface;
            break;
        }
    }

    return (find_iface);
}

/* Return the interface having assigned the address passed as a parameter  */
iface_t *
get_interface_with_address(lisp_addr_t *address)
{
    glist_entry_t *     iface_it    = NULL;
    iface_t *           iface       = NULL;

    glist_for_each_entry(iface_it,interface_list){
        iface = (iface_t *)glist_entry_data(iface_it);
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
    }
    LMLOG(LDBG_2,"get_interface_with_address: No interface found for the address %s", lisp_addr_to_char(address));
    return (NULL);
}

int *
get_out_socket_ptr_from_address(lisp_addr_t *address)
{
    iface_t * iface = NULL;
    int afi;

    afi = lisp_addr_ip_afi(address);

    iface = get_interface_with_address(address);
    if (iface == NULL){
        return (NULL);
    }

    return(iface_socket_pointer(iface, afi));
}


/*
 * Print the interfaces and locators of the lisp node
 */

void
iface_list_to_char(int log_level)
{
    glist_entry_t *     iface_it    = NULL;
    iface_t *           iface       = NULL;
    char str[4000];

    if ((interface_list != NULL && glist_size(interface_list) == 0) || is_loggable(log_level) == FALSE) {
        return;
    }

    sprintf(str, "*** LISP RLOC Interfaces List ***\n\n");

    glist_for_each_entry(iface_it,interface_list){
        iface = (iface_t *)glist_entry_data(iface_it);
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
    glist_entry_t *     iface_it    = NULL;
    iface_t *           iface       = NULL;
    iface_t *           find_iface  = NULL;

    switch (afi) {
    case AF_INET:
        glist_for_each_entry(iface_it,interface_list){
            iface = (iface_t *)glist_entry_data(iface_it);
            if ((lisp_addr_lafi(iface->ipv4_address) != LM_AFI_NO_ADDR)
                    && (iface->status == UP)) {
                find_iface = iface;
                break;
            }
        }
        break;
    case AF_INET6:
        glist_for_each_entry(iface_it,interface_list){
            iface = (iface_t *)glist_entry_data(iface_it);
            if ((lisp_addr_lafi(iface->ipv6_address) != LM_AFI_NO_ADDR)
                    && (iface->status == UP)) {
                find_iface = iface;
                break;
            }
        }
        break;
    default:
        LMLOG(LDBG_2, "get_output_iface: unknown afi %d", afi);
        break;
    }

    return (find_iface);
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
        LMLOG(LDBG_2, "get_default_output_address: AFI %s not valid", afi);
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
        LMLOG(LDBG_2, "get_default_output_socket: AFI %s not valid", afi);
        break;
    }

    return (out_socket);
}

void
set_default_output_ifaces()
{

    default_out_iface_v4 = get_any_output_iface(AF_INET);

    if (default_out_iface_v4 != NULL) {
       LMLOG(LDBG_2,"Default IPv4 iface %s\n",default_out_iface_v4->iface_name);
    }
    
    default_out_iface_v6 = get_any_output_iface(AF_INET6);
    if (default_out_iface_v6 != NULL) {
       LMLOG(LDBG_2,"Default IPv6 iface %s\n", default_out_iface_v6->iface_name);
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
       LMLOG(LDBG_2,"Default IPv4 control iface %s: %s\n",
               default_ctrl_iface_v4->iface_name,
               lisp_addr_to_char(default_ctrl_iface_v4->ipv4_address));
    }

    default_ctrl_iface_v6 = get_any_output_iface(AF_INET6);
    if (default_ctrl_iface_v6 != NULL) {
        LMLOG(LDBG_2,"Default IPv6 control iface %s: %s\n",
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

int *
iface_socket_pointer(iface_t *iface, int afi)
{
    int * out_socket   = NULL;

    switch(afi){
    case AF_INET:
        out_socket = &(iface->out_socket_v4);
        break;
    case AF_INET6:
        out_socket = &(iface->out_socket_v6);
        break;
    default:
        out_socket = NULL;
        break;
    }

    return (out_socket);
}


char *
get_interface_name_from_address(lisp_addr_t *addr)
{
    char *iface  = NULL;

    if (lisp_addr_lafi(addr) != LM_AFI_IP) {
        LMLOG(LDBG_1, "get_interface_name_from_address: failed for %s. Function"
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


#ifdef ANDROID

/*
 * populate_ifaddr_entry()
 *
 * Fill in the ifaddr data structure with the info from
 * the rtnetlink message.
 */
int populate_ifaddr_entry(ifaddrs *ifaddr, int family, void *data, int ifindex, size_t count)
{
    char buf[IFNAMSIZ];
    char *name;
    void *dst;
    int   sockfd;
    struct ifreq ifr;
    int   retval;


    name = if_indextoname(ifindex, buf);
    if (name == NULL) {
        return (BAD);
    }

    ifaddr->ifa_name = strdup(name); // Must free elsewhere XXX

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        free(ifaddr->ifa_name);
        close(sockfd);
        return (BAD);
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, name); //ifr_name space reserved by the structure

    retval = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
    if (retval == -1) {
        free(ifaddr->ifa_name);
        close(sockfd);
        return (BAD);

    }
    ifaddr->ifa_flags = ifr.ifr_flags;
    ifaddr->ifa_index = ifindex;

    ifaddr->ifa_addr = malloc(sizeof(struct sockaddr));
    ifaddr->ifa_addr->sa_family = family;
    if (family == AF_INET || family == AF_INET6) {
        dst = &((struct sockaddr_in *)(ifaddr->ifa_addr))->sin_addr;
        memcpy(dst, data, count);
    }

    close(sockfd);
    return (0);
}

/*
 * getifaddrs()
 *
 * Android (and other) compatible getifaddrs function, using
 * rtnetlink. Enumerates all interfaces on the device.
 */
int getifaddrs(ifaddrs **addrlist) {
    request_struct        req;
    struct ifaddrmsg     *addr;
    ifaddrs              *prev;
    struct rtattr        *rta;
    int                   afi;
    size_t                msglen;
    int                   sockfd;
    char                  rcvbuf[4096];
    int                   readlen;
    int                   retval;
    struct nlmsghdr      *rcvhdr;

    *addrlist = NULL;


    /*
     * We open a separate socket here so the response can
     * be synchronous
     */
    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        return -1;
    }

    /*
     * Construct the request
     */
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(request_struct)));
    req.rtmsg.rtgen_family = AF_UNSPEC;

    /*
     * Send it
     */
    retval = send(sockfd, &req, req.nlh.nlmsg_len, 0);

    if (retval <= 0) {
        close(sockfd);
        return -1;
    }
    /*
     * Receive the responses from the kernel
     */
    while ((readlen = read(sockfd, rcvbuf, 4096)) > 0) {
        rcvhdr = (struct nlmsghdr *)rcvbuf;

        /*
         * Walk through everything it sent us
         */
        for (; NLMSG_OK(rcvhdr, (unsigned int)readlen); rcvhdr = NLMSG_NEXT(rcvhdr, readlen)) {

            switch (rcvhdr->nlmsg_type) {
            case NLMSG_DONE:
                close(sockfd);
                return 0;
            case NLMSG_ERROR:
                close(sockfd);
                return -1;
            case RTM_NEWADDR:
                addr = (struct ifaddrmsg *)NLMSG_DATA(rcvhdr);
                rta = IFA_RTA(addr);
                msglen = IFA_PAYLOAD(rcvhdr);

                while (RTA_OK(rta, msglen)) {
                    /*
                     * Only care about local addresses of our interfaces
                     */
                    if (rta->rta_type == IFA_LOCAL) {
                        afi = addr->ifa_family;

                        if (*addrlist) {
                            prev = *addrlist;
                        } else {
                            prev = NULL;
                        }
                        *addrlist = calloc(1,sizeof(ifaddrs));  // Must free elsewhere XXX
                        (*addrlist)->ifa_next = prev;

                        if ((populate_ifaddr_entry(*addrlist, afi, RTA_DATA(rta), addr->ifa_index, RTA_PAYLOAD(rta)))!=GOOD){
                            free (addrlist);
                        }
                    }
                    rta = RTA_NEXT(rta, msglen);
                }
                break;
            default:
                break;
            }

        }
    }
    close(sockfd);
    return 0;
}

int freeifaddrs(ifaddrs *addrlist)
{
    return 0; // XXX TODO
}
#endif

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
