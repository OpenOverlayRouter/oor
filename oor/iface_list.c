/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <linux/rtnetlink.h>

#include "data-plane/data-plane.h"
#include "control/oor_control.h"
#include "net_mgr/net_mgr.h"
#include "iface_list.h"
#include "oor_external.h"
#include "lib/prefixes.h"
#include "lib/routing_tables_lib.h"
#include "lib/sockets.h"
#include "lib/shash.h"
#include "lib/sockets-util.h"
#include "lib/oor_log.h"

/* List with all the interfaces used by OOR */
glist_t *interface_list = NULL;

shash_t *iface_addr_ht = NULL;


int
ifaces_init()
{
    interface_list = glist_new_managed((glist_del_fct)iface_destroy);
    iface_addr_ht = net_mgr->netm_build_addr_to_if_name_hasht();
    if (!iface_addr_ht){
        return (BAD);
    }
    return(GOOD);
}


void
iface_destroy(iface_t *iface)
{
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

int
iface_configure (iface_t *iface, int afi)
{
    glist_t *addr_list;
    lisp_addr_t *addr, *gw;



    if (afi == AF_INET  && default_rloc_afi == AF_INET6){
        return (BAD);
    }
    if (afi == AF_INET6  && default_rloc_afi == AF_INET){
        return (BAD);
    }

    /* Configure the gateway */

    gw = iface_gateway(iface, afi);
    if (!gw){
        gw = net_mgr->netm_get_iface_gw(iface->iface_name, afi);

        switch (afi) {
        case AF_INET:
            iface->ipv4_gateway = gw;
            break;
        case AF_INET6:
            iface->ipv6_gateway = gw;
            break;
        default:
            OOR_LOG(LDBG_2,"iface_setup: Unknown afi: %d", afi);
            return (ERR_AFI);
        }

        if (!gw || lisp_addr_is_no_addr(gw)) {
            OOR_LOG(LDBG_1,"iface_configure: No %s gateway found for interface %s",
                    afi == AF_INET ? "IPv4" : "IPv6", iface->iface_name);
        }else {
            OOR_LOG(LDBG_1,"iface_configure: %s gateway found for interface %s: %s",
                                afi == AF_INET ? "IPv4" : "IPv6", iface->iface_name,lisp_addr_to_char(gw));
            data_plane->datap_add_iface_gw(iface,afi);
            lctrl->control_data_plane->control_dp_add_iface_gw(lctrl,iface,afi);
        }
    }

    /* Get the correct address of the interface */
    if (!iface_address(iface, afi)){
        /* If we don't have gateway, we use the first address of the list of addresses of the interface*/
        if (!gw || lisp_addr_is_no_addr(gw)){
            addr_list = net_mgr->netm_get_iface_addr_list(iface->iface_name, afi);
            if (glist_size(addr_list) == 0){
                OOR_LOG(LDBG_1, "iface_configure: No %s RLOC configured for interface "
                        "%s\n", (afi == AF_INET) ? "IPv4" : "IPv6", iface->iface_name);
                addr = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
                goto end;
            }
            addr = (lisp_addr_t *)glist_first_data(addr_list);
            goto end;
        }
        addr = net_mgr->netm_get_src_addr_to(gw);

        if (!addr){
            OOR_LOG(LDBG_1, "iface_configure: Gateway %s is not reachable. This should never happen",
                    lisp_addr_to_char(gw));
            addr = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
        }
    }else{
        return (GOOD);
    }

    end:
    switch (afi) {
    case AF_INET:
        iface->ipv4_address = addr;
        break;
    case AF_INET6:
        iface->ipv6_address = addr;
        break;
    default:
        OOR_LOG(LDBG_2,"iface_setup: Unknown afi: %d", afi);
        return (ERR_AFI);
    }
    /* Configure the new address in the contol and data plane */
    if (!lisp_addr_is_no_addr(addr)) {
        OOR_LOG(LDBG_1,"iface_configure: %s address selected for interface %s: %s",
                afi == AF_INET ? "IPv4" : "IPv6", iface->iface_name,lisp_addr_to_char(addr));
        data_plane->datap_add_iface_addr(iface,afi);
        lctrl->control_data_plane->control_dp_add_iface_addr(lctrl,iface,afi);
    }

    return (GOOD);
}


char *
iface_to_char(iface_t *iface)
{

    static char buf[5][500];
    static int i=0;

    if (iface == NULL){
        sprintf(buf[i], "_NULL_");
        return (buf[i]);
    }
    /* hack to allow more than one locator per line */
    i++; i = i % 5;
    snprintf(buf[i],sizeof(buf[i]), "Iface: %s (%s), IPv4 addr: %s, IPv4 gw: %s, "
            "socket: %d, IPv6 addr: %s, IPv6 gw: %s, socket: %d",
            iface->iface_name, iface->status ? "Up" : "Down",
                    lisp_addr_to_char(iface->ipv4_address),lisp_addr_to_char(iface->ipv4_gateway),
                    iface->out_socket_v4,
                    lisp_addr_to_char(iface->ipv6_address),lisp_addr_to_char(iface->ipv6_gateway),
                    iface->out_socket_v6);

    return (buf[i]);
}

/* Return the interface if it already exists. If it doesn't exist,
 * create and add an interface element to the list of interfaces.
 * To configure address use iface_setup_addr after */
iface_t *
add_interface(char *iface_name)
{
    iface_t *iface;

    if (net_mgr->netm_get_iface_index(iface_name) == 0) {
        OOR_LOG(LERR, "Configuration file: INVALID INTERFACE or not initialized "
                "virtual interface: %s ", iface_name);
        return(NULL);
    }

    /* Creating the new interface*/
    iface = xzalloc(sizeof(iface_t));

    iface->iface_name = strdup(iface_name); /* MUST FREE */
    iface->iface_index = net_mgr->netm_get_iface_index(iface_name);

    /* set up all fields to default, null values */
    iface->ipv4_address = NULL;
    iface->ipv6_address = NULL;
    iface->out_socket_v4 = ERR_SOCKET;
    iface->out_socket_v6 = ERR_SOCKET;

    iface->status = net_mgr->netm_get_iface_status(iface_name);
    if (iface->status <= BAD){
        iface_destroy(iface);
        return(NULL);
    }

    OOR_LOG(LDBG_1, "Adding interface %s with index %d to iface list",
            iface_name, iface->iface_index);

    iface->ipv4_gateway = NULL;
    iface->ipv6_gateway = NULL;

    /* Add iface to the list */
    glist_add(iface,interface_list);

    OOR_LOG(LDBG_2, "Interface %s with index %d added to interfaces lists\n",
            iface_name, iface->iface_index);

    return (iface);
}


/* Look up an interface based in the iface_name.
 * Return the iface element if it is found or NULL if not. */
iface_t *
get_interface(char *iface_name)
{
    glist_entry_t * iface_it;
    iface_t * iface;
    iface_t * find_iface = NULL;

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
iface_t *
get_interface_from_index(int iface_index)
{
    glist_entry_t * iface_it;
    iface_t * iface;
    iface_t * find_iface  = NULL;

    glist_for_each_entry(iface_it,interface_list){
        iface = (iface_t *)glist_entry_data(iface_it);
        if (iface->iface_index == 0) {
            iface->iface_index = net_mgr->netm_get_iface_index(iface->iface_name);
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
    glist_entry_t * iface_it;
    iface_t * iface;

    glist_for_each_entry(iface_it,interface_list){
        iface = (iface_t *)glist_entry_data(iface_it);
        switch (lisp_addr_ip_afi(address)) {
        case AF_INET:
            if (iface->ipv4_address && lisp_addr_cmp(address, iface->ipv4_address) == 0) {
                return (iface);
            }
            break;
        case AF_INET6:
            if (iface->ipv6_address && lisp_addr_cmp(address, iface->ipv6_address) == 0) {
                return (iface);
            }
            break;
        }
    }
    OOR_LOG(LDBG_2,"get_interface_with_address: No interface found for the address %s", lisp_addr_to_char(address));
    return (NULL);
}

int *
get_out_socket_ptr_from_address(lisp_addr_t *address)
{
    iface_t * iface;
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
    glist_entry_t * iface_it;
    iface_t * iface;
    char str[4000];
    size_t str_size = sizeof(str);

    if ((interface_list != NULL && glist_size(interface_list) == 0) || is_loggable(log_level) == FALSE) {
        return;
    }

    sprintf(str, "*** LISP RLOC Interfaces List ***\n\n");

    glist_for_each_entry(iface_it,interface_list){
        iface = (iface_t *)glist_entry_data(iface_it);
        snprintf(str + strlen(str),str_size - strlen(str),"== %s   (%s)==\n", iface->iface_name,
                iface->status ? "Up" : "Down");
        if (iface->ipv4_address) {
            snprintf(str + strlen(str),str_size - strlen(str), "  IPv4 RLOC: %s \n",
                    lisp_addr_to_char(iface->ipv4_address));
        }
        if (iface->ipv6_address) {
            snprintf(str + strlen(str),str_size - strlen(str), "  IPv6 RLOC: %s \n",
                    lisp_addr_to_char(iface->ipv6_address));
        }
    }
    OOR_LOG(log_level, "%s", str);
}

/* Search the iface list for the first UP iface that has an 'afi' address*/
iface_t *
get_any_output_iface(int afi)
{
    glist_entry_t * iface_it;
    iface_t * iface;
    iface_t * find_iface = NULL;

    switch (afi) {
    case AF_INET:
        glist_for_each_entry(iface_it,interface_list){
            iface = (iface_t *)glist_entry_data(iface_it);
            if (iface->ipv4_address && !lisp_addr_is_no_addr(iface->ipv4_address)
                    && (iface->status == UP)) {
                find_iface = iface;
                break;
            }
        }
        break;
    case AF_INET6:
        glist_for_each_entry(iface_it,interface_list){
            iface = (iface_t *)glist_entry_data(iface_it);
            if (iface->ipv6_address && !lisp_addr_is_no_addr(iface->ipv6_address)
                    && (iface->status == UP)) {
                find_iface = iface;
                break;
            }
        }
        break;
    default:
        OOR_LOG(LDBG_2, "get_output_iface: unknown afi %d", afi);
        break;
    }

    return (find_iface);
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

lisp_addr_t *
iface_gateway(iface_t *iface, int afi)
{
    lisp_addr_t *gw = NULL;

    switch (afi) {
    case AF_INET:
        gw = iface->ipv4_gateway;
        break;
    case AF_INET6:
        gw = iface->ipv6_gateway;
        break;
    }

    return (gw);
}

int
iface_socket(iface_t *iface, int afi)
{
    int out_socket = ERR_SOCKET;

    switch(afi){
    case AF_INET:
        out_socket = iface->out_socket_v4;
        break;
    case AF_INET6:
        out_socket = iface->out_socket_v6;
        break;
    default:
        break;
    }

    return (out_socket);
}

int *
iface_socket_pointer(iface_t *iface, int afi)
{
    int * out_socket = NULL;

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


/*
 * This function should only be used during the configuration process
 */
char *
get_interface_name_from_address(lisp_addr_t *addr)
{
    char *iface;

    if (lisp_addr_lafi(addr) != LM_AFI_IP) {
        OOR_LOG(LDBG_1, "get_interface_name_from_address: failed for %s. Function"
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
