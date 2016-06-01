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
#ifndef ANDROID
  #include <ifaddrs.h>
#endif
#include <errno.h>
#include <linux/rtnetlink.h>

#include "data-plane/data-plane.h"
#include "iface_list.h"
#include "iface_mgmt.h"
#include "oor_external.h"
#include "lib/routing_tables_lib.h"
#include "lib/sockets.h"
#include "lib/shash.h"
#include "lib/sockets-util.h"
#include "lib/oor_log.h"

#ifdef ANDROID
  int getifaddrs(ifaddrs **addrlist);
  int freeifaddrs(ifaddrs *addrlist);
#endif

/* List with all the interfaces used by OOR */
glist_t *interface_list = NULL;

shash_t *iface_addr_ht = NULL;

int
build_iface_addr_hash_table()
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    OOR_LOG(LINF, "Building address to interface hash table");
    if (getifaddrs(&ifaddr) == -1) {
        OOR_LOG(LCRIT, "Can't read the interfaces of the system. Exiting .. ");
        exit_cleanup();
    }

    iface_addr_ht = shash_new_managed((free_value_fn_t)free);

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
                OOR_LOG(LWRN, "getnameinfo() failed: %s. Skipping interface. ",
                        gai_strerror(s));
                continue;
            }

            shash_insert(iface_addr_ht, strdup(host), strdup(ifa->ifa_name));

            OOR_LOG(LDBG_2, "Found interface %s with address %s", ifa->ifa_name,
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
    *buf[i] = '\0';
    sprintf(buf[i], "Iface: %s (%s), IPv4 addr: %s, IPv4 gw: %s, "
            "socket: %d, IPv6 addr: %s, IPv6 gw: %s, socket: %d",
            iface->iface_name, iface->status ? "Up" : "Down",
                    lisp_addr_to_char(iface->ipv4_address),lisp_addr_to_char(iface->ipv4_gateway),
                    iface->out_socket_v4,
                    lisp_addr_to_char(iface->ipv6_address),lisp_addr_to_char(iface->ipv6_gateway),
                    iface->out_socket_v6);

    return (buf[i]);
}

/*
 * get_iface_address: If iface doesn't have address. Return a LM_AFI_NO_ADDR address
 */
lisp_addr_t *
get_iface_address(char *ifacename, int afi)
{
    lisp_addr_t *addr;
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;
    struct sockaddr_in *s4;
    struct sockaddr_in6 *s6;
    ip_addr_t ip;

    addr = lisp_addr_new_lafi(LM_AFI_NO_ADDR);

    /* search for the interface */
    if (getifaddrs(&ifaddr) !=0) {
        OOR_LOG(LDBG_2, "get_iface_address: getifaddrs error: %s",
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
                OOR_LOG(LDBG_2, "get_iface_address: interface address from "
                        "%s discarded (%s)", ifacename, ip_addr_to_char(&ip));
                continue;
            }

            lisp_addr_init_from_ip(addr, &ip);
            freeifaddrs(ifaddr);
            return(addr);
        case AF_INET6:
            s6 = (struct sockaddr_in6 *) ifa->ifa_addr;
            ip_addr_init(&ip, &s6->sin6_addr, AF_INET6);

            if (ip_addr_is_link_local(&ip) == TRUE) {
                OOR_LOG(LDBG_2, "get_iface_address: interface address from "
                        "%s discarded (%s)", ifacename, ip_addr_to_char(&ip));
                continue;
            }
            lisp_addr_init_from_ip(addr, &ip);
            freeifaddrs(ifaddr);
            return(addr);

        default:
            continue;                   /* XXX */
        }
    }
    freeifaddrs(ifaddr);
    OOR_LOG(LDBG_3, "get_iface_address: No %s RLOC configured for interface "
            "%s\n", (afi == AF_INET) ? "IPv4" : "IPv6", ifacename);

    lisp_addr_set_lafi(addr, LM_AFI_NO_ADDR);
    return(addr);
}

/* set address, open socket, insert rule */
int
iface_setup_addr(iface_t *iface, int afi)
{
    lisp_addr_t **addr;

    if (afi == AF_INET  && default_rloc_afi == AF_INET6){
        return (BAD);
    }
    if (afi == AF_INET6  && default_rloc_afi == AF_INET){
        return (BAD);
    }

    switch (afi) {
    case AF_INET:
        addr = &iface->ipv4_address;
        break;
    case AF_INET6:
        addr = &iface->ipv6_address;
        break;
    default:
        OOR_LOG(LDBG_2,"iface_setup: Unknown afi: %d", afi);
        return (ERR_AFI);
    }

    *addr = get_iface_address(iface->iface_name, afi);

    if (lisp_addr_is_no_addr(*addr)) {
        return(BAD);
    }

    iface->status = UP;
    return(GOOD);
}

/* Return the interface if it already exists. If it doesn't exist,
 * create and add an interface element to the list of interfaces.
 * To configure address use iface_setup_addr after */
iface_t *
add_interface(char *iface_name)
{
    iface_t *iface;

    if (if_nametoindex(iface_name) == 0) {
        OOR_LOG(LERR, "Configuration file: INVALID INTERFACE or not initialized "
                "virtual interface: %s ", iface_name);
        return(NULL);
    }

    /* Creating the new interface*/
    iface = xzalloc(sizeof(iface_t));

    iface->iface_name = strdup(iface_name); /* MUST FREE */
    iface->iface_index = if_nametoindex(iface_name);

    /* set up all fields to default, null values */
    iface->ipv4_address = NULL;
    iface->ipv6_address = NULL;
    iface->out_socket_v4 = ERR_SOCKET;
    iface->out_socket_v6 = ERR_SOCKET;
    iface->status = DOWN;


    OOR_LOG(LDBG_2, "Adding interface %s with index %d to iface list",
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


#ifdef ANDROID

/*
 * populate_ifaddr_entry()
 *
 * Fill in the ifaddr data structure with the info from
 * the rtnetlink message.
 */
int
populate_ifaddr_entry(ifaddrs *ifaddr, int family, void *data, int ifindex,
        size_t count)
{
    char buf[IFNAMSIZ];
    char *name;
    int   sockfd;
    struct ifreq ifr;
    int   retval;
    struct sockaddr_in * sock_addr4;
    struct sockaddr_in6 * sock_addr6;

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

    if (family == AF_INET){
        sock_addr4 = xzalloc(sizeof(struct sockaddr_in));
        sock_addr4->sin_family = AF_INET;
        memcpy(&sock_addr4->sin_addr, data, sizeof(struct in_addr));
        ifaddr->ifa_addr = (struct sockaddr *)sock_addr4;
    }else if (family == AF_INET6){
        sock_addr6 = xzalloc(sizeof(struct sockaddr_in6));
        sock_addr6->sin6_family = AF_INET6;
        memcpy(&sock_addr6->sin6_addr, data, sizeof(struct in6_addr));
        ifaddr->ifa_addr = (struct sockaddr *)sock_addr6;
    }

    close(sockfd);
    return (GOOD);
}

/*
 * getifaddrs()
 *
 * Android (and other) compatible getifaddrs function, using
 * rtnetlink. Enumerates all interfaces on the device.
 */
int
getifaddrs(ifaddrs **addrlist)
{
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
    lisp_addr_t new_addr = { .lafi = LM_AFI_IP };
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
    memset (&req,0,sizeof(request_struct));
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP; //NLM_F_MATCH;
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
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
                    if (rta->rta_type == IFA_ADDRESS) {
                        afi = addr->ifa_family;

                        if (*addrlist) {
                            prev = *addrlist;
                        } else {
                            prev = NULL;
                        }
                        *addrlist = calloc(1,sizeof(ifaddrs));  // Must free elsewhere XXX
                        (*addrlist)->ifa_next = prev;
                        lisp_addr_ip_init(&new_addr, RTA_DATA(rta), afi);

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
    return (0);
}

int
freeifaddrs(ifaddrs *addrlist)
{
    ifaddrs *ifa = addrlist;
    ifaddrs *ifa_prev;
    while (ifa){
        free (ifa->ifa_name);
        switch (ifa->ifa_addr->sa_family){
        case AF_INET:
            free ((struct sockaddr_in *)ifa->ifa_addr);
            break;
        case AF_INET6:
            free ((struct sockaddr_in6 *)ifa->ifa_addr);
            break;
        }
        ifa_prev = ifa;
        ifa = ifa->ifa_next;
        free (ifa_prev);
    }

    return (0);
}
#endif

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
