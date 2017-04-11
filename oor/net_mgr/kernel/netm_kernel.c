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


#include <errno.h>
#ifndef ANDROID
  #include <ifaddrs.h>
#endif
#include <netdb.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>

#include "iface_mgmt.h"
#include "netm_kernel.h"
#include "../net_mgr.h"
#include "../../lib/oor_log.h"
#include "../../lib/sockets.h"


int krn_netm_init();
void krn_netm_uninit();
glist_t * krn_get_ifaces_names();
lisp_addr_t * krn_get_iface_addr(char *iface_name, int afi);
uint8_t krn_get_iface_status(char * iface_name);
int krn_get_iface_index(char *iface_name);
void krn_get_iface_mac_addr(char *iface_name, uint8_t *mac);
int krn_reload_routes(uint32_t table, int afi);
shash_t *krn_build_addr_to_if_name_hasht();
#ifdef ANDROID
  int getifaddrs(ifaddrs **addrlist);
  int freeifaddrs(ifaddrs *addrlist);
#endif


net_mgr_class_t netm_kernel = {
        .netm_init = krn_netm_init,
        .netm_uninit = krn_netm_uninit,
        .netm_get_ifaces_names = krn_get_ifaces_names,
        .netm_get_iface_addr = krn_get_iface_addr,
        .netm_get_iface_status = krn_get_iface_status,
        .netm_get_iface_index = krn_get_iface_index,
        .netm_get_iface_mac_addr = krn_get_iface_mac_addr,
        .netm_reload_routes = krn_reload_routes,
        .netm_build_addr_to_if_name_hasht = krn_build_addr_to_if_name_hasht,
        .data = NULL
};


int
krn_netm_init()
{
    struct sock *nl_sl;
    netm_data_type *data;
    data = xzalloc(sizeof(netm_data_type));
    if (!data){
        return (BAD);
    }
    netm_kernel.data = data;

    /* Create net_link socket to receive notifications of changes of RLOC
     * status. */
    data->netlink_fd = opent_netlink_socket();

    nl_sl = sockmstr_register_read_listener(smaster, process_netlink_msg, NULL,
            data->netlink_fd);

    /* Request to dump the routing tables to obtain the gatways when
     * processing the netlink messages  */
    krn_reload_routes(RT_TABLE_MAIN, AF_INET);
    process_netlink_msg(nl_sl);
    krn_reload_routes(RT_TABLE_MAIN, AF_INET6);
    process_netlink_msg(nl_sl);

    return (GOOD);
}

void
krn_netm_uninit()
{
    netm_data_type *data = (netm_data_type *)netm_kernel.data;
    //socket is closed by sockmstr
    free(data);
}

glist_t *
krn_get_ifaces_names()
{
    glist_t *iface_names = glist_new_managed((glist_del_fct)free);
    struct nlmsghdr *nlh, *rcvhdr;
    struct ifinfomsg *ifm, *if_msg;
    char sndbuf[4096],rcvbuf[4096],name[IF_NAMESIZE];
    int ifa_len, retval,readlen;
    int netlk_fd;

    netlk_fd = opent_netlink_socket();
    if (netlk_fd == ERR_SOCKET){
        OOR_LOG(LERR, "krn_get_ifaces_names: Error opening netlink socket");
        return (BAD);
    }
    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);

    nlh = (struct nlmsghdr *)sndbuf;
    ifm = (struct ifinfomsg *)(CO(sndbuf,sizeof(struct nlmsghdr)));

    ifa_len = sizeof(struct ifinfomsg);

    nlh->nlmsg_len   = NLMSG_LENGTH(ifa_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_type  = RTM_GETLINK;


    ifm->ifi_family    = AF_PACKET;

    retval = send(netlk_fd, sndbuf, NLMSG_LENGTH(ifa_len), 0);

    if (retval < 0) {
        OOR_LOG(LERR, "krn_get_ifaces_names: send netlink command failed: %s", strerror(errno));
        close(netlk_fd);
        return(NULL);
    }

    /*
     * Receive the responses from the kernel
     */
    while ((readlen = recv(netlk_fd,rcvbuf,4096,MSG_DONTWAIT)) > 0){
        rcvhdr = (struct nlmsghdr *)rcvbuf;
        /*
         * Walk through everything it sent us
         */
        for (; NLMSG_OK(rcvhdr, (unsigned int)readlen); rcvhdr = NLMSG_NEXT(rcvhdr, readlen)) {
            if (rcvhdr->nlmsg_type == RTM_NEWLINK) {
                if_msg = (struct ifinfomsg *)NLMSG_DATA(rcvhdr);
                if (if_indextoname(if_msg->ifi_index, name) != NULL){
                    glist_add(strdup(name),iface_names);
                }
            }
        }
    }
    close(netlk_fd);

    return (iface_names);
}

lisp_addr_t *
krn_get_iface_addr(char *iface_name, int afi)
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
         OOR_LOG(LDBG_2, "krn_get_iface_addr: getifaddrs error: %s",
                 strerror(errno));
         return(addr);
     }
     for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
         if ((ifa->ifa_addr == NULL)
              || ((ifa->ifa_flags & IFF_UP) == 0)
              || (ifa->ifa_addr->sa_family != afi)
              || strcmp(ifa->ifa_name, iface_name) != 0) {
             continue;
         }

         switch (ifa->ifa_addr->sa_family) {
         case AF_INET:
             s4 = (struct sockaddr_in *) ifa->ifa_addr;
             ip_addr_init(&ip, &s4->sin_addr, AF_INET);

             if (ip_addr_is_link_local(&ip) == TRUE) {
                 OOR_LOG(LDBG_2, "krn_get_iface_addr: interface address from "
                         "%s discarded (%s)", iface_name, ip_addr_to_char(&ip));
                 continue;
             }

             lisp_addr_init_from_ip(addr, &ip);
             freeifaddrs(ifaddr);
             return(addr);
         case AF_INET6:
             s6 = (struct sockaddr_in6 *) ifa->ifa_addr;
             ip_addr_init(&ip, &s6->sin6_addr, AF_INET6);

             if (ip_addr_is_link_local(&ip) == TRUE) {
                 OOR_LOG(LDBG_2, "krn_get_iface_addr: interface address from "
                         "%s discarded (%s)", iface_name, ip_addr_to_char(&ip));
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
     OOR_LOG(LDBG_3, "krn_get_iface_addr: No %s RLOC configured for interface "
             "%s\n", (afi == AF_INET) ? "IPv4" : "IPv6", iface_name);

     lisp_addr_set_lafi(addr, LM_AFI_NO_ADDR);
     return(addr);
}

uint8_t
krn_get_iface_status(char * iface_name)
{
    uint8_t status = ERR_NO_EXIST;
    struct nlmsghdr *nlh, *rcvhdr;
    struct ifinfomsg *ifm, *if_msg;
    char sndbuf[4096],rcvbuf[4096];
    int ifa_len, retval,readlen;
    int netlk_fd;
    int iface_index;
    iface_index = if_nametoindex(iface_name);
    if (iface_index == 0){
        OOR_LOG(LERR, "krn_get_iface_status: Iface %s doesn't exist",iface_name);
        return (ERR_NO_EXIST);
    }

    netlk_fd = opent_netlink_socket();
    if (netlk_fd == ERR_SOCKET){
        OOR_LOG(LERR, "krn_get_iface_status: Error opening netlink socket");
        return (ERR_SOCKET);
    }
    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);

    nlh = (struct nlmsghdr *)sndbuf;
    ifm = (struct ifinfomsg *)(CO(sndbuf,sizeof(struct nlmsghdr)));

    ifa_len = sizeof(struct ifinfomsg);

    nlh->nlmsg_len   = NLMSG_LENGTH(ifa_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_type  = RTM_GETLINK;

    ifm->ifi_family    = AF_PACKET;

    retval = send(netlk_fd, sndbuf, NLMSG_LENGTH(ifa_len), 0);

    if (retval < 0) {
        OOR_LOG(LERR, "krn_get_iface_status: send netlink command failed: %s", strerror(errno));
        close(netlk_fd);
        return(ERR_SOCKET);
    }
    /*
     * Receive the responses from the kernel
     */
    while ((readlen = recv(netlk_fd,rcvbuf,4096,MSG_DONTWAIT)) > 0){
        rcvhdr = (struct nlmsghdr *)rcvbuf;
        /*
         * Walk through everything it sent us
         */
        for (; NLMSG_OK(rcvhdr, (unsigned int)readlen); rcvhdr = NLMSG_NEXT(rcvhdr, readlen)) {
            if (rcvhdr->nlmsg_type == RTM_NEWLINK) {
                if_msg = (struct ifinfomsg *)NLMSG_DATA(rcvhdr);
                if (if_msg->ifi_index == iface_index){
                    /* Get the new status */
                    if ((if_msg->ifi_flags & IFF_RUNNING) != 0) {
                        status = UP;
                    } else {
                        status = DOWN;
                    }
                    break;
                }
            }
        }
    }
    close(netlk_fd);

    return (status);
}

int
krn_get_iface_index(char *iface_name)
{
    return (if_nametoindex(iface_name));
}

void
krn_get_iface_mac_addr(char *iface_name, uint8_t *mac)
{
    int fd;
    struct ifreq ifr;
    int i = 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);
    for (i = 0 ; i < 6 ; i++){
        mac[i] = (unsigned char)ifr.ifr_hwaddr.sa_data[i];
    }

    return;
}

/*
 * Request to the kernel the routing table with the selected afi
 */
int
krn_reload_routes(uint32_t table, int afi)
{
    struct nlmsghdr *nlh = NULL;
    struct rtmsg *rtm = NULL;
    char sndbuf[4096];
    int rta_len = 0;
    int retval = 0;
    netm_data_type *data;

    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);

    nlh = (struct nlmsghdr *)sndbuf;
    rtm = (struct rtmsg *)(CO(sndbuf,sizeof(struct nlmsghdr)));

    rta_len = sizeof(struct rtmsg);

    nlh->nlmsg_len = NLMSG_LENGTH(rta_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_type = RTM_GETROUTE;


    rtm->rtm_family = afi;
    if (table == 0){
        rtm->rtm_table = RT_TABLE_MAIN;
    }else{
        rtm->rtm_table = table;
    }

    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type = RTN_UNICAST;
    rtm->rtm_src_len = 0;
    rtm->rtm_tos = 0;
    rtm->rtm_dst_len = 0;

    data = (netm_data_type *)netm_kernel.data;
    retval = send(data->netlink_fd, sndbuf, NLMSG_LENGTH(rta_len), 0);

    if (retval < 0) {
        OOR_LOG(LCRIT, "krn_reload_routes: send netlink command failed %s", strerror(errno));
        return (BAD);
    }

    return (GOOD);
}

shash_t *krn_build_addr_to_if_name_hasht()
{
    shash_t *ht;
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    OOR_LOG(LDBG_1, "Building address to interface hash table");
    if (getifaddrs(&ifaddr) == -1) {
        OOR_LOG(LCRIT, "Can't read the interfaces of the system. Exiting .. ");
        exit_cleanup();
    }

    ht = shash_new_managed((free_value_fn_t)free);

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

            shash_insert(ht, strdup(host), strdup(ifa->ifa_name));

            OOR_LOG(LDBG_2, "Found interface %s with address %s", ifa->ifa_name,
                    host);
        }
    }

    freeifaddrs(ifaddr);
    return(ht);
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
