/*
 * iface_mgmt.c
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
 *    Albert López   <alopez@ac.upc.edu>
 *    Florin Coras   <fcoras@ac.upc.edu>
 *
 */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "lispd_external.h"
#include "iface_mgmt.h"
//#include "lispd_lib.h"
#include "defs.h"
#include "lisp_mapping.h"
#include "routing_tables_lib.h"
#include "timers.h"
#include "lispd_tun.h"
#include "lisp_control.h"
#include "sockets-util.h"
#include "lmlog.h"

/************************* FUNCTION DECLARTAION ********************************/

void process_nl_add_address (struct nlmsghdr *nlh);
void process_nl_del_address (struct nlmsghdr *nlh);
void process_nl_new_link (struct nlmsghdr *nlh);
void process_nl_new_route (struct nlmsghdr *nlh);
void process_nl_new_unicast_route (struct rtmsg *rtm, int rt_length);
void process_nl_new_multicast_route (struct rtmsg *rtm, int rt_length);
void process_nl_del_route (struct nlmsghdr *nlh);
void process_nl_del_multicast_route (struct rtmsg *rtm, int rt_length);
int process_nl_mcast_route_attributes(struct rtmsg *rtm, int rt_length,
        lisp_addr_t *src, lisp_addr_t *grp);

/* Change the address of the interface. If the address belongs to a not
 * initialized locator, activate it. Program SMR */
void process_address_change(iface_t *iface, lisp_addr_t *new_addr);

/* Change the satus of the interface. Recalculate default control and output
 * interfaces if it's needed. Program SMR */
void process_link_status_change(iface_t *iface, int new_status);

void process_new_gateway(iface_t *iface,lisp_addr_t *gateway);



/*******************************************************************************/

int
opent_netlink_socket()
{
    int netlink_fd = 0;
    struct sockaddr_nl addr;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR
                   | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_MROUTE
                   | RTMGRP_IPV6_MROUTE;

    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (netlink_fd < 0) {
        LMLOG(LERR, "opent_netlink_socket: Failed to connect to "
                "netlink socket");
        return (BAD);
    }

    bind(netlink_fd, (struct sockaddr *) &addr, sizeof(addr));

    return (netlink_fd);
}

int
process_netlink_msg(struct sock *sl)
{
    int len = 0;
    char buffer[4096];
    struct iovec iov;
    struct sockaddr_nl dst_addr;
    struct msghdr msgh;
    struct nlmsghdr *nlh = NULL;

    nlh = (struct nlmsghdr *) buffer;

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *) nlh;
    iov.iov_len = sizeof(nlh);

    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_name = (void *) &(dst_addr);
    msgh.msg_namelen = sizeof(dst_addr);
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    while ((len = recv(sl->fd, nlh, 4096, MSG_DONTWAIT)) > 0) {
        for (; (NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE);
                nlh = NLMSG_NEXT(nlh, len)) {
            switch (nlh->nlmsg_type) {
            case RTM_NEWADDR:
                LMLOG(DBG_3, "=>process_netlink_msg: Received new address "
                        "message");
                process_nl_add_address(nlh);
                break;
            case RTM_DELADDR:
                LMLOG(DBG_3, "=>process_netlink_msg: Received del address "
                        "message");
                process_nl_del_address(nlh);
                break;
            case RTM_NEWLINK:
                LMLOG(DBG_3, "=>process_netlink_msg: Received link "
                        "message");
                process_nl_new_link(nlh);
                break;
            case RTM_NEWROUTE:
                LMLOG(DBG_3, "=>process_netlink_msg: Received new route "
                        "message");
                process_nl_new_route(nlh);
                break;
            case RTM_DELROUTE:
                LMLOG(DBG_3, "=>process_netlink_msg: Received delete route "
                        "message");
                process_nl_del_route(nlh);
                break;
            default:
                break;

            }
        }
        nlh = (struct nlmsghdr *) buffer;
        memset(nlh, 0, 4096);
    }

    return (GOOD);
}


void
process_nl_add_address (struct nlmsghdr *nlh)
{
    struct ifaddrmsg *ifa = NULL;
    struct rtattr *rth = NULL;
    int iface_index = 0;
    int rt_length = 0;
    iface_t *iface = NULL;
    lisp_addr_t new_addr = { .lafi = LM_AFI_IP };
    char iface_name[IF_NAMESIZE];

    /*
     * Get the new address from the net link message
     */
    ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);
    iface_index = ifa->ifa_index;

    iface = get_interface_from_index(iface_index);

    if (iface == NULL) {
        if_indextoname(iface_index, iface_name);
        LMLOG(DBG_2, "process_nl_add_address: netlink message not for an "
                "interface with associated RLOCs (%s / %d)", iface_name,
                iface_index);
        return;
    }
    rth = IFA_RTA (ifa);

    rt_length = IFA_PAYLOAD(nlh);
    for (;rt_length && RTA_OK (rth, rt_length);rth = RTA_NEXT (rth,rt_length))
    {
        if ((ifa->ifa_family == AF_INET && rth->rta_type == IFA_LOCAL)
                || (ifa->ifa_family == AF_INET6 && rth->rta_type == IFA_ADDRESS)){
            lisp_addr_ip_init(&new_addr, RTA_DATA(rth), ifa->ifa_family);
            process_address_change(iface, &new_addr);
        }
    }
}

/* Change the address of the interface. If the address belongs to a not
 * initialized locator, activate it. Program SMR */
void
process_address_change(iface_t *iface, lisp_addr_t *new_addr)
{
    lisp_addr_t *iface_addr = NULL;
    lisp_addr_t *new_addr_cpy   = NULL;
    lisp_addr_t *old_addr_cpy   = NULL;
    int new_addr_ip_afi;
    int old_lafi;

    new_addr_ip_afi = lisp_addr_ip_afi(new_addr);

    /* XXX To be modified when full NAT implemented --> When Nat Aware active
     * no IPv6 RLOCs supported */
    if (nat_aware == TRUE && lisp_addr_ip_afi(new_addr) == AF_INET6){
        return;
    }

    /* Check if the addres is a global address*/
    if (ip_addr_is_link_local(lisp_addr_ip(new_addr)) == TRUE) {
        LMLOG(DBG_2,"precess_address_change: the address in netlink messages "
                "is a local link address: %s discarded",
                lisp_addr_to_char(new_addr));
        return;
    }
    /* If default RLOC afi defined (-a 4 or 6), only accept addresses of the
     * specified afi */
    if (default_rloc_afi != -1
        && default_rloc_afi != new_addr_ip_afi) {
        LMLOG(DBG_2,"precess_address_change: Default RLOC afi defined (-a #): "
                "Skipped %s address in iface %s",
                (new_addr_ip_afi == AF_INET) ? "IPv4" : "IPv6",
                iface->iface_name);
        return;
    }

    /* Actions to be done due to a change of address: SMR  */


    switch (new_addr_ip_afi){
        case AF_INET:
            iface_addr = iface->ipv4_address;
            break;
        case AF_INET6:
            iface_addr = iface->ipv6_address;
            break;
    }

    /* Same address that we already have */
    if (lisp_addr_cmp(iface_addr, new_addr) == 0) {
        LMLOG(DBG_2, "precess_address_change: The change of address detected "
                "for interface %s doesn't affect", iface->iface_name);
        /* We must rebind the socket just in case the address is from a
         * virtual interface which has changed its interface number */
        switch (new_addr_ip_afi) {
        case AF_INET:
            bind_socket_address(iface->out_socket_v4, new_addr);
            break;
        case AF_INET6:
            bind_socket_address(iface->out_socket_v6, new_addr);
            break;
        }

        return;
    };

    old_lafi = lisp_addr_afi(iface_addr);

    /* The interface was down during initial configuration process and now it
     * is up. Create sockets */
    if (old_lafi == LM_AFI_NO_ADDR) {

        LMLOG(DBG_2, "process_address_change: Generating sockets for the initialized interface "
                "%s", lisp_addr_to_char(new_addr));

        switch(new_addr_ip_afi){
        case AF_INET:
            iface->out_socket_v4 = open_device_bound_raw_socket(iface->iface_name,AF_INET);
            break;
        case AF_INET6:
            iface->out_socket_v6 = open_device_bound_raw_socket(iface->iface_name,AF_INET6);
            break;
        }

        if (iface->status == UP) {
            /* If no default control and data interface, recalculate it */
            if ((default_ctrl_iface_v4 == NULL
                    && new_addr_ip_afi == AF_INET)
                 || (default_ctrl_iface_v6 == NULL
                            && new_addr_ip_afi == AF_INET6)) {
                LMLOG(DBG_2, "No default control interface. Recalculate new "
                        "control interface");
                set_default_ctrl_ifaces();
            }

            if ((default_out_iface_v4 == NULL
                    && new_addr_ip_afi == AF_INET)
                 || (default_out_iface_v6 == NULL
                         && new_addr_ip_afi == AF_INET6)) {
                LMLOG(DBG_2, "No default output interface. Recalculate new "
                        "output interface");
                set_default_output_ifaces();
            }
        }
    }

    LMLOG(DBG_2,"process_address_change: New address detected for interface "
            "%s -> %s", iface->iface_name, lisp_addr_to_char(new_addr));


    /* Change source routing rules for this interface and binding */
    if (lisp_addr_is_no_addr(iface_addr) == FALSE) {
        del_rule(new_addr_ip_afi, 0, iface->iface_index, iface->iface_index, RTN_UNICAST,
                iface_addr, NULL, 0);
    }
    add_rule(new_addr_ip_afi, 0, iface->iface_index, iface->iface_index, RTN_UNICAST,
            new_addr, NULL, 0);

    /* Rebind sockets */
    switch (new_addr_ip_afi) {
    case AF_INET:
        bind_socket_address(iface->out_socket_v4, new_addr);
        break;
    case AF_INET6:
        bind_socket_address(iface->out_socket_v6, new_addr);
        break;
    }

    lisp_addr_copy(iface_addr, new_addr);
    old_addr_cpy = lisp_addr_clone(iface_addr);
    new_addr_cpy = lisp_addr_clone(new_addr);

    /* raise event in ctrl */
    ctrl_if_addr_update(lctrl, iface, old_addr_cpy, new_addr_cpy);

}


void
process_nl_del_address(struct nlmsghdr *nlh)
{
    struct ifaddrmsg *ifa = NULL;
    struct rtattr *rth = NULL;
    int iface_index = 0;
    int rt_length = 0;
    iface_t *iface = NULL;
    lisp_addr_t new_addr;
    char iface_name[IF_NAMESIZE];

    ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
    iface_index = ifa->ifa_index;

    iface = get_interface_from_index(iface_index);

    if (iface == NULL) {
        if_indextoname(iface_index, iface_name);
        LMLOG(DBG_2, "process_nl_add_address: the netlink message is not "
                "for any interface associated with RLOCs (%s)", iface_name);
        return;
    }

    rth = IFA_RTA(ifa);
    rt_length = IFA_PAYLOAD(nlh);
    for (; rt_length && RTA_OK(rth, rt_length);rth = RTA_NEXT(rth, rt_length)) {
        if ((ifa->ifa_family == AF_INET && rth->rta_type == IFA_LOCAL)
                        || (ifa->ifa_family == AF_INET6 && rth->rta_type == IFA_ADDRESS)){
            lisp_addr_ip_init(&new_addr, RTA_DATA(rth), ifa->ifa_family);
            break;
        }
    }
    /* Actions to be done when address is removed */
    LMLOG(DBG_2, "   deleted address: %s\n", lisp_addr_to_char(&new_addr));
}

void
process_nl_new_link(struct nlmsghdr *nlh)
{
    struct ifinfomsg *ifi = NULL;
    iface_t *iface = NULL;
    int iface_index = 0;
    uint8_t status = UP;
    char iface_name[IF_NAMESIZE];
    uint32_t old_iface_index = 0;

    ifi = (struct ifinfomsg *) NLMSG_DATA (nlh);
    iface_index = ifi->ifi_index;


    iface = get_interface_from_index(iface_index);

    if (iface == NULL) {
        /*
         * In some OS when a virtual interface is removed and added again,
         * the index of the interface change. Search iface_t by the interface
         * name and update the index. */
        if (if_indextoname(iface_index, iface_name) != NULL) {
            iface = get_interface(iface_name);
        }
        if (iface == NULL) {
            LMLOG(DBG_2, "process_nl_new_link: the netlink message is not for "
                    "any interface associated with RLOCs  (%s)", iface_name);
            return;
        } else {
            old_iface_index = iface->iface_index;
            iface->iface_index = iface_index;
            LMLOG(DBG_2, "process_nl_new_link: The new index of the interface "
                    "%s is: %d. Updating tables", iface_name,
                    iface->iface_index);
            /* Update routing tables and reopen sockets*/
            if (lisp_addr_ip_afi(iface->ipv4_address) != LM_AFI_NO_ADDR) {
                del_rule(AF_INET, 0, old_iface_index, old_iface_index,
                        RTN_UNICAST, iface->ipv4_address, NULL, 0);
                add_rule(AF_INET, 0, iface_index, iface_index, RTN_UNICAST,
                        iface->ipv4_address, NULL, 0);
                close(iface->out_socket_v4);
                iface->out_socket_v4 = open_device_bound_raw_socket(
                        iface->iface_name, AF_INET);
                bind_socket_address(iface->out_socket_v4, iface->ipv4_address);
            }
            if (lisp_addr_ip_afi(iface->ipv6_address) != LM_AFI_NO_ADDR) {
                del_rule(AF_INET6, 0, old_iface_index, old_iface_index,
                        RTN_UNICAST, iface->ipv6_address, NULL, 0);
                add_rule(AF_INET6, 0, iface_index, iface_index, RTN_UNICAST,
                        iface->ipv6_address, NULL, 0);
                close(iface->out_socket_v6);
                iface->out_socket_v6 = open_device_bound_raw_socket(
                        iface->iface_name, AF_INET6);
                bind_socket_address(iface->out_socket_v6, iface->ipv6_address);
            }
        }
    }

    if ((ifi->ifi_flags & IFF_RUNNING) != 0) {
        LMLOG(DBG_1, "process_nl_new_link: Interface %s changes its status to "
                "UP", iface->iface_name);
        status = UP;
    } else {
        LMLOG(DBG_1, "process_nl_new_link: Interface %s changes its status to "
                "DOWN", iface->iface_name);
        status = DOWN;
    }

    process_link_status_change(iface, status);
}


void
process_nl_new_route (struct nlmsghdr *nlh)
{
    struct rtmsg *rtm = NULL;
    int rt_length = 0;

    rtm = (struct rtmsg *) NLMSG_DATA (nlh);
    rt_length = RTM_PAYLOAD(nlh);

    /* Interested only in unicast or multicast updates */
    if (rtm->rtm_type == RTN_UNICAST) {
        process_nl_new_unicast_route(rtm, rt_length);
    } else if (rtm->rtm_type == RTN_MULTICAST) {
        process_nl_new_multicast_route(rtm, rt_length);
    }

}

void
process_nl_new_unicast_route(struct rtmsg *rtm, int rt_length)
{
    struct rtattr *rt_attr = NULL;
    iface_t *iface = NULL;
    int iface_index = 0;
    char iface_name[IF_NAMESIZE];
    lisp_addr_t gateway = { .lafi = LM_AFI_IP };
    lisp_addr_t dst = { .lafi = LM_AFI_IP };

    /* Interested only in main table updates for unicast */
    if (rtm->rtm_table != RT_TABLE_MAIN)
        return;

    if ( rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6 ) {
        LMLOG(DBG_3,"process_nl_new_unicast_route: New unicast route of "
                "unknown adddress family %d", rtm->rtm_family);
        return;
    }

    rt_attr = (struct rtattr *)RTM_RTA(rtm);

    for (; RTA_OK(rt_attr, rt_length);
            rt_attr = RTA_NEXT(rt_attr, rt_length)) {
        switch (rt_attr->rta_type) {
        case RTA_OIF:
            iface_index = *(int *)RTA_DATA(rt_attr);
            iface = get_interface_from_index(iface_index);
            if_indextoname(iface_index, iface_name);
            if (iface == NULL){
                LMLOG(DBG_3, "process_nl_new_unicast_route: the netlink "
                        "message is not for any interface associated with "
                        "RLOCs (%s)", iface_name);
                return;
            }
            break;
        case RTA_GATEWAY:
            lisp_addr_ip_init(&gateway, RTA_DATA(rt_attr), rtm->rtm_family);
            break;
        case RTA_DST:
            /* We check if the new route message contains a destination. If
             * it is, then the gateway address is not a default route.
             * Discard it */
            lisp_addr_ip_init(&dst, RTA_DATA(rt_attr), rtm->rtm_family);
            break;
        default:
            break;
        }
    }

    if (lisp_addr_ip_afi(&gateway) != LM_AFI_NO_ADDR
        && iface_index != 0 && lisp_addr_ip_afi(&dst) == LM_AFI_NO_ADDR) {
        /* Check default afi*/
        if (default_rloc_afi != -1
            && default_rloc_afi != lisp_addr_ip_afi(&gateway)) {
            LMLOG(DBG_1, "process_nl_new_unicast_route: Default RLOC afi "
                    "defined (-a #): Skipped %s gateway in iface %s",
                    (lisp_addr_ip_afi(&gateway)== AF_INET) ? "IPv4" : "IPv6",
                    iface->iface_name);
            return;
        }

        /* Check if the addres is a global address*/
        if (ip_addr_is_link_local(lisp_addr_ip(&gateway)) == TRUE) {
            LMLOG(DBG_3,"process_nl_new_unicast_route: the extractet address "
                    "from the netlink messages is a local link address: %s "
                    "discarded", lisp_addr_to_char(&gateway));
            return;
        }

        /* Process the new gateway */
        LMLOG(DBG_1,  "process_nl_new_unicast_route: Process new gateway "
                "associated to the interface %s:  %s", iface_name,
                lisp_addr_to_char(&gateway));
        process_new_gateway(iface,&gateway);
    }
}

void
process_nl_new_multicast_route(struct rtmsg *rtm, int rt_length)
{
    lisp_addr_t srcaddr = {.lafi = LM_AFI_IP};
    lisp_addr_t grpaddr = {.lafi = LM_AFI_IP};

    /* IPv4 multicast routes are part of the default table and have
     * family 128, while IPv6 multicast routes are part of the main table
     * and have family 129 ... */
    if ( !((rtm->rtm_table == RT_TABLE_DEFAULT && rtm->rtm_family == 128) ||
           (rtm->rtm_table == RT_TABLE_MAIN && rtm->rtm_family == 129) ) )
        return;

    if (process_nl_mcast_route_attributes(rtm, rt_length, &srcaddr, &grpaddr)
            == BAD) {
        return;
    }

    multicast_join_channel(&srcaddr, &grpaddr);
}

int
process_nl_mcast_route_attributes(struct rtmsg *rtm, int rt_length,
        lisp_addr_t *rt_srcaddr, lisp_addr_t *rt_grpaddr)
{
    struct rtattr *rt_attr = NULL;
    iface_t *iface = NULL;
    int iface_index = 0;
    char iface_name[IF_NAMESIZE];
    struct rtnexthop *rt_nh = NULL;
    int nb_oifs = 0;
    int rtnh_length = 0;
    char ifnames[1024] = { 0 };

    rt_attr = (struct rtattr *)RTM_RTA(rtm);

    for (; RTA_OK(rt_attr, rt_length);
            rt_attr = RTA_NEXT(rt_attr, rt_length)) {
        switch (rt_attr->rta_type) {
            case RTA_DST:
                switch(rtm->rtm_family) {
                    case 128:
                        lisp_addr_ip_init(rt_grpaddr, RTA_DATA(rt_attr),
                                AF_INET);
                        break;
                    case 129:
                        lisp_addr_ip_init(rt_grpaddr, RTA_DATA(rt_attr),
                                AF_INET6);
                        break;
                    default:
                        break;
                }
                break;
            case RTA_SRC:
                switch (rtm->rtm_family) {
                    case 128:
                        lisp_addr_ip_init(rt_srcaddr, RTA_DATA(rt_attr),
                                AF_INET);
                        break;
                    case 129:
                        lisp_addr_ip_init(rt_srcaddr, RTA_DATA(rt_attr),
                                AF_INET6);
                        break;
                    default:
                        break;
                }
                break;
            case RTA_MULTIPATH:
                rt_nh = (struct rtnexthop *)RTA_DATA(rt_attr);
                rtnh_length = RTA_PAYLOAD(rt_attr);
                for (; RTNH_OK(rt_nh, rtnh_length); rt_nh = RTNH_NEXT(rt_nh)) {
                    /* Check if one of the interfaces is the gateway */
                    iface = get_interface_from_index(rt_nh->rtnh_ifindex);
                    iface_index = *(int *)RTA_DATA(rt_attr);
                    iface = get_interface_from_index(iface_index);
                    if (iface != NULL){
                        if_indextoname(iface_index, iface_name);
                        LMLOG(LINF, "process_nl_new_multicast_route: the "
                                "multicast route message is for an interface "
                                "that has RLOCs associated (%s). Ignoring!",
                                iface_name);
                        return BAD;
                    }

                    /* Prepare output for debug */
                    if_indextoname(rt_nh->rtnh_ifindex, iface_name);
                    sprintf(ifnames, "%s ", iface_name);
                    nb_oifs++;
                }
                break;
            default:
                break;
        }
    }

    if (nb_oifs == 0){
        LMLOG(DBG_1, "process_nl_new_multicast_route: New multicast route has "
                "no output interface list, ignored!");
        return BAD;
    }

    LMLOG(LINF, "New multicast route with source %s, group %s for interfaces "
            "%s", lisp_addr_to_char(rt_srcaddr), lisp_addr_to_char(rt_grpaddr),
            ifnames);

    return GOOD;
}

void
process_nl_del_route(struct nlmsghdr *nlh)
{

    struct rtmsg             *rtm                       = NULL;
    int                      rt_length                  = 0;

    rtm = (struct rtmsg *) NLMSG_DATA (nlh);
    rt_length = RTM_PAYLOAD(nlh);

    /* Process removed routes only for multicast */
    if (rtm->rtm_type == RTN_MULTICAST)
        process_nl_del_multicast_route (rtm, rt_length);
}

void
process_nl_del_multicast_route (struct rtmsg *rtm, int rt_length)
{

    lisp_addr_t  rt_groupaddr               = {.lafi=LM_AFI_IP};
    lisp_addr_t  rt_srcaddr                 = {.lafi=LM_AFI_IP};

    if ( !((rtm->rtm_table == RT_TABLE_DEFAULT && rtm->rtm_family == 128) ||
           (rtm->rtm_table == RT_TABLE_MAIN && rtm->rtm_family == 129) ) )
        return;


    if (process_nl_mcast_route_attributes(rtm, rt_length, &rt_srcaddr, &rt_groupaddr) == BAD)
        return;

    multicast_leave_channel(&rt_srcaddr, &rt_groupaddr);
}


void
process_new_gateway(iface_t *iface,lisp_addr_t *gateway)
{
    lisp_addr_t **gw_addr    = NULL;
    int         afi          = LM_AFI_NO_ADDR;
    int         route_metric = 100;

    switch(lisp_addr_ip_afi(gateway)){
        case AF_INET:
            gw_addr = &(iface->ipv4_gateway);
            afi = AF_INET;
            break;
        case AF_INET6:
            gw_addr = &(iface->ipv6_gateway);
            afi = AF_INET6;
            break;
        default:
            return;
    }
    if (*gw_addr == NULL) { // The default gateway of this interface is not deffined yet
        *gw_addr = lisp_addr_new();
        lisp_addr_copy(*gw_addr,gateway);
    }else{
        lisp_addr_copy(*gw_addr,gateway);
    }
    // XXX Add NAT and android stuff

    add_route(afi,iface->iface_index,NULL,NULL,*gw_addr,route_metric,iface->iface_index);
}

/*
 * Change the satus of the interface. Recalculate default control and output interfaces if it's needed.
 * Program SMR */
void
process_link_status_change(iface_t *iface, int new_status)
{
    if (iface->status == new_status){
        LMLOG(DBG_2,"process_link_status_change: The detected change of status"
                " doesn't affect");
        return;
    }

    /* Change status of the interface */
    iface->status = new_status;

    /* If the affected interface is the default control or output iface,
     * recalculate it */

    if (default_ctrl_iface_v4 == iface
            || default_ctrl_iface_v6 == iface
            || default_ctrl_iface_v4 == NULL
            || default_ctrl_iface_v6 == NULL){
        LMLOG(DBG_2,"Default control interface down. Recalculate new control"
                " interface");
        set_default_ctrl_ifaces();
    }

    if (default_out_iface_v4 == iface
            || default_out_iface_v6 == iface
            || default_out_iface_v4 == NULL
            || default_out_iface_v6 == NULL){
        LMLOG(DBG_2,"Default output interface down. Recalculate new output "
                "interface");
        set_default_output_ifaces();
    }

    /* raise event in ctrl */
    ctrl_if_status_update(lctrl, iface);

}





