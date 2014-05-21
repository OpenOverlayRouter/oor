/*
 * routing_tables_lib.c
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
 *    Preethi Natarajan         <prenatar@cisco.com>
 *    Lorand Jakab              <ljakab@ac.upc.edu>
 *    Albert López              <alopez@ac.upc.edu>
 *    Alberto Rodriguez Natal   <arnatal@ac.upc.edu>
 *
 */

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>

#include "routing_tables_lib.h"
#include "lispd_external.h"
#include "lmlog.h"


/**************************** FUNCTION DECLARATION ***************************/

/*
 * ifindex:     Output interface
 * dest:        Destination address
 * gw:          Gateway
 * prefix_len:  Destination address mask (/n)
 * metric:      Route metric
 * table:       Routing table. 0 = main table
 *
 */


inline int modify_route(
        int                 command,                    /* add or del */
        int                 afi,
        uint32_t            ifindex,
        lisp_addr_t         *dest,
        lisp_addr_t         *src,
        lisp_addr_t         *gw,
        uint32_t            prefix_len,
        uint32_t            metric,
        uint32_t            table);


/*
 * This function modifies kernel's list of ip rules
 */
inline int modify_rule (
        int             afi,
        int             if_index,       // interface index
        int             command,            // add or del the rule?
        uint8_t         table,          // rule for which routing table?
        uint32_t        priority,       // rule priority
        uint8_t         type,           // type of route
        lisp_addr_t     *src_addr,      // src addr to match
        int             src_plen,       // src addr prefix length
        lisp_addr_t     *dst_addr,      // dst addr to match
        int             dst_plen,       // dst addr prefix length
        int             flags);          // flags, if any

/*****************************************************************************/

/*
 * This function modifies kernel's list of ip rules
 */
inline int modify_rule (
        int             afi,
        int             if_index,       // interface index
        int             command,        // add or del the rule?
        uint8_t         table,          // rule for which routing table?
        uint32_t        priority,       // rule priority
        uint8_t         type,           // type of route
        lisp_addr_t     *src_addr,      // src addr to match
        int             src_plen,       // src addr prefix length
        lisp_addr_t     *dst_addr,      // dst addr to match
        int             dst_plen,       // dst addr prefix length
        int             flags)          // flags, if any
{
    struct nlmsghdr     *nlh            = NULL;
    struct rtmsg        *rtm            = NULL;
    struct rtattr       *rta            = NULL;
    char                buf[4096];
    int                 rta_len         = 0;
    int                 addr_size       = 0;
    int                 sockfd          = 0;
    int                 result          = BAD;


    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        LMLOG(LCRIT, "Failed to connect to netlink socket for creating route");
        exit_cleanup();
    }

    if (afi == AF_INET){
        addr_size = sizeof(struct in_addr);
    }
    else{
        addr_size = sizeof(struct in6_addr);
    }

    /*
     * Build the command
     */

    memset(buf, 0, sizeof(buf));

    nlh = (struct nlmsghdr *)buf;
    //rtm = (struct rtmsg *)(CO(buf,sizeof(struct nlmsghdr)));
    rtm = NLMSG_DATA(nlh);

    rta_len = sizeof(struct rtmsg);

    rta = (struct rtattr *)(CO(rtm, sizeof(struct rtmsg)));


    /*
     * Add src address for the route
     */
    if (src_addr != NULL){
        rta->rta_type = RTA_SRC;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
        memcpy(((char *)rta) + sizeof(struct rtattr), &src_addr->address, addr_size);
        rta_len += rta->rta_len;
    }

    /*
     * Add the destination
     */
    if (dst_addr != NULL){
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        rta->rta_type = RTA_DST;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
        memcpy(((char *)rta) + sizeof(struct rtattr), &dst_addr->address, addr_size);
        rta_len += rta->rta_len;
    }

    /*
     * Add priority
     */
    if (priority != 0){
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        rta->rta_type = RTA_PRIORITY;
        rta->rta_len = sizeof(struct rtattr) + sizeof(uint32_t);
        memcpy(((char *)rta) + sizeof(struct rtattr), &priority, sizeof(uint32_t));
        rta_len += rta->rta_len;
    }

    /*
     * Select interface
     */
    if (if_index != 0){
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        rta->rta_type = RTA_IIF;
        rta->rta_len = sizeof(struct rtattr) + sizeof(int);
        memcpy(((char *)rta) + sizeof(struct rtattr), &if_index, sizeof(int));
        rta_len += rta->rta_len;
    }

    /*
     * Fill up the netlink message flags and attributes
     */
    nlh->nlmsg_len =  NLMSG_LENGTH(rta_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    if (command == RTM_NEWRULE) {
        nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
        nlh->nlmsg_type = RTM_NEWRULE;
    }else{
        nlh->nlmsg_type = RTM_DELRULE;
    }

    rtm->rtm_family = afi;
    rtm->rtm_dst_len = dst_plen;
    rtm->rtm_src_len = src_plen;
    if (table == 0){
        rtm->rtm_table     = RT_TABLE_MAIN;
    }else{
        rtm->rtm_table     = table;
    }
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type  = type;
    rtm->rtm_flags = flags;


    /*
     * Send the netlink message to kernel
     */
    result = send(sockfd, buf, NLMSG_LENGTH(rta_len), 0);

    if (result < 0) {
        LMLOG(LCRIT, "mod_route: send netlink command failed %s", strerror(errno));
        close(sockfd);
        exit_cleanup();
    }
    close(sockfd);
    return(GOOD);
}

/*
 * This function adds a specific ip rule to
 * kernel's rule list
 */
int add_rule(
        int         afi,
        int         if_index,
        uint8_t     table,
        uint32_t    priority,
        uint8_t     type,
        lisp_addr_t *src_addr,
        int         src_plen,
        lisp_addr_t *dst_addr,
        int         dst_plen,
        int         flags)
{
    int result = BAD;
    result = modify_rule(afi, if_index, RTM_NEWRULE, table,priority, type, src_addr, src_plen, dst_addr, dst_plen, flags);
    if (result == GOOD){
        LMLOG(DBG_1, "add_rule: Add rule for source routing of src addr: %s",
                lisp_addr_to_char(src_addr));
    }

    return (result);
}

/*
 * This function deletes a specific ip rule to
 * kernel's rule list
 */
int del_rule(
        int         afi,
        int         if_index,
        uint8_t     table,
        uint32_t    priority,
        uint8_t     type,
        lisp_addr_t *src_addr,
        int         src_plen,
        lisp_addr_t *dst_addr,
        int         dst_plen,
        int         flags)
{
    int result = BAD;
    result = modify_rule(afi, if_index, RTM_DELRULE, table,priority, type, src_addr, src_plen, dst_addr, dst_plen, flags);
    if (result == GOOD){
        LMLOG(DBG_1, "del_rule: Removed rule for source routing of src addr: %s",
                lisp_addr_to_char(src_addr));
    }

    return (result);
}

/*
 * Remove all the created rules to the source routing tables
 */
void remove_created_rules()
{
    iface_list_elt    *interface_list = NULL;
    iface_t         *iface          = NULL;

    interface_list = head_interface_list;
    while (interface_list != NULL){
        iface = interface_list->iface;

        if (iface->ipv4_address->afi != AF_UNSPEC){
            if (iface->ipv4_gateway != NULL){
                del_route(AF_INET,iface->iface_index,NULL,NULL,iface->ipv4_gateway,0,0,iface->iface_index);
            }
            del_rule(AF_INET,0,iface->iface_index,iface->iface_index,RTN_UNICAST,iface->ipv4_address,32,NULL,0,0);
        }
        if (iface->ipv6_address->afi != AF_UNSPEC){
            if (iface->ipv6_gateway != NULL){
                del_route(AF_INET6,iface->iface_index,NULL,NULL,iface->ipv6_gateway,0,0,iface->iface_index);
            }
            del_rule(AF_INET6,0,iface->iface_index,iface->iface_index,RTN_UNICAST,iface->ipv6_address,128,NULL,0,0);
        }
        interface_list = interface_list->next;
    }
}

/*
 * Request to the kernel the routing table with the selected afi
 */
int request_route_table(uint32_t table, int afi)
{
    struct nlmsghdr *nlh    = NULL;
    struct rtmsg    *rtm    = NULL;
    char   sndbuf[4096];
    int    rta_len          = 0;
    int    retval           = 0;

    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);

    nlh = (struct nlmsghdr *)sndbuf;
    rtm = (struct rtmsg *)(CO(sndbuf,sizeof(struct nlmsghdr)));

    rta_len = sizeof(struct rtmsg);

    nlh->nlmsg_len =   NLMSG_LENGTH(rta_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_type  = RTM_GETROUTE;


    rtm->rtm_family    = afi;
    if (table == 0){
        rtm->rtm_table     = RT_TABLE_MAIN;
    }else{
        rtm->rtm_table     = table;
    }

    rtm->rtm_protocol  = RTPROT_STATIC;
    rtm->rtm_scope     = RT_SCOPE_UNIVERSE;
    rtm->rtm_type      = RTN_UNICAST;
    rtm->rtm_src_len   = 0;
    rtm->rtm_tos       = 0;
    rtm->rtm_dst_len   = 0;


    retval = send(netlink_fd, sndbuf, NLMSG_LENGTH(rta_len), 0);

    if (retval < 0) {
        LMLOG(LCRIT, "request_route_table: send netlink command failed %s", strerror(errno));
        exit_cleanup();
    }
    return(GOOD);
}

/*
 * ifindex:     Output interface
 * dest:        Destination address
 * gw:          Gateway
 * prefix_len:  Destination address mask (/n)
 * metric:      Route metric
 * table:       Routing table. 0 = main table
 *
 */

inline int modify_route(
        int                 command,                    /* add or del */
        int                 afi,
        uint32_t            ifindex,
        lisp_addr_t         *dest,
        lisp_addr_t         *src,
        lisp_addr_t         *gw,
        uint32_t            prefix_len,
        uint32_t            metric,
        uint32_t            table)
{
    struct nlmsghdr *nlh    = NULL;
    struct rtmsg    *rtm    = NULL;
    struct rtattr   *rta    = NULL;
    char   sndbuf[4096];
    int    rta_len          = 0;
    int    retval           = 0;
    int    sockfd           = 0;
    int    addr_size        = 0;

    if (afi == AF_INET){
        addr_size = sizeof(struct in_addr);
    }
    else{
        addr_size = sizeof(struct in6_addr);
    }

    addr_size = ip_sock_afi_to_size(afi);


    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        LMLOG(LCRIT, "modify_route: Failed to connect to netlink socket");
        exit_cleanup();
    }

    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);

    nlh = (struct nlmsghdr *)sndbuf;
    rtm = (struct rtmsg *)(CO(sndbuf,sizeof(struct nlmsghdr)));

    rta_len = sizeof(struct rtmsg);


    rta = (struct rtattr *)(CO(rtm, sizeof(struct rtmsg)));
    /*
     * Add the destination
     */

    if (dest != NULL){
        rta->rta_type = RTA_DST;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
//        memcpy(((char *)rta) + sizeof(struct rtattr), &dest->address, addr_size);
        lisp_addr_copy_to(((char *)rta) + sizeof(struct rtattr), dest);
        rta_len += rta->rta_len;
    }


    /*
     * Add src address for the route
     */
    if (src != NULL){
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        rta->rta_type = RTA_PREFSRC;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
        memcpy(((char *)rta) + sizeof(struct rtattr), &src->address, addr_size);
        rta_len += rta->rta_len;
    }

    /*
     * Add the outgoing interface
     */
    if (ifindex>0)
    {
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        rta->rta_type = RTA_OIF;
        rta->rta_len = sizeof(struct rtattr) + sizeof(uint32_t); // if_index
        memcpy(((char *)rta) + sizeof(struct rtattr), &ifindex, sizeof(uint32_t));
        rta_len += rta->rta_len;
    }

    /*
     * Add the gateway
     */

    if (gw != NULL){
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        rta->rta_type = RTA_GATEWAY;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
        memcpy(((char *)rta) + sizeof(struct rtattr), &gw->address, addr_size);
        rta_len += rta->rta_len;
    }


    /* Add the route metric */

    if (metric > 0){
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        //rta->rta_type = RTA_METRICS;
        rta->rta_type = RTA_PRIORITY; /* This is the actual atr type to set the metric... */
        rta->rta_len = sizeof(struct rtattr) + sizeof(uint32_t);
        memcpy(((char *)rta) + sizeof(struct rtattr), &metric, sizeof(uint32_t));
        rta_len += rta->rta_len;
    }


    nlh->nlmsg_len =   NLMSG_LENGTH(rta_len);
    if ( command == RTM_NEWROUTE){
        nlh->nlmsg_flags = NLM_F_REQUEST | (NLM_F_CREATE | NLM_F_REPLACE);
        nlh->nlmsg_type  = RTM_NEWROUTE;
    }else{
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_type  = RTM_DELROUTE;
    }


    rtm->rtm_family    = afi;
    if (table == 0){
        rtm->rtm_table     = RT_TABLE_MAIN;
    }else{
        rtm->rtm_table     = table;
    }

    rtm->rtm_protocol  = RTPROT_STATIC;
    rtm->rtm_scope     = RT_SCOPE_UNIVERSE;
    rtm->rtm_type      = RTN_UNICAST;
    rtm->rtm_src_len   = 0;
    rtm->rtm_tos       = 0;

    rtm->rtm_dst_len   = prefix_len;


    retval = send(sockfd, sndbuf, NLMSG_LENGTH(rta_len), 0);

    if (retval < 0) {
        LMLOG(LCRIT, "modify_route: send netlink command failed %s", strerror(errno));
        close(sockfd);
        exit_cleanup();
    }
    close(sockfd);
    return(GOOD);
}

int add_route(
        int                 afi,
        uint32_t            ifindex,
        lisp_addr_t         *dest,
        lisp_addr_t         *src,
        lisp_addr_t         *gw,
        uint32_t            prefix_len,
        uint32_t            metric,
        uint32_t            table)
{
    int result = BAD;
    result = modify_route(RTM_NEWROUTE, afi,ifindex, dest, src, gw, prefix_len, metric, table);
    if (result == GOOD){
        LMLOG(DBG_1, "add_route: added route to the system: src addr: %s, dst prefix:%s/%d, gw: %s, table: %d",
                (src != NULL) ? lisp_addr_to_char(src) : "-",
                (dest != NULL) ? lisp_addr_to_char(dest) : "-",
                prefix_len,
                (gw != NULL) ? lisp_addr_to_char(gw) : "-",
                table);
    }

    return (result);
}

int del_route(
        int                 afi,
        uint32_t            ifindex,
        lisp_addr_t         *dest,
        lisp_addr_t         *src,
        lisp_addr_t         *gw,
        uint32_t            prefix_len,
        uint32_t            metric,
        uint32_t            table)
{
    int result = BAD;
    result = modify_route(RTM_DELROUTE, afi, ifindex, dest, src, gw, prefix_len, metric, table);
    if (result == GOOD){
        LMLOG(DBG_1, "del_route: deleted route  from the system");
    }
    return (result);
}

