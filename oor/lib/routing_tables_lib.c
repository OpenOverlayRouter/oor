/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <errno.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include "oor_log.h"
#include "routing_tables_lib.h"
#include "sockets-util.h"
#include "../oor_external.h"




/**************************** FUNCTION DECLARATION ***************************/

/*
 * ifindex: Output interface
 * dest: Destination address
 * gw: Gateway
 * prefix_len: Destination address mask (/n)
 * metric: Route metric
 * table: Routing table. 0 = main table
 *
 */

/* command could be add or del */
inline int modify_route(int command, int afi, uint32_t ifindex,
        lisp_addr_t *dest_pref, lisp_addr_t *src, lisp_addr_t *gw,
        uint32_t metric, uint32_t table);


/*
 * This function modifies kernel's list of ip rules
 * @param afi AF_INE or AF_INET6
 * @paramif_index interface index
 * @param command add or del the rule?
 * @param table rule for which routing table?
 * @param priority rule priority
 * @param type type of route
 * @param src_pref src prefix to match
 * @param dst_pref dst prefix to match
 * @param flags flags, if any
 */
inline int modify_rule (int afi, int if_index, int command, uint8_t table,
        uint32_t priority, uint8_t type, lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, int flags);

/*****************************************************************************/

/*
 * This function modifies kernel's list of ip rules
 */
inline int
modify_rule (int afi, int if_index, int command, uint8_t table,
        uint32_t priority, uint8_t type, lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, int flags)
{
    struct nlmsghdr *nlh = NULL;
    struct rtmsg *rtm = NULL;
    struct rtattr *rta = NULL;
    char buf[4096];
    int rta_len = 0;
    int addr_size = 0;
    int sockfd = 0;
    int result = BAD;
    int src_pref_len = 0;
    int dst_pref_len = 0;

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        OOR_LOG(LCRIT, "Failed to connect to netlink socket for creating route");
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
    if (src_pref != NULL){
        rta->rta_type = RTA_SRC;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
        lisp_addr_copy_to(((char *)rta) + sizeof(struct rtattr),src_pref);
        rta_len += rta->rta_len;
        src_pref_len = lisp_addr_ip_get_plen(src_pref);
    }

    /*
     * Add the destination
     */
    if (dst_pref != NULL){
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        rta->rta_type = RTA_DST;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
        lisp_addr_copy_to(((char *)rta) + sizeof(struct rtattr),dst_pref);
        rta_len += rta->rta_len;
        dst_pref_len = lisp_addr_ip_get_plen(dst_pref);
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
    nlh->nlmsg_len = NLMSG_LENGTH(rta_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    if (command == RTM_NEWRULE) {
        nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
        nlh->nlmsg_type = RTM_NEWRULE;
    }else{
        nlh->nlmsg_type = RTM_DELRULE;
    }

    rtm->rtm_family = afi;
    rtm->rtm_dst_len = dst_pref_len;
    rtm->rtm_src_len = src_pref_len;
    if (table == 0){
        rtm->rtm_table = RT_TABLE_MAIN;
    }else{
        rtm->rtm_table = table;
    }
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type = type;
    rtm->rtm_flags = flags;


    /*
     * Send the netlink message to kernel
     */
    result = send(sockfd, buf, NLMSG_LENGTH(rta_len), 0);

    if (result < 0) {
        OOR_LOG(LCRIT, "mod_route: send netlink command failed %s", strerror(errno));
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
int
add_rule(int afi, int if_index, uint8_t table, uint32_t priority, uint8_t type,
        lisp_addr_t *src_pref, lisp_addr_t *dst_pref, int flags)
{
    int result = BAD;
    result = modify_rule(afi, if_index, RTM_NEWRULE, table,priority, type, src_pref, dst_pref, flags);
    if (result == GOOD){
        OOR_LOG(LDBG_1, "add_rule: Add rule -> Send packets with source address %s and destination address %s"
                " to the table %d with priority %d.",lisp_addr_to_char(src_pref),
                lisp_addr_to_char(dst_pref),table,priority);
    }

    return (result);
}

/*
 * This function deletes a specific ip rule to
 * kernel's rule list
 */
int
del_rule(int afi, int if_index, uint8_t table, uint32_t priority, uint8_t type,
        lisp_addr_t *src_pref, lisp_addr_t *dst_pref, int flags)
{
    int result = BAD;
    result = modify_rule(afi, if_index, RTM_DELRULE, table,priority, type, src_pref, dst_pref, flags);
    if (result == GOOD){
        OOR_LOG(LDBG_1, "del_rule: Removed rule for source routing of src addr: %s",
                lisp_addr_to_char(src_pref));
    }

    return (result);
}

/*
 * Request to the kernel the routing table with the selected afi
 */
int
request_route_table(uint32_t table, int afi)
{
    struct nlmsghdr *nlh = NULL;
    struct rtmsg *rtm = NULL;
    char sndbuf[4096];
    int rta_len = 0;
    int retval = 0;

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


    retval = send(netlink_fd, sndbuf, NLMSG_LENGTH(rta_len), 0);

    if (retval < 0) {
        OOR_LOG(LCRIT, "request_route_table: send netlink command failed %s", strerror(errno));
        exit_cleanup();
    }
    return(GOOD);
}


/*
 * ifindex: Output interface
 * dest: Destination address
 * gw: Gateway
 * prefix_len: Destination address mask (/n)
 * metric: Route metric
 * table: Routing table. 0 = main table
 *
 */

inline int
modify_route(int  command, int  afi, uint32_t ifindex, lisp_addr_t *dest_pref,
        lisp_addr_t *src_addr, lisp_addr_t *gw_addr, uint32_t metric,
        uint32_t table)
{
    struct nlmsghdr *nlh = NULL;
    struct rtmsg *rtm = NULL;
    struct rtattr *rta = NULL;
    char sndbuf[4096];
    int rta_len = 0;
    int retval = 0;
    int sockfd = 0;
    int addr_size = 0;
    int dst_pref_len = 0;

    if (afi == AF_INET){
        addr_size = sizeof(struct in_addr);
    }
    else{
        addr_size = sizeof(struct in6_addr);
    }

    addr_size = ip_sock_afi_to_size(afi);


    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        OOR_LOG(LCRIT, "modify_route: Failed to connect to netlink socket");
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

    if (dest_pref != NULL){
        rta->rta_type = RTA_DST;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
        lisp_addr_copy_to(((char *)rta) + sizeof(struct rtattr), dest_pref);
        rta_len += rta->rta_len;
        dst_pref_len = lisp_addr_ip_get_plen(dest_pref);
    }


    /*
     * Add src address for the route
     */
    if (src_addr != NULL){
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        rta->rta_type = RTA_PREFSRC;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
        lisp_addr_copy_to(((char *)rta) + sizeof(struct rtattr), src_addr);
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

    if (gw_addr != NULL){
        if (rta_len > sizeof(struct rtmsg)){
            rta = (struct rtattr *)(CO(rta, rta->rta_len));
        }
        rta->rta_type = RTA_GATEWAY;
        rta->rta_len = sizeof(struct rtattr) + addr_size;
        lisp_addr_copy_to(((char *)rta) + sizeof(struct rtattr), gw_addr);
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


    nlh->nlmsg_len = NLMSG_LENGTH(rta_len);
    if ( command == RTM_NEWROUTE){
        nlh->nlmsg_flags = NLM_F_REQUEST | (NLM_F_CREATE | NLM_F_REPLACE);
        nlh->nlmsg_type = RTM_NEWROUTE;
    }else{
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_type = RTM_DELROUTE;
    }


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

    rtm->rtm_dst_len = dst_pref_len;


    retval = send(sockfd, sndbuf, NLMSG_LENGTH(rta_len), 0);

    if (retval < 0) {
        OOR_LOG(LCRIT, "modify_route: send netlink command failed %s", strerror(errno));
        close(sockfd);
        exit_cleanup();
    }
    close(sockfd);
    return(GOOD);
}

int
add_route(int afi, uint32_t ifindex, lisp_addr_t *dest_pref, lisp_addr_t *src,
        lisp_addr_t *gw, uint32_t metric, uint32_t table)
{
    int result = BAD;
    result = modify_route(RTM_NEWROUTE, afi,ifindex, dest_pref, src, gw, metric, table);
    if (result == GOOD){
        OOR_LOG(LDBG_1, "add_route: added route to the system: src addr: %s, dst prefix:%s, gw: %s, table: %d",
                (src != NULL) ? lisp_addr_to_char(src) : "-",
                (dest_pref != NULL) ? lisp_addr_to_char(dest_pref) : "-",
                (gw != NULL) ? lisp_addr_to_char(gw) : "-",
                table);
    }

    return (result);
}

int
del_route(int  afi, uint32_t ifindex, lisp_addr_t *dest_pref, lisp_addr_t *src,
        lisp_addr_t *gw, uint32_t metric, uint32_t table)
{
    int result = BAD;
    result = modify_route(RTM_DELROUTE, afi, ifindex, dest_pref, src, gw, metric, table);
    if (result == GOOD){
        OOR_LOG(LDBG_1, "del_route: deleted route from the system: src addr: %s, dst prefix:%s, gw: %s, table: %d",
                (src != NULL) ? lisp_addr_to_char(src) : "-",
                (dest_pref != NULL) ? lisp_addr_to_char(dest_pref) : "-",
                (gw != NULL) ? lisp_addr_to_char(gw) : "-",
                table);
    }
    return (result);
}

