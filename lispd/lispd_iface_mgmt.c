/*
 * lispd_iface_mgmt.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Netlink support and related routines for interface management.
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
 *    Vijay Subramanian <vijaynsu@cisco.com>
 *    Pere Monclus      <pmonclus@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *    Pranathi Mamidi   <pranathi.3961@gmail.com>
 *
 */

#include "lispd_external.h"

#define BUF_SIZE                    512
#define RT_TABLE_LISP_MN            5
#define LISP_MN_EID_IFACE_MTU       1300
#define LISP_MN_IP_RULE_PRIORITY    1

typedef struct _reqaddr_t {
    struct nlmsghdr n;
    struct ifaddrmsg r;
    char buf [BUF_SIZE];
} reqaddr_t;

typedef     struct _reqinfo_t {
    struct nlmsghdr     n;
    struct ifinfomsg    r;
    char            buf[BUF_SIZE];
} reqinfo_t;

typedef struct _reqmsg_t {
    struct nlmsghdr     n;
    struct rtmsg        r;
    char            buf[BUF_SIZE];
} reqmsg_t;

/*
 * This function sends a netlink message
 * to the kernel 
 */
static int nlsock_talk(n)
        struct nlmsghdr *n;
{
    struct sockaddr_nl nladdr;

    /* 
     * Set the netlink socket addr details so that the message
     * is received by the kernel
     */
    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pad = 0;
    nladdr.nl_pid = 0;      // destination == kernel
    nladdr.nl_groups = 0;

    /*
     * Package the netlink msg inside an iovec
     */
    struct iovec iov = {
        (void *)n,      // actual vector to be txd 
        n->nlmsg_len    // length of vector
    };

    struct msghdr msg = {
            (void *)&nladdr,        // destination
            sizeof(nladdr),         // destination length
            &iov,                   // Vector data 
            1,                      // Vector data len
            NULL,                   // Ancillary data 
            0,                      // Ancillary data len
            0                       // falgs
    };

    if(sendmsg(nlh.fd, &msg, 0) < 0) {
        syslog (LOG_DAEMON, "sendmsg (nlsock_talk()) failed: %s\n",
                strerror(errno));
        return 0;
    }

    return 1;
}

#define NLMSG_TAIL(nmsg) \
        ((struct rtattr *)(((void * )(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

/* 
 * This function populates the tail of a netlink msg
 * with new rtattr struct
 */
static int addattr_l(n, maxlen, type, data, alen)
        struct nlmsghdr *n;     // the netlink msg header
        int maxlen;             // max length of the netlink msg
        int type;               // RTA attr type of the data
        void *data;             // data to add
        int alen;               // data length
{

    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
        syslog(LOG_DAEMON, "Align issue (addattr_l): netlink msg buf too small for data\n");
        return 0;
    }
                
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;

    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 1;

}

/* 
 * As a result of this function, the kernel will send a RTM_NEWROUTE
 * message for each of its routing entries
 */
int dump_routing_table(afi, table)
    uint16_t afi;
    int table;
{
#ifdef DEBUG
    syslog(LOG_DAEMON, "RTNETLINK: ip route list table %d", table);
#endif
    return(route_mod(RTM_GETROUTE, afi, NULL, 0, NULL, 0, NULL, NULL, table, 0, 0));
}

/*
 * This function deletes a specific route
 */
static int route_del(afi, src, src_plen,
        dst, dst_plen,
        gateway, device_id, table)
    uint16_t afi;
    lisp_addr_t *src;
    int src_plen;
    lisp_addr_t *dst;
    int dst_plen;
    lisp_addr_t *gateway;
    int device_id; 
    int table;
{

#ifdef DEBUG
    char buf[BUF_SIZE];
    char tmp[BUF_SIZE];
    sprintf(buf, "RTNETLINK: ip route del");
    if (dst == NULL)
        strcat(buf, " default");
    if (table != RT_TABLE_MAIN) {
        sprintf(tmp, " table %d", table);
        strcat(buf, tmp);
    }
    syslog(LOG_DAEMON, "%s", buf);
#endif
    return (route_mod(RTM_DELROUTE, afi,
                src, src_plen,
                dst, dst_plen,
                gateway, device_id, table, 0, 0));

}

/* 
 * This function adds a specific route
 */
int route_add(afi, src, src_plen,
        dst, dst_plen, 
        gateway, device_id, table, metric, realm)
    uint16_t afi;
    lisp_addr_t *src;
    int src_plen;
    lisp_addr_t *dst;
    int dst_plen;
    lisp_addr_t *gateway;
    int device_id; 
    int table;
    int metric;
    int realm;
{

#ifdef DEBUG
    char buf[BUF_SIZE];
    char tmp[BUF_SIZE];
    sprintf(buf, "RTNETLINK: ip route add");
    if (dst == NULL)
        strcat(buf, " default");
    if (table != RT_TABLE_MAIN) {
        sprintf(tmp, " table %d", table);
        strcat(buf, tmp);
    }
    syslog(LOG_DAEMON, "%s", buf);
#endif
    return (route_mod(RTM_NEWROUTE, afi,
                src, src_plen,
                dst, dst_plen,
                gateway, device_id, table, metric, realm));

}

/*
 * This function modifies (add/del) a route via
 * netlink
 */
int route_mod(cmd, afi, src, src_plen, dst, dst_plen,
        gateway, device_id, table, metric, realm)
    int cmd;                    /* add or del */
    uint16_t afi;               /* IPv4 or IPv6 routing table */
    lisp_addr_t *src;           /* src address */
    int src_plen;               /* src addr prefix length */
    lisp_addr_t *dst;           /* dst address */
    int dst_plen;               /* dst addr prefix length */
    lisp_addr_t *gateway;       /* gateway addr */
    int device_id;              /* outgoing iface id */
    int table;                  /* routing table number */
    int metric;                 /* route metric (priority) */
    int realm;                  /* route realm */
{

        reqmsg_t       req;
        int attr_size =0;
        memset(&req, 0, sizeof(req));

        /*
         * Fill up the netlink msg with appropriate flags and data
         */
        req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
        req.n.nlmsg_type = cmd;
        req.n.nlmsg_flags = NLM_F_REQUEST;

        if (cmd == RTM_NEWROUTE) {
            req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
        }

        if (cmd == RTM_GETROUTE) {
            req.n.nlmsg_flags |= NLM_F_DUMP;
        }

        req.n.nlmsg_seq = ++nlh.seq;
        req.n.nlmsg_pid = getpid();

        req.r.rtm_table = table;
        req.r.rtm_protocol = RTPROT_BOOT;
        req.r.rtm_scope = RT_SCOPE_UNIVERSE;
        req.r.rtm_type = RTN_UNICAST;
        req.r.rtm_src_len = src_plen;
        req.r.rtm_dst_len = dst_plen;
        req.r.rtm_family = afi;

        if (gateway)
            req.r.rtm_family = gateway->afi;

        if(device_id)
                addattr_l(&req.n, sizeof(req), RTA_OIF, &device_id, 
                        sizeof(int));
        if(metric)
                addattr_l(&req.n, sizeof(req), RTA_PRIORITY, &metric,
                        sizeof(int));
        if(realm)
                addattr_l(&req.n, sizeof(req), RTA_FLOW, &realm,
                        sizeof(int));
        if(src) {
            attr_size = ((src->afi == AF_INET6) ? 
                sizeof(struct in6_addr) : sizeof(struct in_addr));
            addattr_l(&req.n, sizeof(req), RTA_DST, 
                        &(src->address), attr_size); 
        }
        if(dst) {
            attr_size = ((dst->afi == AF_INET6) ? 
                sizeof(struct in6_addr) : sizeof(struct in_addr));
            addattr_l(&req.n, sizeof(req), RTA_DST, 
                        &(dst->address), attr_size); 
        }
        if(gateway) {
            attr_size = ((gateway->afi == AF_INET6) ? 
                sizeof(struct in6_addr) : sizeof(struct in_addr));
            addattr_l(&req.n, sizeof(req), RTA_GATEWAY, 
                        &(gateway->address), attr_size);
        }

        /* 
         * Send netlink msg to kernel
         */
        if (!nlsock_talk(&req.n)) {
            syslog (LOG_DAEMON, "nlsock_talk (route_mod()) failed\n");
            return (0);
        }

        return 1;
}

/*
 * This function parses netlink error messages
 */
static void parse_nl_error(nlHdr)
        struct nlmsghdr *nlHdr;
{
    struct nlmsgerr *nlErr;

    nlErr = (struct nlmsgerr *)NLMSG_DATA(nlHdr);
#ifndef DEBUG
    if(nlErr->error)
#endif
        syslog(LOG_DAEMON, "RTNETLINK answers: %s\n",
                strerror(-nlErr->error));
}

/*
 * This function parses and gathers information from
 * netlink route messages
 */
static iface_list_elt *parse_nl_route (nlHdr, gateway, dev, metric, realm)
        struct nlmsghdr * nlHdr;
        lisp_addr_t     * gateway;
        int             * dev;
        int             * metric;
        int             * realm;
{

    struct rtmsg *rt;
    struct rtattr *rtAttr;
    int rtLen;
    char tempBuf[BUF_SIZE];
    iface_list_elt  *iface_elt = NULL;

    switch (nlHdr->nlmsg_type) {
        case RTM_NEWROUTE:
            sprintf(tempBuf, "Parsing RTM_NEWROUTE Message:\n");
            break;
        case RTM_DELROUTE:
            sprintf(tempBuf, "Parsing RTM_DELROUTE Message:\n");
            break;
        default:
            syslog(LOG_DAEMON,"parse_nl_route(): Unknown message type\n");
            return (NULL);
    }

    rt = (struct rtmsg *)NLMSG_DATA(nlHdr);
    if ((rt->rtm_family != AF_INET) && (rt->rtm_family != AF_INET6)) {
        syslog(LOG_DAEMON, "parse_nl_route: Unknown adddress family\n");
        return NULL;
    }

    if (rt->rtm_table != RT_TABLE_MAIN) {

        /* not interested in routes/gateways affecting
         * tables other the main routing table
         */
        return NULL;
    }
    syslog(LOG_DAEMON,"%s", tempBuf);

    rtAttr = (struct rtattr *)RTM_RTA(rt);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            if_indextoname(*(int *)RTA_DATA(rtAttr), tempBuf);
            syslog(LOG_DAEMON, "  Output interface: %s\n", tempBuf);
            iface_elt = search_iface_list(tempBuf);
            if(dev)
                memcpy(dev, (int *)RTA_DATA(rtAttr), sizeof(int));
            break;
        case RTA_PRIORITY:
            if(metric) {
                memcpy(metric, (int *)RTA_DATA(rtAttr), sizeof(int));
                syslog(LOG_DAEMON, "  Metric: %d\n", *metric);
            }
            break;
        case RTA_FLOW:
            if(realm) {
                memcpy(realm, (int *)RTA_DATA(rtAttr), sizeof(int));
                syslog(LOG_DAEMON, "  Realm: %d\n", *realm);
            }
            break;
        case RTA_GATEWAY:
            inet_ntop(rt->rtm_family, RTA_DATA(rtAttr), tempBuf,
                    sizeof(tempBuf));
            syslog(LOG_DAEMON, "  Gateway address: %s\n", tempBuf);
            gateway->afi = rt->rtm_family;
            switch (gateway->afi) {
            case AF_INET:
                memcpy(&(gateway->address),
                    (struct in_addr *)RTA_DATA(rtAttr),
                    sizeof(struct in_addr));
                break;
            case AF_INET6:
                memcpy(&(gateway->address),
                    (struct in6_addr *)RTA_DATA(rtAttr),
                    sizeof(struct in6_addr));
                break;
            }
            break;
        case RTA_DST:
            inet_ntop(rt->rtm_family, RTA_DATA(rtAttr), tempBuf,
                    sizeof(tempBuf));
            syslog(LOG_DAEMON, "  Destination address: %s\n", tempBuf);
            /* We are only interested in default gateway changes */
            syslog(LOG_DAEMON, "Not a default route, ignored...");
            return NULL;
            break;
        }
    }

    return (iface_elt);

}

/* 
 * This function parses and gathers information from 
 * netlink address messages
 */
static iface_list_elt *parse_nl_addr(nlHdr, addr)
        struct nlmsghdr *nlHdr;
        lisp_addr_t     *addr;

{
    struct ifaddrmsg  *ifaddr;
    struct rtattr *rtAttr;
    int rtLen;
    char tempBuf[BUF_SIZE];
    iface_list_elt  *iface_elt =   NULL;
        
    switch (nlHdr->nlmsg_type) {
    case RTM_NEWADDR:
        sprintf(tempBuf, "Parsing RTM_NEWADDR Message:\n");
        break;
    case RTM_DELADDR:
        sprintf(tempBuf, "Parsing RTM_DELADDR Message:\n");
        break;
    default:
        syslog(LOG_DAEMON, "parse_nl_addr(): Unknown Message Type\n\n");
        return NULL;
        break;
    }

    ifaddr = (struct ifaddrmsg *)NLMSG_DATA(nlHdr);
    if ((ifaddr->ifa_family != AF_INET) &&
        (ifaddr->ifa_family != AF_INET6)) {
        syslog(LOG_DAEMON, "parse_nl_addr(): Unknown address family\n");
        return NULL;
    }
    syslog(LOG_DAEMON, "%s", tempBuf);

    addr->afi = ifaddr->ifa_family;

    rtAttr = (struct rtattr *)IFA_RTA(ifaddr);
    rtLen = IFA_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case IFA_LOCAL:
            inet_ntop(addr->afi, RTA_DATA(rtAttr), tempBuf,
                sizeof(tempBuf));
            syslog(LOG_DAEMON, "Local address: %s\n", tempBuf);
            break;
        case IFA_BROADCAST:
            inet_ntop(addr->afi, RTA_DATA(rtAttr), tempBuf,
                sizeof(tempBuf));
            syslog(LOG_DAEMON, "Broadcast address: %s\n", tempBuf);
            break;
        case IFA_ANYCAST:
            inet_ntop(addr->afi, RTA_DATA(rtAttr), tempBuf,
                sizeof(tempBuf));
            syslog(LOG_DAEMON, "Anycast address: %s\n", tempBuf);
            break;
        case IFA_ADDRESS:
            inet_ntop(addr->afi, RTA_DATA(rtAttr), tempBuf,
                sizeof(tempBuf));
            syslog(LOG_DAEMON, "Interface address: %s\n", tempBuf);
            switch (addr->afi) {
            case AF_INET:
                memcpy(&(addr->address),
                    (struct in_addr *)RTA_DATA(rtAttr),
                    sizeof(struct in_addr));
                break;
            case AF_INET6:
                memcpy(&(addr->address),
                    (struct in6_addr *)RTA_DATA(rtAttr),
                    sizeof(struct in6_addr));
                break;
            }
            break;
        case IFA_LABEL:
            syslog(LOG_DAEMON, "Interface name: %s\n",
                    (char *)RTA_DATA(rtAttr));
            iface_elt = search_iface_list(
                    (char *)RTA_DATA(rtAttr));
            break;
        }
    }
    return iface_elt;
}

/*
 * This function modifies kernel's list of ip rules
 */
static int rule_mod (if_index, cmd, 
        table, priority, type, 
        src, src_plen, dst, dst_plen, flags)
        int if_index;       // interface index
        int cmd;            // add or del the rule?
        uint8_t table;      // rule for which routing table?
        uint32_t priority;  // rule priority
        uint8_t type;       // type of route 
        lisp_addr_t *src;   // src addr to match
        int src_plen;       // src addr prefix length
        lisp_addr_t *dst;   // dst addr to match
        int dst_plen;       // dst addr prefix length
        int flags;          // flags, if any
{
    uint8_t buf[BUF_SIZE];
    struct nlmsghdr *n;
    struct rtmsg *rtm;
    int attr_size;

    memset(buf, 0, sizeof(buf));
    n = (struct nlmsghdr *)buf;

    /*
     * Fill up the netlink message flags and attributes
     */
    n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

    if (cmd == RTM_NEWRULE) {
        n->nlmsg_flags |= NLM_F_CREATE;
    }

    n->nlmsg_type = cmd;
    n->nlmsg_seq = ++nlh.seq;
    n->nlmsg_pid = getpid();

    rtm = NLMSG_DATA(n);
    if (src) rtm->rtm_family = src->afi; /* assume family == src family */
    else rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = dst_plen;
    rtm->rtm_src_len = src_plen;
    rtm->rtm_table = table;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type = type;
    rtm->rtm_flags = flags;

    if(dst) {
        attr_size = ((dst->afi == AF_INET6) ?  
                sizeof(struct in6_addr) : sizeof(struct in_addr));
        addattr_l(n, sizeof(buf), RTA_DST, &(dst->address), attr_size);
    }
    if (src) {
        attr_size = ((src->afi == AF_INET6) ?  
                sizeof(struct in6_addr) : sizeof(struct in_addr));
        addattr_l(n, sizeof(buf), RTA_SRC, &(src->address), attr_size);
    }
    if (priority)
        addattr_l(n, sizeof(buf), RTA_PRIORITY, &priority,
                sizeof(uint32_t));  
    if (if_index)
        addattr_l(n, sizeof(buf), RTA_IIF, &if_index, 
                sizeof(int));

    /*
     * Send the netlink message to kernel 
     */
    if (!nlsock_talk(n, 0, 0, NULL)) {
        syslog (LOG_DAEMON, "nlsock_talk (rule_mod()) failed\n");
        return (0);
    }
     
    return 1;
}

/*
 * This function adds a specific ip rule to 
 * kernel's rule list
 */
static int rule_add(int if_index, uint8_t table,
         uint32_t priority, uint8_t type,
         lisp_addr_t *src, int src_plen,
         lisp_addr_t *dst, int dst_plen, int flags)
{
#ifdef DEBUG
    syslog(LOG_DAEMON, "RTNETLINK: ip rule add (...)");
#endif
    return rule_mod(if_index, RTM_NEWRULE, table,
            priority, type,
            src, src_plen, dst, dst_plen, flags);
}

/*
 * This function deletes a specific ip rule to 
 * kernel's rule list
 */
static int rule_del(int if_index, uint8_t table,
         uint32_t priority, uint8_t type,
         lisp_addr_t *src, int src_plen,
         lisp_addr_t *dst, int dst_plen, int flags)
{
#ifdef DEBUG
    syslog(LOG_DAEMON, "RTNETLINK: ip rule del (...)");
#endif
    return rule_mod(if_index, RTM_DELRULE, table,
            priority, type,
            src, src_plen, dst, dst_plen, flags);
}

/*
 * This function configures source address based
 * policy routing in the kernel
 */
static int setup_source_routing(iface_name, src_rloc, gateway)
    char *iface_name;       // outgoing interface
    lisp_addr_t *src_rloc;  // src address to match
    lisp_addr_t *gateway;   // default gateway address
{

    /* 
     * Step 1:
     * add the ip rule for the LISP_MN routing table
     * ip rule add from <src_rloc> table RT_TABLE_LISP_MN
     */
    if (!rule_add(0, RT_TABLE_LISP_MN, LISP_MN_IP_RULE_PRIORITY, 
            RTN_UNICAST, src_rloc, 
            ((src_rloc->afi == AF_INET6) ? 128 : 32),
            NULL, 0, 0 )) {
        syslog(LOG_DAEMON, "rule_add (setup_source_routing()) failed\n");
        return 0;
    }

    /*
     * Step 2:
     * add the default gateway for this rule
     * ip route add default via <gtw> dev <iface> table RT_TABLE_LISP_MN
     */
    int if_index = if_nametoindex(iface_name);
    if (!route_add(0, NULL, 0,
                NULL, 0, 
                gateway, if_index, RT_TABLE_LISP_MN, 0, 0)) {
        syslog(LOG_DAEMON, "route_add (setup_source_routing()) failed\n");
        return 0;
    }
    return 1;
}

/* This function deletes the rule and default gateway
 * for a particular policy route
 */
static int delete_source_routing(iface_name, src_rloc, gateway)
    char *iface_name;       // outgoing interface
    lisp_addr_t *src_rloc;  // src address to match
    lisp_addr_t *gateway;   // default gateway address
{
    int if_index = if_nametoindex(iface_name);

    /* 
     * Step 1:
     * delete the ip rule for the LISP_MN routing table
     * ip rule del from <src_rloc> table RT_TABLE_LISP_MN
     */
    if (!rule_del(0, RT_TABLE_LISP_MN, LISP_MN_IP_RULE_PRIORITY, 
            RTN_UNICAST, src_rloc, 
            ((src_rloc->afi == AF_INET6) ? 128 : 32), 
            NULL, 0, 0 )) {
        syslog(LOG_DAEMON, "rule_del (delete_source_routing()) failed\n");
        return 0;
    }

    /*
     * Step 2:
     * delete the default gateway for this rule
     * ip route del default via <gtw> dev <iface> table RT_TABLE_LISP_MN
     */
    if (!route_del(0, NULL, 0,
                NULL, 0, gateway, if_index, RT_TABLE_LISP_MN)) {
        syslog(LOG_DAEMON, "route_del (delete_source_routing()) failed\n");
        return 0;
    }
    return 1;
}

/*
 * This function deletes the rloc from lispd's
 * patricia tree database and updates interface list
 */
int delete_rloc (iface_elt, rloc, node)
    iface_list_elt    *iface_elt;
    lisp_addr_t       *rloc;
    patricia_node_t   *node;
{
    lispd_locator_chain_t       *locator_chain  = NULL;
    lispd_db_entry_t            *db_entry       = NULL;
    lispd_locator_chain_elt_t   *del_elt        = NULL;
    lispd_locator_chain_elt_t   *prev_elt       = NULL;
    char                        *eid            = NULL;
    char                        addr_str[MAX_INET_ADDRSTRLEN];

    /*
     * First find the eid associated with this interface
     * How do we know which eid to use -- the v4 or v6 one?
     * XXX: Assume eid's afi == rloc's afi
     * Then, find the patricia node associated with the eid
     */


    if (node == NULL) {
        syslog(LOG_DAEMON, "delete_rloc(): EID (%s) not found in database", eid);
        free(eid);
        return(0);
    }

    if (node->data == NULL) {           
        syslog(LOG_DAEMON, "delete_rloc(): NULL locator chain for eid (%s)\n", eid);
        free(eid);
        return(0);
    }

    /*
     * Find the matching locator_chain_elt
     * Note: There can be situations where an interface is
     * associated with multiple rlocs. That's why its better
     * to search for the excat rloc match instead of the simpler
     * match by interface name (locator_chain_elt->locator_name)
     */
    locator_chain = (lispd_locator_chain_t *)node->data;
    del_elt   = locator_chain->head;
    prev_elt  = locator_chain->head;

    while (del_elt) {
        if (!(memcmp(&del_elt->db_entry->locator, 
                        &rloc->address, sizeof(lisp_addr_t)))) {

            /* Found the matching locator;
             * Delete the locator form the locator chain
             */ 
            db_entry = del_elt->db_entry;
            if ((del_elt == locator_chain->head) && 
                (del_elt == locator_chain->tail)) {

                /* single entry in locator chain 
                 */
                locator_chain->head = NULL;
                locator_chain->tail = NULL;

            }
            else {
                prev_elt->next = del_elt->next;
                if (del_elt == locator_chain->head) {
                    /* set the new head */
                    locator_chain->head = del_elt->next;
                }
                if (del_elt == locator_chain->tail) {
                    /* set the new tail */
                    locator_chain->tail = prev_elt;
                }
            }
            locator_chain->locator_count -= 1;

            syslog(LOG_DAEMON, "delete_rloc(): %s deleted from interface %s", 
                    inet_ntop(db_entry->locator.afi,
                            &(db_entry->locator.address), addr_str, 
                            MAX_INET_ADDRSTRLEN),
                    iface_elt->iface_name);

            /* 
             * Update iface_elt by deleting the corresponding
             * db_entry from iface_elt
             */
            switch (rloc->afi) {
            case AF_INET:
                del_item_from_db_entry_list(iface_elt->AF4_locators, db_entry);
                break;
            case AF_INET6:
                del_item_from_db_entry_list(iface_elt->AF6_locators, db_entry);
                break;
            }

            free(db_entry);
            free(del_elt->locator_name);
            free(del_elt);
            free (eid);
            return (1); // success

        }
        prev_elt = del_elt;
        del_elt = del_elt->next;
    }

    /* we didn't find the locator */
    syslog(LOG_DAEMON, "delete_rloc(): %s not found in patricia tree\n",
             inet_ntop (rloc->afi,
                     &(rloc->address), addr_str,
                     MAX_INET_ADDRSTRLEN));
    free(eid);
    return(0);
} 

lispd_db_entry_t *add_rloc (iface_elt, rloc, node, eid)
    iface_list_elt    *iface_elt;
    lisp_addr_t       *rloc;
    patricia_node_t   *node;
    char              *eid;
{
    lispd_locator_chain_t       *locator_chain  = NULL;
    lispd_db_entry_t            *db_entry       = NULL;
    lispd_locator_chain_elt_t   *add_elt        = NULL;
    char                        *token          = NULL;
    db_entry_list_elt           *db_elt         = NULL;
    int                         afi;
    char                        addr_str[MAX_INET_ADDRSTRLEN];

    /*
     * First find the eid associated with this interface
     * How do we know which eid to use -- the v4 or v6 one?
     * XXX: Assume eid's afi == rloc's afi
     * Then, find the patricia node associated with the eid
     */

    if (node == NULL) {
        syslog(LOG_DAEMON, "add_rloc(): EID (%s) not found in database", eid);
        free(eid);
        return(0);
    }

    if ((db_entry = malloc(sizeof(lispd_db_entry_t))) == NULL) {
        syslog(LOG_DAEMON,"add_rloc(): malloc(sizeof(lispd_database_t)): %s", strerror(errno));
        free (eid);
        return(0);
    }
    memset(db_entry,0,sizeof(lispd_db_entry_t));

    /* 
     * Fill up db_entry 
     */
    db_entry->locator_name = strdup(iface_elt->iface_name);
    memcpy((void *) &(db_entry->locator), rloc, sizeof(lisp_addr_t));

    afi = get_afi(eid);

    if ((token = strtok(eid, "/")) == NULL) {
        syslog(LOG_DAEMON,"eid prefix not of the form prefix/length");
        free (eid);
        free(db_entry);
        return(0);
    }

    /* 
     *  get the EID prefix into the right place/format
     */
    if (inet_pton(afi, token, &(db_entry->eid_prefix.address)) != 1) {
        syslog(LOG_DAEMON, "inet_pton: %s", strerror(errno));
        free(db_entry);
        free (eid);
        return(0);
    }

    /*
     *  get the prefix length into token
     */
    if ((token = strtok(NULL,"/")) == NULL) {
        syslog(LOG_DAEMON, "strtok: %s", strerror(errno));
        free(db_entry);
        free (eid);
        return(0);
    }

    db_entry->eid_prefix_length = atoi(token);
    db_entry->eid_prefix.afi    = afi;

    /* 
     * XXX: Assume priority and weight are 
     * identical for all locators of this iface 
     */
    db_entry->priority          = iface_elt->priority; 
    db_entry->weight            = iface_elt->weight;
    
    /*
     *  link up db_entry into the patricia tree
     */
    if ((add_elt = malloc(sizeof(lispd_locator_chain_elt_t))) == NULL) {
        syslog(LOG_DAEMON, "add_rloc(): Can't malloc(sizeof(lispd_locator_chain_elt_t)): %s", strerror(errno));
        free(db_entry);
        free(eid);
        return(0);
    }
    memset(add_elt, 0, sizeof(lispd_locator_chain_elt_t));
    add_elt->db_entry      = db_entry;  
    add_elt->locator_name  = db_entry->locator_name;

    if (node->data == NULL) {           
        /*
         * Setup node->data
         */
        if ((locator_chain = malloc(sizeof(lispd_locator_chain_t))) == NULL) {
            syslog(LOG_DAEMON, "Can't malloc(sizeof(lispd_locator_chain_t))");
            free(db_entry);
            free(eid);
            return(0);
        }
        memset(locator_chain,0,sizeof(lispd_locator_chain_t));
        node->data = (lispd_locator_chain_t *) locator_chain;   
        /*
         *      put the eid_prefix information into the locator_chain
         */
        copy_lisp_addr_t(&(locator_chain->eid_prefix),
                         &(db_entry->eid_prefix),
                         0);            
        locator_chain->eid_prefix_length    = db_entry->eid_prefix_length;
        locator_chain->eid_prefix.afi       = db_entry->eid_prefix.afi;
        locator_chain->eid_name             = strdup(eid);
        locator_chain->has_dynamic_locators = DYNAMIC_LOCATOR;
        locator_chain->timer                = DEFAULT_MAP_REGISTER_TIMEOUT;
    } else {                            
        /* there's an existing locator_chain */
        locator_chain = (lispd_locator_chain_t *) node->data; 
    }

    /*
     * Setup a new locator_chain_elt for this rloc
     */
    if ((add_elt = malloc(sizeof(lispd_locator_chain_elt_t))) == NULL) {
        syslog(LOG_DAEMON, 
                "add_rloc(): Can't malloc(sizeof(lispd_locator_chain_elt_t)): %s", 
                strerror(errno));
        free(db_entry);
        free(eid);
        return(0);
    }
    memset(add_elt, 0, sizeof(lispd_locator_chain_elt_t));
    add_elt->db_entry      = db_entry;  
    add_elt->locator_name  = db_entry->locator_name;

    /*
     *  connect up the locator_chain and locator_chain_elt
     */
    if (locator_chain->head == NULL) {
        locator_chain->head = add_elt;
        locator_chain->tail = add_elt;
    } else {
        locator_chain->tail->next = add_elt;
        locator_chain->tail       = add_elt;
    }

    locator_chain->locator_count ++;

    syslog(LOG_DAEMON, "add_rloc(): %s added to interface %s", 
                    inet_ntop (db_entry->locator.afi,
                            &(db_entry->locator.address), addr_str, 
                            MAX_INET_ADDRSTRLEN),
                    iface_elt->iface_name);

    /* 
     * Update iface_elt with the new db_entry element
     */
    if ((db_elt = malloc (sizeof(db_entry_list_elt))) == NULL) {
        syslog(LOG_DAEMON, "add_rloc(): Can't malloc(sizeof(db_entry_list_elt))\n");
        free(eid);
        return (0);
    }
    memset (db_elt, 0, sizeof(db_entry_list_elt));
    db_elt->db_entry    = db_entry;
    db_elt->next        = NULL;
    
    switch (rloc->afi) {
    case AF_INET:
        add_item_to_db_entry_list(iface_elt->AF4_locators, db_elt);
        break;
    case AF_INET6:
        add_item_to_db_entry_list(iface_elt->AF6_locators, db_elt);
        break;
    }

    return db_entry;

}

void smr_pitrs(void) {
    patricia_node_t *node;
    lispd_locator_chain_t *locator_chain = NULL;
    lispd_addr_list_t *elt = proxy_itrs;
    char pitr_name[128];

    PATRICIA_WALK(AF4_database->head, node) {
        locator_chain = ((lispd_locator_chain_t *)(node->data));
        if (locator_chain) {
            while (elt) {
                inet_ntop(elt->address->afi, &(elt->address->address), pitr_name, 128);
                if (build_and_send_map_request_msg(elt->address,
                        &(locator_chain->eid_prefix),
                        (get_addr_len(locator_chain->eid_prefix.afi) * 8),
                        locator_chain->eid_name,
                        0, 0, 1, 0, 0, 0, LISPD_INITIAL_MRQ_TIMEOUT, 0))
                    syslog(LOG_DAEMON, "SMR'ing %s", pitr_name);
                elt = elt->next;
            }
        }
    } PATRICIA_WALK_END;
}

int setup_netlink_iface ()
{
    struct sockaddr_nl addr;

    memset(&nlh, 0, sizeof(nlsock_handle));
    if ((nlh.fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0)
        return (0);

    memset((void *)&addr, 0, sizeof(addr));

    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = LISPD_IFACE_NLMGRPS;

    if (bind(nlh.fd,
        (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_DAEMON, 
                "bind (setup_netlink_iface()) failed: %s\n", strerror(errno));
        return (0);
    }
    return (1);
}

int process_netlink_iface ()
{

    struct  sockaddr_nl nladdr;
    struct  msghdr msg;
    char    buffer[65536];
    struct  iovec iov;
    struct  nlmsghdr *nh;
    int     len;
    struct  ifinfomsg   *iface;
    char    iface_name[IFNAMSIZ];
    lispd_db_entry_t    *db_entry = NULL;
    iface_list_elt      *elt = NULL;
    patricia_node_t             *node           = NULL;
    prefix_t                    *prefix         = NULL;
    char                        *eid            = NULL;
    lisp_addr_t     rloc;
    lisp_addr_t     gateway;
    int             metric = 0;
    int             realm = 0;

    memset (buffer, 0, sizeof(buffer));
    iov.iov_base    =   (void *)buffer;
    iov.iov_len     =   sizeof(buffer);

    memset (&msg, 0, sizeof(struct msghdr));
    msg.msg_name    =   (void *)&(nladdr);
    msg.msg_namelen =   sizeof(nladdr);
    msg.msg_iov     =   &iov;
    msg.msg_iovlen  =   1;

    len = recvmsg(nlh.fd, &msg, 0);
    if (len < 0) {
        syslog (LOG_DAEMON, "process_netlink(): Error reading netlink message (%d)", len);
        return (0);
    }

    nh = (struct nlmsghdr *)buffer;
    while (NLMSG_OK(nh, len)) {

        memset (&rloc, 0, sizeof(lisp_addr_t));
        elt = NULL;
        iface = NULL;
        memset (&gateway, 0, sizeof(lisp_addr_t));

        switch (nh->nlmsg_type) {
            case NLMSG_DONE:
                break;

            case NLMSG_ERROR:
                parse_nl_error(nh);
                break; 

            case RTM_NEWLINK:
                iface   =   NLMSG_DATA(nh);
                if_indextoname(iface->ifi_index, iface_name);
                elt = search_iface_list(iface_name);
                if (elt == NULL) {
                    nh = NLMSG_NEXT(nh, len);
                    continue;
                }
                syslog (LOG_DAEMON, "process_netlink(): RTM_NEWLINK on %s\n", iface_name);

                /* 
                 * Update interface status
                 * If needed, find another active interface for control
                 * messages
                 */
                if ((iface->ifi_flags & IFF_UP) && 
                        (iface->ifi_flags & IFF_RUNNING)) 
                    elt->ready = 1;
                else {
                    elt->ready = 0;
                    if (elt == ctrl_iface) 
                        ctrl_iface = NULL;
                }
                
                if (ctrl_iface == NULL) {
                  ctrl_iface = find_active_ctrl_iface ();
                }
                break;

            /*    
             * RTM_DELLINK is never received on Ubuntu 10.04
             */
            /* case RTM_DELLINK:
                iface   =   NLMSG_DATA(nh);
                if_indextoname(iface->ifi_index, iface_name);
                syslog (LOG_DAEMON, "RTM_DELLINK on %s\n", iface_name);
                break;
            */

            case RTM_NEWADDR:
                elt = parse_nl_addr(nh, &rloc);
                if (elt == NULL) {
                    nh = NLMSG_NEXT(nh, len);
                    continue;
                }

                //Pranathi
                if (elt->AF4_eid_prefix) {
                    eid = strdup(elt->AF4_eid_prefix);
                    prefix = ascii2prefix(AF_INET, eid);
                    node = patricia_search_exact(AF4_database, prefix);
                    db_entry = add_rloc(elt, &rloc, node, eid);
                    sleep (2);
#ifdef DEBUG
                    syslog(LOG_DAEMON, "Updating RLOC in mapping database");
#endif
                    if(db_entry) {
                        install_database_mapping(db_entry);
                    }
                }

                if (elt->AF6_eid_prefix) {
                    eid = strdup(elt->AF6_eid_prefix);
                    prefix = ascii2prefix(AF_INET6, eid);
                    node = patricia_search_exact(AF6_database, prefix);
                    db_entry = add_rloc(elt, &rloc, node, eid);
                    sleep (2);
#ifdef DEBUG
                    syslog(LOG_DAEMON, "Updating RLOC in mapping database");
#endif
                    if(db_entry) {
                        install_database_mapping(db_entry);
                    }
                }


                /* 
                 * Install the new RLOC in lisp_mod.
                 * Note that lisp_mod will start using the 
                 * new RLOC as soon as the RLOC is installed.
                 * The corresponding policy routing may not even
                 * be setup then.
                 * Until policy routing is setup, LISP packets
                 * with the new src RLOC will not be routed 
                 * correclty.
                 */
                 
                /* XXX:
                 * Delay by a few seconds before installing
                 * the new address in lisp_mod.
                 * Else, seems to be a race condition?
                 */

                set_rloc(&rloc);

                if (ctrl_iface == NULL) {
                    ctrl_iface = find_active_ctrl_iface();
                }

                break;

            case RTM_NEWROUTE:
                elt = parse_nl_route(nh, &gateway, NULL, &metric, &realm);
                if ((elt == NULL) || (gateway.afi == 0) || (realm > 0)) {
                    nh = NLMSG_NEXT(nh, len);
                    continue;
                }

                /*
                 * We raise the metric for the new route, so the EID route
                 * is preferred and applications bind to the EID. We set a
                 * realm, to avoid recursive calling of this code due to
                 * re-adding the route.
                 */

                if(metric == 0) {
                    syslog(LOG_DAEMON, "Raising metric of RLOC default route to 101 on %s",
                            elt->iface_name);
                    if(!route_del(0, NULL, 0, NULL, 0, &gateway,
                                if_nametoindex(elt->iface_name),
                                RT_TABLE_MAIN)) {
                          syslog(LOG_DAEMON, "process_netlink(): route_del failed\n");
                    }
                    if(!route_add(0, NULL, 0, NULL, 0, &gateway,
                                if_nametoindex(elt->iface_name),
                                RT_TABLE_MAIN, 101, 7)) {
                          syslog(LOG_DAEMON, "process_netlink(): route_add failed\n");
                    }
                }

                /* 
                 * Make sure LISP-MN eid iface is still the default
                 * gateway
                 */
                syslog(LOG_DAEMON, 
                        "process_netlink(): Setting %s as default gateway",
                        LISP_MN_EID_IFACE_NAME);

                if(!route_add(AF_INET, NULL, 0, NULL, 0, NULL,
                            if_nametoindex(LISP_MN_EID_IFACE_NAME),
                            RT_TABLE_MAIN, 0, 0)) {
                      syslog(LOG_DAEMON, "process_netlink(): route_add failed\n");
                }

                if(!route_add(AF_INET6, NULL, 0, NULL, 0, NULL,
                            if_nametoindex(LISP_MN_EID_IFACE_NAME),
                            RT_TABLE_MAIN, 0, 0)) {
                      syslog(LOG_DAEMON, "process_netlink(): route_add failed\n");
                }

                /*
                 * Set the EID addr on the LISP-MN Iface
                 * Assume its the same family as the gateway family
                 */

                lisp_addr_t eid_addr;
                memset(&eid_addr, 0, sizeof(lisp_addr_t));

               //Pranathi
               if(ctrl_iface->AF4_locators->head)
               {
                   memcpy(&eid_addr, &(elt->AF4_locators->head->db_entry->eid_prefix), sizeof(lisp_addr_t));
               }    
              if(ctrl_iface->AF6_locators->head)
               {
                   memcpy(&eid_addr, &(elt->AF6_locators->head->db_entry->eid_prefix), sizeof(lisp_addr_t));
               }

                /* 
                 * Remember the new gateway for future policy 
                 * routing updates
                 */
                memset(&(elt->gateway), 0, sizeof(lisp_addr_t));
                memcpy(&(elt->gateway), &gateway, sizeof(lisp_addr_t));

                /* 
                 * setup policy routing for this interface using
                 * this gateway
                 */
                syslog(LOG_DAEMON, "process_netlink(): Setup policy routing\n");
                lisp_addr_t src_rloc;
                memset (&src_rloc, 0, sizeof(lisp_addr_t));

                /*
                 * Assume src rloc afi == gateway's afi
                 */

                src_rloc.afi = gateway.afi;

                /* XXX
                 * What is the src rloc for policy routing?
                 * Assume src rloc to use == head entry of
                 * the list of locators
                 * Ideally, we should find the src rloc in a more robust
                 * way such as:
                 * - go through the list of locators and find 
                 *   the one that matches the gateway's network;
                 *   To do this, db_entry must also store the 
                 *   locator's netmask?
                 */

                db_entry = ((src_rloc.afi == AF_INET6) ? 
                     elt->AF6_locators->head->db_entry : 
                     elt->AF4_locators->head->db_entry);
                memcpy(&src_rloc,
                        &(db_entry->locator),
                        sizeof(lisp_addr_t));

                setup_source_routing (elt->iface_name,
                    &src_rloc, &gateway);
                memcpy(&source_rloc, &src_rloc, sizeof(lisp_addr_t));

                /*
                 * Install the new src rloc/db_netry in lisp_mod
                 * NOTE: the rloc might've already been installed
                 * during RTM_NEWADDR
                 */
                install_database_mapping(db_entry);
                set_rloc(&src_rloc);

                /*
                 * Update control interface for lispd control messages
                 * if needed
                 */
                if (ctrl_iface == NULL)
                    ctrl_iface = find_active_ctrl_iface();

                /*
                 * Map register the new RLOC
                 */
                /* XXX:
                 * Delay sending map register by a few secs
                 * Otherwise seems like a race condition?
                 */
                sleep (3);
                syslog(LOG_DAEMON, "process_netlink_iface(): Map register\n");

                start_periodic_map_register();

                /*
                 * Trigger SMR to PITRs and the MN's peers
                 */
                smr_pitrs();
                get_map_cache_list();

                break; 

            case RTM_DELROUTE:
                elt = parse_nl_route(nh, &gateway, NULL, NULL, NULL);
                if ((elt == NULL) || (gateway.afi == 0)) {
                    nh = NLMSG_NEXT(nh, len);
                    continue;
                }
                break; 

            case RTM_DELADDR:
                elt = parse_nl_addr(nh, &rloc);

                if (elt == NULL) {
                    nh = NLMSG_NEXT(nh, len);
                    continue;
                }

                /* 
                 * Delete the rloc from lispd's database
                 * and interface list
                 */

                //Pranathi
                if (elt->AF4_eid_prefix) {
                    eid = strdup(elt->AF4_eid_prefix);
                    prefix = ascii2prefix(AF_INET, eid);
                    node = patricia_search_exact(AF4_database, prefix);
                    delete_rloc(elt, &rloc, node);
                }

                if (elt->AF6_eid_prefix) {
                    eid = strdup(elt->AF6_eid_prefix);
                    prefix = ascii2prefix(AF_INET6, eid);
                    node = patricia_search_exact(AF6_database, prefix);
                    delete_rloc(elt, &rloc, node);
                }

                /*
                 * XXX:
                 * Delete rloc from lisp_mod via netlink.
                 * To do this, we need a new netlink msg 
                 * and corresponding support in lisp_mod.
                 * Also, lisp_mod should update LSB info
                 * and stop encapping lisp packets with src 
                 * addr = deleted addr
                 */

                /* 
                 * Delete policy routing associated
                 * with the interface
                 */
                if (elt->gateway.afi)
                {
                    delete_source_routing(elt->iface_name, &rloc,
                            &(elt->gateway));

                    memset(&elt->gateway, 0, sizeof(lisp_addr_t));

                }

                /*
                 * Update ctrl_iface if needed
                 */
                if (elt == ctrl_iface) {
                    ctrl_iface = NULL;
                    ctrl_iface = find_active_ctrl_iface();
                }
                break;

            default:
                printf("arrived at default\n");
                break;
        }

        if (nh->nlmsg_type == NLMSG_DONE)
            break; //from while
        nh = NLMSG_NEXT(nh, len);

    }

    return (1);
}

/*
 * This function brings up an interface
 * and sets the mtu on it
 */
int lisp_eid_iface_config(iface_name, mtu)
    char *iface_name;
    int mtu;
{
    int sd;
    int rc;
    struct ifreq ifr;
    memset (&ifr, 0, sizeof(struct ifreq));

    if ((sd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_DAEMON, "socket (iface_config): %s", 
                strerror(errno));
        return 0;
    }

    strcpy(ifr.ifr_name, iface_name);
        
    if ((rc = ioctl(sd, SIOCGIFFLAGS, &ifr)) < 0) {
        syslog(LOG_DAEMON, "ioctl SIOCGIFFLAGS (iface_config): %s", 
                strerror(errno));
        close(sd);
        return 0;
    }

    if (!(ifr.ifr_flags & IFF_UP)) {
        /*
         * Get the interface up and running
         */
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

        if ((rc = ioctl(sd, SIOCSIFFLAGS, &ifr)) < 0) {
            syslog(LOG_DAEMON, "ioctl SIOCSIFFLAGS (iface_config): %s", 
                strerror(errno));
            close(sd);
            return 0;
        }
    }

    /*
     * Set the MTU on the interface
     */
    ifr.ifr_mtu = mtu;
    if ((rc = ioctl(sd, SIOCSIFMTU, &ifr)) < 0) {
        syslog(LOG_DAEMON, "ioctl SIOCSIFMTU (iface_config): %s", 
                strerror(errno));
        close(sd);
        return 0;
    }

    close(sd);
    return 1;

}

/* 
 * This function configures the lisp eid interface (ex: lmn0) 
 * 1. Configures the iface with eid addr
 * 2. Brings up the interface and sets the mtu
 * 3. Configures the interface as the default gw
 */
int setup_lisp_eid_iface(eid_iface_name, eid_addr, eid_prefix_len)

        char *eid_iface_name;
        lisp_addr_t *eid_addr;
        int eid_prefix_len;
{

        /*struct in_addr ifa_broadcast;*/
        int if_index = if_nametoindex(eid_iface_name);

        /* 
         * Step 1:
         * Configure the interface with appropriate parameters
         * such as EID addr, local addr, broadcast addr etc
         */
        reqaddr_t  raddr;
        memset(&raddr, 0, sizeof(raddr));
        raddr.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        raddr.n.nlmsg_type = RTM_NEWADDR;
        raddr.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        raddr.n.nlmsg_seq = ++nlh.seq;
        raddr.n.nlmsg_pid = getpid();
        raddr.r.ifa_flags = IFA_F_PERMANENT; 
        raddr.r.ifa_scope = RT_SCOPE_UNIVERSE; 
        raddr.r.ifa_index = if_index;
        raddr.r.ifa_prefixlen = eid_prefix_len;
        raddr.r.ifa_family = eid_addr->afi;

        int attr_size = ((eid_addr->afi == AF_INET6) ? 
                sizeof(struct in6_addr) : sizeof(struct in_addr));
        
        if (!addattr_l(&(raddr.n), sizeof(raddr), IFA_ADDRESS,
                      &(eid_addr->address), attr_size)) {
                syslog(LOG_DAEMON, "addattr_l(IFA_ADDRESS) failed \n");
                return 0;
        }

        /* PN:
         * XXX IFA_LOCAL addr == IFA_ADDRESS ?
         */
        if (!addattr_l(&(raddr.n), sizeof(raddr), IFA_LOCAL,
                      &(eid_addr->address), attr_size)) {
                syslog(LOG_DAEMON, "addattr_l(IFA_LOCAL) failed\n");
                return 0;
        }

        /* PN
         * XXX: Set the right broadcast address
         */
        /* struct in_addr ifa_broadcast;
        if (addattr_l(&raddr.n, sizeof(raddr), IFA_BROADCAST,
                      &ifa_broadcast.s_addr,
                      sizeof(ifa_broadcast.s_addr)) < 0) {
                syslog(LOG_DAEMON, "addattr_l(IFA_BROADCAST) failed\n");
                return 0;
        } */


        /*
         * Send the netlink message to kernel 
         */
        if (!nlsock_talk(&raddr.n, 0, 0, NULL)) {
            syslog(LOG_DAEMON, "nlsock_talk (setup_lisp_eid_iface()) failed\n");
            return 0;
        }

        /* Step 2: 
         * Configure the LISP EID interface:
         */
        if (!lisp_eid_iface_config(eid_iface_name, 
                    LISP_MN_EID_IFACE_MTU)) {
            syslog(LOG_DAEMON, "lisp_eid_iface_config (setup_lisp_eid_iface()) failed\n");
            return 0;
        }

        /* 
         * Step 3:
         * Set the LISP EID interface as the default gateway/interface
         */
        if(!route_add(eid_addr->afi, NULL, 0, NULL, 0, NULL, if_index, RT_TABLE_MAIN, 0, 0)) {
            syslog(LOG_DAEMON, "route_add (setup_lisp_eid_iface()) failed\n");
            return 0;
        }

        /*
         * Step 4:
         * (when required) Inform The Kernel Module about the new EID
         */
#ifdef TESTLOCALEID
        if(!add_local_eid(eid_addr)){
        	syslog(LOG_DAEMON, "add_local_eid (setup_lisp_eid_iface()) failed\n");
        	return 0;
        }
#endif
        syslog(LOG_DAEMON, "Configured LISP-MN EID interface\n");
        return 1;
}

static int lower_default_route_metric(void) {
    iface_list_elt *elt;

    elt = find_active_ctrl_iface();
    syslog(LOG_DAEMON, "Lowering metric of default route to 0 on %s",
            elt->iface_name);
    if(!route_del(0, NULL, 0, NULL, 0, &(elt->gateway),
                if_nametoindex(elt->iface_name),
                RT_TABLE_MAIN)) {
          syslog(LOG_DAEMON, "process_netlink(): route_del failed\n");
          return 0;
    }
    if(!route_add(0, NULL, 0, NULL, 0, &(elt->gateway),
                if_nametoindex(elt->iface_name),
                RT_TABLE_MAIN, 0, 0)) {
          syslog(LOG_DAEMON, "process_netlink(): route_add failed\n");
          return 0;
    }
    return 1;
}

/*
 *  exit_cleanup()
 *
 *  remove lisp modules (and restore network settings)
 */

void exit_cleanup(void) {
    /* Close timer file descriptors */
    close(map_register_timer_fd);

    /* Close receive sockets */
    close(v6_receive_fd);
    close(v4_receive_fd);

    /* Close LISP netlink socket */
    close(netlink_fd);

    /* Remove lisp modules */
    system("/sbin/modprobe -r lisp lisp_int");

    /* Remove source routing ip rule */
    delete_source_routing(ctrl_iface, &source_rloc, NULL);

    /* Lower metric on default route to 0 and remove realm */
    lower_default_route_metric();

    /* Close routing netlink socket */
    close(nlh.fd);

    /* Close syslog */
    closelog();

    exit(EXIT_SUCCESS);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
