/*
 * lispd_tun.c
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2012 Cisco Systems, Inc, 2012. All rights reserved.
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
 * Based on code from Chris White <chris@logicalelegance.com>
 * 
 * Written or modified by:
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 */

#include "lispd_external.h"
#include "lispd_log.h"
#include "lispd_tun.h"

int create_tun(
    char                *tun_dev_name,
    unsigned int        tun_receive_size,
    int                 tun_mtu,
    int                 *tun_receive_fd,
    int                 *tun_ifindex,
    char                **tun_receive_buf)
{

    struct ifreq ifr;
    int err = 0;
    int tmpsocket = 0;
    int flags = IFF_TUN | IFF_NO_PI; // Create a tunnel without persistence
    char *clonedev = CLONEDEV;


    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if( (*tun_receive_fd = open(clonedev, O_RDWR)) < 0 ) {
        lispd_log_msg(LISP_LOG_CRIT, "TUN/TAP: Failed to open clone device");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, tun_dev_name, IFNAMSIZ);

    // try to create the device
    if ((err = ioctl(*tun_receive_fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(*tun_receive_fd);
        lispd_log_msg(LISP_LOG_CRIT, "TUN/TAP: Failed to create tunnel interface, errno: %d.", errno);
        exit(EXIT_FAILURE);
    }

    // get the ifindex for the tun/tap
    tmpsocket = socket(AF_INET, SOCK_DGRAM, 0); // Dummy socket for the ioctl, type/details unimportant
    if ((err = ioctl(tmpsocket, SIOCGIFINDEX, (void *)&ifr)) < 0) {
        close(*tun_receive_fd);
        close(tmpsocket);
        lispd_log_msg(LISP_LOG_CRIT, "TUN/TAP: unable to determine ifindex for tunnel interface, errno: %d.", errno);
        exit(EXIT_FAILURE);
    } else {
        lispd_log_msg(LISP_LOG_DEBUG_3, "TUN/TAP ifindex is: %d", ifr.ifr_ifindex);
        *tun_ifindex = ifr.ifr_ifindex;

        // Set the MTU to the configured MTU
        ifr.ifr_ifru.ifru_mtu = tun_mtu;
        if ((err = ioctl(tmpsocket, SIOCSIFMTU, &ifr)) < 0) {
            close(tmpsocket);
            lispd_log_msg(LISP_LOG_CRIT, "TUN/TAP: unable to set interface MTU to %d, errno: %d.", tun_mtu, errno);
            exit(EXIT_FAILURE);
        } else {
            lispd_log_msg(LISP_LOG_DEBUG_1, "TUN/TAP mtu set to %d", tun_mtu);
        }
    }

    close(tmpsocket);

    *tun_receive_buf = (char *)malloc(tun_receive_size);

    if (tun_receive_buf == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "create_tun: Unable to allocate memory for tun_receive_buf: %s", strerror(errno));
        return(BAD);
    }

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    lispd_log_msg(LISP_LOG_DEBUG_2, "Tunnel fd at creation is %d", *tun_receive_fd);

    /*
    if (!tuntap_install_default_routes()) {
        return(FALSE);
    }*/
    
    return(GOOD);
}



/*
 * tun_bring_up_iface_v4_eid
 *
 * Bring up and assign an ipv4 EID to the TUN/TAP interface
 */
int tun_bring_up_iface_v4_eid(
    lisp_addr_t         eid_address_v4,
    char                *tun_dev_name)
{
    struct ifreq ifr; //arnatal: XXX how to initialize?
    struct sockaddr_in *sp = NULL;
    int    netsock = 0;
    int    err = 0;

   lispd_log_msg(LISP_LOG_DEBUG_1,"LISP EID v4 address %s\n",get_char_from_lisp_addr_t(eid_address_v4));
    
    netsock = socket(eid_address_v4.afi, SOCK_DGRAM, 0);
    if (netsock < 0) {
        lispd_log_msg(LISP_LOG_ERR, "tun_bring_up_iface_v4_eid assign: socket() %s", strerror(errno));
        return(BAD);
    }

    /*
     * Fill in the request
     */
    strcpy(ifr.ifr_name, tun_dev_name);

    sp = (struct sockaddr_in *)&ifr.ifr_addr;
    sp->sin_family = eid_address_v4.afi;
    sp->sin_addr = eid_address_v4.address.ip;

    // Set the address

    if ((err = ioctl(netsock, SIOCSIFADDR, &ifr)) < 0) {
        lispd_log_msg(LISP_LOG_ERR, "TUN/TAP could not set EID on tun device, errno %d.", errno);
        return(BAD);
    }
    sp->sin_addr.s_addr = 0xFFFFFFFF;
    if ((err = ioctl(netsock, SIOCSIFNETMASK, &ifr)) < 0) {
        lispd_log_msg(LISP_LOG_ERR, "TUN/TAP could not set netmask on tun device, errno %d", errno);
        return(BAD);
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING; // Bring it up

    if ((err = ioctl(netsock, SIOCSIFFLAGS, &ifr)) < 0) {
        lispd_log_msg(LISP_LOG_CRIT, "TUN/TAP could not bring up tun device, errno %d.", errno);
        exit(EXIT_FAILURE);
    }
    close(netsock);
    return(GOOD);
}

/*
 * tun_add_v6_eid_to_iface()
 *
 * Add an ipv6 EID to the TUN/TAP interface
 */
int tun_add_v6_eid_to_iface(
    lisp_addr_t         eid_address_v6,
    char                *tun_dev_name)
{
    struct rtattr       *rta = NULL;
    struct ifaddrmsg    *ifa = NULL;
    struct nlmsghdr     *nlh = NULL;
    char                sndbuf[4096];
    int                 retval = 0;
    int                 sockfd = 0;
    int                 tun_ifindex = 0;

    tun_ifindex = if_nametoindex (tun_dev_name);

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        lispd_log_msg(LISP_LOG_ERR, "Failed to connect to netlink socket for tun_add_v6_eid_to_iface()");
        return(BAD);
    }

    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);
    nlh = (struct nlmsghdr *)sndbuf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg) + sizeof(struct rtattr) +
                                  sizeof(struct in6_addr));
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_type = RTM_NEWADDR;
    ifa = (struct ifaddrmsg *)(sndbuf + sizeof(struct nlmsghdr));

    ifa->ifa_prefixlen = 128;
    ifa->ifa_family = AF_INET6;
    ifa->ifa_index  = tun_ifindex;
    ifa->ifa_scope = RT_SCOPE_HOST;
    rta = (struct rtattr *)(sndbuf + sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg));
    rta->rta_type = IFA_LOCAL;

    rta->rta_len = sizeof(struct rtattr) + sizeof(struct in6_addr);
    memcpy(((char *)rta) + sizeof(struct rtattr), eid_address_v6.address.ipv6.s6_addr,
           sizeof(struct in6_addr));

    retval = send(sockfd, sndbuf, nlh->nlmsg_len, 0);

    if (retval < 0) {
        lispd_log_msg(LISP_LOG_ERR, "tun_add_v6_eid_to_iface: send() failed %s", strerror(errno));
        close(sockfd);
        return(BAD);
    }

    lispd_log_msg(LISP_LOG_DEBUG_1, "added ipv6 EID to TUN interface.");
    close(sockfd);
    return(GOOD);
}

/* 
 * ifindex:     Output interface
 * dest:        Destination address
 * gw:          Gateway
 * prefix_len:  Destination address mask (/n)
 * metric:      Route metric
 * 
 */


int add_route_v4(
    uint32_t            ifindex,
    lisp_addr_t         *dest,
    lisp_addr_t         *src,
    lisp_addr_t         *gw,
    uint32_t            prefix_len,
    uint32_t            metric)
{
    struct nlmsghdr *nlh;
    struct rtmsg    *rtm;
    struct rtattr  *rta;
    int    rta_len = 0;
    char   sndbuf[4096];
    int    retval;
    int    sockfd;
    
    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    
    if (sockfd < 0) {
        lispd_log_msg(LISP_LOG_CRIT, "Failed to connect to netlink socket for install_default_route()");
        exit(EXIT_FAILURE);
    }
    
    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);
    
    nlh = (struct nlmsghdr *)sndbuf;
    rtm = (struct rtmsg *)(sndbuf + sizeof(struct nlmsghdr));
    
    rta_len = sizeof(struct rtmsg);
    
    /*
     * Add the destination
     */
    rta = (struct rtattr *)((char *)rtm + sizeof(struct rtmsg));
    rta->rta_type = RTA_DST;
    rta->rta_len = sizeof(struct rtattr) + sizeof(struct in_addr);
    memcpy(((char *)rta) + sizeof(struct rtattr), &dest->address.ip, sizeof(struct in_addr));
    rta_len += rta->rta_len;

    /*
     * Add src address for the route
     */
    if (src != NULL){
        rta = (struct rtattr *)(((char *)rta) + rta->rta_len);
        rta->rta_type = RTA_PREFSRC;
        rta->rta_len = sizeof(struct rtattr) + sizeof(struct in_addr);
        memcpy(((char *)rta) + sizeof(struct rtattr), &src->address.ip, sizeof(struct in_addr));
        rta_len += rta->rta_len;
    }
    
    /*
     * Add the outgoing interface
     */
    rta = (struct rtattr *)(((char *)rta) + rta->rta_len);
    rta->rta_type = RTA_OIF;
    rta->rta_len = sizeof(struct rtattr) + sizeof(uint32_t); // if_index
    memcpy(((char *)rta) + sizeof(struct rtattr), &ifindex, sizeof(uint32_t));
    rta_len += rta->rta_len;

    /*
     * Add the gateway
     */

    if (gw != NULL){
        rta = (struct rtattr *) (((char *)rta) + rta->rta_len);
        rta->rta_type = RTA_GATEWAY;
        rta->rta_len = sizeof(struct rtattr) + sizeof(struct in_addr);
        memcpy(((char *)rta) + sizeof(struct rtattr), &gw->address.ip, sizeof(struct in_addr));
        //inet_pton(AF_INET, "192.168.2.1", ((char *)rta) + sizeof(struct rtattr));
        rta_len += rta->rta_len;
    }

    
    /* Add the route metric */
    
    rta = (struct rtattr *)(((char *)rta) + rta->rta_len);
    //rta->rta_type = RTA_METRICS;
    rta->rta_type = RTA_PRIORITY; /* This is the actual atr type to set the metric... */
    rta->rta_len = sizeof(struct rtattr) + sizeof(uint32_t);
    memcpy(((char *)rta) + sizeof(struct rtattr), &metric, sizeof(uint32_t));
    rta_len += rta->rta_len;
    
    nlh->nlmsg_len =   NLMSG_LENGTH(rta_len);
    nlh->nlmsg_flags = NLM_F_REQUEST | (NLM_F_CREATE | NLM_F_REPLACE);
    nlh->nlmsg_type =  RTM_NEWROUTE;
    
    rtm->rtm_family    = AF_INET;
    rtm->rtm_table     = RT_TABLE_MAIN;

    rtm->rtm_protocol  = RTPROT_STATIC;
    rtm->rtm_scope     = RT_SCOPE_UNIVERSE;
    rtm->rtm_type      = RTN_UNICAST;
    rtm->rtm_src_len   = 0;
    rtm->rtm_tos       = 0;
    
    rtm->rtm_dst_len   = prefix_len;

    
    retval = send(sockfd, sndbuf, NLMSG_LENGTH(rta_len), 0);

    if (retval < 0) {
        lispd_log_msg(LISP_LOG_CRIT, "install_default_route: send() failed %s", strerror(errno));
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    lispd_log_msg(LISP_LOG_DEBUG_1, "Installed default route via TUN device");
    close(sockfd);
    return(GOOD);
}

int set_tun_default_route_v4(int tun_ifindex)
{

    /*
     * Assign route to 0.0.0.0/1 and 128.0.0.0/1 via tun interface
     */

    lisp_addr_t dest;
    lisp_addr_t *src = NULL;
    lisp_addr_t gw;
    uint32_t prefix_len = 0;
    uint32_t metric = 0;

    prefix_len = 1;
    metric = 0;
    
    get_lisp_addr_from_char("0.0.0.0",&gw);

#ifdef OPENWRT
    if (default_out_iface_v4 != NULL){
        src = default_out_iface_v4->ipv4_address;
    }
#endif

    get_lisp_addr_from_char("0.0.0.0",&dest);

    add_route_v4(tun_ifindex,
            &dest,
            src,
            NULL,
            prefix_len,
            metric);


    get_lisp_addr_from_char("128.0.0.0",&dest);

    add_route_v4(tun_ifindex,
            &dest,
            src,
            NULL,
            prefix_len,
            metric);

    return(GOOD);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
