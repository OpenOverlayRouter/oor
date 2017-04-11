/*
 *  Universal TUN/TAP device driver.
 *  Copyright (C) 1999-2000 Maxim Krasnyansky <max_mk@yahoo.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>


#include "interfaces_lib.h"
#include "oor_log.h"
#include "../oor_external.h"



int
create_tun_tap(iface_type_t type, const char *iface_name, int mtu)
{
    struct ifreq ifr;
    int err = 0;
    int tmpsocket = 0;
    int flags = IFF_TAP | IFF_NO_PI; // Create a tunnel without persistence
    char *clonedev = CLONEDEV;
    int receive_fd;

    switch (type){
    case TUN:
        flags = flags | IFF_TUN;
        break;
    case TAP:
        flags = flags | IFF_TAP;
        break;
    default:
        OOR_LOG(LCRIT, "create_tun_tap: Unknown interface type");
        return (BAD);
    }

    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if( (receive_fd = open(clonedev, O_RDWR)) < 0 ) {
        OOR_LOG(LCRIT, "TUN/TAP: Failed to open clone device");
        return(BAD);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    // try to create the device
    if ((err = ioctl(receive_fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(receive_fd);
        OOR_LOG(LCRIT, "TUN/TAP: Failed to create tunnel interface: %s.", strerror(errno));
        if (errno == 16){
            OOR_LOG(LCRIT, "Check no other instance of oor is running. Exiting ...");
        }
        return(BAD);
    }

    // get the ifindex for the tun/tap
    tmpsocket = socket(AF_INET, SOCK_DGRAM, 0); // Dummy socket for the ioctl, type/details unimportant
    if ((err = ioctl(tmpsocket, SIOCGIFINDEX, (void *)&ifr)) < 0) {
        close(receive_fd);
        close(tmpsocket);
        OOR_LOG(LCRIT, "TUN/TAP: unable to determine ifindex for tunnel interface, errno: %d.", errno);
        return(BAD);
    } else {
        OOR_LOG(LDBG_3, "TUN/TAP ifindex is: %d", ifr.ifr_ifindex);

        // Set the MTU to the configured MTU
        ifr.ifr_ifru.ifru_mtu = mtu;
        if ((err = ioctl(tmpsocket, SIOCSIFMTU, &ifr)) < 0) {
            close(tmpsocket);
            OOR_LOG(LCRIT, "TUN/TAP: unable to set interface MTU to %d, errno: %d.", mtu, errno);
            return(BAD);
        } else {
            OOR_LOG(LDBG_1, "TUN/TAP mtu set to %d", mtu);
        }
    }


    close(tmpsocket);

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    OOR_LOG(LDBG_2, "Tunnel fd at creation is %d", receive_fd);

    if (bring_up_iface(iface_name) != GOOD){
        return (BAD);
    }

    return (receive_fd);
}

/*
 * bring_up_iface()
 *
 * Bring up interface
 */
int
bring_up_iface(const char *iface_name)
{
    struct ifinfomsg    *ifi = NULL;
    struct nlmsghdr     *nlh = NULL;
    char                sndbuf[4096];
    int                 retval = 0;
    int                 sockfd = 0;
    int                 ifindex = 0;

    ifindex = if_nametoindex (iface_name);

    sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        OOR_LOG(LERR, "bring_up_iface: Failed to connect to netlink socket");
        return(BAD);
    }

    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);
    nlh = (struct nlmsghdr *)sndbuf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlh->nlmsg_flags = NLM_F_REQUEST | (NLM_F_CREATE | NLM_F_REPLACE);
    nlh->nlmsg_type = RTM_SETLINK;

    ifi = (struct ifinfomsg *)(sndbuf + sizeof(struct nlmsghdr));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_type = IFLA_UNSPEC;
    ifi->ifi_index = ifindex;
    ifi->ifi_flags = IFF_UP | IFF_RUNNING; // Bring it up
    ifi->ifi_change = 0xFFFFFFFF;

    retval = send(sockfd, sndbuf, nlh->nlmsg_len, 0);

    if (retval < 0) {
        OOR_LOG(LERR, "bring_up_iface: send() failed %s", strerror(errno));
        close(sockfd);
        return(BAD);
    }

    OOR_LOG(LDBG_1, "Interface %s UP.", iface_name);
    close(sockfd);
    return(GOOD);
}

/*
 * tun_add_eid_to_iface()
 *
 * Add an EID to the TUN/TAP interface
 */
int
add_addr_to_iface(const char *iface_name, lisp_addr_t *addr)
{
    struct rtattr       *rta = NULL;
    struct ifaddrmsg    *ifa = NULL;
    struct nlmsghdr     *nlh = NULL;
    char                sndbuf[4096];
    int                 retval = 0;
    int                 sockfd = 0;
    int                 ifindex = 0;

    int                 addr_size = 0;
    int                 prefix_length = 0;

    ifindex = if_nametoindex (iface_name);

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        OOR_LOG(LERR, "add_addr_to_iface: Failed to connect to netlink socket");
        return(BAD);
    }

    switch (lisp_addr_ip_afi(addr)){
    case AF_INET:
        addr_size = sizeof(struct in_addr);
        prefix_length = 32;
        break;
    case AF_INET6:
        addr_size = sizeof(struct in6_addr);
        prefix_length = 128;
        break;
    default:
        OOR_LOG(LERR, "add_addr_to_iface: Address no IP address %s",
                lisp_addr_to_char(addr));
        return(BAD);
    }

    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);
    nlh = (struct nlmsghdr *)sndbuf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg) + sizeof(struct rtattr) + addr_size);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_type = RTM_NEWADDR;
    ifa = (struct ifaddrmsg *)(sndbuf + sizeof(struct nlmsghdr));

    ifa->ifa_prefixlen = prefix_length;
    ifa->ifa_family = lisp_addr_ip_afi(addr);
    ifa->ifa_index  = ifindex;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;
    ifa->ifa_flags = 0; // Bring it up

    rta = (struct rtattr *)(sndbuf + sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = sizeof(struct rtattr) + addr_size;
    lisp_addr_copy_to((void *)((char *)rta + sizeof(struct rtattr)),addr);


    retval = send(sockfd, sndbuf, nlh->nlmsg_len, 0);

    if (retval < 0) {
        OOR_LOG(LERR, "add_addr_to_iface: send() failed %s", strerror(errno));
        close(sockfd);
        return(BAD);
    }

    OOR_LOG(LDBG_1, "Added %s to interface %s.",lisp_addr_to_char(addr), iface_name);
    close(sockfd);
    return(GOOD);
}

/*
 * del_addr_from_iface()
 *
 * Remove an EID to the TUN/TAP interface
 */
int
del_addr_from_iface(const char *iface_name, lisp_addr_t *addr)
{
    struct rtattr       *rta = NULL;
    struct ifaddrmsg    *ifa = NULL;
    struct nlmsghdr     *nlh = NULL;
    char                sndbuf[4096];
    int                 retval = 0;
    int                 sockfd = 0;
    int                 ifindex = 0;

    int                 addr_size = 0;
    int                 prefix_length = 0;

    ifindex = if_nametoindex (iface_name);

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        OOR_LOG(LERR, "del_addr_from_iface: Failed to connect to netlink socket");
        return(BAD);
    }

    switch (lisp_addr_ip_afi(addr)){
    case AF_INET:
        addr_size = sizeof(struct in_addr);
        prefix_length = 32;
        break;
    case AF_INET6:
        addr_size = sizeof(struct in6_addr);
        prefix_length = 128;
        break;
    default:
        OOR_LOG(LERR, "del_addr_from_iface: Address no IP address %s",
                lisp_addr_to_char(addr));
        return(BAD);
    }

    /*
     * Build the command
     */
    memset(sndbuf, 0, 4096);
    nlh = (struct nlmsghdr *)sndbuf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg) + sizeof(struct rtattr) + addr_size);
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_type = RTM_DELADDR;
    ifa = (struct ifaddrmsg *)(sndbuf + sizeof(struct nlmsghdr));

    ifa->ifa_prefixlen = prefix_length;
    ifa->ifa_family = lisp_addr_ip_afi(addr);
    ifa->ifa_index  = ifindex;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;
    ifa->ifa_flags = 0; // Bring it up

    rta = (struct rtattr *)(sndbuf + sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = sizeof(struct rtattr) + addr_size;
//    memcopy_lisp_addr((void *)((char *)rta + sizeof(struct rtattr)),&eid_address);
    lisp_addr_copy_to((void *)((char *)rta + sizeof(struct rtattr)),addr);


    retval = send(sockfd, sndbuf, nlh->nlmsg_len, 0);

    if (retval < 0) {
        OOR_LOG(LERR, "del_addr_from_iface: send() failed %s", strerror(errno));
        close(sockfd);
        return(BAD);
    }

    OOR_LOG(LDBG_1, "Removed %s from interface %s.",lisp_addr_to_char(addr), iface_name);
    close(sockfd);
    return(GOOD);
}

