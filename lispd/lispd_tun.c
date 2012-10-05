#include "lispd_tun.h"


int create_tun(char *tun_dev_name,
		      unsigned int tun_receive_size,
		      int tun_mtu,
		      int *tun_receive_fd,
		      int *tun_ifindex,
		      char **tun_receive_buf) {

    struct ifreq ifr;
    int err, tmpsocket, flags = IFF_TUN | IFF_NO_PI; // Create a tunnel without persistence
    char *clonedev = CLONEDEV;


    /* Arguments taken by the function:
     *
     * char *dev: the name of an interface (or '\0'). MUST have enough
     *   space to hold the interface name if '\0' is passed
     * int flags: interface flags (eg, IFF_TUN etc.)
     */

    /* open the clone device */
    if( (*tun_receive_fd = open(clonedev, O_RDWR)) < 0 ) {
        syslog(LOG_DAEMON, "TUN/TAP: Failed to open clone device");
        return(0);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, tun_dev_name, IFNAMSIZ);

    // try to create the device
    if ((err = ioctl(*tun_receive_fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(*tun_receive_fd);
        syslog(LOG_DAEMON, "TUN/TAP: Failed to create tunnel interface, errno: %d.", errno);
        return(0);
    }

    // get the ifindex for the tun/tap
    tmpsocket = socket(AF_INET, SOCK_DGRAM, 0); // Dummy socket for the ioctl, type/details unimportant
    if ((err = ioctl(tmpsocket, SIOCGIFINDEX, (void *)&ifr)) < 0) {
        close(*tun_receive_fd);
        close(tmpsocket);
        syslog(LOG_DAEMON, "TUN/TAP: unable to determine ifindex for tunnel interface, errno: %d.", errno);
        return(0);
    } else {
        syslog(LOG_DAEMON, "TUN/TAP ifindex is: %d", ifr.ifr_ifindex);
        *tun_ifindex = ifr.ifr_ifindex;

        // Set the MTU to the configured MTU
        ifr.ifr_ifru.ifru_mtu = tun_mtu;
        if ((err = ioctl(tmpsocket, SIOCSIFMTU, &ifr)) < 0) {
            close(tmpsocket);
            syslog(LOG_DAEMON, "TUN/TAP: unable to set interface MTU to %d, errno: %d.", tun_mtu, errno);
            return(0);
        } else {
            syslog(LOG_DAEMON, "TUN/TAP mtu set to %d", tun_mtu);
        }
    }

    close(tmpsocket);

    *tun_receive_buf = (char *)malloc(tun_receive_size);
    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    syslog(LOG_DAEMON, "tunnel fd at creation is %d", *tun_receive_fd);

    /*
    
    if (!tuntap_set_eids()) {
        return(FALSE);
    }

    if (!tuntap_install_default_routes()) {
        return(FALSE);
    }*/
    
    return(1);
}



/*
 * tuntap_set_v4_eid
 *
 * Assign an ipv4 EID to the TUN/TAP interface
 */
int tun_set_v4_eid(lisp_addr_t eid_address_v4,
		      char *tun_dev_name)
{
    struct ifreq ifr;
    struct sockaddr_in *sp;
    int    netsock, err;

    netsock = socket(eid_address_v4.afi, SOCK_DGRAM, 0);
    if (netsock < 0) {
        syslog(LOG_DAEMON, "assign: socket() %s", strerror(errno));
        return(0);
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
        syslog(LOG_DAEMON, "TUN/TAP could not set EID on tun device, errno %d.",
                errno);
        return(0);
    }
    sp->sin_addr.s_addr = 0xFFFFFFFF;
    if ((err = ioctl(netsock, SIOCSIFNETMASK, &ifr)) < 0) {
        syslog(LOG_DAEMON, "TUN/TAP could not set netmask on tun device, errno %d",
                errno);
        return(0);
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING; // Bring it up

    if ((err = ioctl(netsock, SIOCSIFFLAGS, &ifr)) < 0) {
        syslog(LOG_DAEMON, "TUN/TAP could not bring up tun device, errno %d.",
                errno);
        return(0);
    }
    close(netsock);
    return(1);
}

/*
 * tuntap_set_v6_eid()
 *
 * Assign an ipv6 EID to the TUN/TAP interface
 */
int tun_set_v6_eid(lisp_addr_t eid_address_v6,
		      char *tun_dev_name,
		      int tun_ifindex)
{
    struct rtattr       *rta;
    struct ifaddrmsg    *ifa;
    struct nlmsghdr     *nlh;
    char                 sndbuf[4096];
    int                  retval;
    int                  sockfd;

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        syslog(LOG_DAEMON, "Failed to connect to netlink socket for install_host_route()");
        return(0);
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
        syslog(LOG_DAEMON, "tuntap_set_v6_eid: send() failed %s", strerror(errno));
        close(sockfd);
        return(0);
    }

    syslog(LOG_DAEMON, "added ipv6 EID to TUN interface.");
    close(sockfd);
    return(1);
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
