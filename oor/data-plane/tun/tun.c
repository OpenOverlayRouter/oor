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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdarg.h>
#include <unistd.h>
#include "tun.h"
#include "tun_input.h"
#include "tun_output.h"
#include "../data-plane.h"
#include "../../oor_external.h"
#include "../../lib/oor_log.h"
#include "../../lib/routing_tables_lib.h"


int tun_configure_data_plane(oor_dev_type_e dev_type, oor_encap_t encap_type, ...);
void tun_uninit_data_plane();
int tun_add_datap_iface_addr(iface_t *iface,int afi);
int tun_add_eid_prefix(oor_dev_type_e dev_type, lisp_addr_t *eid_prefix);
int tun_remove_eid_prefix(oor_dev_type_e dev_type, lisp_addr_t *eid_prefix);

int configure_routing_to_tun_router(int afi);
//int configure_routing_to_tun_mn(lisp_addr_t *eid_addr);
int remove_routing_to_tun_mn(lisp_addr_t *eid_addr);
int create_tun();
int configure_routing_to_tun_mn(lisp_addr_t *eid_addr);
int tun_bring_up_iface();
int tun_add_eid_to_iface(lisp_addr_t *addr);
int tun_del_eid_from_iface(lisp_addr_t *addr);
int set_tun_default_route_v4();
int del_tun_default_route_v4();
int set_tun_default_route_v6();
int del_tun_default_route_v6();
int tun_updated_route (int command, iface_t *iface, lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway);
int tun_updated_addr(iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr);
int tun_updated_link(iface_t *iface, int old_iface_index, int new_iface_index, int status);
void tun_process_new_gateway(iface_t *iface,lisp_addr_t *gateway);
void tun_process_rm_gateway(iface_t *iface,lisp_addr_t *gateway);

void tun_set_default_output_ifaces();
void tun_iface_remove_routing_rules(iface_t *iface);


data_plane_struct_t dplane_tun = {
        .datap_init = tun_configure_data_plane,
        .datap_uninit = tun_uninit_data_plane,
        .datap_add_iface_addr = tun_add_datap_iface_addr,
        .datap_add_eid_prefix = tun_add_eid_prefix,
        .datap_remove_eid_prefix = tun_remove_eid_prefix,
        .datap_input_packet = tun_process_input_packet,
        .datap_rtr_input_packet = tun_rtr_process_input_packet,
        .datap_output_packet = tun_output_recv,
        .datap_updated_route = tun_updated_route,
        .datap_updated_addr = tun_updated_addr,
        .datap_update_link = tun_updated_link,
        .datap_data = NULL
};


/*
 * tun_configure_data_plane not has variable list of parameters
 */
int
tun_configure_data_plane(oor_dev_type_e dev_type, oor_encap_t encap_type, ...)
{
    int (*cb_func)(sock_t *) = NULL;
    int ipv4_data_input_fd = -1;
    int ipv6_data_input_fd = -1;
    int data_port;
    tun_dplane_data_t *data;

    /* Configure data plane */
    if (create_tun() <= BAD){
        return (BAD);
    }

    switch (dev_type){
    case MN_MODE:
        sockmstr_register_read_listener(smaster, tun_output_recv, NULL,tun_receive_fd);
        cb_func = tun_process_input_packet;
        break;
    case xTR_MODE:
        /* We add route tables for IPv4 and IPv6 even no EID exists for this afi*/
        /* Rules created for EID will redirect traffic to this table*/
        configure_routing_to_tun_router(AF_INET);
        configure_routing_to_tun_router(AF_INET6);
        sockmstr_register_read_listener(smaster, tun_output_recv, NULL,tun_receive_fd);
        cb_func = tun_process_input_packet;
        break;
    case RTR_MODE:
        cb_func = tun_rtr_process_input_packet;
        break;
    default:
        return (BAD);
    }

    switch (encap_type){
    case ENCP_LISP:
        data_port = LISP_DATA_PORT;
        break;
    case ENCP_VXLAN_GPE:
        data_port = VXLAN_GPE_DATA_PORT;
        break;
    }

    /* Generate receive sockets for data port (4341) */
    if (default_rloc_afi != AF_INET6) {
        ipv4_data_input_fd = open_data_raw_input_socket(AF_INET, data_port);
        sockmstr_register_read_listener(smaster, cb_func, NULL,
                ipv4_data_input_fd);
    }

    if (default_rloc_afi != AF_INET) {
        ipv6_data_input_fd = open_data_raw_input_socket(AF_INET6, data_port);
        sockmstr_register_read_listener(smaster, cb_func, NULL,
                ipv6_data_input_fd);
    }
    data = xmalloc(sizeof(tun_dplane_data_t));
    data->encap_type = encap_type;
    dplane_tun.datap_data = (void *)data;
    tun_output_init();

    /* Select the default rlocs for output data packets and output control
     * packets */
    tun_set_default_output_ifaces();

    return (GOOD);

}

void
tun_uninit_data_plane()
{
    tun_dplane_data_t *data = (tun_dplane_data_t *)dplane_tun.datap_data;
    glist_entry_t *iface_it;
    iface_t *iface;

    if (data){
        /* Remove routes associated to each interface */
        glist_for_each_entry(iface_it, interface_list){
            iface = (iface_t *)glist_entry_data(iface_it);
            tun_iface_remove_routing_rules(iface);
        }

        tun_output_uninit();
        free(data);
    }
}

int
tun_add_datap_iface_addr(iface_t *iface, int afi)
{
    int sock;
    lisp_addr_t *addr;
    tun_dplane_data_t *data;
    data = (tun_dplane_data_t *)dplane_tun.datap_data;

    switch (afi){
    case AF_INET:
        addr = iface_address(iface, AF_INET);
        if (addr  && !lisp_addr_is_no_addr(addr)){
            sock = open_ip_raw_socket(AF_INET);
            bind_socket(sock, AF_INET,addr,0);
            add_rule(AF_INET, 0, iface->iface_index, iface->iface_index, RTN_UNICAST,
                    addr, NULL, 0);
            iface->out_socket_v4 = sock;
            if (data && !data->default_out_iface_v4){
                // It will only enter here when adding interfaces after init process
                tun_set_default_output_ifaces();
            }
        }
        break;
    case AF_INET6:
        addr = iface_address(iface, AF_INET6);
        if (addr  && !lisp_addr_is_no_addr(addr)){
            sock = open_ip_raw_socket(AF_INET6);
            bind_socket(sock, AF_INET6, addr, 0);
            add_rule(AF_INET6, 0, iface->iface_index, iface->iface_index, RTN_UNICAST,
                    addr, NULL, 0);
            iface->out_socket_v6 = sock;
            if (data && !data->default_out_iface_v6){
                // It will only enter here when adding interfaces after init process
                tun_set_default_output_ifaces();
            }
        }
        break;
    }

    return (GOOD);
}

int
tun_add_eid_prefix(oor_dev_type_e dev_type, lisp_addr_t *eid_prefix){

    lisp_addr_t *eid_ip_prefix = lisp_addr_get_ip_pref_addr(eid_prefix);

    switch(dev_type){
    case xTR_MODE:
        /* Route to send dtraffic to TUN */
        if (add_rule(lisp_addr_ip_afi(eid_ip_prefix),
                0,
                LISP_TABLE,
                RULE_TO_LISP_TABLE_PRIORITY,
                RTN_UNICAST,
                eid_ip_prefix,
                NULL,0)!=GOOD){
            return (BAD);
        }
        /* Route to avoid to encapsulate traffic destined to the RLOC lan */
        if (add_rule(lisp_addr_ip_afi(eid_ip_prefix),
                0,
                RT_TABLE_MAIN,
                RULE_AVOID_LISP_TABLE_PRIORITY,
                RTN_UNICAST,
                NULL,
                eid_ip_prefix,
                0)!=GOOD){
            return (BAD);
        }
        break;
    case MN_MODE:
        configure_routing_to_tun_mn(eid_ip_prefix);
        break;
    case RTR_MODE:
    default:
        break;
    }
    return (GOOD);
}

int
tun_remove_eid_prefix(oor_dev_type_e dev_type, lisp_addr_t *eid_prefix){
    switch(dev_type){
    case xTR_MODE:
        if (del_rule(lisp_addr_ip_afi(eid_prefix),
                0,
                LISP_TABLE,
                RULE_TO_LISP_TABLE_PRIORITY,
                RTN_UNICAST,
                eid_prefix,
                NULL,0)!=GOOD){
            return (BAD);
        }
        if (del_rule(lisp_addr_ip_afi(eid_prefix),
                0,
                RT_TABLE_MAIN,
                RULE_AVOID_LISP_TABLE_PRIORITY,
                RTN_UNICAST,
                NULL,
                eid_prefix,
                0)!=GOOD){
            return (BAD);
        }
        break;
    case MN_MODE:
        remove_routing_to_tun_mn(eid_prefix);
        break;
    case RTR_MODE:
    default:
        break;
    }
    return (GOOD);
}



int
create_tun()
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
    if( (tun_receive_fd = open(clonedev, O_RDWR)) < 0 ) {
        OOR_LOG(LCRIT, "TUN/TAP: Failed to open clone device");
        return(BAD);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, TUN_IFACE_NAME, IFNAMSIZ - 1);

    // try to create the device
    if ((err = ioctl(tun_receive_fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(tun_receive_fd);
        OOR_LOG(LCRIT, "TUN/TAP: Failed to create tunnel interface, errno: %d.", errno);
        if (errno == 16){
            OOR_LOG(LCRIT, "Check no other instance of oor is running. Exiting ...");
        }
        return(BAD);
    }

    // get the ifindex for the tun/tap
    tmpsocket = socket(AF_INET, SOCK_DGRAM, 0); // Dummy socket for the ioctl, type/details unimportant
    if ((err = ioctl(tmpsocket, SIOCGIFINDEX, (void *)&ifr)) < 0) {
        close(tun_receive_fd);
        close(tmpsocket);
        OOR_LOG(LCRIT, "TUN/TAP: unable to determine ifindex for tunnel interface, errno: %d.", errno);
        return(BAD);
    } else {
        OOR_LOG(LDBG_3, "TUN/TAP ifindex is: %d", ifr.ifr_ifindex);
        tun_ifindex = ifr.ifr_ifindex;

        // Set the MTU to the configured MTU
        ifr.ifr_ifru.ifru_mtu = TUN_MTU;
        if ((err = ioctl(tmpsocket, SIOCSIFMTU, &ifr)) < 0) {
            close(tmpsocket);
            OOR_LOG(LCRIT, "TUN/TAP: unable to set interface MTU to %d, errno: %d.", TUN_MTU, errno);
            return(BAD);
        } else {
            OOR_LOG(LDBG_1, "TUN/TAP mtu set to %d", TUN_MTU);
        }
    }


    close(tmpsocket);

    tun_receive_buf = (uint8_t *)malloc(TUN_RECEIVE_SIZE);

    if (tun_receive_buf == NULL){
        OOR_LOG(LWRN, "create_tun: Unable to allocate memory for tun_receive_buf: %s", strerror(errno));
        return(BAD);
    }

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    OOR_LOG(LDBG_2, "Tunnel fd at creation is %d", tun_receive_fd);

    if (tun_bring_up_iface(TUN_IFACE_NAME) != GOOD){
        return (BAD);
    }

    return (tun_receive_fd);
}

/*
* For mobile node mode, we create two /1 routes covering the full IP addresses space to route all traffic
* generated by the node to the lispTun0 interface
*          IPv4: 0.0.0.0/1 and 128.0.0.0/1
*          IPv6: ::/1      and 8000::/1
*/


int
configure_routing_to_tun_mn(lisp_addr_t *eid_addr)
{

    if (tun_add_eid_to_iface(eid_addr) != GOOD){
        return (BAD);
    }

    switch (lisp_addr_ip_afi(eid_addr)){
    case AF_INET:
        if (set_tun_default_route_v4() != GOOD){
            return (BAD);
        }
        break;
    case AF_INET6:
        if (set_tun_default_route_v6() != GOOD){
            return (BAD);
        }
        break;
    default:
        return (BAD);
        break;
    }

    return (GOOD);
}


/*
* For mobile node mode, we remove two /1 routes covering the full IP addresses space to route all traffic
* generated by the node to the lispTun0 interface
*          IPv4: 0.0.0.0/1 and 128.0.0.0/1
*          IPv6: ::/1      and 8000::/1
*/


int
remove_routing_to_tun_mn(lisp_addr_t *eid_addr)
{
    if (tun_del_eid_from_iface(eid_addr) != GOOD){
        return (BAD);
    }

    switch (lisp_addr_ip_afi(eid_addr)){
    case AF_INET:
        if (del_tun_default_route_v4() != GOOD){
            return (BAD);
        }
        break;
    case AF_INET6:
        if (del_tun_default_route_v6() != GOOD){
            return (BAD);
        }
        break;
    default:
        return (BAD);
        break;
    }

    return (GOOD);
}


/*
* For router mode, add a new routing table with default route to tun interface. Using source routing,
* We send all traffic generated by EIDs to this table.
*/

int
configure_routing_to_tun_router(int afi)
{


    uint32_t    iface_index     = 0;

    iface_index = if_nametoindex(TUN_IFACE_NAME);

    return add_route(afi,iface_index,NULL,NULL,NULL,RULE_TO_LISP_TABLE_PRIORITY,LISP_TABLE);
}



/*
 * tun_bring_up_iface()
 *
 * Bring up interface
 */
int
tun_bring_up_iface()
{
    struct ifinfomsg    *ifi = NULL;
    struct nlmsghdr     *nlh = NULL;
    char                sndbuf[4096];
    int                 retval = 0;
    int                 sockfd = 0;
    int                 tun_ifindex = 0;

    tun_ifindex = if_nametoindex (TUN_IFACE_NAME);

    sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        OOR_LOG(LERR, "tun_add_eid_to_iface: Failed to connect to netlink socket");
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
    ifi->ifi_index = tun_ifindex;
    ifi->ifi_flags = IFF_UP | IFF_RUNNING; // Bring it up
    ifi->ifi_change = 0xFFFFFFFF;

    retval = send(sockfd, sndbuf, nlh->nlmsg_len, 0);

    if (retval < 0) {
        OOR_LOG(LERR, "tun_bring_up_iface: send() failed %s", strerror(errno));
        close(sockfd);
        return(BAD);
    }

    OOR_LOG(LDBG_1, "TUN interface UP.");
    close(sockfd);
    return(GOOD);
}

/*
 * tun_add_eid_to_iface()
 *
 * Add an EID to the TUN/TAP interface
 */
int
tun_add_eid_to_iface(lisp_addr_t *addr)
{
    struct rtattr       *rta = NULL;
    struct ifaddrmsg    *ifa = NULL;
    struct nlmsghdr     *nlh = NULL;
    char                sndbuf[4096];
    int                 retval = 0;
    int                 sockfd = 0;
    int                 tun_ifindex = 0;

    int                 addr_size = 0;
    int                 prefix_length = 0;

    tun_ifindex = if_nametoindex (TUN_IFACE_NAME);

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        OOR_LOG(LERR, "tun_add_eid_to_iface: Failed to connect to netlink socket");
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
        OOR_LOG(LERR, "tun_add_eid_to_iface: Address no IP address %s",
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
    ifa->ifa_index  = tun_ifindex;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;
    ifa->ifa_flags = 0; // Bring it up

    rta = (struct rtattr *)(sndbuf + sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = sizeof(struct rtattr) + addr_size;
    lisp_addr_copy_to((void *)((char *)rta + sizeof(struct rtattr)),addr);


    retval = send(sockfd, sndbuf, nlh->nlmsg_len, 0);

    if (retval < 0) {
        OOR_LOG(LERR, "tun_add_eid_to_iface: send() failed %s", strerror(errno));
        close(sockfd);
        return(BAD);
    }

    OOR_LOG(LDBG_1, "added %s EID to TUN interface.",lisp_addr_to_char(addr));
    close(sockfd);
    return(GOOD);
}


/*
 * tun_add_eid_to_iface()
 *
 * Remove an EID to the TUN/TAP interface
 */
int
tun_del_eid_from_iface(lisp_addr_t *addr)
{
    struct rtattr       *rta = NULL;
    struct ifaddrmsg    *ifa = NULL;
    struct nlmsghdr     *nlh = NULL;
    char                sndbuf[4096];
    int                 retval = 0;
    int                 sockfd = 0;
    int                 tun_ifindex = 0;

    int                 addr_size = 0;
    int                 prefix_length = 0;

    tun_ifindex = if_nametoindex (TUN_IFACE_NAME);

    sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

    if (sockfd < 0) {
        OOR_LOG(LERR, "tun_del_eid_from_iface: Failed to connect to netlink socket");
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
        OOR_LOG(LERR, "tun_del_eid_from_iface: Address no IP address %s",
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
    ifa->ifa_index  = tun_ifindex;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;
    ifa->ifa_flags = 0; // Bring it up

    rta = (struct rtattr *)(sndbuf + sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = sizeof(struct rtattr) + addr_size;
//    memcopy_lisp_addr((void *)((char *)rta + sizeof(struct rtattr)),&eid_address);
    lisp_addr_copy_to((void *)((char *)rta + sizeof(struct rtattr)),addr);


    retval = send(sockfd, sndbuf, nlh->nlmsg_len, 0);

    if (retval < 0) {
        OOR_LOG(LERR, "tun_del_eid_from_iface: send() failed %s", strerror(errno));
        close(sockfd);
        return(BAD);
    }

    OOR_LOG(LDBG_1, "Removed %s EID from TUN interface.",lisp_addr_to_char(addr));
    close(sockfd);
    return(GOOD);
}

int
set_tun_default_route_v4()
{

    /*
     * Assign route to 0.0.0.0/1 and 128.0.0.0/1 via tun interface
     */
    lisp_addr_t dest;
    lisp_addr_t *src = NULL;
    uint32_t metric = 0;

    metric = 0;

    lisp_addr_ippref_from_char("0.0.0.0/1",&dest);

    add_route(AF_INET,
            tun_ifindex,
            &dest,
            src,
            NULL,
            metric,
            RT_TABLE_MAIN);

    lisp_addr_ippref_from_char("128.0.0.0/1",&dest);

    add_route(AF_INET,
            tun_ifindex,
            &dest,
            src,
            NULL,
            metric,
            RT_TABLE_MAIN);
    return(GOOD);


}

int
del_tun_default_route_v4()
{

    /*
     * Assign route to 0.0.0.0/1 and 128.0.0.0/1 via tun interface
     */
    lisp_addr_t dest;
    lisp_addr_t *src = NULL;
    uint32_t metric = 0;

    metric = 0;

    lisp_addr_ippref_from_char("0.0.0.0/1",&dest);

    del_route(AF_INET,
            tun_ifindex,
            &dest,
            src,
            NULL,
            metric,
            RT_TABLE_MAIN);

    lisp_addr_ippref_from_char("128.0.0.0/1",&dest);

    del_route(AF_INET,
            tun_ifindex,
            &dest,
            src,
            NULL,
            metric,
            RT_TABLE_MAIN);
    return(GOOD);


}

int
set_tun_default_route_v6()
{

    /*
     * Assign route to ::/1 and 8000::/1 via tun interface
     */

    lisp_addr_t dest;
    lisp_addr_t *src = NULL;
    uint32_t metric = 0;

    metric = 512;

    lisp_addr_ippref_from_char("::/1",&dest);

    add_route(AF_INET6,
            tun_ifindex,
            &dest,
            src,
            NULL,
            metric,
            RT_TABLE_MAIN);

    lisp_addr_ippref_from_char("8000::/1",&dest);

    add_route(AF_INET6,
            tun_ifindex,
            &dest,
            src,
            NULL,
            metric,
            RT_TABLE_MAIN);

    return(GOOD);
}

int
del_tun_default_route_v6()
{
    /*
     * Assign route to ::/1 and 8000::/1 via tun interface
     */

    lisp_addr_t dest;
    lisp_addr_t *src    = NULL;
    lisp_addr_t *gw     = NULL;
    uint32_t metric     = 0;

    metric = 512;


    lisp_addr_ippref_from_char("::/1",&dest);

    del_route(AF_INET6,
            tun_ifindex,
            &dest,
            src,
            gw,
            metric,
            RT_TABLE_MAIN);

    lisp_addr_ippref_from_char("8000::/1",&dest);

    del_route(AF_INET6,
            tun_ifindex,
            &dest,
            src,
            gw,
            metric,
            RT_TABLE_MAIN);

    return(GOOD);
}

int
tun_updated_route (int command, iface_t *iface, lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    /* We check if the new route message contains a destination. If
     * it is, then the gateway address is not a default route.
     * Discard it */

    if (command == RTM_NEWROUTE){
        if (lisp_addr_ip_afi(gateway) != LM_AFI_NO_ADDR
                && lisp_addr_ip_afi(dst_pref) == LM_AFI_NO_ADDR) {

            /* Check if the addres is a global address*/
            if (ip_addr_is_link_local(lisp_addr_ip(gateway)) == TRUE) {
                OOR_LOG(LDBG_3,"tun_update_route: the extractet address "
                        "from the netlink messages is a local link address: %s "
                        "discarded", lisp_addr_to_char(gateway));
                return (GOOD);
            }

            /* Process the new gateway */
            OOR_LOG(LDBG_1,  "tun_update_route: Process new gateway "
                    "associated to the interface %s:  %s", iface->iface_name,
                    lisp_addr_to_char(gateway));
            tun_process_new_gateway(iface,gateway);
        }
    }else{
        if (lisp_addr_ip_afi(gateway) != LM_AFI_NO_ADDR
                && lisp_addr_ip_afi(dst_pref) == LM_AFI_NO_ADDR) {

            /* Check if the addres is a global address*/
            if (ip_addr_is_link_local(lisp_addr_ip(gateway)) == TRUE) {
                OOR_LOG(LDBG_3,"tun_update_route: the extractet address "
                        "from the netlink messages is a local link address: %s "
                        "discarded", lisp_addr_to_char(gateway));
                return (GOOD);
            }

            /* Process the new gateway */
            OOR_LOG(LDBG_1,  "tun_update_route: Process remove gateway "
                    "associated to the interface %s:  %s", iface->iface_name,
                    lisp_addr_to_char(gateway));
            tun_process_rm_gateway(iface,gateway);
        }
    }

    return (GOOD);
}

int
tun_updated_addr(iface_t *iface, lisp_addr_t *old_addr, lisp_addr_t *new_addr)
{
    int old_addr_lafi, new_addr_ip_afi;
    int sckt;
    lisp_addr_t *iface_addr;
    tun_dplane_data_t *data;

    data = (tun_dplane_data_t *)dplane_tun.datap_data;
    old_addr_lafi = lisp_addr_lafi(old_addr);
    new_addr_ip_afi = lisp_addr_ip_afi(new_addr);

    /* Check if the detected change of address id the same. */
    if (lisp_addr_cmp(old_addr, new_addr) == 0) {
        OOR_LOG(LDBG_2, "tun_updated_addr: The change of address detected "
                "for interface %s doesn't affect", iface->iface_name);
        /* We must rebind the socket just in case the address is from a
         * virtual interface which has changed its interface number */
        switch (new_addr_ip_afi) {
        case AF_INET:
            bind_socket(iface->out_socket_v4, AF_INET, new_addr, 0);
            break;
        case AF_INET6:
            bind_socket(iface->out_socket_v6, AF_INET6,  new_addr, 0);
            break;
        }

        return (GOOD);
    };

    /* If interface was down during initial configuration process and now it
     * is up. Create sockets */
    if (old_addr_lafi == LM_AFI_NO_ADDR) {
        OOR_LOG(LDBG_2, "tun_updated_addr: Generating sockets for the initialized interface "
                "%s", lisp_addr_to_char(new_addr));

        switch(new_addr_ip_afi){
        case AF_INET:
            iface->out_socket_v4 = open_ip_raw_socket(AF_INET);
            sckt = iface->out_socket_v4;
            iface_addr = iface->ipv4_address;
            break;
        case AF_INET6:
            iface->out_socket_v6 = open_ip_raw_socket(AF_INET6);
            sckt = iface->out_socket_v6;
            iface_addr = iface->ipv6_address;
            break;
        }

        if (iface->status == UP) {
            /* If no default control interface, recalculate it */
            if ((data->default_out_iface_v4 == NULL && new_addr_ip_afi == AF_INET) ||
                    (data->default_out_iface_v6 == NULL && new_addr_ip_afi == AF_INET6)) {
                OOR_LOG(LDBG_2, "No default output interface. Recalculate new "
                        "output interface");
                tun_set_default_output_ifaces();
            }
        }

    }else{
        switch(new_addr_ip_afi){
        case AF_INET:
            sckt = iface->out_socket_v4;
            iface_addr = iface->ipv4_address;
            break;
        case AF_INET6:
            sckt = iface->out_socket_v6;
            iface_addr = iface->ipv6_address;
            break;
        }

        del_rule(new_addr_ip_afi, 0, iface->iface_index, iface->iface_index, RTN_UNICAST,
                old_addr, NULL, 0);
    }
    /* Rebind socket and add new routing */
    add_rule(new_addr_ip_afi, 0, iface->iface_index, iface->iface_index, RTN_UNICAST,
            new_addr, NULL, 0);

    bind_socket(sckt, new_addr_ip_afi, new_addr,0);

    lisp_addr_copy(iface_addr, new_addr);

    return (GOOD);
}

int
tun_updated_link(iface_t *iface, int old_iface_index, int new_iface_index,
        int status)
{
    tun_dplane_data_t *data;
    data = (tun_dplane_data_t *)dplane_tun.datap_data;

    /* In some OS when a virtual interface is removed and added again,
     * the index of the interface change. Search iface_t by the interface
     * name and update the index. */
    if (old_iface_index != new_iface_index){
        iface->iface_index = new_iface_index;
        OOR_LOG(LDBG_2, "process_nl_new_link: The new index of the interface "
                "%s is: %d. Updating tables", iface->iface_name,
                iface->iface_index);

        /* Update routing tables and reopen sockets*/
        if (iface->ipv4_address && !lisp_addr_is_no_addr(iface->ipv4_address)) {
            del_rule(AF_INET, 0, old_iface_index, old_iface_index,
                    RTN_UNICAST, iface->ipv4_address, NULL, 0);
            add_rule(AF_INET, 0, new_iface_index, new_iface_index, RTN_UNICAST,
                    iface->ipv4_address, NULL, 0);
            close(iface->out_socket_v4);
            iface->out_socket_v4 = open_ip_raw_socket( AF_INET);
            bind_socket(iface->out_socket_v4, AF_INET, iface->ipv4_address, 0);
        }
        if (iface->ipv6_address && !lisp_addr_is_no_addr(iface->ipv6_address)) {
            del_rule(AF_INET6, 0, old_iface_index, old_iface_index,
                    RTN_UNICAST, iface->ipv6_address, NULL, 0);
            add_rule(AF_INET6, 0, new_iface_index, new_iface_index, RTN_UNICAST,
                    iface->ipv6_address, NULL, 0);
            close(iface->out_socket_v6);
            iface->out_socket_v6 = open_ip_raw_socket(AF_INET6);
            bind_socket(iface->out_socket_v6,AF_INET6, iface->ipv6_address, 0);
        }
    }

    /* Change status of the interface */
    iface->status = status;

    if (data->default_out_iface_v4 == iface
            || data->default_out_iface_v6 == iface
            || data->default_out_iface_v4 == NULL
            || data->default_out_iface_v6 == NULL){
        OOR_LOG(LDBG_2,"Default output interface down. Recalculate new output "
                "interface");
        tun_set_default_output_ifaces();
    }

    return (GOOD);
}



void
tun_process_new_gateway(iface_t *iface,lisp_addr_t *gateway)
{
    lisp_addr_t **gw_addr = NULL;
    int afi = LM_AFI_NO_ADDR;
    int route_metric = 100;

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
    }else if (lisp_addr_cmp(*gw_addr, gateway) == 0){
        OOR_LOG(LDBG_3,"tun_process_new_gateway: the gatweay address has not changed: %s. Discard message.",
                            lisp_addr_to_char(gateway));
        return;
    }else{
        lisp_addr_copy(*gw_addr,gateway);
    }

    add_route(afi,iface->iface_index,NULL,NULL,gateway,route_metric,iface->iface_index);
}

void
tun_process_rm_gateway(iface_t *iface,lisp_addr_t *gateway)
{
    lisp_addr_t **gw_addr = NULL;
    int afi = LM_AFI_NO_ADDR;
    int route_metric = 100;

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

    del_route(afi,iface->iface_index,NULL,NULL,gateway,route_metric,iface->iface_index);
    lisp_addr_del(*gw_addr);
    *gw_addr = NULL;
}


void
tun_set_default_output_ifaces()
{
    tun_dplane_data_t *data;
    data = (tun_dplane_data_t *)dplane_tun.datap_data;

    data->default_out_iface_v4 = get_any_output_iface(AF_INET);

    if (data->default_out_iface_v4 != NULL) {
       OOR_LOG(LDBG_2,"Default IPv4 data iface %s: %s\n",data->default_out_iface_v4->iface_name,
               lisp_addr_to_char(data->default_out_iface_v4->ipv4_address));
    }

    data->default_out_iface_v6 = get_any_output_iface(AF_INET6);
    if (data->default_out_iface_v6 != NULL) {
       OOR_LOG(LDBG_2,"Default IPv6 data iface %s: %s\n", data->default_out_iface_v6->iface_name,
               lisp_addr_to_char(data->default_out_iface_v6->ipv6_address));
    }

    if (!data->default_out_iface_v4 && !data->default_out_iface_v6){
        OOR_LOG(LCRIT,"NO OUTPUT IFACE: all the locators are down");
    }
}

lisp_addr_t *
tun_get_default_output_address(int afi)
{
    lisp_addr_t *addr = NULL;
    tun_dplane_data_t *data;
    data = (tun_dplane_data_t *)dplane_tun.datap_data;

    switch (afi) {
    case AF_INET:
        if (data->default_out_iface_v4 != NULL) {
            addr = data->default_out_iface_v4->ipv4_address;
        }
        break;
    case AF_INET6:
        if (data->default_out_iface_v6 != NULL) {
            addr = data->default_out_iface_v6->ipv6_address;
        }
        break;
    default:
        OOR_LOG(LDBG_2, "tun_get_default_output_address: AFI %s not valid", afi);
        return(NULL);
    }

    return(addr);
}

int
tun_get_default_output_socket(int afi)
{
    int out_socket = ERR_SOCKET;
    tun_dplane_data_t *data;
    data = (tun_dplane_data_t *)dplane_tun.datap_data;

    switch (afi) {
    case AF_INET:
        if (data->default_out_iface_v4 != NULL) {
            out_socket = data->default_out_iface_v4->out_socket_v4;
        }
        break;
    case AF_INET6:
        if (data->default_out_iface_v6 != NULL) {
            out_socket = data->default_out_iface_v6->out_socket_v6;
        }
        break;
    default:
        OOR_LOG(LDBG_2, "tun_get_default_output_socket: AFI %s not valid", afi);
        break;
    }

    return (out_socket);
}


void
tun_iface_remove_routing_rules(iface_t *iface)
{
    if (iface->ipv4_address && !lisp_addr_is_no_addr(iface->ipv4_address)) {
        if (iface->ipv4_gateway != NULL) {
            del_route(AF_INET, iface->iface_index, NULL, NULL,
                    iface->ipv4_gateway, 0, iface->iface_index);
        }

        del_rule(AF_INET, 0, iface->iface_index, iface->iface_index,
                RTN_UNICAST, iface->ipv4_address, NULL, 0);
    }
    if (iface->ipv6_address && !lisp_addr_is_no_addr(iface->ipv6_address)) {
        if (iface->ipv6_gateway != NULL) {
            del_route(AF_INET6, iface->iface_index, NULL, NULL,
                    iface->ipv6_gateway, 0, iface->iface_index);
        }
        del_rule(AF_INET6, 0, iface->iface_index, iface->iface_index,
                RTN_UNICAST, iface->ipv6_address, NULL, 0);
    }
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
