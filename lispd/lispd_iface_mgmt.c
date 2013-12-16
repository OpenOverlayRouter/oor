/*
 * lispd_iface_mgmt.c
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
 *
 */
#include "lispd_external.h"
#include "lispd_iface_mgmt.h"
#include "lispd_info_request.h"
#include "lispd_lib.h"
#include "lispd_log.h"
#include "lispd_mapping.h"
#include "lispd_routing_tables_lib.h"
#include "lispd_smr.h"
#include "lispd_sockets.h"
#include "lispd_timers.h"
#include "lispd_tun.h"
#include "defs_re.h"

/************************* FUNCTION DECLARTAION ********************************/

void process_nl_add_address (struct nlmsghdr *nlh);
void process_nl_del_address (struct nlmsghdr *nlh);
void process_nl_new_link (struct nlmsghdr *nlh);
void process_nl_new_route (struct nlmsghdr *nlh);
void process_nl_new_unicast_route (struct rtmsg *rtm, int rt_length);
void process_nl_new_multicast_route (struct rtmsg *rtm, int rt_length);
void process_nl_del_route (struct nlmsghdr *nlh);
void process_nl_del_multicast_route (struct rtmsg *rtm, int rt_length);
int  process_nl_multicast_route_attributes (struct rtmsg *rtm, int rt_length, ip_addr_t *src, ip_addr_t *grp);

/*
 * Change the address of the interface. If the address belongs to a not initialized locator, activate it.
 * Program SMR
 */

void process_address_change (
        lispd_iface_elt     *iface,
        lisp_addr_t         new_addr);


/*
 * Change the satus of the interface. Recalculate default control and output interfaces if it's needed.
 * Program SMR
 */

void process_link_status_change(
        lispd_iface_elt     *iface,
        int                 new_status);

/*
 *
 */

void process_new_gateway (
        lisp_addr_t         gateway,
        lispd_iface_elt     *iface );
/*
 * Activate the locators associated with the interface using the new address
 * This function is only used when an interface is down during the initial configuration process and then is activated
 */
void activate_interface_address(lispd_iface_elt *iface,lisp_addr_t new_address);


/*******************************************************************************/

int opent_netlink_socket()
{
    int netlink_fd          = 0;
    struct sockaddr_nl addr;


    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_MROUTE | RTMGRP_IPV6_MROUTE;

    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

    if (netlink_fd < 0) {
        lispd_log_msg(LISP_LOG_ERR, "opent_netlink_socket: Failed to connect to netlink socket");
        return(BAD);
    }

    bind(netlink_fd, (struct sockaddr *) &addr, sizeof(addr));

    return (netlink_fd);
}

void process_netlink_msg(int netlink_fd){
    int                 len             = 0;
    char                buffer[4096];
    struct iovec        iov;
    struct sockaddr_nl  dst_addr;
    struct msghdr       msgh;
    struct nlmsghdr     *nlh    = NULL;

    nlh = (struct nlmsghdr *)buffer;

    memset(&iov, 0, sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len = sizeof(nlh);

    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_name = (void *)&(dst_addr);
    msgh.msg_namelen = sizeof(dst_addr);
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    while ((len = recv (netlink_fd,nlh,4096,MSG_DONTWAIT)) > 0){
        for (;(NLMSG_OK (nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE); nlh = NLMSG_NEXT(nlh, len)){
            switch(nlh->nlmsg_type){
            case RTM_NEWADDR:
                lispd_log_msg(LISP_LOG_DEBUG_2, "=>process_netlink_msg: Received new address message");
                process_nl_add_address (nlh);
                break;
            case RTM_DELADDR:
                lispd_log_msg(LISP_LOG_DEBUG_2, "=>process_netlink_msg: Received del address message");
                process_nl_del_address (nlh);
                break;
            case RTM_NEWLINK:
                lispd_log_msg(LISP_LOG_DEBUG_2, "=>process_netlink_msg: Received link message");
                process_nl_new_link (nlh);
                break;
            case RTM_NEWROUTE:
                lispd_log_msg(LISP_LOG_DEBUG_2, "=>process_netlink_msg: Received new route message");
                process_nl_new_route (nlh);
                break;
            case RTM_DELROUTE:
                lispd_log_msg(LISP_LOG_DEBUG_2, "=>process_netlink_msg: Received delete route message");
                process_nl_del_route (nlh);
                break;
            default:
                break;

            }
        }
        nlh = (struct nlmsghdr *)buffer;
        memset(nlh,0,4096);
    }

    return;
}


void process_nl_add_address (struct nlmsghdr *nlh)
{
    struct ifaddrmsg            *ifa                = NULL;
    struct rtattr               *rth                = NULL;
    int                         iface_index         = 0;
    int                         rt_length           = 0;
    lispd_iface_elt             *iface              = NULL;
    lisp_addr_t                 new_addr;
    char                        iface_name[IF_NAMESIZE];

    /*
     * Get the new address from the net link message
     */
    ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);
    iface_index = ifa->ifa_index;

    iface = get_interface_from_index(iface_index);

    if (iface == NULL){
        if_indextoname(iface_index, iface_name);
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_nl_add_address: the netlink message is not for any interface associated with RLOCs  (%s / %d)",
                iface_name, iface_index);
        return;
    }
    rth = IFA_RTA (ifa);

    rt_length = IFA_PAYLOAD (nlh);
    for (;rt_length && RTA_OK (rth, rt_length); rth = RTA_NEXT (rth,rt_length))
    {
        if (rth->rta_type == IFA_ADDRESS){
            if (ifa->ifa_family == AF_INET){
                memcpy (&(new_addr.address),(struct in_addr *)RTA_DATA(rth),sizeof(struct in_addr));
                new_addr.afi = AF_INET;
            }else if (ifa->ifa_family == AF_INET6){
                memcpy (&(new_addr.address),(struct in6_addr *)RTA_DATA(rth),sizeof(struct in6_addr));
                new_addr.afi = AF_INET6;
            }
            process_address_change (iface, new_addr);
        }
    }
}

/*
 * Change the address of the interface. If the address belongs to a not initialized locator, activate it.
 * Program SMR
 */

void process_address_change (
        lispd_iface_elt     *iface,
        lisp_addr_t         new_addr)
{
    lisp_addr_t                 *iface_addr         = NULL;
    lispd_iface_mappings_list   *mapping_list       = NULL;
    int                         aux_afi             = 0;

    // XXX To be modified when full NAT implemented --> When Nat Aware active no IPv6 RLOCs supported
    if (nat_aware == TRUE && new_addr.afi == AF_INET6){
        return;
    }

    /* Check if the addres is a global address*/
    if (is_link_local_addr(new_addr) == TRUE){
        lispd_log_msg(LISP_LOG_DEBUG_2,"precess_address_change: the extractet address from the netlink "
                "messages is a local link address: %s discarded", get_char_from_lisp_addr_t(new_addr));
        return;
    }
    /* If default RLOC afi defined (-a 4 or 6), only accept addresses of the specified afi */
    if (default_rloc_afi != -1 && default_rloc_afi != new_addr.afi){
        lispd_log_msg(LISP_LOG_DEBUG_2,"precess_address_change: Default RLOC afi defined (-a #): Skipped %s address in iface %s",
                (new_addr.afi == AF_INET) ? "IPv4" : "IPv6",iface->iface_name);
        return;
    }
    /*
     * Actions to be done due to a change of address: SMR
     */

    switch (new_addr.afi){
    case AF_INET:
        iface_addr = iface->ipv4_address;
        break;
    case AF_INET6:
        iface_addr = iface->ipv6_address;
        break;
    }

    // Same address that we already have
    if (compare_lisp_addr_t(iface_addr,&new_addr)==0){
        lispd_log_msg(LISP_LOG_DEBUG_2,"precess_address_change: The detected change of address for interface %s "
                "doesn't affect",iface->iface_name);
        /* We must rebind the socket just in case the address is from a virtual interface who has changed its interafce number */
        switch (new_addr.afi){
        case AF_INET:
            bind_socket_src_address(iface->out_socket_v4,&new_addr);
            break;
        case AF_INET6:
            bind_socket_src_address(iface->out_socket_v6,&new_addr);
            break;
        }

        return;
    }

    /*
     * Change source routing rules for this interface and binding
     */

    if (iface_addr->afi != AF_UNSPEC){
        del_rule(iface_addr->afi,
                0,
                iface->iface_index,
                iface->iface_index,
                RTN_UNICAST,
                iface_addr,
                (iface_addr->afi == AF_INET) ? 32 : 128,
                NULL,0,0);
    }
    add_rule(new_addr.afi,
            0,
            iface->iface_index,
            iface->iface_index,
            RTN_UNICAST,
            &new_addr,
            (new_addr.afi == AF_INET) ? 32 : 128,
            NULL,0,0);

    switch (new_addr.afi){
    case AF_INET:
        bind_socket_src_address(iface->out_socket_v4,&new_addr);
        break;
    case AF_INET6:
        bind_socket_src_address(iface->out_socket_v6,&new_addr);
        break;
    }


    aux_afi = iface_addr->afi;
    // Update the new address
    copy_lisp_addr(iface_addr, &new_addr);


    /* The interface was down during initial configuratiopn process and now it is up. Activate address */
    if (aux_afi == AF_UNSPEC){
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_address_change: Activating the locator address %s"
                , get_char_from_lisp_addr_t(new_addr));
        activate_interface_address(iface, new_addr);
        if (iface->status == UP){
            iface_balancing_vectors_calc(iface);

            /*
             * If no default control and data interface, recalculate it
             */

            if ((default_ctrl_iface_v4 == NULL && new_addr.afi == AF_INET) ||
                    (default_ctrl_iface_v6 == NULL && new_addr.afi == AF_INET6)){
                lispd_log_msg(LISP_LOG_DEBUG_2,"No default control interface. Recalculate new control interface");
                set_default_ctrl_ifaces();
            }

            if ((default_out_iface_v4 == NULL && new_addr.afi == AF_INET) ||
                    (default_out_iface_v6 == NULL && new_addr.afi == AF_INET6)){
                lispd_log_msg(LISP_LOG_DEBUG_2,"No default output interface. Recalculate new output interface");
                set_default_output_ifaces();
            }
        }
    }

    lispd_log_msg(LISP_LOG_DEBUG_1,"precess_address_change: New address detected for interface %s -> %s",
            iface->iface_name, get_char_from_lisp_addr_t(new_addr));

    mapping_list = iface->head_mappings_list;
    /* Sort again the locators list of the affected mappings*/
    while (mapping_list != NULL){
        if (aux_afi != AF_UNSPEC && // When the locator is activated, it is automatically sorted
                ((new_addr.afi == AF_INET && mapping_list->use_ipv4_address == TRUE) ||
                        (new_addr.afi == AF_INET6 && mapping_list->use_ipv6_address == TRUE))){
            sort_locators_list_elt (mapping_list->mapping, iface_addr);
        }
        mapping_list = mapping_list->next;
    }

    /* Indicate change of address in the interface */

    switch (new_addr.afi){
    case AF_INET:
        iface->ipv4_changed = TRUE;
        break;
    case AF_INET6:
        iface->ipv6_changed = TRUE;
        break;
    }


    /* If it is compiled in router mode, then recompile default routes changing the indicated src address*/

#ifdef ROUTER
    switch (new_addr.afi){
    case AF_INET:
        if (iface == default_out_iface_v4){
            set_tun_default_route_v4();
        }
        break;
    case AF_INET6:
        if (iface == default_out_iface_v6){
            del_tun_default_route_v6();
            set_tun_default_route_v6();
        }
        break;
    }
#endif

    /* Check if the new address is behind NAT */

    if(nat_aware==TRUE){
        // TODO : To be modified when implementing NAT per multiple interfaces
        nat_status = UNKNOWN;
        if (iface->status == UP){
            initial_info_request_process();
        }
    }

    /* Reprograming SMR timer*/
    if (smr_timer == NULL){
        smr_timer = create_timer (SMR_TIMER);
    }

    start_timer(smr_timer, LISPD_SMR_TIMEOUT,(timer_callback)init_smr, NULL);
}


void process_nl_del_address (struct nlmsghdr *nlh)
{
    struct ifaddrmsg    *ifa            = NULL;
    struct rtattr       *rth            = NULL;
    int                 iface_index     = 0;
    int                 rt_length       = 0;
    lispd_iface_elt     *iface          = NULL;
    lisp_addr_t         new_addr;
    char                iface_name[IF_NAMESIZE];

    ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);
    iface_index = ifa->ifa_index;

    iface = get_interface_from_index(iface_index);

    if (iface == NULL){
        if_indextoname(iface_index, iface_name);
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_nl_add_address: the netlink message is not for any interface associated with RLOCs (%s)",
                iface_name);
        return;
    }
    rth = IFA_RTA (ifa);

    rth = IFA_RTA (ifa);
    rt_length = IFA_PAYLOAD (nlh);
    for (;rt_length && RTA_OK (rth, rt_length); rth = RTA_NEXT (rth,rt_length))
    {
        if (rth->rta_type == IFA_ADDRESS){
            if (ifa->ifa_family == AF_INET){
                memcpy (&(new_addr.address),(struct in_addr *)RTA_DATA(rth),sizeof(struct in_addr));
                new_addr.afi = AF_INET;
            }else if (ifa->ifa_family == AF_INET6){
                memcpy (&(new_addr.address),(struct in6_addr *)RTA_DATA(rth),sizeof(struct in6_addr));
                new_addr.afi = AF_INET6;
            }
            break;
        }
    }
    /* Actions to be done when address is removed */
    lispd_log_msg(LISP_LOG_DEBUG_2,"   deleted address: %s\n", get_char_from_lisp_addr_t(new_addr));
}

void process_nl_new_link (struct nlmsghdr *nlh)
{
    struct ifinfomsg                    *ifi            = NULL;
    lispd_iface_elt                     *iface          = NULL;
    int                                 iface_index     = 0;
    uint8_t                             status          = UP;
    char                                iface_name[IF_NAMESIZE];
    uint32_t                            old_iface_index = 0;

    ifi = (struct ifinfomsg *) NLMSG_DATA (nlh);
    iface_index = ifi->ifi_index;


    iface = get_interface_from_index(iface_index);

    if (iface == NULL){
        /*
         * In some OS when a virtual interface is removed and added again, the index of the interface change.
         * Search lispd_iface_elt by the interface name and update the index.
         */
        if (if_indextoname(iface_index, iface_name) != NULL){
            iface = get_interface(iface_name);
        }
        if (iface == NULL){
            lispd_log_msg(LISP_LOG_DEBUG_2, "process_nl_new_link: the netlink message is not for any interface associated with RLOCs  (%s)",
                    iface_name);
            return;
        }else{
            old_iface_index = iface->iface_index;
            iface->iface_index = iface_index;
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_nl_new_link: The new index of the interface %s is: %d. Updating tables",
                    iface_name, iface->iface_index);
            /* Update routing tables and reopen sockets*/
            if (iface->ipv4_address->afi != AF_UNSPEC){
                del_rule(AF_INET,0,old_iface_index,old_iface_index,RTN_UNICAST,iface->ipv4_address,32,NULL,0,0);
                add_rule(AF_INET,0,iface_index,iface_index,RTN_UNICAST,iface->ipv4_address,32,NULL,0,0);
                close(iface->out_socket_v4);
                iface->out_socket_v4 = open_device_binded_raw_socket(iface->iface_name,AF_INET);
                bind_socket_src_address(iface->out_socket_v4,iface->ipv4_address);
            }
            if (iface->ipv6_address->afi != AF_UNSPEC){
                del_rule(AF_INET6,0,old_iface_index,old_iface_index,RTN_UNICAST,iface->ipv6_address,128,NULL,0,0);
                add_rule(AF_INET6,0,iface_index,iface_index,RTN_UNICAST,iface->ipv6_address,128,NULL,0,0);
                close(iface->out_socket_v6);
                iface->out_socket_v6 = open_device_binded_raw_socket(iface->iface_name,AF_INET6);
                bind_socket_src_address(iface->out_socket_v6,iface->ipv6_address);
            }
        }
    }

    if ((ifi->ifi_flags & IFF_RUNNING) != 0){
        lispd_log_msg(LISP_LOG_DEBUG_1, "process_nl_new_link: Interface %s changes its status to UP",iface->iface_name);
        status = UP;
    }
    else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "process_nl_new_link: Interface %s changes its status to DOWN",iface->iface_name);
        status = DOWN;
    }

    process_link_status_change (iface, status);
}


void process_nl_new_route (struct nlmsghdr *nlh)
{
    struct rtmsg             *rtm                       = NULL;
    int                      rt_length                  = 0;

    rtm = (struct rtmsg *) NLMSG_DATA (nlh);
    rt_length = RTM_PAYLOAD(nlh);

//    printf ("-------------> type %d  table %d and family %u scope %d protocol %d\n",rtm->rtm_type, rtm->rtm_table, rtm->rtm_family, rtm->rtm_scope, rtm->rtm_protocol);

    /* Interested only in unicast or multicast updates */
    if (rtm->rtm_type == RTN_UNICAST)
        process_nl_new_unicast_route(rtm, rt_length);
    else if (rtm->rtm_type == RTN_MULTICAST)
        process_nl_new_multicast_route(rtm, rt_length);

}

void process_nl_new_unicast_route(struct rtmsg *rtm, int rt_length) {

    struct rtattr            *rt_attr                   = NULL;
    lispd_iface_elt          *iface                     = NULL;
    int                      iface_index                = 0;
    char                     iface_name[IF_NAMESIZE];
    lisp_addr_t              gateway                    = {.afi=AF_UNSPEC};
    lisp_addr_t              dst                        = {.afi=AF_UNSPEC};

    /* Interested only in main table updates for unicast */
    if (rtm->rtm_table != RT_TABLE_MAIN)
        return;

    if ( rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6 ) {
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_nl_new_unicast_route: New unicast route of unknown adddress family %d",
                rtm->rtm_family);
        return;
    }

    rt_attr = (struct rtattr *)RTM_RTA(rtm);

    for (; RTA_OK(rt_attr, rt_length); rt_attr = RTA_NEXT(rt_attr, rt_length)) {
        switch (rt_attr->rta_type) {
        case RTA_OIF:
            iface_index = *(int *)RTA_DATA(rt_attr);
            iface = get_interface_from_index(iface_index);
            if (iface == NULL){
                if_indextoname(iface_index, iface_name);
                lispd_log_msg(LISP_LOG_DEBUG_2, "process_nl_new_unicast_route: the netlink message is not for any interface associated with RLOCs (%s)",
                        iface_name);
                return;
            }
            break;
        case RTA_GATEWAY:
            lisp_addr_set_afi(&gateway, LM_AFI_IP);
            ip_addr_init(lisp_addr_get_ip(&gateway), RTA_DATA(rt_attr),  rtm->rtm_family);
//            gateway.afi = rtm->rtm_family;
//            switch (gateway.afi) {
//            case AF_INET:
//                memcpy(&(gateway.address),(struct in_addr *)RTA_DATA(rt_attr), sizeof(struct in_addr));
//                break;
//            case AF_INET6:
//                memcpy(&(gateway.address),(struct in6_addr *)RTA_DATA(rt_attr), sizeof(struct in6_addr));
//                break;
//            default:
//                break;
//            }

            break;
        case RTA_DST:
//            memcpy(&(dst.address),(struct in_addr *)RTA_DATA(rt_attr), sizeof(struct in_addr));
            /* XXX: why the above? */


            /*
             * We check if the new route message contains a destination. If it is, then the gateway
             * address is not a default route. Discard it
             */
            lisp_addr_set_afi(&dst, LM_AFI_IP);
            ip_addr_init(lisp_addr_get_ip(&dst), RTA_DATA(rt_attr), rtm->rtm_family);

//            dst.afi = rtm->rtm_family;
//            switch (dst.afi) {
//            case AF_INET:
//                memcpy(&(dst.address),(struct in_addr *)RTA_DATA(rt_attr), sizeof(struct in_addr));
//                break;
//            case AF_INET6:
//                memcpy(&(dst.address),(struct in6_addr *)RTA_DATA(rt_attr), sizeof(struct in6_addr));
//                break;
//            default:
//                break;
//            }
            break;
        default:
            break;
        }
    }

    if (gateway.afi != AF_UNSPEC && iface_index != 0 && dst.afi == AF_UNSPEC) {
        /* Check default afi*/
        if (default_rloc_afi != -1 && default_rloc_afi != gateway.afi) {
            lispd_log_msg(LISP_LOG_DEBUG_1,  "process_nl_new_unicast_route: Default RLOC afi defined (-a #): Skipped %s gateway in iface %s",
                    (gateway.afi == AF_INET) ? "IPv4" : "IPv6",iface->iface_name);
            return;
        }

        /* Check if the addres is a global address*/
        if (is_link_local_addr(gateway) == TRUE) {
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_nl_new_unicast_route: the extractet address from the netlink "
                    "messages is a local link address: %s discarded", lisp_addr_to_char(&gateway));
            return;
        }

        /* Process the new gateway */
        lispd_log_msg(LISP_LOG_DEBUG_1,  "process_nl_new_unicast_route: Process new gateway associated to the interface %s:  %s",
                iface_name, lisp_addr_to_char(&gateway));
        process_new_gateway(gateway,iface);
    }
}

void process_nl_new_multicast_route(struct rtmsg *rtm, int rt_length) {

    ip_addr_t   srcaddr, grpaddr;

    /*
     * IPv4 multicast routes are part of the default table and have family 128, while
     * IPv6 multicast routes are part of the main table and have family 129 ...
     */
    if ( !((rtm->rtm_table == RT_TABLE_DEFAULT && rtm->rtm_family == 128) ||
           (rtm->rtm_table == RT_TABLE_MAIN && rtm->rtm_family == 129) ) )
        return;


    if (process_nl_multicast_route_attributes(rtm, rt_length, &srcaddr, &grpaddr) == BAD)
        return;

    multicast_join_channel(&srcaddr, &grpaddr);

}

int process_nl_multicast_route_attributes (
        struct rtmsg    *rtm,
        int             rt_length,
        ip_addr_t       *rt_srcaddr,
        ip_addr_t       *rt_groupaddr) {

    struct rtattr            *rt_attr                   = NULL;
    lispd_iface_elt          *iface                     = NULL;
    int                      iface_index                = 0;
    char                     iface_name[IF_NAMESIZE];

    struct rtnexthop         *rt_nh                     = NULL;
    int                      nb_oifs                    = 0;
    int                      rtnh_length                = 0;
    char                     ifnames[1024]              = {0};

    rt_attr = (struct rtattr *)RTM_RTA(rtm);

    for (; RTA_OK(rt_attr, rt_length); rt_attr = RTA_NEXT(rt_attr, rt_length)) {
        switch (rt_attr->rta_type) {
            case RTA_DST:
                switch(rtm->rtm_family) {
                    case 128:
                        ip_addr_set_v4(rt_groupaddr, (void *)RTA_DATA(rt_attr) );
//                        rt_groupaddr->afi = AF_INET;
//                        memcpy(&(rt_groupaddr->address),(struct in_addr *)RTA_DATA(rt_attr), sizeof(struct in_addr));
                        break;
                    case 129:
                        ip_addr_set_v6(rt_groupaddr, (void *)RTA_DATA(rt_attr));
//                        rt_groupaddr->afi = AF_INET6;
//                        memcpy(&(rt_groupaddr->address),(struct in6_addr *)RTA_DATA(rt_attr), sizeof(struct in6_addr));
                        break;
                    default:
                        break;
                }
                break;
            case RTA_SRC:
                switch (rtm->rtm_family) {
                    case 128:
                        ip_addr_set_v4(rt_srcaddr, (struct in_addr *)RTA_DATA(rt_attr));
//                        rt_srcaddr->afi = AF_INET;
//                        memcpy(&(rt_srcaddr->address),(struct in_addr *)RTA_DATA(rt_attr), sizeof(struct in_addr));
                        break;
                    case 129:
                        ip_addr_set_v6(rt_srcaddr, (struct in6_addr *)RTA_DATA(rt_attr));
//                        rt_srcaddr->afi = AF_INET6;
//                        memcpy(&(rt_srcaddr->address),(struct in6_addr *)RTA_DATA(rt_attr), sizeof(struct in6_addr));
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
                        lispd_log_msg(LISP_LOG_INFO, "process_nl_new_multicast_route: the multicast route message is for an interface that has RLOCs associated (%s). Ignoring!",
                                iface_name);
                        return BAD;
                    }

                    /* Prepare output for debug */
                    if_indextoname(rt_nh->rtnh_ifindex, iface_name);
                    sprintf(ifnames, "%s ", iface_name);
//                    strcat(ifnames, iface_name);
//                    strcat(ifnames, " ");
                    nb_oifs++;
                }
                break;
            default:
                break;
        }
    }

    if (nb_oifs == 0){
        lispd_log_msg(LISP_LOG_DEBUG_1, "process_nl_new_multicast_route: New multicast route has no output interface list, ignored!");
        return BAD;
    }

    lispd_log_msg(LISP_LOG_INFO, "New multicast route with source %s, group %s for interfaces %s",
            ip_addr_to_char(rt_srcaddr), ip_addr_to_char(rt_groupaddr), ifnames);

    return GOOD;
}

void process_nl_del_route (struct nlmsghdr *nlh) {

    struct rtmsg             *rtm                       = NULL;
    int                      rt_length                  = 0;

    rtm = (struct rtmsg *) NLMSG_DATA (nlh);
    rt_length = RTM_PAYLOAD(nlh);

    /* Process removed routes only for multicast */
    if (rtm->rtm_type == RTN_MULTICAST)
        process_nl_del_multicast_route (rtm, rt_length);
}

void process_nl_del_multicast_route (struct rtmsg *rtm, int rt_length) {

    ip_addr_t  rt_groupaddr               = {.afi=AF_UNSPEC};
    ip_addr_t  rt_srcaddr                 = {.afi=AF_UNSPEC};

    if ( !((rtm->rtm_table == RT_TABLE_DEFAULT && rtm->rtm_family == 128) ||
           (rtm->rtm_table == RT_TABLE_MAIN && rtm->rtm_family == 129) ) )
        return;


    if (process_nl_multicast_route_attributes(rtm, rt_length, &rt_srcaddr, &rt_groupaddr) == BAD)
        return;

    multicast_leave_channel(&rt_srcaddr, &rt_groupaddr);
}


void process_new_gateway (
        lisp_addr_t         gateway,
        lispd_iface_elt     *iface )
{
    lisp_addr_t **gw_addr   = NULL;
    int         afi         = AF_UNSPEC;


    switch(gateway.afi){
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
    if (*gw_addr == NULL){ // The default gateway of this interface is not deffined yet
        if ((*gw_addr = (lisp_addr_t *)malloc(sizeof(lisp_addr_t))) == NULL){
            lispd_log_msg(LISP_LOG_WARNING,"process_new_gateway: Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
            return;
        }
        if ((copy_lisp_addr_t(*gw_addr,&gateway,FALSE)) != GOOD){
            free (*gw_addr);
            *gw_addr = NULL;
            return;
        }
    }else{
        copy_lisp_addr(*gw_addr,&gateway);
    }

    add_route(afi,iface->iface_index,NULL,NULL,*gw_addr,0,100,iface->iface_index);
}

/*
 * Change the satus of the interface. Recalculate default control and output interfaces if it's needed.
 * Program SMR
 */

void process_link_status_change (
    lispd_iface_elt     *iface,
    int                 new_status)
{
    if (iface->status == new_status){
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_link_status_change: The detected change of status doesn't affect");
        return;
    }

    if (iface->status_changed == TRUE){
        iface->status_changed = FALSE;
    }else{
        iface->status_changed = TRUE;
    }

    // Change status of the interface
    iface->status = new_status;

    /*
     * If the affected interface is the default control or output iface, recalculate it
     */

    if (default_ctrl_iface_v4 == iface
            || default_ctrl_iface_v6 == iface
            || default_ctrl_iface_v4 == NULL
            || default_ctrl_iface_v6 == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"Default control interface down. Recalculate new control interface");
        set_default_ctrl_ifaces();
    }

    if (default_out_iface_v4 == iface
            || default_out_iface_v6 == iface
            || default_out_iface_v4 == NULL
            || default_out_iface_v6 == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_2,"Default output interface down. Recalculate new output interface");
        set_default_output_ifaces();
    }

    iface_balancing_vectors_calc(iface);

    /* Reprograming SMR timer*/
    if (smr_timer == NULL){
        smr_timer = create_timer (SMR_TIMER);
    }
    start_timer(smr_timer, LISPD_SMR_TIMEOUT,(timer_callback)init_smr, NULL);

}



/*
 * Activate the locators associated with the interface using the new address
 * This function is only used when an interface is down during the initial configuration process and then is activated
 */

void activate_interface_address (
        lispd_iface_elt     *iface,
        lisp_addr_t         new_address)
{
    lispd_iface_mappings_list       *mapping_list               = NULL;
    lispd_mapping_elt               *mapping                    = NULL;
    lispd_locators_list             **not_init_locators_list    = NULL;
    lispd_locators_list             **locators_list             = NULL;
    lispd_locator_elt               *locator                    = NULL;

    switch(new_address.afi){
    case AF_INET:
        iface->out_socket_v4 = open_device_binded_raw_socket(iface->iface_name,AF_INET);
        bind_socket_src_address(iface->out_socket_v4, &new_address);
        break;
    case AF_INET6:
        iface->out_socket_v6 = open_device_binded_raw_socket(iface->iface_name,AF_INET6);
        bind_socket_src_address(iface->out_socket_v6, &new_address);
        break;
    }

    mapping_list = iface->head_mappings_list;
    /*
     * Activate the locator for each mapping associated with the interface
     */
    while (mapping_list != NULL){
        mapping = mapping_list->mapping;
        lispd_log_msg(LISP_LOG_DEBUG_2,"Activating locator %s associated to the EID %s/%d\n",
                get_char_from_lisp_addr_t(new_address),
                get_char_from_lisp_addr_t(mapping->eid_prefix),
                mapping->eid_prefix_length);
        not_init_locators_list = &(((lcl_mapping_extended_info *)mapping->extended_info)->head_not_init_locators_list);
        locator = extract_locator_from_list (not_init_locators_list, new_address);
        if (locator != NULL){
            switch(new_address.afi){
            case AF_INET:
                mapping_list->use_ipv4_address = TRUE;
                locators_list = &mapping->head_v4_locators_list;
                break;
            case AF_INET6:
                mapping_list->use_ipv6_address = TRUE;
                locators_list = &mapping->head_v6_locators_list;
                break;
            }
            /* Add the activated locator */
            if (add_locator_to_list (locators_list,locator) == GOOD){
                mapping->locator_count = mapping->locator_count + 1;
            }else{
                free_locator(locator);
            }
        }else{
            lispd_log_msg(LISP_LOG_DEBUG_1,"activate_interface_address: No locator with address %s has been found"
                    " in the not init locators list of the mapping %s/%d. Is priority equal to -1 for this EID and afi?",
                    get_char_from_lisp_addr_t(new_address),
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length);
        }
        mapping_list = mapping_list->next;
    }
}





