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
#include "lispd_iface_mgmt.h"
#include "lispd_lib.h"
#include "lispd_log.h"
#include "lispd_mapping.h"
#include "lispd_smr.h"
#include "lispd_timers.h"

void process_nl_add_address (struct nlmsghdr *nlh);
void process_nl_del_address (struct nlmsghdr *nlh);
void process_nl_new_link (struct nlmsghdr *nlh);
int interface_change_update(
    timer *timer,
    void *arg);

int opent_netlink_socket()
{
    int netlink_fd          = 0;
    struct sockaddr_nl addr;


    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;


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

    //recvmsg(netlink_fd, &msgh, 0);
    while ((len = recv (netlink_fd,nlh,4096,0)) > 0){
        for (;(NLMSG_OK (nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE); nlh = NLMSG_NEXT(nlh, len)){
            switch(nlh->nlmsg_type){
            case RTM_NEWADDR:
                lispd_log_msg(LISP_LOG_DEBUG_1, "=============> process_netlink_msg: received  new address message");
                process_nl_add_address (nlh);
                break;
            case RTM_DELADDR:
                lispd_log_msg(LISP_LOG_DEBUG_1, "=============> process_netlink_msg: received  del address message");
                process_nl_del_address (nlh);
                break;
            case RTM_NEWLINK:
                lispd_log_msg(LISP_LOG_DEBUG_1, "=============> process_netlink_msg: received  link message");
                process_nl_new_link (nlh);
                break;
            default:
                break;
            }
        }
    }
}


void process_nl_add_address (struct nlmsghdr *nlh)
{
    struct ifaddrmsg    *ifa            = NULL;
    struct rtattr       *rth            = NULL;
    int                 iface_index     = 0;
    int                 rt_length       = 0;
    lispd_iface_elt     *iface          = NULL;
    lisp_addr_t         new_addr;
    lisp_addr_t         *iface_addr     = NULL;

    /*
     * Get the new address from the net link message
     */
    ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);
    iface_index = ifa->ifa_index;

    iface = get_interface_from_index(iface_index);

    if (iface == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3, "process_nl_add_address: the netlink message is not for any RLOC interface");
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

    /* Check if the addres is a global address*/
    if (is_link_local_addr(new_addr) == TRUE){
        lispd_log_msg(LISP_LOG_DEBUG_3,"process_nl_add_address: the extractet address from the netlink"
                "messages is a local link address: %s discarded", get_char_from_lisp_addr_t(new_addr));
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

    if (iface_addr == NULL){
        /* XXX To be done */
        lispd_log_msg(LISP_LOG_DEBUG_1,"process_nl_add_address: Automatic assignemen of locators is not supported."
                "Restart LISPmob to use %s as a locator", get_char_from_lisp_addr_t(new_addr));
        return;
    }

    if (compare_lisp_addr_t(iface_addr,&new_addr)==0){ // Same address that we already have
        lispd_log_msg(LISP_LOG_DEBUG_2,"process_nl_add_address: The detected change of address for interface %s "
                "doesn't affect",iface->iface_name);
        return;
    }

    lispd_log_msg(LISP_LOG_DEBUG_2,"process_nl_add_address: New address detected for interface %s -> %s: Start SMR process",
                    iface->iface_name, get_char_from_lisp_addr_t(new_addr));

    // Update the new address
    copy_lisp_addr(iface_addr, &new_addr);

    // Init SMR procedure
    switch (new_addr.afi){
    case AF_INET:
        init_smr(iface->head_v4_mappings_list);
        break;
    case AF_INET6:
        init_smr(iface->head_v6_mappings_list);
        break;
    }

}



void process_nl_del_address (struct nlmsghdr *nlh)
{
    struct ifaddrmsg    *ifa            = NULL;
    struct rtattr       *rth            = NULL;
    int                 iface_index     = 0;
    int                 rt_length       = 0;
    lispd_iface_elt     *iface          = NULL;
    lisp_addr_t         new_addr;

    ifa = (struct ifaddrmsg *) NLMSG_DATA (nlh);
    iface_index = ifa->ifa_index;

    iface = get_interface_from_index(iface_index);

    if (iface == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3, "process_nl_add_address: the netlink message is not for any RLOC interface");
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
    timer_iface_status_update_argument  *arguments      = NULL;
    uint8_t                             status          = UP;



    ifi = (struct ifinfomsg *) NLMSG_DATA (nlh);
    iface_index = ifi->ifi_index;

    iface = get_interface_from_index(iface_index);

    if (iface == NULL){
        lispd_log_msg(LISP_LOG_DEBUG_3, "process_nl_new_link: the netlink message is not for any RLOC interface");
        return;
    }
    if ((ifi->ifi_flags & IFF_RUNNING) != 0){
        lispd_log_msg(LISP_LOG_DEBUG_1, "process_nl_new_link: Interface %s changes its status to UP",iface->iface_name);
        status = UP;
    }
    else{
        lispd_log_msg(LISP_LOG_DEBUG_1, "process_nl_new_link: Interface %s changes its status to DOWN",iface->iface_name);
        status = DOWN;
    }

    /* Reprograming timer*/
    if (iface->status_transition_timer == NULL){
        if ((arguments = malloc(sizeof(timer_iface_status_update_argument)))==NULL){
            lispd_log_msg(LISP_LOG_WARNING,"process_nl_new_link: Unable to allocate memory for timer_iface_status_update_argument: %s",
                    strerror(errno));
            return ;
        }

        arguments->iface  = iface;
        arguments->status = status;

        iface->status_transition_timer = create_timer (INTERFACE_CHANGE_TIMER);
    }else {
        arguments = (timer_iface_status_update_argument *)(iface->status_transition_timer->cb_argument);
        arguments->status = status;
    }

    start_timer(iface->status_transition_timer, LISPD_IFACE_TRANS_TIMEOUT,
            (timer_callback)interface_change_update, (void *)arguments);
}

int interface_change_update(
    timer *timer,
    void *arg)
{
    timer_iface_status_update_argument     *argument          = (timer_iface_status_update_argument *)arg;
    lispd_mappings_list                    *mapping_list[2]    = {NULL, NULL};
    int                                     ctr                 = 0;

    /*  If we reached here due to a transition period don't do anyhing */
    if (argument->status == argument->iface->status){
        lispd_log_msg(LISP_LOG_DEBUG_1,"interface_change_update: Transition period of interface %s. No changes", argument->iface->iface_name);
        free (argument->iface->status_transition_timer);
        argument->iface->status_transition_timer = NULL;
        free (argument);
        return (GOOD);
    }

    // Change status of the interface
    argument->iface->status = argument->status;

    mapping_list[0] = argument->iface->head_v4_mappings_list;
    mapping_list[1] = argument->iface->head_v6_mappings_list;
    for (ctr = 0 ; ctr < 2 ; ctr ++){
        /* Initiate SMR for each affected mapping */
        init_smr(mapping_list[ctr]);
        /* Recalculate balancing vector for each affected mapping*/
        while (mapping_list[ctr] != NULL){
            calculate_balancing_vectors (
                    mapping_list[ctr]->mapping,
                    &(((lcl_mapping_extended_info *)(mapping_list[ctr]->mapping->extended_info))->outgoing_balancing_locators_vecs));
            mapping_list[ctr] = mapping_list[ctr]->next;
        }
    }
    free (argument->iface->status_transition_timer);
    argument->iface->status_transition_timer = NULL;
    free (argument);
    return (GOOD);
}


