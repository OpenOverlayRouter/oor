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
#include "lispd_lib.h"
#include "lispd_log.h"
#include "lispd_mapping.h"
#include "lispd_smr.h"
#include "lispd_sockets.h"
#include "lispd_timers.h"
#include "lispd_tun.h"

/************************* FUNCTION DECLARTAION ********************************/

void process_nl_add_address (struct nlmsghdr *nlh);
void process_nl_del_address (struct nlmsghdr *nlh);
void process_nl_new_link (struct nlmsghdr *nlh);

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

    while ((len = recv (netlink_fd,nlh,4096,0)) > 0){
        for (;(NLMSG_OK (nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE); nlh = NLMSG_NEXT(nlh, len)){
            switch(nlh->nlmsg_type){
            case RTM_NEWADDR:
                lispd_log_msg(LISP_LOG_DEBUG_2, "===>process_netlink_msg: Received  new address message");
                process_nl_add_address (nlh);
                break;
            case RTM_DELADDR:
                lispd_log_msg(LISP_LOG_DEBUG_2, "===>process_netlink_msg: Received  del address message");
                process_nl_del_address (nlh);
                break;
            case RTM_NEWLINK:
                lispd_log_msg(LISP_LOG_DEBUG_2, "===>process_netlink_msg: Received  link message");
                process_nl_new_link (nlh);
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

    process_address_change (iface, new_addr);
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

    /* Check if the addres is a global address*/
    if (is_link_local_addr(new_addr) == TRUE){
        lispd_log_msg(LISP_LOG_DEBUG_2,"precess_address_change: the extractet address from the netlink"
                "messages is a local link address: %s discarded", get_char_from_lisp_addr_t(new_addr));
        return;
    }
    /* If default RLOC afi defined (-a 4 or 6), only accept addresses of the specified afi */
    if (default_rloc_afi != -1 && default_rloc_afi != new_addr.afi){
        lispd_log_msg(LISP_LOG_DEBUG_2,"precess_address_change: Default RLOC afi defined: Skipped %s address in iface %s",
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
        return;
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
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_nl_add_address: the netlink message is not for any interface associated with RLOCs (%s / %d)",
                iface_name, iface_index);
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
            lispd_log_msg(LISP_LOG_DEBUG_2, "process_nl_new_link: the netlink message is not for any interface associated with RLOCs  (%s / %d)",
                    iface_name,iface_index);
            return;
        }else{
            iface->iface_index = iface_index;
            lispd_log_msg(LISP_LOG_DEBUG_2,"process_nl_new_link: The new index of the interface %s is: %d",
                    iface_name, iface->iface_index);
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


/*
 * Change the satus of the interface. Recalculate default control and output interfaces if it's needed.
 * Program SMR
 */

void process_link_status_change(
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

void activate_interface_address(
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
        break;
    case AF_INET6:
        iface->out_socket_v6 = open_device_binded_raw_socket(iface->iface_name,AF_INET6);
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
                ((lcl_locator_extended_info *)locator->extended_info)->out_socket = iface->out_socket_v4;
                locators_list = &mapping->head_v4_locators_list;
                break;
            case AF_INET6:
                mapping_list->use_ipv6_address = TRUE;
                ((lcl_locator_extended_info *)locator->extended_info)->out_socket = iface->out_socket_v6;
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
                    " in the not init locators list of the mapping %s/%d. It should never reach here",
                    get_char_from_lisp_addr_t(new_address),
                    get_char_from_lisp_addr_t(mapping->eid_prefix),
                    mapping->eid_prefix_length);
        }
        mapping_list = mapping_list->next;
    }
}





