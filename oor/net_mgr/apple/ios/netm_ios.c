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
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>

#include "netm_ios.h"
#include "../../net_mgr.h"
#include "../../net_mgr_proc_fc.h"
#include "iface_mgmt.h"
#include "netm_kernel.h"
#include "../../../lib/oor_log.h"
#include "../../../lib/prefixes.h"
#include "../../../lib/sockets.h"

#include "TargetConditionals.h"
#if TARGET_IPHONE_SIMULATOR
#include "route.h"
#else
#include "route.h"
#endif

#define CTL_NET         4               /* network, see socket.h */

#define ROUNDUP(a, size) \
(((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))

#define NEXT_SA(ap) (ap) = (struct sockaddr *) \
((char *)(ap) + ((ap)->sa_len ? ROUNDUP((ap)->sa_len,sizeof(uint32_t)) : sizeof(uint32_t)))

union ios_net_msg {
    char buf[4096];
    struct rt_msghdr rtm;
    struct if_msghdr ifm;
    struct ifa_msghdr ifam;
};

int ios_netm_init();
void ios_netm_uninit();
glist_t * ios_get_ifaces_names();
glist_t * ios_get_iface_addr_list(char *iface_name, int afi);
lisp_addr_t * ios_get_src_addr_to(lisp_addr_t *addr);
lisp_addr_t * ios_get_iface_gw(char *iface_name, int afi);
lisp_addr_t *ios_get_first_ipv6_addr_from_iface_with_scope (char *iface_name, ipv6_scope_e scope);
uint8_t ios_get_iface_status(char *iface_name);
int ios_get_iface_index(char *iface_name);
void ios_get_iface_mac_addr(char *iface_name, uint8_t *mac);
char * ios_get_iface_name_associated_with_prefix(lisp_addr_t * pref);
int ios_reload_routes(uint32_t table, int afi);
shash_t * ios_build_addr_to_if_name_hasht();
int ios_interface_changed(sock_t *sl);
int ios_network_changed(sock_t *sl);
void process_fbd_route_change (struct rt_msghdr *rtm);
void process_fbd_address_change (struct ifa_msghdr *ifam);
void process_fbd_link_change (struct if_msghdr *ifm);

net_mgr_class_t netm_apple = {
    .netm_init = ios_netm_init,
    .netm_uninit = ios_netm_uninit,
    .netm_get_ifaces_names = ios_get_ifaces_names,
    .netm_get_iface_index = ios_get_iface_index,
    .netm_get_iface_addr_list = ios_get_iface_addr_list,
    .netm_get_src_addr_to = ios_get_src_addr_to,
    .netm_get_iface_gw = ios_get_iface_gw,
    .netm_get_first_ipv6_addr_from_iface_with_scope = ios_get_first_ipv6_addr_from_iface_with_scope,
    .netm_get_iface_status = ios_get_iface_status,
    .netm_get_iface_mac_addr = ios_get_iface_mac_addr,
    .netm_reload_routes = ios_reload_routes,
    .netm_build_addr_to_if_name_hasht = ios_build_addr_to_if_name_hasht,
    .netm_get_iface_associated_with_pref = ios_get_iface_name_associated_with_prefix,
    .data = NULL
};


int ios_netm_init() {
    int netm_socket;
    
    //open routing socket to receive changes of network interfaces
    
    netm_socket = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    sockmstr_register_read_listener(smaster, ios_network_changed, NULL, netm_socket);

    return (GOOD);
}

// UNUSED
void ios_netm_uninit() {}


glist_t * ios_get_ifaces_names() {
    
    glist_t *iface_names = glist_new_managed((glist_del_fct)free);
    
    struct ifaddrs* interfaces = NULL;
    struct ifaddrs* temp_addr = NULL;
    
    // retrieve the current interfaces - returns 0 on success
    int success = getifaddrs(&interfaces);
    if (success == 0) {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while (temp_addr != NULL) {
            if (temp_addr->ifa_addr->sa_family == AF_INET) {
                glist_add(strdup(temp_addr->ifa_name), iface_names);
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    
    // Free memory
    freeifaddrs(interfaces);
    
    return (iface_names);
    
}

glist_t * ios_get_iface_addr_list(char *iface_name, int afi) {
    
    glist_t *addr_list = glist_new_managed((glist_del_fct)lisp_addr_del);
    lisp_addr_t *addr;
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;
    struct sockaddr_in *s4, *s4_mask;
    struct sockaddr_in6 *s6, *s6_mask;
    ip_addr_t ip;
    int i;
    uint8_t is_host = TRUE;
    
    /* search for the interface */
    if (getifaddrs(&ifaddr) !=0) {
        OOR_LOG(LDBG_2, "ios_get_iface_addr_list: getifaddrs error: %s",
                strerror(errno));
        return(addr_list);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr == NULL)
            || ((ifa->ifa_flags & IFF_UP) == 0)
            || (ifa->ifa_addr->sa_family != afi)
            || strcmp(ifa->ifa_name, iface_name) != 0) {
            continue;
        }
        
        switch (ifa->ifa_addr->sa_family) {
            case AF_INET:
                s4 = (struct sockaddr_in *) ifa->ifa_addr;
                ip_addr_init(&ip, &s4->sin_addr, AF_INET);
                
                if (ip_addr_is_link_local(&ip) == TRUE) {
                    OOR_LOG(LDBG_2, "ios_get_iface_addr_list: interface address from "
                            "%s discarded (%s)", iface_name, ip_addr_to_char(&ip));
                    continue;
                }
                if (ifa->ifa_netmask){
                    s4_mask = (struct sockaddr_in *) ifa->ifa_netmask;
                    if (s4_mask->sin_addr.s_addr == 0xFFFFFFFF){
                        OOR_LOG(LDBG_2, "ios_get_iface_addr_list: interface address from "
                                "%s discarded (%s) -> mask 32", iface_name, ip_addr_to_char(&ip));
                        continue;
                    }
                }
                break;
            case AF_INET6:
                s6 = (struct sockaddr_in6 *) ifa->ifa_addr;
                ip_addr_init(&ip, &s6->sin6_addr, AF_INET6);
                
                if (ip_addr_is_link_local(&ip) == TRUE) {
                    OOR_LOG(LERR, "ios_get_iface_addr_list: interface address from "
                            "%s discarded (%s)", iface_name, ip_addr_to_char(&ip));
                    continue;
                }
                if (ifa->ifa_netmask){
                    s6_mask = (struct sockaddr_in6 *) ifa->ifa_netmask;
                    for (i = 0 ; i < 16 ; i++){
                        if (s6_mask->sin6_addr.s6_addr[i] != 0xFF){
                            is_host = FALSE;
                            break;
                        }
                    }
                    if (is_host){
                        OOR_LOG(LDBG_2, "ios_get_iface_addr_list: interface address from "
                                "%s discarded (%s) -> mask 128", iface_name, ip_addr_to_char(&ip));
                        continue;
                    }
                }
                break;
            default:
                continue;                   /* XXX */
        }
        addr = lisp_addr_new();
        lisp_addr_init_from_ip(addr, &ip);
        glist_add(addr, addr_list);
    }
    freeifaddrs(ifaddr);
    
    if (glist_size(addr_list) == 0){
        OOR_LOG(LDBG_3, "ios_get_iface_addr_list: No %s RLOC configured for interface "
                "%s\n", (afi == AF_INET) ? "IPv4" : "IPv6", iface_name);
    }
    
    return(addr_list);
}



lisp_addr_t * ios_get_iface_gw(char *iface_name, int afi) {
    lisp_addr_t gateway = { .lafi = LM_AFI_IP };
    int mib[] = {CTL_NET, PF_ROUTE, 0, afi, NET_RT_FLAGS, RTF_GATEWAY};
    size_t l;
    char * buf, * p;
    struct rt_msghdr * rt;
    struct sockaddr * sa;
    struct sockaddr * sa_tab[RTAX_MAX];
    int iface_index, i;
    
    if(sysctl(mib, sizeof(mib)/sizeof(int), 0, &l, 0, 0) < 0) {
        OOR_LOG(LERR, "ios_get_iface_gw: sysctl 1 failed");
        return (NULL);
    }
    if(l>0) {
        buf = malloc(l);
        if(sysctl(mib, sizeof(mib)/sizeof(int), buf, &l, 0, 0) < 0) {
            OOR_LOG(LERR, "ios_get_iface_gw: sysctl 2 failed");
            return (NULL);
        }
        for(p=buf; p<buf+l; p+=rt->rtm_msglen) {
            rt = (struct rt_msghdr *)p;
            sa = (struct sockaddr *)(rt + 1);
            for(i=0; i<RTAX_MAX; i++) {
                if(rt->rtm_addrs & (1 << i)) {
                    sa_tab[i] = sa;
                    if (sa->sa_family == AF_INET){
                        sa = (struct sockaddr *)((char *)sa + ROUNDUP(sa->sa_len, sizeof(uint32_t)));
                    }else{
                        sa = (struct sockaddr *)((char *)sa + ((struct sockaddr_in6 *)sa)->sin6_len);
                    }
                } else {
                    sa_tab[i] = NULL;
                }
            }

            iface_index = if_nametoindex(iface_name);
            if( ((rt->rtm_addrs & (RTA_DST|RTA_GATEWAY|RTM_ADD)) == (RTA_DST|RTA_GATEWAY))
               && sa_tab[RTAX_DST]->sa_family == afi
               && sa_tab[RTAX_GATEWAY]->sa_family == afi
               && iface_index == rt->rtm_index) {
                
                sa = sa_tab[RTAX_GATEWAY];
                switch (afi){
                    case (AF_INET):
                        ip_addr_init(lisp_addr_ip(&gateway),&(((struct sockaddr_in *)sa)->sin_addr),sa->sa_family);
                        goto gw;
                    case (AF_INET6):
                        ip_addr_init(lisp_addr_ip(&gateway),&(((struct sockaddr_in6 *)sa)->sin6_addr),sa->sa_family);
                        goto gw;
                }
                
            }
        }
        free(buf);
    }
    return (NULL);
gw:
    free(buf);
    return (lisp_addr_clone(&gateway));
}

lisp_addr_t *
ios_get_first_ipv6_addr_from_iface_with_scope (char *iface_name, ipv6_scope_e scope)
{
    glist_t *addr_list;
    glist_entry_t *addr_it;
    lisp_addr_t *addr = NULL, *ret_addr = NULL;
    
    addr_list = ios_get_iface_addr_list(iface_name,AF_INET6);
    if (ipv6_scope == SCOPE_GLOBAL){
        glist_for_each_entry(addr_it,addr_list){
            addr = (lisp_addr_t *)glist_entry_data(addr_it);
            if (IN6_IS_ADDR_GLOBAL(ip_addr_get_v6(lisp_addr_ip(addr)))){
                ret_addr = lisp_addr_clone(addr);
                break;
            }
        }
    }
    if (ipv6_scope == SCOPE_SITE_LOCAL){
        glist_for_each_entry(addr_it,addr_list){
            addr = (lisp_addr_t *)glist_entry_data(addr_it);
            if (IN6_IS_ADDR_SITE_LOCAL(ip_addr_get_v6(lisp_addr_ip(addr)))){
                ret_addr = lisp_addr_clone(addr);
                break;
            }
        }
    }
    glist_destroy(addr_list);
    return (ret_addr);
}

uint8_t ios_get_iface_status(char *iface_name) {
    
    char *cellularInterfaceName = "pdp_ip0";
    char *wifiInterfaceName = "en0";
    
    if (strcmp(iface_name, cellularInterfaceName) == 0) {
        if (ios_get_iface_status(wifiInterfaceName) == UP) {
            OOR_LOG(LINF, "ios_get_iface_status: Interface en0 UP, setting interface %s DOWN", iface_name);
            return DOWN;
        }
    }
    
    uint8_t status = ERR_NO_EXIST;
    
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;
    
    int iface_index = if_nametoindex(iface_name);
    if (iface_index == 0){
        OOR_LOG(LERR, "ios_get_iface_status: Iface %s doesn't exist",iface_name);
        return (ERR_NO_EXIST);
    }
    
    /* search for the interface */
    if (getifaddrs(&ifaddr) !=0) {
        OOR_LOG(LDBG_2, "ios_get_iface_addr_list: getifaddrs error: %s",
                strerror(errno));
        return(errno);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, iface_name) == 0) {
            if (ifa->ifa_flags & IFF_RUNNING) {
                lisp_addr_t *gate = ios_get_iface_gw(iface_name, AF_INET);
                
                if(lisp_addr_to_char(gate) != NULL) {
                    status = UP;                    
                }
                else {
                    status = DOWN;
                    break;
                }
            }
            else status = DOWN;
            break;
        }
    }
    freeifaddrs(ifaddr);
    
    return status;
}

int ios_get_iface_index(char *iface_name) {
    return (if_nametoindex(iface_name));
}

// UNUSED
void ios_get_iface_mac_addr(char *iface_name, uint8_t *mac) {}

// UNUSED
char * ios_get_iface_name_associated_with_prefix(lisp_addr_t * pref) {
    return (NULL);
}

// UNUSED
int ios_reload_routes(uint32_t table, int afi) {
    return (GOOD);
}

shash_t * ios_build_addr_to_if_name_hasht() {
    shash_t *ht;
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    
    OOR_LOG(LDBG_1, "Building address to interface hash table");
    if (getifaddrs(&ifaddr) == -1) {
        OOR_LOG(LCRIT, "Can't read the interfaces of the system. Exiting .. ");
        exit_cleanup();
    }
    
    ht = shash_new_managed((free_value_fn_t)free);
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        family = ifa->ifa_addr->sa_family;
        
        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                            (family == AF_INET) ? sizeof(struct sockaddr_in) :
                            sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                OOR_LOG(LWRN, "getnameinfo() failed: %s. Skipping interface. ",
                        gai_strerror(s));
                continue;
            }
            
            shash_insert(ht, strdup(host), strdup(ifa->ifa_name));
            
            OOR_LOG(LDBG_2, "Found interface %s with address %s", ifa->ifa_name,
                    host);
        }
    }
    
    freeifaddrs(ifaddr);
    return(ht);
}

lisp_addr_t * ios_get_src_addr_to(lisp_addr_t *dst_addr) {
    lisp_addr_t *src_addr;
    int afi, sock;
    size_t addr_len;
    struct sockaddr *sock_addr, *lcl_addr;

    afi = lisp_addr_ip_afi(dst_addr);
    
    sock_addr = lisp_addr_to_scockaddr(dst_addr);
    if (!sock_addr){
        return (NULL);
    }
    addr_len = SA_LEN(sock_addr);
    sock = socket( afi, SOCK_DGRAM, IPPROTO_UDP );
    if (sock == -1){
        OOR_LOG(LDBG_2,"ios_get_src_addr_to: Unable to open socket: %s", strerror(errno));
        free(sock_addr);
        return (NULL);
    }
    if (connect( sock, sock_addr, (socklen_t)addr_len) == -1){
        OOR_LOG(LDBG_2,"ios_get_src_addr_to: Unable to connect socket: %s", strerror(errno));
        free(sock_addr);
        close(sock);
        return (NULL);
    }
    
    lcl_addr = xmalloc(addr_len);
    getsockname(sock, lcl_addr, (socklen_t *)&addr_len);
    src_addr = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
    if (sockaddr_to_lisp_addr (lcl_addr,src_addr) != GOOD){
        lisp_addr_del(src_addr);
        src_addr = NULL;
    }
    
    free(sock_addr);
    free(lcl_addr);
    close(sock);
    OOR_LOG(LDBG_3,"ios_get_src_addr_to: Selected src address to %s is %s",
            lisp_addr_to_char(dst_addr), lisp_addr_to_char(src_addr));
    
    return (src_addr);
}

int ios_network_changed(sock_t *sl) {
    int len = 0;
    union ios_net_msg u;
    
    while ((len = recv(sl->fd, &u, 4096, MSG_DONTWAIT)) > 0) {
        if (u.ifm.ifm_version != RTM_VERSION) {
            OOR_LOG(LDBG_2,"ios_network_changed: Unknown RTM version");
            continue;
        }
        switch (u.ifm.ifm_type){
            case RTM_NEWADDR:
                OOR_LOG(LDBG_1, "ios_network_changed: process_netlink_msg: Received new address message");
                process_fbd_address_change (&u.ifam);
                break;
            case RTM_DELADDR:
                OOR_LOG(LDBG_1, "ios_network_changed: process_netlink_msg: Received del address message");
                process_fbd_address_change (&u.ifam);
                break;
            case RTM_IFINFO:
                OOR_LOG(LDBG_1, "ios_network_changed: process_netlink_msg: Received link message");
                process_fbd_link_change (&u.ifm);
                break;
            case RTM_ADD:
                OOR_LOG(LDBG_1, "ios_network_changed: process_netlink_msg: Received new route message");
                process_fbd_route_change (&u.rtm);
                break;
            case RTM_DELETE:
                OOR_LOG(LDBG_1, "ios_network_changed: process_netlink_msg: Received delete route message");
                process_fbd_route_change (&u.rtm);
                break;
            default:
                break;
        }
    }
    return (GOOD);
}

void
process_fbd_route_change (struct rt_msghdr *rtm)
{
    int iface_index = ~0;
    int iface_gw = ~0;
    lisp_addr_t gateway = { .lafi = LM_AFI_NO_ADDR };
    lisp_addr_t src = { .lafi = LM_AFI_NO_ADDR };
    lisp_addr_t dst = { .lafi = LM_AFI_NO_ADDR };
    lisp_addr_t dst_mask = { .lafi = LM_AFI_NO_ADDR };
    struct sockaddr *sa;
    int dst_len = ~0, i, type, res;
    
    iface_index = rtm->rtm_index;
    sa = (struct sockaddr *)(rtm + 1);
    for (i = 0; i < RTAX_MAX; i++) {
        if (rtm->rtm_addrs & (1 << i)) {
            type = (1 << i);
            if ( type == RTA_IFA){
                sockaddr_to_lisp_addr(sa,&src);
            }else if (type == RTA_DST){
                sockaddr_to_lisp_addr(sa,&dst);
            }else if (type == RTA_GATEWAY){
                res = sockaddr_to_lisp_addr(sa,&gateway);
                if (res == BAD && sa->sa_family == AF_LINK){
                    iface_gw = ((struct sockaddr_dl *)sa)->sdl_index;
                }
            }else if (type == RTA_NETMASK){
                res = sockaddr_to_lisp_addr(sa, &dst_mask);
                // XXX When previous read address is AF_LINK, NETMASK is not correctly initiated
                if (res == GOOD){
                    dst_len = pref_mask_addr_to_length(&dst_mask);
                }
            }
            NEXT_SA(sa);
        }
    }
    if (lisp_addr_is_ip(&dst) && dst_len != ~0){
        lisp_addr_set_plen(&dst,dst_len);
    }
    
    if (rtm->rtm_type ==  RTM_ADD){
        if (iface_gw == ~0){
            OOR_LOG (LDBG_2,"process_fbd_route_change: Add route src: %s dst: %s gw: %s iface_index: %d",
                lisp_addr_to_char(&src),lisp_addr_to_char(&dst),lisp_addr_to_char(&gateway), iface_index);
        }else{
            OOR_LOG (LDBG_2,"process_fbd_route_change: Add route src: %s dst: %s iface_gw: %d iface_index: %d",
                     lisp_addr_to_char(&src),lisp_addr_to_char(&dst), iface_gw, iface_index);
        }
        nm_process_route_change(ADD, iface_index, &src,&dst,&gateway);
    }else{
        if (iface_gw == ~0){
            OOR_LOG (LDBG_2,"process_fbd_route_change:Remove route src: %s dst: %s gw: %s iface_index: %d",
                     lisp_addr_to_char(&src),lisp_addr_to_char(&dst),lisp_addr_to_char(&gateway), iface_index);
        }else{
            OOR_LOG (LDBG_2,"process_fbd_route_change:Remove route src: %s dst: %s iface_gw: %d iface_index: %d",
                     lisp_addr_to_char(&src),lisp_addr_to_char(&dst), iface_gw, iface_index);
        }
        nm_process_route_change(RM, iface_index, &src,&dst,&gateway);
    }
}

void
process_fbd_address_change (struct ifa_msghdr *ifam)
{
    int iface_index = ~0;
    lisp_addr_t new_addr = { .lafi = LM_AFI_NO_ADDR };
    struct sockaddr *sa;
    int i,type;
    
    iface_index = ifam->ifam_index;
    sa = (struct sockaddr *)(ifam + 1);
    for (i = 0; i < RTAX_MAX; i++) {
        if (ifam->ifam_addrs & (1 << i)) {
            type = (1 << i);
            if ( type == RTA_IFA){
                if (sockaddr_to_lisp_addr(sa, &new_addr) == BAD){
                    OOR_LOG (LDBG_2,"process_fbd_address_change: Couldn't process new address message. Wrong address format");
                    return;
                }
                break;
            }
            NEXT_SA(sa);
        }
    }
    
    if (ifam->ifam_type == RTM_NEWADDR){
        OOR_LOG (LDBG_2,"process_fbd_address_change: Added address %s from the interface with iface_index: %d with flags: %d and metric: %d", lisp_addr_to_char(&new_addr), iface_index, ifam->ifam_flags, ifam->ifam_metric);
        nm_process_address_change (ADD,iface_index, &new_addr);
    }else{
        OOR_LOG (LDBG_2,"process_fbd_address_change: Rm address %s from the interface with iface_index: %d with flags: %d and metric: %d", lisp_addr_to_char(&new_addr), iface_index, ifam->ifam_flags, ifam->ifam_metric);
        nm_process_address_change (RM,iface_index, &new_addr);
    }
}

void
process_fbd_link_change (struct if_msghdr *ifm)
{
    iface_t *iface;
    int iface_index;
    int old_iface_index;
    uint8_t new_status;
    char iface_name[IF_NAMESIZE];
    
    
    iface_index = ifm->ifm_index;
    
    iface = get_interface_from_index(iface_index);
    
    if (iface == NULL) {
        /*
         * In some OS when a virtual interface is removed and added again,
         * the index of the interface change. Search iface_t by the interface
         * name and update the index. */
        if (if_indextoname(iface_index, iface_name) != NULL) {
            iface = get_interface(iface_name);
        }
        if (iface == NULL) {
            OOR_LOG(LDBG_2, "process_fbd_link_change: the routing message is not for "
                    "any interface associated with RLOCs  (%s)", iface_name);
            return;
        } else {
            old_iface_index = iface->iface_index;
        }
    }else{
        old_iface_index = iface_index;
    }
    
    /* Get the new status */
    if (ifm->ifm_flags & IFF_UP) {
        new_status = UP;
    } else {
        new_status = DOWN;
    }
    OOR_LOG(LDBG_2, "process_fbd_link_change: Status of the link (%s) changed to %s", iface_name, new_status ? "UP":"DOWN");
    nm_process_link_change(old_iface_index, iface_index, new_status);
}
