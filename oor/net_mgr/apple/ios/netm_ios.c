//
//  netm_ios.c
//  oor-iOS
//
//  Created by Oriol Marí Marqués on 29/06/2017.
//  Copyright © 2017 Oriol Marí Marqués. All rights reserved.
//

#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>

#include "netm_ios.h"
#include "../../net_mgr.h"
#include "../../net_mgr_proc_fc.h"
#include "iface_mgmt.h"
#include "netm_kernel.h"
#include "../../../lib/oor_log.h"
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
((caddr_t)(ap) + ((ap)->sa_len ? ROUNDUP((ap)->sa_len,\
sizeof(uint32_t)) :\
sizeof(uint32_t)))

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

#define BUFLEN 512

int ios_interface_changed(sock_t *sl) {

    iface_t *iface;
    
    struct sockaddr_in si_other;
    
    int slen = sizeof(si_other) , recv_len;
    char buf[BUFLEN];
    
    //try to receive some data, this is a blocking call
    if ((recv_len = recvfrom(sl->fd, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == -1)
    {
        OOR_LOG(LINF, "recvfrom()");
    }
    
    
    int i = atoi(buf);
    if (i == 1) {
        iface = get_interface("en0");
        nm_process_link_change(iface->iface_index, iface->iface_index, DOWN);
        iface = get_interface("pdp_ip0");
        nm_process_link_change(iface->iface_index, iface->iface_index, UP);
    }
    else if (i == 2) {
        
        iface = get_interface("en0");
       
        glist_t *addr_list = NULL;
        lisp_addr_t **addr;

        addr = &iface->ipv4_address;
        addr_list = net_mgr->netm_get_iface_addr_list(iface->iface_name, AF_INET);
        // For IPv4 get the first address of the list. It should be the only one
        *addr = lisp_addr_clone((lisp_addr_t *)glist_first_data(addr_list));
        glist_destroy(addr_list);
        nm_process_address_change(ADD, iface->iface_index, *addr);
        *addr = ios_get_iface_gw(iface->iface_name, AF_INET);
        lisp_addr_ip_from_char("0.0.0.0", *addr);
        nm_process_route_change(ADD, iface->iface_index, *addr, *addr, *addr);
        nm_process_link_change(iface->iface_index, iface->iface_index, UP);
        iface = get_interface("pdp_ip0");
        nm_process_link_change(iface->iface_index, iface->iface_index, DOWN);
        
    }
    return(GOOD);
}

int ios_netm_init() {
    
    int netm_socket;
    
    //open socket to connect with TunnelProvider
    netm_socket = open_data_datagram_input_socket(AF_INET, 10002);
    sockmstr_register_read_listener(smaster, ios_interface_changed, NULL, netm_socket);
    
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
    src_addr = sockaddr_to_lisp_addr (lcl_addr);
    
    free(sock_addr);
    free(lcl_addr);
    close(sock);
    OOR_LOG(LDBG_3,"ios_get_src_addr_to: Selected src address to %s is %s",
            lisp_addr_to_char(dst_addr), lisp_addr_to_char(src_addr));
    
    return (src_addr);
}
