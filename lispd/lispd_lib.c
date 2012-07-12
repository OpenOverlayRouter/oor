/*
 * lispd_lib.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Various library routines.
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
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "linux/netlink.h"
#include "lispd_external.h"

/*
 *      build_receive_sockets
 *
 *      Set up the receive sockets. Note that if you use a 
 *      a random port, which is used as  the source port used 
 *      in the inner UDP header of the encapsulated 
 *      map-request. If proxy-reply on, you will receive map-replies
 *      destined to this port (i.e., the destination port). e.g.,
 *
 *      No. Time     Source         Destination     Protocol Info
 *      97  5.704114 128.223.156.23 128.223.156.117 LISP     Map-Reply
 *      ...
 *      Internet Protocol, Src: 128.223.156.23 (128.223.156.23), Dst: 128.223.156.117 (128.223.156.117)
 *      User Datagram Protocol, Src Port: lisp-control (4342), Dst Port: 48849 (48849)
 *      Locator/ID Separation Protocol
 *
 *      In this case, 48849 was the random source port I put in the 
 *      inner UDP header source port in the encapsulated map-request 
 *      which was sent to to the map-server at 128.223.156.23. 
 *
 *      So we'll just use src port == dest port == 4342. Note that you
 *      need to setsockopt SO_REUSEADDR or you'll get bind: address in use. 
 *
 */

int build_receive_sockets(void)
{

    struct protoent     *proto;
    struct sockaddr_in  v4;
    struct sockaddr_in6 v6;
    int                 tr = 1;
    
    if ((proto = getprotobyname("UDP")) == NULL) {
        syslog(LOG_DAEMON, "getprotobyname: %s", strerror(errno));
        return(0);
    }

    /*
     *  build the v4_receive_fd, and make the port reusable
     */

    if ((v4_receive_fd = socket(AF_INET,SOCK_DGRAM,proto->p_proto)) < 0) {
        syslog(LOG_DAEMON, "socket (v4): %s", strerror(errno));
        return(0);
    }

    if (setsockopt(v4_receive_fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &tr,
                   sizeof(int)) == -1) {
        syslog(LOG_DAEMON, "setsockopt SO_REUSEADDR (v4): %s", strerror(errno));
        return(0);
    }

/*
    if (setsockopt(v4_receive_fd,
                   SOL_SOCKET,
                   SO_BINDTODEVICE,
                   &(ctrl_iface->iface_name),
                   sizeof(int)) == -1) {
        syslog(LOG_DAEMON, "setsockopt SO_BINDTODEVICE (v4): %s", strerror(errno));
    }
*/
    memset(&v4,0,sizeof(v4));           /* be sure */
    v4.sin_port        = htons(LISP_CONTROL_PORT);
    v4.sin_family      = AF_INET;
    v4.sin_addr.s_addr = INADDR_ANY;

    if (bind(v4_receive_fd,(struct sockaddr *) &v4, sizeof(v4)) == -1) {
        syslog(LOG_DAEMON, "bind (v4): %s", strerror(errno));
        return(0);
    }

    /*
     *  build the v6_receive_fd, and make the port reusable
     */

    if ((v6_receive_fd = socket(AF_INET6,SOCK_DGRAM,proto->p_proto)) < 0) {
        syslog(LOG_DAEMON, "socket (v6): %s", strerror(errno));
        return(0);
    }

    if (setsockopt(v6_receive_fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &tr,
                   sizeof(int)) == -1) {
        syslog(LOG_DAEMON, "setsockopt SO_REUSEADDR (v6): %s", strerror(errno));
        return(0);
    }

/*
    if (setsockopt(v6_receive_fd,
                   SOL_SOCKET,
                   SO_BINDTODEVICE,
                   &(ctrl_iface->iface_name),
                   sizeof(int)) == -1) {
        syslog(LOG_DAEMON, "setsockopt SO_BINDTODEVICE (v6): %s", strerror(errno));
    }
*/

    memset(&v6,0,sizeof(v6));                   /* be sure */
    v6.sin6_family   = AF_INET6;
    v6.sin6_port     = htons(LISP_CONTROL_PORT);
    v6.sin6_addr     = in6addr_any;

    if (bind(v6_receive_fd,(struct sockaddr *) &v6, sizeof(v6)) == -1) {
        syslog(LOG_DAEMON, "bind (v6): %s", strerror(errno));
        return(0);
    }
 
    return(1);
}
  

/*
 *      get_afi
 *
 *      Assume if there's a colon in str that its an IPv6 
 *      address. Otherwise its v4.
 *
 *      David Meyer
 *      dmm@1-4-5.net
 *      Wed Apr 21 16:31:34 2010
 *
 *      $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */

int get_afi(str)
     char *str;
{ 
    if (strchr(str,':'))                /* poor-man's afi discriminator */
        return(AF_INET6);
    else        
        return(AF_INET);
}

/*
 *      copy_lisp_addr_t
 *
 *      Copy a lisp_addr_t, converting it using convert
 *      if supplied
 */

int copy_lisp_addr_t(a1,a2,convert)
     lisp_addr_t *a1;
     lisp_addr_t *a2;
     int          convert;
{
    a1->afi = a2->afi;
    switch (a2->afi) {
    case AF_INET:
        if (convert)
            a1->address.ip.s_addr = htonl(a2->address.ip.s_addr);
        else 
            a1->address.ip.s_addr = a2->address.ip.s_addr;
        break;
    case AF_INET6:
        memcpy(a1->address.ipv6.s6_addr,
               a2->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        break;
    default:
        syslog(LOG_DAEMON, "copy_lisp_addr_t: Unknown AFI (%d)", a2->afi);
        return(0);
    }
    return(1);
}



/*
 *      copy_addr
 *
 *      Copy a lisp_addr_t to a memory location, htonl'ing it
 *      it convert != 0. Return the length or 0;
 */

int copy_addr(a1,a2,convert)
     void *a1;
     lisp_addr_t *a2;
     int convert;
{

    switch (a2->afi) {
    case AF_INET:
        if (convert)
            ((struct in_addr *) a1)->s_addr = htonl(a2->address.ip.s_addr);
        else 
            ((struct in_addr *) a1)->s_addr = a2->address.ip.s_addr;
        return(sizeof(struct in_addr));
    case AF_INET6:
        memcpy(((struct in6_addr *) a1)->s6_addr,
               a2->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        return(sizeof(struct in6_addr));
    default:
        syslog(LOG_DAEMON, "copy_addr: Unknown AFI (%d)", a2->afi);
        return(0);
    }
}


/*
 *      find a useable source address with AFI = afi
 */
 
/* TODO (LJ): To avoid memory leaks, the lisp_addr_t should be allocated
 *            by caller and a pointer passed as parameter. Update calls! */
lisp_addr_t *get_my_addr(if_name, afi)
     char       *if_name;
     int        afi;
{
    lisp_addr_t         *addr;
    struct ifaddrs      *ifaddr;
    struct ifaddrs      *ifa;
    struct sockaddr_in  *s4;
    struct sockaddr_in6 *s6;

    if ((addr = malloc(sizeof(lisp_addr_t))) == NULL) {
        syslog(LOG_DAEMON, "malloc (get_my_addr): %s", strerror(errno));
        return(0);
    }

    memset(addr, 0, sizeof(lisp_addr_t));

    if (getifaddrs(&ifaddr) !=0) {
        syslog(LOG_DAEMON, "getifaddrs(get_my_addr): %s", strerror(errno));
        free(addr);
        return(0);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr             == NULL) ||
            ((ifa->ifa_flags & IFF_UP) == 0)    ||
            (ifa->ifa_addr->sa_family  != afi)  ||
            strcmp(ifa->ifa_name, if_name))
            continue;
        switch (ifa->ifa_addr->sa_family) {
        case AF_INET:
            s4 = (struct sockaddr_in *)(ifa->ifa_addr);
            memcpy((void *) &(addr->address),
                   (void *)&(s4->sin_addr), sizeof(struct in_addr));
            addr->afi = (ifa->ifa_addr)->sa_family;
            freeifaddrs(ifaddr);
            return(addr);
        case AF_INET6:
            s6 = (struct sockaddr_in6 *)(ifa->ifa_addr);
            memcpy((void *) &(addr->address),
                   (void *)&(s6->sin6_addr), sizeof(struct in6_addr));
            addr->afi = (ifa->ifa_addr)->sa_family;
            freeifaddrs(ifaddr);
            return(addr);
        default:
            continue;                   /* keep looking */
        }
    }
    free(addr);
    freeifaddrs(ifaddr);
    return(0);                          /* no luck */
}

/*
 *      lispd_get_address
 *
 *      return lisp_addr_t for host/FQDN or 0 if none
 */

lisp_addr_t *lispd_get_address(host, addr, flags)
    char             *host;
    lisp_addr_t      *addr;
    unsigned int     *flags;
{
    struct hostent      *hptr;

    /* 
     * make sure this is clean
     */

    memset(addr, 0, sizeof(lisp_addr_t));

    /*
     *  check to see if hhost is either a FQDN of IPvX address.
     */

    if (((hptr = gethostbyname2(host,AF_INET))  != NULL) ||
        ((hptr = gethostbyname2(host,AF_INET6)) != NULL)) {
        memcpy((void *) &(addr->address),
               (void *) *(hptr->h_addr_list), sizeof(lisp_addr_t));
        addr->afi = hptr->h_addrtype;
        if (isfqdn(host))
            *flags = FQDN_LOCATOR;      
        else 
            *flags = STATIC_LOCATOR;
        return(addr);
    } 
    return(NULL);
}

/*
 *  lispd_get_iface_address
 *
 *  return lisp_addr_t for the interface, 0 if none
 */

lisp_addr_t *lispd_get_iface_address(ifacename, addr)
    char                *ifacename;
    lisp_addr_t         *addr;
{
    struct ifaddrs      *ifaddr;
    struct ifaddrs      *ifa;
    struct sockaddr_in  *s4;
    struct sockaddr_in6 *s6;
    char addr_str[MAX_INET_ADDRSTRLEN];

    /* 
     * make sure this is clean
     */

    memset(addr, 0, sizeof(lisp_addr_t));

    /*
     *  go search for the interface
     */

    if (getifaddrs(&ifaddr) !=0) {
        syslog(LOG_DAEMON,
               "getifaddrs(get_interface_addr): %s", strerror(errno));
        return(0);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr == NULL) || ((ifa->ifa_flags & IFF_UP) == 0))
            continue;
        switch (ifa->ifa_addr->sa_family) {
        case AF_INET:
            s4 = (struct sockaddr_in *)(ifa->ifa_addr);
            if (!strcmp(ifa->ifa_name, ifacename)) {
                memcpy((void *) &(addr->address),
                       (void *)&(s4->sin_addr), sizeof(struct in_addr));
                addr->afi = AF_INET;
                syslog(LOG_DAEMON, "MN's IPv4 RLOC from interface (%s): %s \n",
                        ifacename, 
                        inet_ntop(AF_INET, &(s4->sin_addr), 
                            addr_str, MAX_INET_ADDRSTRLEN));
                freeifaddrs(ifaddr);
                return(addr);
            } else {
                continue;
            }
        case AF_INET6:
            s6 = (struct sockaddr_in6 *)(ifa->ifa_addr);
            if (!strcmp(ifa->ifa_name, ifacename)) {
                memcpy((void *) &(addr->address),
                       (void *)&(s6->sin6_addr),
                       sizeof(struct in6_addr));
                addr->afi = AF_INET6;
                syslog(LOG_DAEMON, "MN's IPv6 RLOC from interface (%s): %s\n",
                        ifacename, 
                        inet_ntop(AF_INET6, &(s6->sin6_addr), 
                            addr_str, MAX_INET_ADDRSTRLEN));
                freeifaddrs(ifaddr);
                return(addr);
            } else {
                continue;
            }
        default:
            continue;                   /* XXX */
        }
    }
    freeifaddrs(ifaddr);
    return(NULL);
}

/*
 *      dump_X
 *
 *      walk the lispd X data structures 
 *
 *      David Meyer
 *      dmm@1-4-5.net
 *      Wed Apr 21 14:08:42 2010
 *
 *      $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */

void dump_database_entry(db_entry)
        lispd_db_entry_t *db_entry;
{
    int              afi;
    char             eid[128];
    char             rloc[128];
    char             buf[128];

    afi = db_entry->eid_prefix.afi;
    inet_ntop(afi,
              &(db_entry->eid_prefix.address),
              eid,
              128);
    inet_ntop(db_entry->locator.afi,
              &(db_entry->locator.address),
              rloc, 128);
    sprintf(buf, "%s (%s)", db_entry->locator_name, rloc);
    syslog(LOG_DAEMON, " %s lisp %s/%d %s p %d w %d",
           (afi == AF_INET) ? "ip":"ipv6",
           eid,
           db_entry->eid_prefix_length,
           buf,
           db_entry->priority,
           db_entry->weight);
}

void dump_database(tree, afi)
        patricia_tree_t *tree;
        int             afi;
{
    patricia_node_t             *node;
    lispd_locator_chain_t       *locator_chain;
    lispd_locator_chain_elt_t   *locator_chain_elt;
    lispd_db_entry_t            *db_entry;

    if (!tree) {
        switch (afi) {
        case AF_INET:
            syslog(LOG_DAEMON, "No database for AF_INET");
            return;
        case AF_INET6:
            syslog(LOG_DAEMON, "No database for AF_INET6");
            return;
        default:        
            syslog(LOG_DAEMON, "Unknown database AFI (%d)", afi);
            return;
        }
    }
    syslog(LOG_DAEMON, "database:");
    PATRICIA_WALK(tree->head, node) {
        locator_chain     = ((lispd_locator_chain_t *)(node->data));
        locator_chain_elt = locator_chain->head;
        while (locator_chain_elt) {
            db_entry = locator_chain_elt->db_entry;
            dump_database_entry(db_entry);
            locator_chain_elt = locator_chain_elt->next;
        }
    } PATRICIA_WALK_END;
}


void dump_servers(list, list_name)
    lispd_addr_list_t   *list;
    const char          *list_name;
{ 
    lisp_addr_t         *addr     = 0;
    lispd_addr_list_t   *iterator = 0;
    int                 afi; 
    char                buf[128];

    if (!list)
        return;

    syslog(LOG_DAEMON, "%s:", list_name);

    iterator = list;
    while (iterator) {
        addr = iterator->address;
        afi = addr->afi;
        inet_ntop(afi, &(addr->address), buf, sizeof(buf));
        syslog(LOG_DAEMON," %s", buf);
        iterator = iterator->next;
    }
}

void dump_map_server(ms)
    lispd_map_server_list_t *ms;
{
    int                     afi;
    lisp_addr_t             *addr;
    char                    buf[128];

    addr = ms->address;
    afi = addr->afi;
    inet_ntop(afi, &(addr->address), buf, sizeof(buf));
    syslog(LOG_DAEMON, " %s key-type: %d key: %s",
       buf,
       ms->key_type,
       ms->key);
}

void dump_map_servers(void)
{
    lispd_map_server_list_t *ms;

    if (!map_servers)
        return;

    syslog(LOG_DAEMON, "map-servers:");
    ms = map_servers;

    while (ms) {
        dump_map_server(ms);
        ms = ms->next;
    }
}

void dump_map_cache(void)
{
    lispd_map_cache_t       *map_cache;
    lispd_map_cache_entry_t *map_cache_entry;
    int              afi; 
    unsigned int     ttl; 
    char             eid[128];
    char             rloc[128];

    if (!lispd_map_cache)
        return;

    syslog(LOG_DAEMON, "map-cache:");
    map_cache = lispd_map_cache;

    while (map_cache) {
        map_cache_entry = &(map_cache->map_cache_entry);
        afi = map_cache_entry->eid_prefix.afi;
        ttl = map_cache_entry->ttl;
        inet_ntop(afi,
                  &(map_cache_entry->eid_prefix.address),
                  eid,
                  128);
        inet_ntop(map_cache_entry->locator.afi,
                  &(map_cache_entry->locator.address),
                  rloc, 128);
        syslog(LOG_DAEMON," %s lisp %s/%d %s p %d w %d ttl %d (%s)",
           (afi == AF_INET) ? "ip":"ipv6",
           eid,
           map_cache_entry->eid_prefix_length, 
           rloc,
           map_cache_entry->priority,
           map_cache_entry->weight,
           ttl,
           (map_cache_entry->how_learned == STATIC_MAP_CACHE_ENTRY)
           ? "static" : "dynamic");
        map_cache = map_cache->next;
    }
}


/* 
 *      isfqdn(char *s)
 *
 *      See if a string qualifies as an FQDN. To qualifiy, s must
 *      contain one or more dots. The dots may not be the first
 *      or the last character. Two dots may not immidiately follow
 *      each other. It must consist of the characters a..z, A..Z,,
 *      0..9, '.', '-'. The first character must be a letter or a digit.
 */

int isfqdn(char *s)
{
    int         i = 1;
    uint8_t     dot = 0;
    char        c;

    if ((!isalnum(s[0])) || (!strchr(s,':')))
        return(0);

    while (((c = s[i]) != 0) && (c != ',') && (c != ':')) {
        if (c == '.') {
            dot = 1;
            if (s[i-1] == '.')
                return(0);
        }
        if (!(isalnum(c) || c=='-' || c=='.'))
            return(0);
        i++;
    }

    if (s[0] == '.' || s[i-1] == '.')
        return(0);

    return(dot);
}

void dump_tree_elt(locator_chain)
    lispd_locator_chain_t *locator_chain;
{
    syslog(LOG_DAEMON, " locator_chain->eid_name = %s",
           locator_chain->eid_name);
}

void dump_tree(afi,tree)
     int afi;
     patricia_tree_t *tree;

{
    patricia_node_t *node;
   
    switch (afi) {
    case AF_INET:
        printf("dump_tree for AF_INET\n");
        break;
    case AF_INET6:
        printf("dump_tree for AF_INET6\n");
        break;
    }

    PATRICIA_WALK(tree->head, node) {
        printf("node: %s/%d\n", 
               prefix_toa(node->prefix), node->prefix->bitlen);
        printf("dump_tree:\t%s (%d)\n",
               ((lispd_locator_chain_t *)(node->data))->eid_name,
               ((lispd_locator_chain_t *)(node->data))->locator_count);
        dump_tree_elt((lispd_locator_chain_t *)(node->data));

    } PATRICIA_WALK_END;
}


/*
 *  connect up the locator_chain and locator_chain_elt sorted by RLOC
 */

int add_locator_chain_elt(locator_chain, locator_chain_elt)
    lispd_locator_chain_t       *locator_chain;
    lispd_locator_chain_elt_t   *locator_chain_elt;
{
    lispd_locator_chain_elt_t   *aux_locator_chain_elt = NULL;
    lispd_locator_chain_elt_t   *prev_aux_locator_chain_elt = NULL;
    int find_bigger_rloc = 0;

    if (locator_chain->head == NULL) {
        locator_chain->head = locator_chain_elt;
        locator_chain->tail = locator_chain_elt;
    } else {
        aux_locator_chain_elt = locator_chain->head;
        while (aux_locator_chain_elt != NULL)
        {
            if (locator_chain_elt->db_entry->locator.afi == AF_INET){
                if (aux_locator_chain_elt->db_entry->locator.afi == AF_INET6){
                    find_bigger_rloc = 1;
                    break;
                }else {
                    if (memcmp(&locator_chain_elt->db_entry->locator.address.ip,&aux_locator_chain_elt->db_entry->locator.address.ip,sizeof(struct in_addr))<0 )
                    {
                        find_bigger_rloc = 1;
                        break;
                    }
                }
            }else{
                if (aux_locator_chain_elt->db_entry->locator.afi == AF_INET6){
                    if (memcmp(&locator_chain_elt->db_entry->locator.address.ipv6,&aux_locator_chain_elt->db_entry->locator.address.ipv6,sizeof(struct in6_addr))<0){
                        find_bigger_rloc = 1;
                        break;
                    }
                }
            }
            prev_aux_locator_chain_elt = aux_locator_chain_elt;
            aux_locator_chain_elt = aux_locator_chain_elt->next;
        }
        if (find_bigger_rloc == 1){
            if (prev_aux_locator_chain_elt == NULL){
                locator_chain_elt->next = aux_locator_chain_elt;
                locator_chain->head = locator_chain_elt;
            }else {
                locator_chain_elt->next = aux_locator_chain_elt;
                prev_aux_locator_chain_elt->next = locator_chain_elt;
            }
        }else{
            locator_chain->tail->next = locator_chain_elt;
            locator_chain->tail       = locator_chain_elt;
        }
    }
    locator_chain->locator_count++;
    return 1;
}


void debug_installed_database_entry(db_entry, locator_chain)
    lispd_db_entry_t            *db_entry;
    lispd_locator_chain_t       *locator_chain;
{
    char        buf[128];
    char        rloc[128];

    inet_ntop(db_entry->locator.afi,
              &(db_entry->locator.address),
              rloc, 128);

    if (db_entry->locator_type == STATIC_LOCATOR)
        sprintf(buf, "%s", rloc);
    else
        sprintf(buf, "%s (%s)", db_entry->locator_name, rloc);
    syslog(LOG_DAEMON, "  Installed %s lisp %s %s p %d w %d",
       (locator_chain->eid_prefix.afi == AF_INET) ? "ip":"ipv6",
       locator_chain->eid_name,
       buf,
       db_entry->priority,
       db_entry->weight);
}

void print_hmac(hmac,len)
     uchar *hmac;
     int len;
{

    int i;

    for (i = 0; i < len; i += 4) {
        printf("i = %d\t(0x%04x)\n", i, (unsigned int) hmac[i]);
    }
    printf("\n");
}
     
     
/*
 *      get_lisp_afi
 *
 *      Map from Internet AFI -> LISP_AFI
 *
 *      Get the length while your at it
 */         

int get_lisp_afi(afi, len)
     int        afi;
     int        *len;
{

    switch (afi) {
    case AF_INET:
        if (len)
            *len = sizeof(struct in_addr);
        return(LISP_AFI_IP);
    case AF_INET6:
        if (len)
            *len = sizeof(struct in6_addr);
        return(LISP_AFI_IPV6);
    default:
        syslog(LOG_DAEMON, "get_lisp_afi: unknown AFI (%d)", afi);
        return(0);
    }
}

/*
 *      lisp2inetafi
 *
 *      Map from Internet LISP AFI -> INET AFI
 *
 */         

int lisp2inetafi(afi)
     int        afi;
{
    switch (afi) {
    case 0:
        return(0);
    case LISP_AFI_IP:
        return(AF_INET);
    case LISP_AFI_IPV6:
        return(AF_INET6);
    default:
        syslog(LOG_DAEMON, "lisp2inetafi: unknown AFI (%d)", afi);
        return(0);
    }
}


/*
 *      given afi, get the IP header length
 */

int get_ip_header_len(afi)
        int afi;
{
    switch (afi) {                      /* == eid_afi */
    case AF_INET:
        return(sizeof(struct ip));
    case AF_INET6:
        return(sizeof(struct ip6_hdr));
    default:
        syslog(LOG_DAEMON, "get_ip_header_len: unknown AFI (%d)", afi);
        return(0);
    }
}


/*
 *      given afi, get sockaddr len
 */

int get_sockaddr_len(afi)
        int afi;
{
    switch (afi) {                      /* == eid_afi */
    case AF_INET:
        return(sizeof(struct sockaddr_in));
    case AF_INET6:
        return(sizeof(struct sockaddr_in6));
    default:
        syslog(LOG_DAEMON, "get_sockaddr_len: unknown AFI (%d)", afi);
        return(0);
    }
}


/*
 *      given afi, get addr len
 */

int get_addr_len(afi)
        int afi;
{
    switch (afi) {                      /* == eid_afi */
    case AF_INET:
        return(sizeof(struct in_addr));
    case AF_INET6:
        return(sizeof(struct in6_addr));
    default:
        syslog(LOG_DAEMON, "get_addr_len: unknown AFI (%d)", afi);
        return(0);
    }
}


/*
 *      given afi, get prefix len
 */

int get_prefix_len(afi)
        int afi;
{
    return(get_addr_len(afi) * 8);
}

struct udphdr *build_ip_header(cur_ptr,my_addr,eid_prefix, ip_len)
        void                  *cur_ptr;
        lisp_addr_t           *my_addr;
        lisp_addr_t           *eid_prefix;
        int                   ip_len;
{
    struct ip      *iph;
    struct ip6_hdr *ip6h;
    struct udphdr  *udph;

    switch (my_addr->afi) {
    case AF_INET:
        iph                = (struct ip *) cur_ptr;
        iph->ip_hl         = 5;
        iph->ip_v          = IPVERSION;
        iph->ip_tos        = 0;
        iph->ip_len        = htons(ip_len);
        iph->ip_id         = htons(54321);
        iph->ip_off        = 0;
        iph->ip_ttl        = 255;
        iph->ip_p          = IPPROTO_UDP;
        iph->ip_sum        = 0;         
        iph->ip_src.s_addr = my_addr->address.ip.s_addr;
        iph->ip_dst.s_addr = eid_prefix->address.ip.s_addr; 
        udph              = (struct udphdr *) CO(iph,sizeof(struct ip));
        break;
    case AF_INET6:
        ip6h           = (struct ip6_hdr *) cur_ptr;
        ip6h->ip6_hops = 255;
        ip6h->ip6_vfc  = (IP6VERSION << 4);
        ip6h->ip6_nxt  = IPPROTO_UDP;
        ip6h->ip6_plen = htons(ip_len);
        memcpy(ip6h->ip6_src.s6_addr,
               my_addr->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        memcpy(ip6h->ip6_dst.s6_addr,
               eid_prefix->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        udph = (struct udphdr *) CO(ip6h,sizeof(struct ip6_hdr));
        break;
    default:
        return(0);
    }
    return(udph);
}

/*
 *      requires librt
 */

uint64_t build_nonce(seed)
     int        seed;
{

    uint64_t            nonce; 
    uint32_t            nonce_lower;
    uint32_t            nonce_upper; 
    struct timespec     ts; 
 
    /* 
     * Put nanosecond clock in lower 32-bits and put an XOR of the nanosecond 
     * clock with the seond clock in the upper 32-bits. 
     */ 

    clock_gettime(CLOCK_MONOTONIC,&ts); 
    nonce_lower = ts.tv_nsec; 
    nonce_upper = ts.tv_sec ^ htonl(nonce_lower); 
 
    /* 
     * OR in a caller provided seed to the low-order 32-bits. 
     */ 
    nonce_lower |= seed; 
 
    /* 
     * Return 64-bit nonce. 
     */ 
    nonce = nonce_upper; 
    nonce = (nonce << 32) | nonce_lower; 
    return(nonce); 
} 
 
/* 
 * lisp_print_nonce 
 * 
 * Print 64-bit nonce in 0x%08x-0x%08x format. 
 */ 
void lispd_print_nonce (nonce)
     uint64_t nonce;
{ 
    uint32_t lower; 
    uint32_t upper; 
 
    lower = nonce & 0xffffffff; 
    upper = (nonce >> 32) & 0xffffffff; 
    syslog(LOG_DAEMON,"nonce: 0x%08x-0x%08x\n", htonl(upper), htonl(lower)); 
} 
 
/*
 *      API functions of datacache entries (updated acabello)
 */

// Build new datacache entry and insert timer into ordered list of timers


int build_datacache_entry(dest,
                        eid_prefix,
                       eid_prefix_length,
                       nonce,
                       islocal,
                       probe,
                       smr_invoked,
                       retries,
                       timeout,
                       encap)
     lisp_addr_t  *dest;
     lisp_addr_t  *eid_prefix;
     uint8_t      eid_prefix_length;
     uint64_t     nonce;
     uint8_t      islocal;
     uint8_t      probe;
     uint8_t      smr_invoked;
     uint8_t      retries;
     uint16_t     timeout;
     uint8_t      encap;
{

    datacache_elt_t *elt;
    timer_rec_t *timer_rec;
    timer_rec_t *temp_rec;
    timer_rec_t *prev_rec;

    if ((elt = malloc(sizeof(datacache_elt_t))) == NULL) {
        syslog(LOG_DAEMON,
           "malloc (build_datacache_entry): %s", strerror(errno));
        return(0);
    }
    memset(elt, 0, sizeof(datacache_elt_t));

    elt->nonce             = nonce;
    elt->local             = islocal;
    elt->ttl               = DEFAULT_DATA_CACHE_TTL;
    if (eid_prefix->afi == AF_INET) {
    memcpy((void*)&(elt->eid_prefix.address.ip),(void*)&(eid_prefix->address.ip),sizeof(struct sockaddr_in));
    }
    else if (eid_prefix->afi == AF_INET6) {
    memcpy((void*)&(elt->eid_prefix.address.ipv6),(void*)&(eid_prefix->address.ipv6),sizeof(struct sockaddr_in6));
    }
    elt->dest.afi          = dest->afi;
    if (elt->dest.afi==AF_INET) {
    memcpy((void*)&(elt->dest.address),(void*) &(dest->address),sizeof(struct sockaddr_in));
    }
    else if (elt->dest.afi==AF_INET6) {
    memcpy((void*)&(elt->dest.address),(void*) &(dest->address),sizeof(struct sockaddr_in6));
    }
    else {
    syslog(LOG_DAEMON,"Unknown AFI (build_datacache_entry): %d", elt->dest.afi);
    return 0;
    }

    elt->eid_prefix_length = eid_prefix_length;
    elt->eid_prefix.afi    = eid_prefix->afi;
    elt->probe             = probe;
    elt->smr_invoked       = smr_invoked;
    elt->retries           = retries;
    elt->encap             = encap;
    elt->timeout           = timeout;
    elt->next              = NULL;
    elt->prev              = datacache->tail;

    /* link up the entry */

    if (datacache->tail)
        (datacache->tail)->next = elt;
    else 
        datacache->head = elt;
    datacache->tail = elt;

    /* insert new nonce into ordered list of timers */

    if ((timer_rec = malloc(sizeof(timer_rec_t))) == NULL) {
        syslog(LOG_DAEMON,
           "malloc (build_datacache_entry): %s", strerror(errno));
        return(0);
    }

    memset(timer_rec,0,sizeof(timer_rec_t));

    timer_rec->elt=elt;
    elt->timer=timer_rec;
    time(&(timer_rec->timer));
    timer_rec->timer=(timer_rec->timer) + timeout;
    // if (smr) timer_rec->timer=(timer_rec->timer)+(datacache->timer_datacache->smr_timeout);
    // else timer_rec->timer=(timer_rec->timer)+(datacache->timer_datacache->mrq_timeout);
    temp_rec = datacache->timer_datacache->head;

    if (temp_rec==NULL) { //timer_datacache is empty
    timer_rec->next=NULL;
    timer_rec->prev=NULL;
    datacache->timer_datacache->head=timer_rec;
    datacache->timer_datacache->tail=timer_rec;
    return (1);
    }

    prev_rec=NULL;
    while(temp_rec!=NULL) {
    if (temp_rec->timer>timer_rec->timer) {
        if (prev_rec==NULL) {// New record is the first one
            timer_rec->next=temp_rec;
            timer_rec->prev=NULL;
            datacache->timer_datacache->head=timer_rec;
        temp_rec->prev=timer_rec;
        return (1);
        }
        else { // This is not the first record
            timer_rec->next=temp_rec;
            timer_rec->prev=prev_rec;
            temp_rec->prev=timer_rec;
            prev_rec->next=timer_rec;
            return (1);
        }
    }
    prev_rec=temp_rec;
    temp_rec=temp_rec->next;
    }

    // New record is the last one
    timer_rec->next=NULL;
    timer_rec->prev=prev_rec;
    prev_rec->next=timer_rec;
    datacache->timer_datacache->tail=timer_rec;

    return(1);
}
    
// Modified by acabello
// Timeout expired entries and trigger appropriate actions
void expire_datacache() {
    time_t current_t;
    timer_rec_t *temp_rec;
    timer_rec_t *next_rec;

    if (datacache->timer_datacache->head==NULL) return;
    current_t=time(NULL);

    temp_rec=datacache->timer_datacache->head;
    while(temp_rec!=NULL) {
        if (temp_rec->timer>current_t) return;
        next_rec=temp_rec->next;
        (*datacache->timer_datacache->callback)(temp_rec->elt);
        temp_rec=next_rec;
    }
}

// Modified by acabello
// Deletes a datacache entry
void delete_datacache_entry(elt)
    datacache_elt_t *elt;
{
    timer_rec_t *temp_rec;

    // Resetting ELT list
    if (elt->next==NULL){ // This is the last entry
        datacache->tail=elt->prev;
        if (elt->prev==NULL){ // This is the only entry
            datacache->head=NULL;
        }
        else {
            (elt->prev)->next=NULL;
        }
    }
    else if (elt->prev==NULL){ // This is the first entry
        datacache->head=elt->next;
        if (elt->next==NULL){ // This is the only entry
            datacache->tail=NULL;
        }
        else {
            (elt->next)->prev=NULL;
        }
    }
    else { // This entry is at the middle of the list
        (elt->next)->prev=elt->prev;
        (elt->prev)->next=elt->next;
    }

    // Resetting timer list
    temp_rec=(timer_rec_t*) elt->timer;

    if (temp_rec->next==NULL){ // This is the last entry
        datacache->timer_datacache->tail=temp_rec->prev;
        if (temp_rec->prev==NULL){ // This is the only entry
            datacache->timer_datacache->head=NULL;
        }
        else {
            (temp_rec->prev)->next=NULL;
        }
    }
    else if (temp_rec->prev==NULL){ // This is the first entry
        datacache->timer_datacache->head=temp_rec->next;
        if (temp_rec->next==NULL){ // This is the only entry
            datacache->timer_datacache->tail=NULL;
        }
        else {
            (temp_rec->next)->prev=NULL;
        }
    }
    else { // This entry is at the middle of the list
        (temp_rec->next)->prev=temp_rec->prev;
        (temp_rec->prev)->next=temp_rec->next;
    }

    // Ready to free
    free((void*)elt);
    free((void*)temp_rec);
}

// Modified by acabello
// Check if address is included into another address
int is_eid_included(elt, eid_prefix_mask_length, eid)
    datacache_elt_t* elt;
    int eid_prefix_mask_length;
    lisp_addr_t *eid;
{
    // ToDo: acabello
    return 1;
}

// Modified by acabello
// Search a datacache entry based on EID prefix and returns it in res_elt
int search_datacache_entry_eid(eid_prefix, res_elt)
    lisp_addr_t* eid_prefix;
    datacache_elt_t **res_elt;
{

        /* PN, DM:
         * Note: Code here checks for an exact eid match.
         * Checking for exact match will work only when map reply is
         * for a MN (/32 or /128). Will not work for lisp sites with
         * eid prefixes.
         * Accomplishing the latter involves more work in terms of
         * suitable datacache structure to search/delete eid prefixes
         *
         */
    datacache_elt_t *elt;

    elt=datacache->head;
    while(elt!=NULL) {
        int res;
        if ((eid_prefix->afi == AF_INET) && (eid_prefix->afi==elt->eid_prefix.afi)) {
            if ((eid_prefix->address).ip.s_addr==(elt->eid_prefix).address.ip.s_addr) {
                return 1;
            //res=memcmp((void*)&((eid_prefix->address).ip.s_addr),(void*)&((elt->eid_prefix).address.ip.s_addr),sizeof(struct sockaddr_in));
            //if (res==0) {
            //  *res_elt=elt;
            //  return 1;
            }

        }
        if ((eid_prefix->afi == AF_INET6) && (eid_prefix->afi==elt->eid_prefix.afi)) {
            res=memcmp((void*)&((eid_prefix->address).ipv6),(void*)&((elt->eid_prefix).address.ipv6),sizeof(struct sockaddr_in6));
            if (res==0) {
                *res_elt=elt;
                return 1;
            }
        }
        elt=elt->next;
    }

    // EID not found
#if (DEBUG > 3)
    syslog(LOG_INFO, "Entry not found in datacache: EID doesn't match");
#endif
    return 0;
}

// Modified by acabello
// Search a datacache entry based on nonce and returns it in res_elt
int search_datacache_entry_nonce (nonce,res_elt)
    uint64_t nonce;
    datacache_elt_t **res_elt;
{


    datacache_elt_t *elt;

    elt=datacache->head;
    while(elt!=NULL) {
        if (elt->nonce==nonce) {
            // Nonce match
            *res_elt=elt;
            return 1;
        }
        elt=elt->next;
    }

    // Nonce not found
#if (DEBUG > 3)
    syslog(LOG_INFO, "Entry not found in datacache: nonce doesn't match");
#endif
    return 0;
}

// Modified by acabello
// Deletes a datacache entry
int init_datacache(cbk)
    void (*cbk)(datacache_elt_t*);
{


    if ((datacache = malloc(sizeof(datacache_t))) == NULL){
        syslog(LOG_DAEMON, "malloc (datacache): %s", strerror(errno));
        return(1);
    }
        memset (datacache, 0, sizeof(datacache_t));

    datacache->head=NULL;
    datacache->tail=NULL;

    if ((datacache->timer_datacache = malloc(sizeof(timer_datacache_t))) == NULL){
        syslog(LOG_DAEMON, "malloc (timer_datacache): %s", strerror(errno));
        return(1);
    }

    datacache->timer_datacache->callback=cbk;
    datacache->timer_datacache->head=NULL;
    datacache->timer_datacache->tail=NULL;

    return(1);
}

/*
 *  Auxiliary definitions
 *
 */
uint16_t min_timeout(uint16_t a,uint16_t b) {
    if (a<b) return a;
    else return b;
}

/*
 *  select from among readfds, the largest of which 
 *  is max_fd.
 */

int have_input(max_fd,readfds)
  int     max_fd;
  fd_set *readfds;
{

    struct timeval tv;

    tv.tv_sec  = 0;
    tv.tv_usec = DEFAULT_SELECT_TIMEOUT;

    if (select(max_fd+1,readfds,NULL,NULL,&tv) == -1) {
    syslog(LOG_DAEMON, "select: %s", strerror(errno));
    return(0);
    } 
    return(1);
}

/*
 *  Process a LISP protocol message sitting on 
 *  socket s with address family afi
 */

int process_lisp_msg(s, afi)
     int    s;
     int    afi;
{

    uint8_t         packet[MAX_IP_PACKET];
    struct sockaddr_in  s4;
    struct sockaddr_in6 s6;

    switch (afi) {
    case AF_INET:
        memset(&s4,0,sizeof(struct sockaddr_in));
        if (!retrieve_lisp_msg(s, packet, &s4, afi))
            return(0);
        /* process it here */
        break;
    case AF_INET6:
        memset(&s6,0,sizeof(struct sockaddr_in6));
        if (!retrieve_lisp_msg(s, packet, &s6, afi))
            return(0);
        /* process it here */
        break;
    default:
        return(0);
    }
    return(1);
}



/*
 *  Retrieve a mesage from socket s
 */

int retrieve_lisp_msg(s, packet, from, afi)
     int    s;
     uint8_t    *packet;
     void   *from;
     int    afi;
    
{

    struct sockaddr_in  *s4;
    struct sockaddr_in6 *s6;
    socklen_t fromlen4 = sizeof(struct sockaddr_in);
    socklen_t fromlen6 = sizeof(struct sockaddr_in6);

    switch (afi) {
    case AF_INET:
        s4 = (struct sockaddr_in *) from;
        if (recvfrom(s, packet, MAX_IP_PACKET, 0, (struct sockaddr *) s4,
                    &fromlen4) < 0) {
            syslog(LOG_DAEMON, "recvfrom (v4): %s", strerror(errno));
            return(0);
        }
        break;
    case AF_INET6:
        s6 = (struct sockaddr_in6 *) from;
        if (recvfrom(s, packet, MAX_IP_PACKET, 0, (struct sockaddr *) s6,
                    &fromlen6) < 0) {
            syslog(LOG_DAEMON, "recvfrom (v6): %s", strerror(errno));
            return(0);
        }
        break;
    default:
        syslog(LOG_DAEMON, "retrieve_msg: Unknown afi %d", afi);
        return(0);
    }
#if (DEBUG > 3)
    syslog(LOG_DAEMON, "Received a LISP control message");
#endif

    switch (((lispd_pkt_encapsulated_control_t *) packet)->type) {
    case LISP_MAP_REPLY:    //Got Map Reply
#ifdef DEBUG
        syslog(LOG_DAEMON, "Received a LISP Map-Reply message");
#endif
        process_map_reply(packet);
        break;
    case LISP_ENCAP_CONTROL_TYPE:   //Got Encapsulated Control Message
#ifdef DEBUG
        syslog(LOG_DAEMON, "Received a LISP Encapsulated Map-Request message");
#endif
        if(!process_map_request_msg(packet, s, from, afi))
            return (0);
        break;
    case LISP_MAP_REQUEST:      //Got Map-Request
#ifdef DEBUG
        syslog(LOG_DAEMON, "Received a LISP Map-Request message");
#endif
        if(!process_map_request_msg(packet, s, from, afi))
            return (0);
        break;
    case LISP_MAP_REGISTER:     //Got Map-Register, silently ignore
        break;
    case LISP_MAP_NOTIFY:
#ifdef DEBUG
        syslog(LOG_DAEMON, "Received a LISP Map-Notify message");
#endif
        if(!process_map_notify(packet))
            return(0);
        break;
    }
#if (DEBUG > 3)
    syslog(LOG_DAEMON, "Completed processing a LISP control message");
#endif


#if (DEBUG > 3)
    switch (((lispd_pkt_encapsulated_control_t *) packet)->type) {
    case LISP_MAP_REPLY:
        printf("Got Map-Reply (%d)\n", afi);
        break;
    case LISP_MAP_REQUEST:
        printf("Got Map-Request: Silently ignoring it (%d)\n", afi);
        break;
    case LISP_MAP_REGISTER:
        printf("Got Map-Register: Silently ignoring it (%d)\n", afi);
        break;
    case LISP_MAP_NOTIFY:
        printf("Got Map-Notify: Silently ignoring it (%d)\n", afi);
        break;
    case LISP_ENCAP_CONTROL_TYPE:
        printf("Got Encapsulated Control Message (%d)\n", afi);
        break;
    }
#endif
    return(1);
}

    
int inaddr2sockaddr(lisp_addr_t *inaddr, struct sockaddr *sockaddr, uint16_t port) {
    struct sockaddr_in  *ipv4;
    struct sockaddr_in6 *ipv6;

    memset(sockaddr, 0, sizeof(struct sockaddr_storage));

    ipv4 = (struct sockaddr_in *) sockaddr;
    ipv6 = (struct sockaddr_in6 *) sockaddr;

    switch (inaddr->afi) {
    case AF_INET:
        ipv4->sin_family      = AF_INET;
        ipv4->sin_port        = htons(port);
        ipv4->sin_addr.s_addr = inaddr->address.ip.s_addr;
        return(1);
    case AF_INET6:
        ipv6->sin6_family      = AF_INET6;
        ipv6->sin6_port        = htons(port);
        memcpy(&(ipv6->sin6_addr), &(inaddr->address.ipv6), sizeof(struct in6_addr));
        return(1);
    default:
        syslog(LOG_DAEMON, "inaddr2sockaddr: unknown AFI %d", inaddr->afi);
        return(0);
    }
}

int sockaddr2lisp(struct sockaddr *src, lisp_addr_t *dst) {
    if (src == NULL) syslog(LOG_DAEMON, "sockaddr NULL");
    if (src == NULL) return(-1);
    if (dst == NULL) syslog(LOG_DAEMON, "lisp NULL");
    if (dst == NULL) return(-1);

    memset(dst, 0, sizeof(lisp_addr_t));

    dst->afi = src->sa_family;

    switch (src->sa_family) {
    case AF_INET:
        dst->address.ip.s_addr = ((struct sockaddr_in *)src)->sin_addr.s_addr;
        break;
    case AF_INET6:
        memcpy(&(dst->address.ipv6), &(((struct sockaddr_in6 *)src)->sin6_addr),
                sizeof(struct in6_addr));
        break;
    default:
        syslog(LOG_DAEMON, "sockaddr2lisp: unknown AFI (%d)", src->sa_family);
        return(-1);
    }
    return(0);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
