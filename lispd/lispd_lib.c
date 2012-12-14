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
#include <time.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/netlink.h>
#include "cksum.h"
#include "lispd_lib.h"
#include "lispd_external.h"
#include "lispd_map_request.h"
#include "lispd_map_reply.h"
#include "lispd_map_notify.h"
#include "patricia/patricia.h"



int isfqdn(char *s);

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
        lispd_log_msg(LOG_DAEMON, "getprotobyname: %s", strerror(errno));
        return(BAD);
    }

    /*
     *  build the ipv4_data_input_fd, and make the port reusable
     */

    if ((ipv4_data_input_fd = socket(AF_INET,SOCK_DGRAM,proto->p_proto)) < 0) {
        lispd_log_msg(LOG_DAEMON, "socket (v4): %s", strerror(errno));
        return(BAD);
    }

    if (setsockopt(ipv4_data_input_fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &tr,
                   sizeof(int)) == -1) {
        lispd_log_msg(LOG_DAEMON, "setsockopt SO_REUSEADDR (v4): %s", strerror(errno));
        return(BAD);
    }

/*
    if (setsockopt(ipv4_data_input_fd,
                   SOL_SOCKET,
                   SO_BINDTODEVICE,
                   &(ctrl_iface->iface_name),
                   sizeof(int)) == -1) {
        lispd_log_msg(LOG_DAEMON, "setsockopt SO_BINDTODEVICE (v4): %s", strerror(errno));
    }
*/
    memset(&v4,0,sizeof(v4));           /* be sure */
    v4.sin_port        = htons(LISP_CONTROL_PORT);
    v4.sin_family      = AF_INET;
    v4.sin_addr.s_addr = INADDR_ANY;

    if (bind(ipv4_data_input_fd,(struct sockaddr *) &v4, sizeof(v4)) == -1) {
        lispd_log_msg(LOG_DAEMON, "bind (v4): %s", strerror(errno));
        return(BAD);
    }

    /*
     *  build the v6_receive_fd, and make the port reusable
     */

    if ((ipv6_data_input_fd = socket(AF_INET6,SOCK_DGRAM,proto->p_proto)) < 0) {
        lispd_log_msg(LOG_DAEMON, "socket (v6): %s", strerror(errno));
        return(BAD);
    }

    if (setsockopt(ipv6_data_input_fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &tr,
                   sizeof(int)) == -1) {
        lispd_log_msg(LOG_DAEMON, "setsockopt SO_REUSEADDR (v6): %s", strerror(errno));
        return(BAD);
    }

/*
    if (setsockopt(v6_receive_fd,
                   SOL_SOCKET,
                   SO_BINDTODEVICE,
                   &(ctrl_iface->iface_name),
                   sizeof(int)) == -1) {
        lispd_log_msg(LOG_DAEMON, "setsockopt SO_BINDTODEVICE (v6): %s", strerror(errno));
    }
*/

    memset(&v6,0,sizeof(v6));                   /* be sure */
    v6.sin6_family   = AF_INET6;
    v6.sin6_port     = htons(LISP_CONTROL_PORT);
    v6.sin6_addr     = in6addr_any;

    if (bind(ipv6_data_input_fd,(struct sockaddr *) &v6, sizeof(v6)) == -1) {
        lispd_log_msg(LOG_DAEMON, "bind (v6): %s", strerror(errno));
        return(BAD);
    }
 
    return(GOOD);
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

int get_afi(char *str)
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

int copy_lisp_addr_t(
     lisp_addr_t    *a1,
     lisp_addr_t    *a2,
     int            convert)
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
        lispd_log_msg(LISP_LOG_DEBUG_2, "copy_lisp_addr_t: Unknown AFI (%d)", a2->afi);
        return(BAD);
    }
    return(GOOD);
}



/*
 *      copy_addr
 *
 *      Copy a lisp_addr_t to a memory location, htonl'ing it
 *      it convert != 0. Return the length or 0;
 */

int copy_addr(
     void           *a1,
     lisp_addr_t    *a2,
     int            convert)
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
        lispd_log_msg(LOG_DAEMON, "copy_addr: Unknown AFI (%d)", a2->afi);
        return(ERR_AFI);
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
        lispd_log_msg(LOG_DAEMON, "malloc (get_my_addr): %s", strerror(errno));
        return(NULL);
    }

    memset(addr, 0, sizeof(lisp_addr_t));

    if (getifaddrs(&ifaddr) !=0) {
        lispd_log_msg(LOG_DAEMON, "getifaddrs(get_my_addr): %s", strerror(errno));
        free(addr);
        return(NULL);
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
    return(NULL);                          /* no luck */
}

/*
 *      lispd_get_address
 *
 *      return lisp_addr_t for host/FQDN or 0 if none
 */

int lispd_get_address(
    char             *host,
    lisp_addr_t      *addr,
    unsigned int     *flags)
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
        return(GOOD);
    } 
    return(BAD);
}

/*
 *  lispd_get_iface_address
 *
 *  return lisp_addr_t for the interface, 0 if none
 */

lisp_addr_t *lispd_get_iface_address(
    char                *ifacename,
    lisp_addr_t         *addr,
    int                 afi)
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
        lispd_log_msg(LISP_LOG_DEBUG_2,
               "lispd_get_iface_address: getifaddrs error: %s", strerror(errno));
        return(BAD);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((ifa->ifa_addr == NULL) || ((ifa->ifa_flags & IFF_UP) == 0) || (ifa->ifa_addr->sa_family != afi))
            continue;
        switch (ifa->ifa_addr->sa_family) {
        case AF_INET:
            s4 = (struct sockaddr_in *)(ifa->ifa_addr);
            if (!strcmp(ifa->ifa_name, ifacename)) {
                memcpy((void *) &(addr->address),
                       (void *)&(s4->sin_addr), sizeof(struct in_addr));
                addr->afi = AF_INET;
                lispd_log_msg(LISP_LOG_DEBUG_3, "lispd_get_iface_address: MN's IPv4 RLOC from interface (%s): %s \n",
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
                lispd_log_msg(LISP_LOG_DEBUG_3, "lispd_get_iface_address: MN's IPv6 RLOC from interface (%s): %s\n",
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
    lispd_log_msg(LISP_LOG_DEBUG_3, "lispd_get_iface_address: No %s RLOC configured for interface %s\n",
            (afi == AF_INET) ? "IPv4" : "IPv6",
            ifacename);
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


void dump_servers(
        lispd_addr_list_t   *list,
        const char          *list_name,
        int                 log_level)
{ 
    lispd_addr_list_t   *iterator = 0;

    if (!list)
        return;

    lispd_log_msg(log_level, "*** %s ***", list_name);

    iterator = list;
    while (iterator) {
        lispd_log_msg(log_level,"\t%s", get_char_from_lisp_addr_t(*(iterator->address)));
        iterator = iterator->next;
    }
}


void dump_proxy_etrs(int log_level)
{
    lispd_weighted_addr_list_t      *iterator = 0;

    if (!proxy_etrs)
        return;

    lispd_log_msg(LOG_DAEMON, "*** Proxy ETRs List ***");

    iterator = proxy_etrs;
    while (iterator) {
        lispd_log_msg(log_level,"\t%s priority: %d  weight: %d",
                get_char_from_lisp_addr_t(*(iterator->address)), iterator->priority, iterator->weight);
        iterator = iterator->next;
    }
}

void dump_map_servers(int log_level)
{
    lispd_map_server_list_t *ms;

    if (!map_servers)
        return;

    lispd_log_msg(log_level, "*** Map-Servers list: ***");
    ms = map_servers;

    while (ms) {
        lispd_log_msg(log_level, "\t%s key-type: %d ",
               get_char_from_lisp_addr_t(*ms->address),
               ms->key_type);
        ms = ms->next;
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
        return(BAD);

    while (((c = s[i]) != 0) && (c != ',') && (c != ':')) {
        if (c == '.') {
            dot = 1;
            if (s[i-1] == '.')
                return(BAD);
        }
        if (!(isalnum(c) || c=='-' || c=='.'))
            return(BAD);
        i++;
    }

    if (s[0] == '.' || s[i-1] == '.')
        return(BAD);

    return(dot);
}


void print_hmac(
        uchar *hmac,
        int len)
{
    int i;

    for (i = 0; i < len; i += 4) {
        lispd_log_msg(LOG_DEBUG,"i = %d\t(0x%04x)\n", i, (unsigned int) hmac[i]);
    }
    lispd_log_msg(LOG_DEBUG,"\n");
}

/*
 * Return lisp_addr_t in a char format;
 */

char *get_char_from_lisp_addr_t (lisp_addr_t addr)
{
    static char address[INET6_ADDRSTRLEN];

    switch (addr.afi){
    case AF_INET:
        inet_ntop(AF_INET, &(addr.address), address, INET_ADDRSTRLEN);
        return (address);
    case AF_INET6:
        inet_ntop(AF_INET6, &(addr.address.ipv6), address, INET6_ADDRSTRLEN);
        return (address);
    default:
        return (NULL);
    }
}

/*
 * Fill lisp_addr with the address.
 * Return GOOD if no error has been found
 */

int get_lisp_addr_from_char (
        char        *address,
        lisp_addr_t *lisp_addr)
{
    lisp_addr->afi = get_afi(address);
    switch (lisp_addr->afi){
    case AF_INET:
        if (inet_pton(AF_INET,address,&(lisp_addr->address.ip))==1)
            return (GOOD);
        else
            return (BAD);
    case AF_INET6:
        if (inet_pton(AF_INET6,address,&(lisp_addr->address.ipv6))==1)
            return (GOOD);
        else
            return (BAD);
    }
    return (BAD);
}

/*
 * Compare two lisp_addr_t.
 * Returns:
 * 			-1: If they are from different afi
 * 			 0: Both address are the same
 * 			 1: Addr1 is bigger than addr2
 * 			 2: Addr2 is bigger than addr1
 */
int compare_lisp_addr_t (
        lisp_addr_t *addr1,
        lisp_addr_t *addr2)
{
	int cmp;
	if (addr1->afi != addr2->afi)
		return (-1);
	if (addr1->afi == AF_INET)
		cmp = memcmp(&(addr1->address.ip),&(addr2->address.ip),sizeof(struct in_addr));
	else if (addr1->afi == AF_INET6)
			cmp = memcmp(&(addr1->address.ipv6),&(addr2->address.ipv6),sizeof(struct in6_addr));
	else
		return (-1);
	if (cmp == 0)
		return (0);
	else if (cmp > 0)
		return (1);
	else
		return (2);
}

/*
 * Parse address and fill lisp_addr and mask.
 * Return GOOD if no error has been found
 */

int get_lisp_addr_and_mask_from_char (
        char            *address,
        lisp_addr_t     *lisp_addr,
        int             *mask)
{
    char                     *token;

    if ((token = strtok(address, "/")) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_1, "get_lisp_addr_and_mask_from_char: Prefix not of the form prefix/length: %s",address);
        return (BAD);
    }
    if (get_lisp_addr_from_char(token,lisp_addr)==BAD)
        return (BAD);
    if ((token = strtok(NULL,"/")) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_1,"get_lisp_addr_and_mask_from_char: strtok: %s", strerror(errno));
        return (BAD);
    }
    *mask = atoi(token);
    if (lisp_addr->afi == AF_INET) {
        if (*mask < 1 || *mask > 32)
            return (BAD);
    }else {
        if (*mask < 1 || *mask > 128)
            return (BAD);
    }
    return (GOOD);
}
     
     
/*
 *      get_lisp_afi
 *
 *      Map from Internet AFI -> LISP_AFI
 *
 *      Get the length while your at it
 */         

uint16_t get_lisp_afi(
     int        afi,
     int        *len)
{

    switch (afi) {
    case AF_INET:
        if (len)
            *len = sizeof(struct in_addr);
        return((uint16_t)LISP_AFI_IP);
    case AF_INET6:
        if (len)
            *len = sizeof(struct in6_addr);
        return((uint16_t)LISP_AFI_IPV6);
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "get_lisp_afi: unknown AFI (%d)", afi);
        return (BAD);
    }
}

/*
 *      lisp2inetafi
 *
 *      Map from Internet LISP AFI -> INET AFI
 *
 */         

int lisp2inetafi(uint16_t afi)
{
    switch (afi) {
    case 0:
        return(0);
    case LISP_AFI_IP:
        return(AF_INET);
    case LISP_AFI_IPV6:
        return(AF_INET6);
    case LISP_AFI_LCAF:
        return(BAD);
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "lisp2inetafi: unknown AFI (%d)", afi);
        return(ERR_AFI);
    }
}


/*
 *      given afi, get the IP header length
 */

int get_ip_header_len(int afi)
{
    switch (afi) {                      /* == eid_afi */
    case AF_INET:
        return(sizeof(struct ip));
    case AF_INET6:
        return(sizeof(struct ip6_hdr));
    default:
        lispd_log_msg(LOG_DAEMON, "get_ip_header_len: unknown AFI (%d)", afi);
        return(ERR_AFI);
    }
}


/*
 *      given afi, get sockaddr len
 */

int get_sockaddr_len(int afi)
{
    switch (afi) {                      /* == eid_afi */
    case AF_INET:
        return(sizeof(struct sockaddr_in));
    case AF_INET6:
        return(sizeof(struct sockaddr_in6));
    default:
        lispd_log_msg(LOG_DAEMON, "get_sockaddr_len: unknown AFI (%d)", afi);
        return(ERR_AFI);
    }
}


/*
 *      given afi, get addr len
 */

int get_addr_len(int afi)
{
    switch (afi) {                      /* == eid_afi */
    case AF_INET:
        return(sizeof(struct in_addr));
    case AF_INET6:
        return(sizeof(struct in6_addr));
    default:
        lispd_log_msg(LOG_DAEMON, "get_addr_len: unknown AFI (%d)", afi);
        return(ERR_AFI);
    }
}


/*
 *      given afi, get prefix len
 */

int get_prefix_len(int afi)
{
    return(get_addr_len(afi) * 8);
}

struct udphdr *build_ip_header(
        void                  *cur_ptr,
        lisp_addr_t           *src_addr,
        lisp_addr_t           *dst_addr,
        int                   ip_len)
{
    struct ip      *iph;
    struct ip6_hdr *ip6h;
    struct udphdr  *udph;

    switch (src_addr->afi) {
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
        iph->ip_src.s_addr = src_addr->address.ip.s_addr;
        iph->ip_dst.s_addr = dst_addr->address.ip.s_addr;
        iph->ip_sum        = 0;
        iph->ip_sum        = ip_checksum((uint16_t *)cur_ptr, sizeof(struct ip));

        udph              = (struct udphdr *) CO(iph,sizeof(struct ip));
        break;
    case AF_INET6:
        ip6h           = (struct ip6_hdr *) cur_ptr;
        ip6h->ip6_hops = 255;
        ip6h->ip6_vfc  = (IP6VERSION << 4);
        ip6h->ip6_nxt  = IPPROTO_UDP;
        ip6h->ip6_plen = htons(ip_len);
        memcpy(ip6h->ip6_src.s6_addr,
               src_addr->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        memcpy(ip6h->ip6_dst.s6_addr,
                dst_addr->address.ipv6.s6_addr,
               sizeof(struct in6_addr));
        udph = (struct udphdr *) CO(ip6h,sizeof(struct ip6_hdr));
        break;
    default:
        return(ERR_AFI);
    }
    return(udph);
}


/*
 *  select from among readfds, the largest of which 
 *  is max_fd.
 */

int have_input(
    int         max_fd,
    fd_set      *readfds)
{
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = DEFAULT_SELECT_TIMEOUT;

    while (1)
    {

        if (select(max_fd+1,readfds,NULL,NULL,&tv) == -1) {
            if (errno == EINTR){
                continue;
            }
            else {
                lispd_log_msg(LISP_LOG_DEBUG_2, "have_input: select error: %s", strerror(errno));
                return(BAD);
            }
        }else{
            break;
        }
    }
    return(GOOD);
}


/*
 *  Process a LISP protocol message sitting on 
 *  socket s with address family afi
 */

int process_lisp_ctr_msg(
        int s,
        int afi)
{

    uint8_t         packet[MAX_IP_PACKET];
    struct sockaddr_in  s4;
    struct sockaddr_in6 s6;
    socklen_t fromlen4 = sizeof(struct sockaddr_in);
    socklen_t fromlen6 = sizeof(struct sockaddr_in6);
    lisp_addr_t *local_rloc = NULL;

    switch (afi) {
    case AF_INET:

        if (recvfrom(s, packet, MAX_IP_PACKET, 0, (struct sockaddr *)&s4,
                    &fromlen4) < 0) {
            lispd_log_msg(LISP_LOG_WARNING, "process_lisp_ctr_msg: recvfrom (v4) error: %s", strerror(errno));
            return(BAD);
        }
        break;
    case AF_INET6:
        if (recvfrom(s, packet, MAX_IP_PACKET, 0, (struct sockaddr *)&s6,
                    &fromlen6) < 0) {
            lispd_log_msg(LISP_LOG_WARNING, "process_lisp_ctr_msg: recvfrom (v6) error: %s", strerror(errno));
            return(BAD);
        }
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_lisp_ctr_msg: retrieve_msg: Unknown afi %d", afi);
        return(BAD);
    }
    lispd_log_msg(LISP_LOG_DEBUG_2, "Received a LISP control message");

    switch (((lispd_pkt_encapsulated_control_t *) packet)->type) {
    case LISP_MAP_REPLY:    //Got Map Reply
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Map-Reply message");
        process_map_reply(packet);
        break;
    case LISP_ENCAP_CONTROL_TYPE:   //Got Encapsulated Control Message
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Encapsulated Map-Request message");
        // XXX alopez: local_rloc shoul be get from packet
        local_rloc = (get_default_output_iface(AF_INET))->ipv4_address;
        if(!process_map_request_msg(packet, local_rloc))
            return (BAD);
        break;
    case LISP_MAP_REQUEST:      //Got Map-Request
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Map-Request message");
        // XXX alopez: local_rloc shoul be get from packet
        local_rloc = (get_default_output_iface(AF_INET))->ipv4_address;
        if(!process_map_request_msg(packet, local_rloc))
            return (BAD);
        break;
    case LISP_MAP_REGISTER:     //Got Map-Register, silently ignore
        break;
    case LISP_MAP_NOTIFY:
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Map-Notify message");
        if(!process_map_notify(packet))
            return(BAD);
        break;
    }
    lispd_log_msg(LISP_LOG_DEBUG_2, "Completed processing of LISP control message");

    return(GOOD);
}

    
int inaddr2sockaddr(
        lisp_addr_t     *inaddr,
        struct sockaddr *sockaddr,
        uint16_t        port)
{
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
        return(GOOD);
    case AF_INET6:
        ipv6->sin6_family      = AF_INET6;
        ipv6->sin6_port        = htons(port);
        memcpy(&(ipv6->sin6_addr), &(inaddr->address.ipv6), sizeof(struct in6_addr));
        return(GOOD);
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "inaddr2sockaddr: unknown AFI %d", inaddr->afi);
        return(ERR_AFI);
    }
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
