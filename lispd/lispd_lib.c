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
#include "lispd_afi.h"
#include "lispd_lib.h"
#include "lispd_external.h"
#include "lispd_map_request.h"
#include "lispd_map_reply.h"
#include "lispd_map_notify.h"
#include "lispd_sockets.h"
#include "patricia/patricia.h"
#include "lispd_info_nat.h"



int isfqdn(char *s);
inline lisp_addr_t *get_server(lispd_addr_list_t *server_list,int afi);
inline int convert_hex_char_to_byte (char val);



/*
 Expects  a lispd_addr_list_t**
*/
int add_lisp_addr_to_list(lisp_addr_t* tempAddr, void* data )
{
    lispd_addr_list_t** list = (lispd_addr_list_t**)data;
    lispd_addr_list_t   *list_elt   = NULL;
    lisp_addr_t*    lisp_addr =  NULL;


    if(list == NULL){
        lispd_log_msg(LISP_LOG_WARNING, "Empty data", strerror(errno));
        return 0;
    }


    if ((list_elt = malloc(sizeof(lispd_addr_list_t))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "Unable to allocate memory for lispd_addr_list_t: %s", strerror(errno));
        return(0);
    }

    memset(list_elt,0,sizeof(lispd_addr_list_t));

    if ((lisp_addr = malloc(sizeof(lisp_addr_t))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
        return(0);
    }
    memset(lisp_addr,0,sizeof(lisp_addr_t));

    copy_lisp_addr( lisp_addr, tempAddr );

    /** Allocate the address **/
    list_elt->address = lisp_addr;
    if (*list) {
        list_elt->next = *list;
        *list = list_elt;
    } else {
        *list = list_elt;
    }

    return 1;
}

/*
 Expects a single lispd_addr_t**
*/
int add_single_lisp_addr(lisp_addr_t* src, void* data )
{
    // TODO allocate
    lisp_addr_t* addr = *( (lisp_addr_t**)data );

    if ((addr = malloc(sizeof(lisp_addr_t))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "Unable to allocate memory for lisp_addr_t: %s", strerror(errno));
        return(BAD);
    }

    copy_lisp_addr(addr, src);
    return 0;
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
 *      if supplied (a2 -> a1)
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
 *      Copy a lisp_addr_t to a memory location, htonl'ing
 *      if convert != 0. Return the length or 0;
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
        lispd_log_msg(LISP_LOG_DEBUG_2, "copy_addr: Unknown AFI (%d)", a2->afi);
        return(ERR_AFI);
    }
}

inline void copy_lisp_addr_V4(lisp_addr_t *dest,
                              lisp_addr_t *orig){

    dest->address.ip.s_addr = orig->address.ip.s_addr;
    dest->afi = orig->afi;
}

inline void copy_lisp_addr_V6(lisp_addr_t *dest,
                              lisp_addr_t *orig){

    memcpy((dest->address.ipv6.s6_addr),
           orig->address.ipv6.s6_addr,
           sizeof(struct in6_addr));

    dest->afi = orig->afi;
}

void copy_lisp_addr(lisp_addr_t *dest,
                    lisp_addr_t *orig){
    switch (orig->afi){
        case AF_INET:
            copy_lisp_addr_V4(dest,orig);
            break;
        case AF_INET6:
            copy_lisp_addr_V6(dest,orig);
            break;
        default:
            //TODO default case?
            break;
    }
}

inline void memcopy_lisp_addr_V4(void *dest,
                                 lisp_addr_t *orig){

    ((struct in_addr *) dest)->s_addr = orig->address.ip.s_addr;
}

inline void memcopy_lisp_addr_V6(void *dest,
                                 lisp_addr_t *orig){

    memcpy(dest,
           orig->address.ipv6.s6_addr,
           sizeof(struct in6_addr));
}

void memcopy_lisp_addr(void *dest,
                       lisp_addr_t *orig){
    switch (orig->afi){
        case AF_INET:
            memcopy_lisp_addr_V4(dest,orig);
            break;
        case AF_INET6:
            memcopy_lisp_addr_V6(dest,orig);
            break;
        default:
            //TODO default case?
            break;
    }
}

int convert_hex_string_to_bytes(char *hex, uint8_t *bytes, int bytes_len)
{
    int         ctr = 0;
    char        hex_digit[2];
    int         partial_byte[2] = {0,0};

    while (hex[ctr] != '\0' && ctr <= bytes_len*2){
        ctr++;
    }
    if (hex[ctr] != '\0' && ctr != bytes_len*2){
        return (BAD);
    }

    for (ctr = 0; ctr < bytes_len; ctr++){
        hex_digit[0] = hex[ctr*2];
        hex_digit[1] = hex[ctr*2+1];
        partial_byte[0] = convert_hex_char_to_byte(hex_digit[0]);
        partial_byte[1] = convert_hex_char_to_byte(hex_digit[1]);
        if (partial_byte[0] == -1 || partial_byte[1] == -1){
            lispd_log_msg(LISP_LOG_DEBUG_2,"convert_hex_string_to_bytes: Invalid hexadecimal number");
            return (BAD);
        }
        bytes[ctr] = partial_byte[0]*16 + partial_byte[1];
    }
    return (GOOD);
}

inline int convert_hex_char_to_byte (char val)
{
    val = (char)toupper (val);

    switch (val){
    case '0':
        return (0);
    case '1':
        return (1);
    case '2':
        return (2);
    case '3':
        return (3);
    case '4':
        return (4);
    case '5':
        return (5);
    case '6':
        return (6);
    case '7':
        return (7);
    case '8':
        return (8);
    case '9':
        return (9);
    case 'A':
        return (10);
    case 'B':
        return (11);
    case 'C':
        return (12);
    case 'D':
        return (13);
    case 'E':
        return (14);
    case 'F':
        return (15);
    default:
        return (-1);
    }
}



/**

@param addr_str Might be a numeric IP or a hostname.
@param number_of_results
@param disable_name_resolution Disables name resolution

macro on new result ? pass it to a callback function ?
**/
/*
convert last field into a bitfield ?
*/
int lispd_get_address5(char *addr_str, on_new_lisp_addr_cb callback, void* data, const int disable_name_resolution , const int preferred_afi )
{
    lisp_addr_t lisp_addr;
    struct addrinfo hints, *servinfo = NULL, *p = NULL;

//    char ipstr[INET6_ADDRSTRLEN];


    if( callback == NULL){
            lispd_log_msg(LISP_LOG_WARNING, "No callback" );
            return(BAD);
    }


    memset(&hints, 0, sizeof hints);


    hints.ai_family = preferred_afi; /* AF_UNSPEC or use AF_INET6 to force IPv6 */
    hints.ai_flags = (disable_name_resolution == TRUE) ? AI_NUMERICHOST : AI_PASSIVE;
    hints.ai_protocol = IPPROTO_UDP;    /* we are interested in UDP only */

    if ((getaddrinfo( addr_str, 0, &hints, &servinfo)) != 0) {
            lispd_log_msg( LISP_LOG_WARNING, "get_addr_info: %s", strerror(errno) );
            return( BAD );
    }


    /* iterate over addresses */
    for (p = servinfo; p != NULL; p = p->ai_next) {

        if( GOOD != copy_addr_from_sockaddr( p->ai_addr, &lisp_addr)  ){
            lispd_log_msg(LISP_LOG_WARNING, "Could not convert sockaddr to lisp_addr");
            continue;
        }

        lispd_log_msg(LISP_LOG_DEBUG_1, "converted addr_str [%s] to address [%s]", addr_str, get_char_from_lisp_addr_t(lisp_addr));

        /* depending on callback return, we continue or not */
        if( (*callback)( &lisp_addr, data) == 0){
            lispd_log_msg(LISP_LOG_DEBUG_3 , "Callback wanna stop ");
            break;
        }

    }

    freeaddrinfo(servinfo); /* free the linked list */
    return (GOOD);
}


int copy_addr_from_sockaddr(struct sockaddr   *addr, lisp_addr_t    *lisp_addr)
{

    lisp_addr->afi = addr->sa_family;
    switch(lisp_addr->afi ) {
        case AF_INET:
            lisp_addr->address.ip = ((struct sockaddr_in *)addr)->sin_addr;
            return GOOD;

        case AF_INET6:
            lisp_addr->address.ipv6 = ((struct sockaddr_in6 *)addr)->sin6_addr;
            return GOOD;
    }

    lispd_log_msg( LISP_LOG_WARNING, "Unknown address family %d", addr->sa_family);
    return BAD;
}


/*
 *      lispd_get_address
 *
 *      return lisp_addr_t for host/FQDN or 0 if none
 */

int lispd_get_address(
    char             *host,
    lisp_addr_t      *addr)
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
        return(GOOD);
    }
    return(BAD);
}

/*
 *  lispd_get_iface_address
 *
 *  fill the parameter addr with the lisp_addr_t of the interface with afi.
 *  Return BAD if no address is present in the interface.
 */

int lispd_get_iface_address(
    char                *ifacename,
    lisp_addr_t         *addr,
    int                 afi)
{
    struct ifaddrs      *ifaddr;
    struct ifaddrs      *ifa;
    struct sockaddr_in  *s4;
    struct sockaddr_in6 *s6;
    lisp_addr_t         ip;
    char addr_str[MAX_INET_ADDRSTRLEN];


    if (default_rloc_afi != -1){ /* If forced a exact RLOC type (Just IPv4 of just IPv6) */
        if(afi != default_rloc_afi){
            lispd_log_msg(LISP_LOG_INFO,"Default RLOC afi defined: Skipped %s address in iface %s",
                          (afi == AF_INET) ? "IPv4" : "IPv6",ifacename);
            return (BAD);
        }
    }

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
            if (strcmp(ifa->ifa_name, ifacename) == 0) {
                memcpy((void *) &(ip.address),
                       (void *)&(s4->sin_addr), sizeof(struct in_addr));
                ip.afi = AF_INET;
                if (is_link_local_addr(ip) != TRUE){
                    copy_lisp_addr(addr,&ip);
                }else{
                    lispd_log_msg(LISP_LOG_DEBUG_2, "lispd_get_iface_address: interface address from %s discarded (%s)",
                            ifacename, get_char_from_lisp_addr_t(ip));
                    continue;
                }
                lispd_log_msg(LISP_LOG_DEBUG_2, "lispd_get_iface_address: IPv4 RLOC from interface (%s): %s \n",
                        ifacename,
                        inet_ntop(AF_INET, &(s4->sin_addr),
                            addr_str, MAX_INET_ADDRSTRLEN));
                freeifaddrs(ifaddr);
                return(GOOD);
            } else {
                continue;
            }
        case AF_INET6:
            s6 = (struct sockaddr_in6 *)(ifa->ifa_addr);
            // XXX sin6_scope_id is an ID depending on the scope of the address.  Linux only supports it for link-
            // local addresses, in that case sin6_scope_id contains the interface index. --> If sin6_scope_id is
            // not zero, is a link-local address
            if (s6->sin6_scope_id != 0){
                lispd_log_msg(LISP_LOG_DEBUG_2, "lispd_get_iface_address: interface address from %s discarded (%s)",
                        ifacename, inet_ntop(AF_INET6, &(s6->sin6_addr), addr_str, MAX_INET_ADDRSTRLEN));
                continue;
            }
            if (!strcmp(ifa->ifa_name, ifacename)) {
                memcpy((void *) &(addr->address),
                       (void *)&(s6->sin6_addr),
                       sizeof(struct in6_addr));
                addr->afi = AF_INET6;
                lispd_log_msg(LISP_LOG_DEBUG_2, "lispd_get_iface_address: IPv6 RLOC from interface (%s): %s\n",
                        ifacename,
                        inet_ntop(AF_INET6, &(s6->sin6_addr),
                            addr_str, MAX_INET_ADDRSTRLEN));
                freeifaddrs(ifaddr);
                return(GOOD);
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
    return(BAD);
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

    lispd_log_msg(log_level, "************* %13s ***************", list_name);
    lispd_log_msg(log_level, "|               Locator (RLOC)            |");

    iterator = list;
    while (iterator) {
        lispd_log_msg(log_level,"| %39s |", get_char_from_lisp_addr_t(*(iterator->address)));
        iterator = iterator->next;
    }
}


void dump_proxy_etrs(int log_level)
{
    lispd_locators_list      *locator_lst_elt[2] = {NULL,NULL};
    int                      ctr                 = 0;

    if (proxy_etrs == NULL || is_loggable(log_level) == FALSE){
        return;
    }

    locator_lst_elt[0] = proxy_etrs->mapping->head_v4_locators_list;
    locator_lst_elt[1] = proxy_etrs->mapping->head_v6_locators_list;

    lispd_log_msg(log_level, "************************* Proxy ETRs List ****************************");
    lispd_log_msg(log_level, "|               Locator (RLOC)            | Status | Priority/Weight |");

    for (ctr = 0 ; ctr<2 ; ctr++){
        while (locator_lst_elt[ctr]){
            dump_locator (locator_lst_elt[ctr]->locator,log_level);
            locator_lst_elt[ctr] = locator_lst_elt[ctr]->next;
        }
    }
}

void dump_map_servers(int log_level)
{
    lispd_map_server_list_t *ms         = NULL;
    char                    str[80];

    if (map_servers == NULL || is_loggable(log_level) == FALSE){
        return;
    }

    lispd_log_msg(log_level, "******************* Map-Servers list ********************************");
    lispd_log_msg(log_level, "|               Locator (RLOC)            |       Key Type          |");
    ms = map_servers;

    while (ms) {
        sprintf(str, "| %39s |",get_char_from_lisp_addr_t(*ms->address));
        if (ms->key_type == NO_KEY){
            sprintf(str + strlen(str),"          NONE           |");
        }else if (ms->key_type == HMAC_SHA_1_96){
            sprintf(str + strlen(str),"     HMAC-SHA-1-96       |");
        }else{
            sprintf(str + strlen(str),"    HMAC-SHA-256-128     |");
        }
        ms = ms->next;
        lispd_log_msg(log_level,"%s",str);
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

/*
 * Return TRUE if the address belongs to:
 *          IPv4: 169.254.0.0/16
 *          IPv6: fe80::/10
 */

int is_link_local_addr (lisp_addr_t addr)
{
    int         is_link_local = FALSE;
    uint32_t    ipv4_network  = 0;
    uint32_t    mask          = 0;

    switch (addr.afi){
    case AF_INET:
        inet_pton(AF_INET,"169.254.0.0",&(ipv4_network));
        inet_pton(AF_INET,"255.255.0.0",&(mask));
        if ((addr.address.ip.s_addr & mask) == ipv4_network){
            is_link_local = TRUE;
        }
        break;
    case AF_INET6:
        if (((addr.address.ipv6.__in6_u.__u6_addr8[0] & 0xff) == 0xfe) &&
                ((addr.address.ipv6.__in6_u.__u6_addr8[1] & 0xc0) == 0x80)){
            is_link_local = TRUE;
        }
        break;
    }

    return (is_link_local);
}


void print_hmac(
        uchar *hmac,
        int len)
{
    int i;

    for (i = 0; i < len; i += 4) {
        lispd_log_msg(LISP_LOG_DEBUG_3,"i = %d\t(0x%04x)\n", i, (unsigned int) hmac[i]);
    }
    lispd_log_msg(LISP_LOG_DEBUG_3,"\n");
}

/*
 * Return lisp_addr_t in a char format;
 */

char *get_char_from_lisp_addr_t (lisp_addr_t addr)
{
    static char address[10][INET6_ADDRSTRLEN];
    static unsigned int i; //XXX Too much memory allocation for this, but standard syntax

    /* Hack to allow more than one addresses per printf line. Now maximum = 5 */
    i++;
    i = i % 10;

    switch (addr.afi){
    case AF_INET:
        inet_ntop(AF_INET, &(addr.address), address[i], INET_ADDRSTRLEN);
        return (address[i]);
    case AF_INET6:
        inet_ntop(AF_INET6, &(addr.address.ipv6), address[i], INET6_ADDRSTRLEN);
        return (address[i]);
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
    uint8_t result = BAD;

    lisp_addr->afi = get_afi(address);
    switch (lisp_addr->afi){
    case AF_INET:
        if (inet_pton(AF_INET,address,&(lisp_addr->address.ip))==1){
            result = GOOD;
        }
        break;
    case AF_INET6:
        if (inet_pton(AF_INET6,address,&(lisp_addr->address.ipv6))==1){
            result = GOOD;
        }
        break;
    default:
        break;
    }
    if (result == BAD){
        lisp_addr->afi = AF_UNSPEC;
    }
    return (result);
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
	if (addr1 == NULL || addr2 == NULL){
	    return (-1);
	}
	if (addr1->afi != addr2->afi){
		return (-1);
	}
	if (addr1->afi == AF_INET){
		cmp = memcmp(&(addr1->address.ip),&(addr2->address.ip),sizeof(struct in_addr));
	}else if (addr1->afi == AF_INET6){
			cmp = memcmp(&(addr1->address.ipv6),&(addr2->address.ipv6),sizeof(struct in6_addr));
	}else{
		return (-1);
	}
	if (cmp == 0){
		return (0);
	}else if (cmp > 0){
		return (1);
    }else{
		return (2);
    }
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
        if (len){
            *len = sizeof(struct in_addr);
        }
        return((uint16_t)LISP_AFI_IP);
    case AF_INET6:
        if (len){
            *len = sizeof(struct in6_addr);
        }
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
    case LISP_AFI_NO_ADDR:
        return(AF_UNSPEC);
    case LISP_AFI_IP:
        return(AF_INET);
    case LISP_AFI_IPV6:
        return(AF_INET6);
    case LISP_AFI_LCAF:
        return(LISP_AFI_LCAF);
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "lisp2inetafi: unknown AFI (%d)", afi);
        return(ERR_AFI);
    }
}

/*
 * Map from Internet INET AFI -> LISP AFI
 */

int inet2lispafi(int afi)

{
    switch (afi) {
    case AF_UNSPEC:
        return (LISP_AFI_NO_ADDR);
    case AF_INET:
        return (LISP_AFI_IP);
    case AF_INET6:
        return (LISP_AFI_IPV6);
    case LISP_AFI_LCAF:
        return(LISP_AFI_LCAF);
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "inet2lispafi: unknown AFI (%d)", afi);
        return (0);
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
        lispd_log_msg(LISP_LOG_DEBUG_2, "get_ip_header_len: unknown AFI (%d)", afi);
        return(ERR_AFI);
    }
}


/*
 *      given afi, get addr len
 */

int get_addr_len(int afi)
{
    switch (afi) {                      /* == eid_afi */
    case AF_UNSPEC:
        return (0);
    case AF_INET:
        return(sizeof(struct in_addr));
    case AF_INET6:
        return(sizeof(struct in6_addr));
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "get_addr_len: unknown AFI (%d)", afi);
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

/*
 * Return the first Map Resolver. If no default rloc afi is specified, then IPv4 has more priority than IPv6
 */


lisp_addr_t *get_map_resolver()
{
    lisp_addr_t *dst_rloc = NULL;

    if (default_ctrl_iface_v4 != NULL){
        dst_rloc = get_server(map_resolvers, AF_INET);
    }
    if (dst_rloc == NULL && default_ctrl_iface_v6 != NULL){
        dst_rloc = get_server(map_resolvers, AF_INET6);
    }

    if (dst_rloc == NULL){
        lispd_log_msg(LISP_LOG_ERR,"No Map Resolver with a RLOC compatible with local RLOCs");
    }
    return dst_rloc;
}

inline lisp_addr_t *get_server(
        lispd_addr_list_t   *server_list,
        int                 afi)
{
    lispd_addr_list_t *server_elt;

    server_elt = server_list;
    while (server_elt != NULL){
        if (server_elt->address->afi == afi){
            return (server_elt->address);
        }
        server_elt = server_elt->next;
    }
    return (NULL);
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
        int sock,
        int afi)
{

    uint8_t             packet[MAX_IP_PACKET];
    lisp_addr_t         local_rloc;
    uint16_t            remote_port;

    if  ( get_packet_and_socket_inf (sock, afi, packet, &local_rloc, &remote_port) != GOOD ){
        return BAD;
    }

    lispd_log_msg(LISP_LOG_DEBUG_2, "Received a LISP control message");

    switch (((lisp_encap_control_hdr_t *) packet)->type) {
    case LISP_MAP_REPLY:    //Got Map Reply
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Map-Reply message");
        process_map_reply(packet);
        break;
    case LISP_ENCAP_CONTROL_TYPE:   //Got Encapsulated Control Message
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Encapsulated Map-Request message");
        if(!process_map_request_msg(packet, &local_rloc, remote_port))
            return (BAD);
        break;
    case LISP_MAP_REQUEST:      //Got Map-Request
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Map-Request message");
        if(!process_map_request_msg(packet, &local_rloc, remote_port))
            return (BAD);
        break;
    case LISP_MAP_REGISTER:     //Got Map-Register, silently ignore
        break;
    case LISP_MAP_NOTIFY:
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Map-Notify message");
        if(!process_map_notify(packet))
            return(BAD);
        break;

    case LISP_INFO_NAT:      //Got Info-Request/Info-Replay
        lispd_log_msg(LISP_LOG_DEBUG_1, "Received a LISP Info-Request/Info-Reply message");
        if(!process_info_nat_msg(packet, local_rloc)){
            return (BAD);
        }
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_1, "Unidentified type control message received");
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
 * Extracts a lisp_addr_t from a memory position (if stored in Network Byte Order)
 */

int extract_lisp_address(
        uint8_t         *ptr,
        lisp_addr_t     *addr)

{
    int result  = GOOD;

    addr->afi = lisp2inetafi(ntohs(*(uint16_t *) ptr));     /* 2 Byte AFI field */
    ptr = CO(ptr, sizeof(uint16_t));

    switch (addr->afi){
    case AF_INET:
        memcpy(&(addr->address), ptr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(&(addr->address), ptr, sizeof(struct in6_addr));
        break;
    case AF_UNSPEC:
        break;
    case LISP_AFI_LCAF:
        lispd_log_msg(LISP_LOG_DEBUG_2, "extract_lisp_address: Couldn't process lcaf address");
        result  = ERR_AFI;
        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "extract_lisp_address: Coudn't extract address. Unknown afi");
        result  = ERR_AFI;
        break;
    }

    return (result);
}

/*
 * Loop to free all the members of a lispd_addr_list_t
 */

void free_lisp_addr_list(lispd_addr_list_t * list)

{

    lispd_addr_list_t *list_pre;

    while (list->next != NULL) {

        list_pre = list;

        list = list->next;

        free(list_pre->address);
        free(list_pre);
    }
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
