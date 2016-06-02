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

#include "lisp_address.h"
#include "../lib/mem_util.h"
#include "../lib/oor_log.h"

/*
 * ip_addr_t functions
 */

inline ip_addr_t *
ip_addr_new()
{
    return(xzalloc(sizeof(ip_addr_t)));
}

inline void
ip_addr_del(ip_addr_t *ip)
{
    free(ip);
}

inline int
ip_addr_afi(ip_addr_t *ipaddr)
{
    return(ipaddr->afi);
}

inline void *
ip_addr_get_addr(ip_addr_t *ipaddr)
{
    return (&(ipaddr->addr));
}

inline struct in_addr *
ip_addr_get_v4(ip_addr_t *ipaddr)
{
    return(&(ipaddr->addr.v4));
}

inline struct in6_addr *
ip_addr_get_v6(ip_addr_t *ipaddr)
{
    return(&(ipaddr->addr.v6));
}

inline uint8_t
ip_addr_get_size(ip_addr_t *ipaddr)
{
    return(ip_sock_afi_to_size(ip_addr_afi(ipaddr)));
}

inline uint8_t
ip_addr_get_size_to_write(ip_addr_t *ipaddr)
{
    /* includes afi size */
    return(ip_sock_afi_to_size(ip_addr_afi(ipaddr))+sizeof(uint16_t));
}

inline uint16_t
ip_addr_get_iana_afi(ip_addr_t *ipaddr)
{
    return(ip_sock_to_iana_afi(ip_addr_afi(ipaddr)));
}

inline int
ip_addr_set_afi(ip_addr_t *ipaddr, int afi)
{
    if (afi != AF_INET && afi != AF_INET6 && afi != AF_UNSPEC) {
        OOR_LOG(LWRN, "ip_addr_set_afi: unknown IP AFI (%d)", afi);
        return(BAD);
    }
    ipaddr->afi = afi;
    return(GOOD);
}

void
ip_addr_set_v4(ip_addr_t *ipaddr, void *src)
{
    ip_addr_set_afi(ipaddr, AF_INET);
    memcpy(ip_addr_get_v4(ipaddr), src, sizeof(struct in_addr));
}

inline void
ip_addr_set_v6(ip_addr_t *ipaddr, void *src)
{
    ip_addr_set_afi(ipaddr, AF_INET6);
    memcpy(ip_addr_get_v6(ipaddr), src, sizeof(struct in6_addr));
}

inline void
ip_addr_init(ip_addr_t *ipaddr, void *src, uint8_t afi)
{
    switch(afi) {
        case AF_INET:
            ip_addr_set_v4(ipaddr, src);
            break;
        case AF_INET6:
            ip_addr_set_v6(ipaddr, src);
            break;
        default:
            OOR_LOG(LWRN, "ip_addr_init: unknown IP AFI (%d)", afi);
            break;
    }
}

char *
ip_addr_to_char(ip_addr_t *addr)
{
    return(ip_to_char(ip_addr_get_addr(addr), ip_addr_afi(addr)));
}

/* ip_addr_copy
 *
 * @dst : the destination where the ip should be copied
 * @src : the ip address to be copied
 * Description: The function copies src structure to dst
 * structure. It does a full memory copy
 */
inline void
ip_addr_copy(ip_addr_t *dst, ip_addr_t *src)
{
    if (!dst || !src) {
        return;
    }
    memcpy(dst, src, sizeof(ip_addr_t));
}

/* ip_addr_copy_to
 *
 * @dst : memory location
 * @src : the ip address to be copied
 * Description: The function copies what is *CONTAINED* in an ip address
 * to a given memory location, NOT the whole structure! See ip_addr_copy
 * for copying ip addresses
 */
inline void
ip_addr_copy_to(void *dst, ip_addr_t *src)
{
    if (!dst || !src) {
        return;
    }
    memcpy(dst, ip_addr_get_addr(src), ip_addr_get_size(src));
}

inline int
ip_addr_write_to_pkt(void *dst, ip_addr_t *src, uint8_t convert)
{
    *(uint16_t *)dst = htons(ip_addr_get_iana_afi(src));
    dst = CO(dst, sizeof(uint16_t));

    if (convert && ip_addr_afi(src) == AF_INET) {
        /* XXX: haven't encountered a case when this is used */
        *((uint32_t *)dst) = htonl(ip_addr_get_v4(src)->s_addr);
    } else {
        memcpy(dst, ip_addr_get_addr(src), ip_addr_get_size(src));
    }
    return(sizeof(uint16_t)+ip_addr_get_size(src));
}

inline int
ip_addr_cmp(ip_addr_t *ip1, ip_addr_t *ip2)
{
    int res = 0;
    if (ip_addr_afi(ip1) != ip_addr_afi(ip2)){
        OOR_LOG(LDBG_3,"ip_addr_cmp: Addresses with different afi: %d - %d",
                ip_addr_afi(ip1),ip_addr_afi(ip2));
        return(-1);
    }
    res = memcmp(ip_addr_get_addr(ip1),
                      ip_addr_get_addr(ip2),
                      ip_addr_get_size(ip1));

    if (res < 0){
        res = 2;
    }else if (res > 0){
        res = 1;
    }

    return(res);
}


inline int
ip_addr_parse(void *offset, uint16_t iana_afi, ip_addr_t *dst)
{
    if(ip_addr_set_afi(dst, ip_iana_to_sock_afi(iana_afi)) == BAD)
        return(0);
    memcpy(ip_addr_get_addr(dst), CO(offset, sizeof(uint16_t)), ip_iana_afi_to_size(iana_afi));
    return(sizeof(uint16_t) + ip_iana_afi_to_size(iana_afi));
}

inline uint8_t
ip_addr_afi_to_default_mask(ip_addr_t *ip)
{
    return(ip_afi_to_default_mask(ip_addr_afi(ip)));
}

/*
 * ip_prefix_t functions
 */

inline uint8_t
ip_prefix_get_plen(ip_prefix_t *pref)
{
    return(pref->plen);
}

inline ip_addr_t *
ip_prefix_addr(ip_prefix_t *pref)
{
    return(&(pref->prefix));
}

inline uint8_t
ip_prefix_afi(ip_prefix_t *pref)
{
    return(ip_addr_afi(ip_prefix_addr(pref)));
}

inline void
ip_prefix_set(ip_prefix_t *pref, ip_addr_t *ipaddr, uint8_t plen)
{
    ip_addr_copy(ip_prefix_addr(pref), ipaddr);
    ip_prefix_set_plen(pref, plen);
}

inline void
ip_prefix_set_plen(ip_prefix_t *pref, uint8_t plen)
{
    pref->plen = plen;
}

inline void
ip_prefix_set_afi(ip_prefix_t *pref, int afi)
{
    ip_addr_set_afi(&pref->prefix, afi);
}

inline void
ip_prefix_copy(ip_prefix_t *dst, ip_prefix_t *src)
{
    ip_prefix_set_plen(dst, ip_prefix_get_plen(src));
    ip_addr_copy(ip_prefix_addr(dst), ip_prefix_addr(src));
}

char *
ip_prefix_to_char(ip_prefix_t *pref)
{
    static char address[10][INET6_ADDRSTRLEN+5];
    static unsigned int i;

    /* Hack to allow more than one addresses per printf line.
     * Now maximum = 5 */
    i++;
    i = i % 10;
    *address[i] = '\0';
    sprintf(address[i], "%s/%d", ip_addr_to_char(ip_prefix_addr(pref)),
            ip_prefix_get_plen(pref));
    return(address[i]);
}



int
ip_addr_from_char(char *addr, ip_addr_t *ip)
{
    int afi;

    afi = ip_afi_from_char(addr);

    if (inet_pton(afi, addr, ip_addr_get_addr(ip)) == 1) {
        ip_addr_set_afi(ip, afi);
    } else{
        return(BAD);
    }

    return(GOOD);
}

int
ip_prefix_from_char(char *addr, ip_prefix_t *ippref)
{
    char *address = strdup(addr);
    char *token;
    int mask;
    if ((token = strtok(address, "/")) == NULL) {
        OOR_LOG(LDBG_1, "ip_prefix_from_char: Prefix not of the form "
                "prefix/length: %s", addr);
        free(address);
        return (BAD);
    }

    if (ip_addr_from_char(token, ip_prefix_addr(ippref)) == BAD) {
        free(address);
        return (BAD);
    }

    if ((token = strtok(NULL, "/")) == NULL) {
        OOR_LOG(LDBG_1, "ip_prefix_from_char: strtok: %s", strerror(errno));
        free(address);
        return (BAD);
    }
    mask = atoi(token);

    free(address);

    if (ip_addr_afi(ip_prefix_addr(ippref)) == AF_INET) {
        if (mask < 0 || mask > 32){
            OOR_LOG(LDBG_2, "ip_prefix_from_char: Invalid mask : %s",address);
            return (BAD);
        }
    } else {
        if (mask < 0 || mask > 128){
            OOR_LOG(LDBG_2, "ip_prefix_from_char: Invalid mask : %s",address);
            return (BAD);
        }
    }

    /* convert the ip addr into a prefix */
    ip_prefix_set_plen(ippref, mask);
    return (GOOD);
}

/*
 * other ip functions
 */

char *
ip_to_char(void *ip, int afi)
{
    static char address[10][INET6_ADDRSTRLEN+1];
    static unsigned int i;
    i++; i = i % 10;
    *address[i] = '\0';
    switch (afi) {
    case AF_INET:
        inet_ntop(AF_INET, ip, address[i], INET_ADDRSTRLEN);
        return(address[i]);
    case AF_INET6:
        inet_ntop(AF_INET6, ip, address[i], INET6_ADDRSTRLEN);
        return(address[i]);
    }

    return(NULL);
}

inline uint16_t
ip_sock_to_iana_afi(uint16_t afi)
{
    switch (afi){
        case AF_INET:
            return(LISP_AFI_IP);
        case AF_INET6:
            return(LISP_AFI_IPV6);
        default:
            OOR_LOG(LWRN, "ip_sock_to_iana_afi: unknown IP AFI (%d)", afi);
            return(0);
    }
}

inline uint16_t
ip_iana_to_sock_afi(uint16_t afi)
{
    switch (afi) {
        case LISP_AFI_IP:
            return(AF_INET);
        case LISP_AFI_IPV6:
            return(AF_INET6);
        default:
            OOR_LOG(LWRN, "ip_iana_to_sock_afi: unknown IP AFI (%d)", afi);
            return(0);
    }
}

inline uint8_t
ip_sock_afi_to_size(uint16_t afi)
{
    switch (afi) {
    case AF_INET:
        return(sizeof(struct in_addr));
    case AF_INET6:
        return(sizeof(struct in6_addr));
    default:
        OOR_LOG(LWRN, "ip_sock_afi_to_size: unknown IP AFI (%d)", afi);
        return(0);
    }
}

/* given afi, get the IP header length */
inline int
ip_sock_afi_to_hdr_len(int afi)
{
    switch (afi) {                      /* == eid_afi */
    case AF_INET:
        return(sizeof(struct ip));
    case AF_INET6:
        return(sizeof(struct ip6_hdr));
    default:
        OOR_LOG(LDBG_2, "get_ip_header_len: unknown AFI (%d)", afi);
        return(ERR_AFI);
    }
}

inline uint8_t
ip_iana_afi_to_size(uint16_t afi)
{
    switch(afi) {
    case LISP_AFI_IP:
        return(sizeof(struct in_addr));
    case LISP_AFI_IPV6:
        return(sizeof(struct in6_addr));
    default:
        OOR_LOG(LDBG_3, "ip_iana_afi_to_size: unknown AFI (%d)", afi);
        return(0);
    }
    return(0);
}

int
ip_addr_is_link_local(ip_addr_t *ip)
{
    return(ip_is_link_local(ip_addr_get_addr(ip), ip_addr_afi(ip)));
}

int
ip_addr_is_any(ip_addr_t *ip)
{

    switch (ip_addr_afi(ip)) {
    case AF_INET: {
        struct in_addr *ip4 = (struct in_addr *) ip_addr_get_addr(ip);
        return(ip4->s_addr == 0);
    }
    case AF_INET6:
        return(IN6_IS_ADDR_UNSPECIFIED((struct in6_addr *)ip_addr_get_addr(ip)));
    }
    return(0);
}

inline uint8_t
ip_addr_is_multicast(ip_addr_t *addr)
{
    return(ip_is_multicast(ip_addr_get_addr(addr), ip_addr_afi(addr)));
}

uint8_t
ip_is_multicast(void *ip, int afi)
{
    switch (afi) {
    case AF_INET:
        return ipv4_is_multicast(ip);
        break;
    case AF_INET6:
        return ipv6_is_multicast(ip);
        break;
    default:
        OOR_LOG(LWRN, "is_multicast_addr: Unknown afi %s", afi);
        break;
    }
    return(0);
}

uint8_t
ipv4_is_multicast(struct in_addr *addr)
{
    if (ntohl(addr->s_addr)>=MCASTMIN4 && ntohl(addr->s_addr)<=MCASTMAX4)
        return(1);
    else
        return(0);
}

uint8_t
ipv6_is_multicast(struct in6_addr *addr)
{
    return(IN6_IS_ADDR_MULTICAST(addr));
}

uint8_t
ip_version_to_sock_afi(uint8_t ver)
{
    switch(ver) {
    case IPVERSION:
        return(AF_INET);
    case IP6VERSION:
        return(AF_INET6);
    default:
        return(0);
    }
}

int
ip_afi_to_default_mask(int afi)
{
    switch (afi) {
    case AF_INET:
        return(32);
    case AF_INET6:
        return(128);
    default:
        return(0);
    }
//    return(ip_sock_afi_to_size(afi)*8);
}

/* Return TRUE if the address belongs to:
 *          IPv4: 169.254.0.0/16
 *          IPv6: fe80::/10
 */
uint8_t
ip_is_link_local(void *addr, int afi)
{
    int         is_link_local = FALSE;
    uint32_t    ipv4_network  = 0;
    uint32_t    mask          = 0;
    struct in_addr  *ipv4;
    struct in6_addr *ipv6;

    switch (afi) {
    case AF_INET:
        ipv4 = addr;
        inet_pton(AF_INET,"169.254.0.0", &ipv4_network);
        inet_pton(AF_INET,"255.255.0.0", &mask);
        if ((ipv4->s_addr & mask) == ipv4_network) {
            is_link_local = TRUE;
        }
        break;
    case AF_INET6:
        /* if (((addr.address.ipv6.__in6_u.__u6_addr8[0] & 0xff) == 0xfe) &&
                ((addr.address.ipv6.__in6_u.__u6_addr8[1] & 0xc0) == 0x80)){
        } */
        ipv6 = addr;
        if (IN6_IS_ADDR_LINKLOCAL(ipv6)) {
            is_link_local = TRUE;
        }
        break;
    }
    return(is_link_local);
}

int
ip_hdr_ver_to_len(int ih_ver)
{
    switch (ih_ver) {
    case IPVERSION:
        return(sizeof(struct ip));
    case IP6VERSION:
        return(sizeof(struct ip6_hdr));
    default:
        OOR_LOG(LDBG_2, "ip_hdr_ver_to_len: Unknown IP version %d!",
                ih_ver);
        return(BAD);
    }
}

/* Assume if there's a colon in str that its an IPv6
 * address. Otherwise its v4. */
int
ip_afi_from_char(char *str)
{
    if (strchr(str,':'))                /* poor-man's afi discriminator */
        return(AF_INET6);
    else
        return(AF_INET);
}




