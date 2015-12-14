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

#ifndef LISPD_IP_H_
#define LISPD_IP_H_

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <stdint.h>

/*
 * Maximum length (in bytes) of an IP address
 */
#define MAX_INET_ADDRSTRLEN INET6_ADDRSTRLEN

#define MCASTMIN4   0xE0000000
#define MCASTMAX4   0xEFFFFFFF


/*
 * IP address type
 */
typedef struct {
    int      afi;
    union {
        struct in_addr      v4;
        struct in6_addr     v6;
    } addr;
} ip_addr_t;

typedef struct {
    ip_addr_t   prefix;
    uint8_t     plen;
} ip_prefix_t;


/*
 * ip_addr_t functions
 */

inline ip_addr_t *ip_addr_new();
inline void ip_addr_del(ip_addr_t *ip);
inline int ip_addr_afi(ip_addr_t *ipaddr);
inline void *ip_addr_get_addr(ip_addr_t *ipaddr);
inline struct in_addr *ip_addr_get_v4(ip_addr_t *ipaddr);
inline struct in6_addr *ip_addr_get_v6(ip_addr_t *ipaddr);
inline uint8_t ip_addr_get_size(ip_addr_t *ipaddr);
inline uint8_t ip_addr_get_size_to_write(ip_addr_t *ipaddr);
inline uint16_t ip_addr_get_iana_afi(ip_addr_t *ipaddr);
inline int ip_addr_set_afi(ip_addr_t *ipaddr, int afi);
inline void ip_addr_set_v4(ip_addr_t *ipaddr, void *src);
inline void ip_addr_set_v6(ip_addr_t *ipaddr, void *src);
inline void ip_addr_init(ip_addr_t *ipaddr, void *src, uint8_t afi);
inline void ip_addr_copy(ip_addr_t *dst, ip_addr_t *src);
inline void ip_addr_copy_to(void *dst, ip_addr_t *src);
inline int ip_addr_write_to_pkt(void *dst, ip_addr_t *src, uint8_t convert);
inline int ip_addr_parse(void *offset, uint16_t afi, ip_addr_t *dst);
inline int ip_addr_cmp(ip_addr_t *ip1, ip_addr_t *ip2);
inline uint8_t ip_addr_afi_to_default_mask(ip_addr_t *ip);
char *ip_addr_to_char (ip_addr_t *addr);

/*
 * ip_prefix_t functions
 */
inline uint8_t ip_prefix_get_plen(ip_prefix_t *pref);
inline ip_addr_t *ip_prefix_addr(ip_prefix_t *pref);
inline uint8_t ip_prefix_afi(ip_prefix_t *pref);
inline void ip_prefix_set(ip_prefix_t *pref, ip_addr_t *ipaddr, uint8_t plen);
inline void ip_prefix_set_plen(ip_prefix_t *pref, uint8_t plen);
inline void ip_prefix_set_afi(ip_prefix_t *pref, int afi);
inline void ip_prefix_copy(ip_prefix_t *dst, ip_prefix_t *src);

char *ip_prefix_to_char(ip_prefix_t *pref);

int ip_addr_from_char(char *address, ip_addr_t *ip);
int ip_prefix_from_char(char *address, ip_prefix_t *ippref);

inline int ip_addr_is_link_local(ip_addr_t *addr);
int ip_addr_is_any(ip_addr_t *ip);
inline uint8_t ip_addr_is_multicast(ip_addr_t *addr);

/* IP-UTIL functions*/
char *ip_to_char(void *ip, int afi);
inline uint16_t ip_sock_to_iana_afi(uint16_t afi);
inline uint16_t ip_iana_to_sock_afi(uint16_t afi);
inline uint8_t ip_sock_afi_to_size(uint16_t afi);
inline int ip_sock_afi_to_hdr_len(int afi);
inline uint8_t ip_iana_afi_to_size(uint16_t afi);
uint8_t ip_is_multicast(void *ip, int afi);
uint8_t ipv4_is_multicast(struct in_addr *addr);
uint8_t ipv6_is_multicast(struct in6_addr *addr);


uint8_t ip_version_to_sock_afi(uint8_t ver);
int ip_afi_to_default_mask(int afi);
uint8_t ip_is_link_local(void *, int afi);
int ip_hdr_ver_to_len(int ih_ver);
int ip_afi_from_char(char *str);

#endif /* LISPD_IP_H_ */
