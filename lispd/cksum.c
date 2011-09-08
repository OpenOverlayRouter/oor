/*
 * cksum.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Implementation for UDP checksum.
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
 *    David Meyer	<dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

#include "lispd.h"

uint16_t ip_checksum(buffer, size) 
    uint16_t *buffer;
    int      size; 
{
    uint32_t cksum = 0;
    
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(uint16_t);
    }

    if (size) {
        cksum += *(uint8_t *) buffer;
    }

    cksum  = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    
    return ((uint16_t)(~cksum));
}


/*    
 *
 *	Calculate the IPv4 UDP checksum (calculated with the whole packet).
 *
 *	Parameters:
 *
 *	buff	-	pointer to the UDP header
 *	len	-	the UDP packet length.
 *	src	-	the IP source address (in network format).
 *	dest	-	the IP destination address (in network format).
 *
 *	Returns:        The result of the checksum
 *
 */

uint16_t udp_ipv4_checksum (buff,len,src,dest)
	const void	*buff;
	unsigned int	len;
	in_addr_t	src;
	in_addr_t	dest;
{

    const uint16_t *buf	   = buff;
    uint16_t	   *ip_src = (void *)&src;
    uint16_t	   *ip_dst = (void *)&dest;
    uint32_t       length  = len;
    uint32_t	   sum     = 0;

    while (len > 1) {
	sum += *buf++;
	if (sum & 0x80000000)
	    sum = (sum & 0xFFFF) + (sum >> 16);
	len -= 2;
    }
 
    /* Add the padding if the packet length is odd */

    if (len & 1)
	sum += *((uint8_t *)buf);
 
    /* Add the pseudo-header */

    sum += *(ip_src++);
    sum += *ip_src;
 
    sum += *(ip_dst++);
    sum += *ip_dst;
 
    sum += htons(IPPROTO_UDP);
    sum += htons(length);
 
    /* Add the carries */

    while (sum >> 16)
	sum = (sum & 0xFFFF) + (sum >> 16);
 
    /* Return the one's complement of sum */

    return ((uint16_t)(~sum));
}


/*
 *	TBD 
 */

uint16_t udp_ipv6_checksum (buff,len,src,dest)
	const void	*buff;
	unsigned int	len;
	struct in6_addr src;
	struct in6_addr dest;
{

    return (0);
}

/*
 *	upd_checksum
 *
 *	Calculate the IPv4 or IPv6 UDP checksum
 *
 */

uint16_t udp_checksum (udph,udp_len,iphdr,afi)
     struct udphdr *udph;
     int	   udp_len;
     void	   *iphdr;
     int	   afi;
{
    switch (afi) {
    case AF_INET:
        return(udp_ipv4_checksum(udph,
				 udp_len,
				 ((struct ip *)iphdr)->ip_src.s_addr,
				 ((struct ip *)iphdr)->ip_dst.s_addr));
    case AF_INET6:
	return(udp_ipv6_checksum(udph,
				 udp_len,
				 ((struct ip6_hdr *)iphdr)->ip6_src.s6_addr,
				 ((struct ip6_hdr *)iphdr)->ip6_dst.s6_addr));
    default:
	syslog(LOG_DAEMON, "udp_checksum: Unknown AFI");
	return(-1);
    }
}
