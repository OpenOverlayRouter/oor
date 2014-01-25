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

#include <cksum.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>


uint16_t ip_checksum(
    uint16_t *buffer,
    int      size)
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

uint16_t udp_ipv4_checksum (
	const void	    *buff,
	unsigned int	len,
	in_addr_t	    src,
	in_addr_t	    dest)
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

uint16_t udp_ipv6_checksum (
        const struct ip6_hdr    *ip6,
        const struct udphdr     *up,
        unsigned int            len)
{
    size_t i;
    register const u_int16_t *sp;
    uint32_t sum;
    union {
        struct {
            struct in6_addr ph_src;
            struct in6_addr ph_dst;
            u_int32_t       ph_len;
            u_int8_t        ph_zero[3];
            u_int8_t        ph_nxt;
        } ph;
        u_int16_t pa[20];
    } phu;

    /* pseudo-header */
    memset(&phu, 0, sizeof(phu));
    phu.ph.ph_src = ip6->ip6_src;
    phu.ph.ph_dst = ip6->ip6_dst;
    phu.ph.ph_len = htonl(len);
    phu.ph.ph_nxt = IPPROTO_UDP;

    sum = 0;
    for (i = 0; i < sizeof(phu.pa) / sizeof(phu.pa[0]); i++)
        sum += phu.pa[i];

    sp = (const u_int16_t *)up;

    for (i = 0; i < (len & ~1); i += 2)
        sum += *sp++;

    if (len & 1)
        sum += htons((*(const u_int8_t *)sp) << 8);

    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum & 0xffff;

    return (sum);
}


/*
 *	upd_checksum
 *
 *	Calculate the IPv4 or IPv6 UDP checksum
 *
 */

uint16_t udp_checksum (
        struct udphdr   *udph,
        int	            udp_len,
        void	        *iphdr,
        int	            afi)
{
    switch (afi) {
    case AF_INET:
        return(udp_ipv4_checksum(udph,
                udp_len,
                ((struct ip *)iphdr)->ip_src.s_addr,
                ((struct ip *)iphdr)->ip_dst.s_addr));
    case AF_INET6:
        return(udp_ipv6_checksum(iphdr, udph, udp_len));
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "udp_checksum: Unknown AFI");
        return(-1);
    }
}


/*
 * Returns the length of the auth data field based on the key_id value
 */

uint16_t get_auth_data_len(int key_id)

{
    switch (key_id) {
    default: // HMAC_SHA_1_96
        return (LISP_SHA1_AUTH_DATA_LEN);   //TODO support more auth algorithms
    }
}


/*
 * Computes the HMAC using SHA1 of packet with length packt_len
 * using key and puting the output in auth_data
 *
 */
int compute_sha1_hmac(char *key,
                      void *packet,
                      int pckt_len,
                      void *auth_data_pos)

{
	uint16_t auth_data_len;
    unsigned int md_len;    /* Length of the HMAC output.  */

    auth_data_len = get_auth_data_len(HMAC_SHA_1_96);

    memset(auth_data_pos, 0, auth_data_len);    /* make sure */

    if (!HMAC((const EVP_MD *) EVP_sha1(),
              (const void *) key,
              strlen(key),
              (uchar *) packet,
              pckt_len,
              (uchar *) auth_data_pos,
              &md_len)) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "HMAC failed");

        return (BAD);
    }
    return (GOOD);
}



/*
 * Compute and fill auth data field
 *
 * TODO Support more than SHA1
 */

int complete_auth_fields(int key_id,
                         uint16_t * key_id_pos,
                         char *key,
                         void *packet,
                         int pckt_len,
                         void *auth_data_pos)

{
    int err;

    *key_id_pos = htons(key_id);

    switch (key_id) {
    default:   //HMAC_SHA_1_96     /* TODO support more auth algorithms */
        err =
            compute_sha1_hmac(key, packet, pckt_len, auth_data_pos);
        return (err);

    }


}



int check_sha1_hmac(char *key,
                    void *packet,
                    int pckt_len,
                    void *auth_data_pos)
{
    uint16_t auth_data_len;
    unsigned int md_len;    /* Length of the HMAC output.  */

    uint8_t* auth_data_copy;

    auth_data_len = get_auth_data_len(HMAC_SHA_1_96);

    auth_data_copy = (uint8_t *) malloc(auth_data_len*sizeof(uint8_t));
    if (auth_data_copy == NULL) {
        lispd_log_msg(LISP_LOG_ERR, "check_sha1_hmac: malloc() failed");
        return(BAD);
    }

    /* Copy the data to another location and put 0's on the auth data field of the packet */
    memcpy(auth_data_copy,auth_data_pos,auth_data_len);
    memset(auth_data_pos,0,auth_data_len);

    if (!HMAC((const EVP_MD *) EVP_sha1(),
              (const void *) key,
              strlen(key),
              (uchar *) packet,
              pckt_len,
              (uchar *) auth_data_pos,
              &md_len)) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "SHA1 HMAC failed");
        free(auth_data_copy);
        return(BAD);
    }
    if ((strncmp((char *)auth_data_pos, (char *)auth_data_copy, (size_t)auth_data_len)) == 0) {
        free(auth_data_copy);
        return(GOOD);
    } else {
        free(auth_data_copy);
        return(BAD);
    }
}

int check_auth_field(int key_id,
                     char *key,
                     void *packet,
                     int pckt_len,
                     void *auth_data_pos)

{

    switch (key_id){
        default:      /* Only sha1 hmac supported at the moment */
            return(check_sha1_hmac(key,
                                   packet,
                                   pckt_len,
                                   auth_data_pos));

    }


}







