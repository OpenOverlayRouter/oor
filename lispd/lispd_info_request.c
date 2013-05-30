/*
 * lispd_info_request.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Builds and sends Info-Request messages.
 *
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
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
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

#include <openssl/hmac.h>
#include <openssl/evp.h>

//#define _BSD_SOURCE             // needed?
#include <endian.h>

#include "linux/netlink.h"
#include "lispd_external.h"

#include "lispd_info_request.h"
#include "lispd_sockets.h"


/*
 *  build_info_request_pkt
 *
 *  Build the info-request.
 *
 *  Once done with the packet, it should be free()!
 */

lispd_pkt_info_nat_t *build_info_request_pkt(nonce,auth_data_len,ttl,
                                             eid_mask_length,eid_prefix, pkt_len)
uint64_t nonce;
uint16_t auth_data_len;
uint32_t ttl;
uint8_t eid_mask_length;
lisp_addr_t *eid_prefix;
uint32_t *pkt_len;

{
    lispd_pkt_info_nat_t *irp;
    lispd_pkt_info_request_lcaf_t *irp_lcaf;
    unsigned int irp_len = 0;
    unsigned int header_len = 0;
    unsigned int lcaf_hdr_len = 0;


    irp = create_and_fill_info_nat_header(LISP_INFO_NAT,
                                          NAT_NO_REPLY,
                                          nonce,
                                          auth_data_len,
                                          ttl,
                                          eid_mask_length,
                                          eid_prefix,
                                          &header_len);

    if (irp == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "Error building info-request header");
        return (NULL);
    }



    lcaf_hdr_len = sizeof(lispd_pkt_info_request_lcaf_t);

    /* Total length of the packet */

    irp_len = header_len + lcaf_hdr_len;

    /*  Expand the amount of memory assigned to the packet */
    irp = realloc(irp, irp_len);

    if (irp == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "realloc (post-header info-nat packet): %s",
               strerror(errno));
        return (NULL);
    }


    /*
     * Skip over the fixed part and build the lcaf
     */

    irp_lcaf = (lispd_pkt_info_request_lcaf_t *) CO(irp, header_len);

    /*
     *  Make sure this is clean
     */

    memset(irp_lcaf, 0, lcaf_hdr_len);

    /* Previous draft implementation */
    /* Fill lcaf info-request fields */
    /*
    irp_lcaf->lcaf_afi = htons(LISP_AFI_LCAF);
    irp_lcaf->flags = 0;
    irp_lcaf->lcaf_type = LISP_LCAF_NULL;
    irp_lcaf->length = htons(0);
    */
 
    /* New draft implementation */
	irp_lcaf->afi = htons(0); /* AFI = 0 */

    /* Return the len of the packet */
    *pkt_len = irp_len;

    return (irp);
}




int build_and_send_info_request(uint64_t nonce,
                                uint16_t key_type,
                                char *key,
                                uint32_t ttl,
                                uint8_t eid_mask_length,
                                lisp_addr_t *eid_prefix,
                                lisp_addr_t *src_addr,
                                unsigned int src_port,
                                lisp_addr_t *dst_addr,
                                unsigned int dst_port)


{
    int packet_len;
    int auth_data_len;


    lispd_pkt_info_nat_t *info_request_pkt;

    auth_data_len = get_auth_data_len(key_type);

    info_request_pkt = build_info_request_pkt(nonce,
                                              auth_data_len,
                                              ttl,
                                              eid_mask_length,
                                              eid_prefix,
                                              &packet_len);

    if (info_request_pkt == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "Couldn't build info request packet");
        return (BAD);
    }


    if (BAD == complete_auth_fields(key_type,
                                      &(info_request_pkt->key_id),
                                      key,
                                      info_request_pkt,
                                      packet_len,
                                      info_request_pkt->auth_data)) {
        free(info_request_pkt);
        lispd_log_msg(LISP_LOG_DEBUG_2, "HMAC failed for info-request");
        return (BAD);
    }


    if (BAD == send_udp_ipv4_packet(src_addr,
                             dst_addr,
                             src_port,
                             dst_port,
                             info_request_pkt,
                             packet_len)) {
        lispd_log_msg(LISP_LOG_DEBUG_2,"Couldn't send info-request for",eid_prefix);
        free(info_request_pkt);
        return (BAD);
    }


    free(info_request_pkt);
    return (GOOD);
}





/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
