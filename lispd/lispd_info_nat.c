/*
 * lispd_info_nat.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Common functions for NAT traversal messages
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
 *    Alberto Rodriguez Natal    <arnatal@ac.upc.edu>
 *
 */

#include <sys/timerfd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <endian.h>

#include "lispd_external.h"

#include "lispd_info_nat.h"
#include "lispd_info_reply.h"
#include "lispd_lib.h"
#include "lispd_log.h"


int nat_aware = FALSE;
int behind_nat = UNKNOWN;
lisp_addr_t natt_rtr; 


/*
 *  Process Info-Request Message
 *  Receive a Info-Request message and process based on control bits
 *
 */

int process_info_nat_msg(uint8_t *packet)

{
    lispd_pkt_info_nat_t *nat_pkt;

    nat_pkt = (lispd_pkt_info_nat_t *) packet;

    switch (nat_pkt->rbit) {
    case NAT_NO_REPLY:
        lispd_log_msg(LISP_LOG_DEBUG_2, "process_info_nat_msg: r-bit value not supported");
        return (BAD);

    case NAT_REPLY:
        return (process_info_reply_msg(packet));

    default:
        return (BAD);         // We should never reach here
    }
}

/* Create and fill the common header part of info-request and info-reply
 *
 * TODO Pass the type of auth data and get the length by a function
 */

lispd_pkt_info_nat_t *create_and_fill_info_nat_header(int lisp_type,
                                                      int reply,
                                                      unsigned long nonce,
                                                      uint16_t auth_data_len,
                                                      uint32_t ttl,
                                                      uint8_t eid_mask_length,
                                                      lisp_addr_t *eid_prefix,
                                                      unsigned int *header_len)

{

    lispd_pkt_info_nat_t *hdr;
    lispd_pkt_info_nat_eid_t *eid_part;
    unsigned int eid_afi_lisp;
    unsigned int afi_len;
    unsigned int hdr_len;

    /* get the length of the eid prefix and map to LISP_AFI types */

    eid_afi_lisp = inet2lispafi(eid_prefix->afi);

    afi_len = get_addr_len(eid_prefix->afi);

    /* compute space needed for the header */

    hdr_len = sizeof(lispd_pkt_info_nat_t) +
              sizeof(lispd_pkt_info_nat_eid_t) + /* EID fixed part */
              afi_len;                /* length of the eid prefix */

    /* TODO variable auth data */

    /* Reserve memory for the header */
    if ((hdr = (lispd_pkt_info_nat_t *) malloc(hdr_len)) == NULL) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "malloc (header info-nat packet): %s", strerror(errno));
        return (NULL);
    }

    /*
     *  make sure this is clean
     */

    memset(hdr, 0, hdr_len);

    /*
     *  build the header
     *
     *  Compute the HMAC later
     *
     */

    hdr->lisp_type = lisp_type;
    hdr->rbit = reply;
    hdr->nonce = htobe64(nonce);        /* needs #include <endian.h> */

    hdr->key_id = 0;            /* XXX not sure */
    hdr->auth_data_len = htons(auth_data_len);

    /* skip over the fixed part */

    eid_part = (lispd_pkt_info_nat_eid_t *) CO(hdr, sizeof(lispd_pkt_info_nat_t));
    eid_part->ttl = htonl(ttl);
    eid_part->eid_mask_length = eid_mask_length;
    eid_part->eid_prefix_afi = htons(eid_afi_lisp);

    /*
     * skip over the eid fixed part and put the eid prefix immediately
     * following...
     */


    if ((copy_addr((void *) CO(eid_part,
                   sizeof(lispd_pkt_info_nat_eid_t)),
                   eid_prefix,
                   0)) != afi_len) {
        lispd_log_msg(LISP_LOG_DEBUG_2, "Error coping eid address ",eid_prefix);
        free(hdr);
        return (NULL);
    }


    /* If everything OK return the pointer to the header and the length of the header */

    *header_len = hdr_len;

    return (hdr);

}



int extract_info_nat_header(lispd_pkt_info_nat_t *hdr,
                            uint8_t *type,
                            uint8_t *reply,
                            uint64_t *nonce,
                            uint16_t *key_id,
                            uint16_t *auth_data_len,
                            uint8_t **auth_data,
                            uint32_t *ttl,
                            uint8_t *eid_mask_len,
                            lisp_addr_t *eid_prefix)
{
    lispd_pkt_info_nat_eid_t *eid_part;
    void *eid_ptr;
    unsigned int hdr_len;

    *type = hdr->lisp_type;
    *reply = hdr->rbit;
    *nonce = be64toh(hdr->nonce);       /* Requieres #include <endian.h>*/
    *key_id = ntohs(hdr->key_id);
    *auth_data_len = ntohs(hdr->auth_data_len);
    *auth_data = (uint8_t *) &(hdr->auth_data);


    /*
     * auth_data has (or will have) variable lentgh
     *
     * cur_ptr = CO(&(msg->auth_data), LISP_SHA1_AUTH_DATA_LEN*sizeof(uint8_t));
     */


    eid_part = (lispd_pkt_info_nat_eid_t *) CO(hdr, sizeof(lispd_pkt_info_nat_t));

    *ttl = ntohl(eid_part->ttl);
    *eid_mask_len = eid_part->eid_mask_length;

    /* Put the pointer just before the EID AFI field to use the extract_lisp_address function */
    eid_ptr = CO(eid_part, sizeof(lispd_pkt_info_nat_eid_t) - sizeof(uint16_t));

    *eid_prefix = extract_lisp_address((void *) eid_ptr);

    hdr_len = sizeof(lispd_pkt_info_nat_t) + sizeof(lispd_pkt_info_nat_eid_t);

    return (hdr_len);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
