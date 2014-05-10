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
#include <lisp_messages.h>




/* Returns the length of the auth data field based on the key_id value */
uint16_t
get_auth_data_len(int key_id)
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
int
compute_sha1_hmac(char *key, void *pkt, int pkt_len, void *ad_pos)

{
    uint16_t auth_data_len;
    unsigned int md_len; /* Length of the HMAC output.  */

    auth_data_len = get_auth_data_len(HMAC_SHA_1_96);

    memset(ad_pos, 0, auth_data_len); /* make sure */

    if (!HMAC((const EVP_MD *) EVP_sha1(), (const void *) key, strlen(key),
            (uchar *) pkt, pkt_len, (uchar *) ad_pos, &md_len)) {
        lmlog(LISP_LOG_DEBUG_2, "HMAC failed");

        return (BAD);
    }
    return (GOOD);
}



/*
 * Compute and fill auth data field
 *
 * TODO Support more than SHA1
 */

int complete_auth_fields(int key_id, uint16_t * key_id_pos, char *key,
        void *packet, int pckt_len, void *auth_data_pos)
{
    int err;

    *key_id_pos = htons(key_id);

    switch (key_id) {
    default:   //HMAC_SHA_1_96     /* TODO support more auth algorithms */
        err = compute_sha1_hmac(key, packet, pckt_len, auth_data_pos);
        return (err);

    }

}



int
check_sha1_hmac(char *key, void *packet, int pckt_len, void *auth_data_pos)
{
    uint16_t auth_data_len;
    unsigned int md_len; /* Length of the HMAC output.  */

    uint8_t* auth_data_copy;

    auth_data_len = get_auth_data_len(HMAC_SHA_1_96);

    auth_data_copy = (uint8_t *) malloc(auth_data_len * sizeof(uint8_t));
    if (auth_data_copy == NULL) {
        lmlog(LISP_LOG_ERR, "check_sha1_hmac: malloc() failed");
        return (BAD);
    }

    /* Copy the data to another location and put 0's on the auth data field of the packet */
    memcpy(auth_data_copy, auth_data_pos, auth_data_len);
    memset(auth_data_pos, 0, auth_data_len);

    if (!HMAC((const EVP_MD *) EVP_sha1(), (const void *) key, strlen(key),
            (uchar *) packet, pckt_len, (uchar *) auth_data_pos, &md_len)) {
        lmlog(LISP_LOG_DEBUG_2, "SHA1 HMAC failed");
        free(auth_data_copy);
        return (BAD);
    }
    if ((strncmp((char *) auth_data_pos, (char *) auth_data_copy,
            (size_t) auth_data_len)) == 0) {
        free(auth_data_copy);
        return (GOOD);
    } else {
        free(auth_data_copy);
        return (BAD);
    }
}

int
check_auth_field(int key_id, char *key, void *packet, int pckt_len,
        void *auth_data_pos)
{

    switch (key_id) {
    default: /* Only sha1 hmac supported at the moment */
        return (check_sha1_hmac(key, packet, pckt_len, auth_data_pos));

    }

}







