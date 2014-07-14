/*
 * hmac.c
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
 *    Albert López   <alopez@ac.upc.edu>
 *
 */

#include "../lispd.h"
#include "../lispd_log.h"
#include "hmac.h"
#include "hmac-sha1.h"
#include "hmac-sha256.h"
#include <stdlib.h>

/*
 * Compute and fill auth data field
 *
 * TODO Support more than SHA1
 */

int complete_auth_fields(uint8_t key_id,
                         char *key,
                         void *packet,
                         int pckt_len,
                         void *auth_data_pos)
{
    uint16_t auth_data_len;

    auth_data_len = get_auth_data_len(key_id);

    memset(auth_data_pos,0,auth_data_len);
    switch (key_id) {
    case HMAC_SHA_1_96:
        sha1_hmac((const unsigned char *) key,
                strlen(key),
                (const unsigned char *) packet,
                pckt_len,
                (unsigned char *) auth_data_pos);
        return(GOOD);
//    case HMAC_SHA_256_128:
//        sha256_hmac((const unsigned char *) key,
//                strlen(key),
//                (const unsigned char *) packet,
//                pckt_len,
//                (unsigned char *) auth_data_pos,
//                0);
//        return(GOOD);
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "complete_auth_fields: HMAC unknown key type: %d", (int)key_id);
        return(BAD);
    }
}


int check_auth_field(uint8_t key_id,
                     char *key,
                     void *packet,
                     int pckt_len,
                     void *auth_data_pos)
{
    uint16_t auth_data_len;
    uint8_t* auth_data_copy;

    auth_data_len = get_auth_data_len(key_id);

    auth_data_copy = (uint8_t *) malloc(auth_data_len*sizeof(uint8_t));
    if (auth_data_copy == NULL) {
        lispd_log_msg(LISP_LOG_ERR, "check_sha1_hmac: malloc() failed");
        return(ERR_MALLOC);
    }

    /* Copy the data to another location and put 0's on the auth data field of the packet */
    memcpy(auth_data_copy,auth_data_pos,auth_data_len);
    memset(auth_data_pos,0,auth_data_len);

    switch (key_id){
    case HMAC_SHA_1_96:
        sha1_hmac((const unsigned char *) key,
                strlen(key),
                (const unsigned char *) packet,
                pckt_len,
                (unsigned char *) auth_data_pos);
        break;
//    case HMAC_SHA_256_128:
//        sha256_hmac((const unsigned char *) key,
//                strlen(key),
//                (const unsigned char *) packet,
//                pckt_len,
//                (unsigned char *) auth_data_pos,
//                0);
//        break;
    default:
        lispd_log_msg(LISP_LOG_DEBUG_2, "check_auth_field: HMAC unknown key type: %d", (int)key_id);
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


/*
 * Returns the length of the auth data field based on the key_id value
 */

uint16_t get_auth_data_len(uint8_t key_id)

{
    switch (key_id) {
    case HMAC_SHA_1_96:
        return (LISP_SHA1_AUTH_DATA_LEN);
    case HMAC_SHA_256_128:
        return (LISP_SHA256_AUTH_DATA_LEN);
    default: // HMAC_SHA_1_96
        return (LISP_SHA1_AUTH_DATA_LEN);   //TODO support more auth algorithms
    }
}
