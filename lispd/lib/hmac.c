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

#include <stdlib.h>

#include "hmac.h"
#include "lmlog.h"
#include "../elibs/mbedtls/md.h"
#include "../liblisp/lisp_message_fields.h"



/*
 * Compute and fill auth data field
 *
 * TODO Support more than SHA1
 */

int
complete_auth_fields(uint8_t key_id, const char *key, void *packet, size_t pckt_len,
        void *auth_data_pos)
{
    const mbedtls_md_info_t *md_info;
    mbedtls_md_type_t md_type;
    size_t auth_data_len;

    switch (key_id) {
    case HMAC_SHA_1_96:
        md_type = MBEDTLS_MD_SHA1;
        auth_data_len = SHA1_AUTH_DATA_LEN;
        break;
    default:
        LMLOG(LDBG_2, "complete_auth_fields: HMAC unknown key type: %d", (int)key_id);
        return(BAD);
    }

    md_info = mbedtls_md_info_from_type(md_type);

    memset(auth_data_pos,0,auth_data_len);
    if (mbedtls_md_hmac(md_info,
            (const unsigned char *)key,
            strlen(key),
            (const unsigned char *)packet,
            pckt_len,
            (unsigned char *)auth_data_pos) != 0){
        LMLOG(LDBG_2, "complete_auth_fields: Error using mbedtls");
        return (BAD);
    }

    return (GOOD);
}


int
check_auth_field(uint8_t key_id, const char *key, void *packet, size_t pckt_len,
        void *auth_data_pos)
{
    size_t auth_data_len;
    uint8_t* auth_data_copy;

    const mbedtls_md_info_t *md_info;
    mbedtls_md_type_t md_type;

    switch (key_id) {
    case HMAC_SHA_1_96:
        md_type = MBEDTLS_MD_SHA1;
        auth_data_len = SHA1_AUTH_DATA_LEN;
        break;
    default:
        LMLOG(LDBG_2, "complete_auth_fields: HMAC unknown key type: %d", (int)key_id);
        return(BAD);
    }

    auth_data_copy = (uint8_t *) xmalloc(auth_data_len*sizeof(uint8_t));
    if (auth_data_copy == NULL) {
        LMLOG(LERR, "check_sha1_hmac: malloc() failed");
        return(ERR_MALLOC);
    }

    /* Copy the data to another location and put 0's on the auth data field of the packet */
    memcpy(auth_data_copy,auth_data_pos,auth_data_len);
    memset(auth_data_pos,0,auth_data_len);


    md_info = mbedtls_md_info_from_type(md_type);
    if (mbedtls_md_hmac(md_info,
            (const unsigned char *)key,
            strlen(key),
            (const unsigned char *)packet,
            pckt_len,
            (unsigned char *)auth_data_pos) != 0){
        LMLOG(LDBG_2, "check_auth_field: Error using mbedtls");
        return (BAD);
    }

    if ((strncmp((char *)auth_data_pos, (char *)auth_data_copy, auth_data_len)) == 0) {
        free(auth_data_copy);
        return(GOOD);
    } else {
        free(auth_data_copy);
        return(BAD);
    }
}

