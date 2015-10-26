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
#ifndef LISPD_API_H_
#define LISPD_API_H_

#include <stdint.h>

#define IPC_FILE "ipc:///tmp/lispmob-ipc"

#define MAX_API_PKT_LEN 4096 //MAX_IP_PKT_LEN

enum {
    LMAPI_NOFLAGS,
	LMAPI_DONTWAIT,
	LMAPI_ERROR = -1,
	LMAPI_NOTHINGTOREAD = -2
};

typedef enum lmapi_msg_device_e_ {

    LMAPI_DEV_XTR,
    LMAPI_DEV_MS,
    LMAPI_DEV_MR,
    LMAPI_DEV_RTR

} lmapi_msg_device_e; //Device of the operation

typedef enum lmapi_msg_opr_e_ {

    LMAPI_OPR_CREATE,
    LMAPI_OPR_READ,
    LMAPI_OPR_UPDATE,
    LMAPI_OPR_DELETE

} lmapi_msg_opr_e; //Type of operation

typedef enum lmapi_msg_target_e_ {

    LMAPI_TRGT_MRLIST,
    LMAPI_TRGT_MSLIST,
    LMAPI_TRGT_PETRLIST,
    LMAPI_TRGT_MAPCACHE,
    LMAPI_TRGT_MAPDB

} lmapi_msg_target_e; //Target of the operation

typedef enum lmapi_msg_type_e_ {

    LMAPI_TYPE_REQUEST,
    LMAPI_TYPE_RESULT

} lmapi_msg_type_e; //Type

typedef enum lmapi_msg_result_e_ {

    LMAPI_RES_OK,
    LMAPI_RES_ERR

} lmapi_msg_result_e; //Results

typedef struct lmapi_msg_hdr_t_ {

    uint8_t device;
    uint8_t target;
    uint8_t operation;
    uint8_t type;
    uint32_t datalen;

} lmapi_msg_hdr_t;

/*
*      0                   1                   2                   3
*       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*      |               Address AFI     |      MS Address  ...          |
*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*      |P|           Reserved          |            Key ID             |
*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*      |                          Key Length                           |
*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*      |                          Key  ...                             |
*      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

typedef struct lmapi_msg_ms_t_{
#ifdef LITTLE_ENDIANS
    uint8_t reserved:7;
    uint8_t proxy_bit:1;
#else
    uint8_t proxy_bit:1;
    uint8_t reserved:7;
#endif
    uint8_t reserved2;
    uint16_t key_id;
    uint32_t key_len;
}lmapi_msg_ms_t;

typedef struct lmapi_connection_t_ {
    void *context;
    void *socket;
} lmapi_connection_t;

/* Initialize API system (client) */
int lmapi_init_client(lmapi_connection_t *conn);

/* Shutdown API system */
void lmapi_end(lmapi_connection_t *conn);

uint8_t *lmapi_hdr_push(uint8_t *buf, lmapi_msg_hdr_t * hdr);

int lmapi_send(lmapi_connection_t *conn, void *msg, int len, int flags);

int lmapi_recv(lmapi_connection_t *conn, void *buffer, int flags);

void fill_lmapi_hdr(lmapi_msg_hdr_t *hdr, lmapi_msg_device_e dev,
        lmapi_msg_target_e trgt, lmapi_msg_opr_e opr,
        lmapi_msg_type_e type, int dlen);

int lmapi_result_msg_new(uint8_t **buf,lmapi_msg_device_e  dev,
        lmapi_msg_target_e trgt, lmapi_msg_opr_e opr,
        lmapi_msg_result_e res);

int lmapi_apply_config(lmapi_connection_t *conn, int dev, int trgt, int opr,
        uint8_t *data, int dlen);

#endif /*LISPD_API_H_*/
