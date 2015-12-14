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
#ifndef OOR_API_H_
#define OOR_API_H_

#include <stdint.h>

#define IPC_FILE "ipc:///tmp/oor-ipc"

#define MAX_API_PKT_LEN 4096 //MAX_IP_PKT_LEN

enum {
    OOR_API_NOFLAGS,
	OOR_API_DONTWAIT,
	OOR_API_ERROR = -1,
	OOR_API_NOTHINGTOREAD = -2
};

typedef enum oor_api_msg_device_e_ {

    OOR_API_DEV_XTR,
    OOR_API_DEV_MS,
    OOR_API_DEV_MR,
    OOR_API_DEV_RTR

} oor_api_msg_device_e; //Device of the operation

typedef enum oor_api_msg_opr_e_ {

    OOR_API_OPR_CREATE,
    OOR_API_OPR_READ,
    OOR_API_OPR_UPDATE,
    OOR_API_OPR_DELETE

} oor_api_msg_opr_e; //Type of operation

typedef enum oor_api_msg_target_e_ {

    OOR_API_TRGT_MRLIST,
    OOR_API_TRGT_MSLIST,
    OOR_API_TRGT_PETRLIST,
    OOR_API_TRGT_MAPCACHE,
    OOR_API_TRGT_MAPDB

} oor_api_msg_target_e; //Target of the operation

typedef enum lmapi_msg_type_e_ {

    OOR_API_TYPE_REQUEST,
    OOR_API_TYPE_RESULT

} oor_api_msg_type_e; //Type

typedef enum lmapi_msg_result_e_ {

    OOR_API_RES_OK,
    OOR_API_RES_ERR

} oor_api_msg_result_e; //Results

typedef struct oor_api_msg_hdr_t_ {

    uint8_t device;
    uint8_t target;
    uint8_t operation;
    uint8_t type;
    uint32_t datalen;

} oor_api_msg_hdr_t;

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

typedef struct oor_api_msg_ms_t_{
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
}oor_api_msg_ms_t;

typedef struct oor_api_connection_t_ {
    void *context;
    void *socket;
} oor_api_connection_t;

/* Initialize API system (client) */
int oor_api_init_client(oor_api_connection_t *conn);

/* Shutdown API system */
void oor_api_end(oor_api_connection_t *conn);

uint8_t *oor_api_hdr_push(uint8_t *buf, oor_api_msg_hdr_t * hdr);

int oor_api_send(oor_api_connection_t *conn, void *msg, int len, int flags);

int oor_api_recv(oor_api_connection_t *conn, void *buffer, int flags);

void oor_api_fill_hdr(oor_api_msg_hdr_t *hdr, oor_api_msg_device_e dev,
        oor_api_msg_target_e trgt, oor_api_msg_opr_e opr,
        oor_api_msg_type_e type, int dlen);

int oor_api_result_msg_new(uint8_t **buf,oor_api_msg_device_e  dev,
        oor_api_msg_target_e trgt, oor_api_msg_opr_e opr,
        oor_api_msg_result_e res);

int oor_api_apply_config(oor_api_connection_t *conn, int dev, int trgt, int opr,
        uint8_t *data, int dlen);

#endif /*OOR_API_H_*/
