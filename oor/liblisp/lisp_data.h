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

#ifndef LISP_DATA_H_
#define LISP_DATA_H_

//#include "stdint.h"
#include "../lib/util.h"

 /* LISP data packet header */

 typedef struct lisphdr {
     #ifdef __LITTLE_ENDIAN_BITFIELD
     uint8_t rflags:3;
     uint8_t instance_id:1;
     uint8_t map_version:1;
     uint8_t echo_nonce:1;
     uint8_t lsb:1;
     uint8_t nonce_present:1;
     #else
     uint8_t nonce_present:1;
     uint8_t lsb:1;
     uint8_t echo_nonce:1;
     uint8_t map_version:1;
     uint8_t instance_id:1;
     uint8_t rflags:3;
     #endif
     uint8_t nonce[3];
     uint32_t lsb_bits;
 } lisphdr_t;

/* LISP Data header structure */
typedef struct lisp_data_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t rflags:3;
    uint8_t instance_id:1;
    uint8_t map_version:1;
    uint8_t echo_nonce:1;
    uint8_t lsb:1;
    uint8_t nonce_present:1;
#else
    uint8_t nonce_present:1;
    uint8_t lsb:1;
    uint8_t echo_nonce:1;
    uint8_t map_version:1;
    uint8_t instance_id:1;
    uint8_t rflags:3;
#endif
    uint8_t nonce[3];
    uint32_t lsb_bits;
} lisp_data_hdr_t;


void lisp_data_hdr_init(lisphdr_t *lhdr);

#endif /* LISP_DATA_H_ */
