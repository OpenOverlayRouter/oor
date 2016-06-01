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

#ifndef VXLAN_GPE_H_
#define VXLAN_GPE_H_

#include "../../lib/lbuf.h"
#include "../../lib/mem_util.h"
#include "../../liblisp/lisp_address.h"

#define VXLAN_GPE_DATA_PORT  4790

/*
 * VXLAN-GPE data packet header
 *
 *     0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |R|R|Ver|I|P|R|O|       Reserved                |Next Protocol  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                VXLAN Network Identifier (VNI) |   Reserved    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

 typedef struct vxlan_gpe_hdr {
     #ifdef LITTLE_ENDIANS
     uint8_t oam_flag:1;
     uint8_t resv_flags_1:1;
     uint8_t next_prot_flag:1;
     uint8_t vni_flag:1;
     uint8_t vxlan_ver:2;
     uint8_t resv_flags_2:2;
     #else
     uint8_t resv_flags_2:2;
     uint8_t vxlan_ver:2;
     uint8_t vni_flag:1;
     uint8_t next_prot_flag:1;
     uint8_t resv_flags_1:1;
     uint8_t oam_flag:1;
     #endif
     uint8_t reserved_1[2];
     uint8_t next_proto;
     uint8_t vni[3];
     uint8_t reserved_2;
 } vxlan_gpe_hdr_t;


 typedef enum {
     NP_IPv4 = 0x1,
     NP_IPv6 = 0x2,
     NP_ETH = 0x3,
     NP_NSH = 0x4,
     NP_MLS = 0x5
 }vxlan_gpe_nprot_t;

void * vxlan_gpe_data_push_hdr(lbuf_t *b, uint32_t vni, vxlan_gpe_nprot_t np);
void * vxlan_gpe_data_encap(lbuf_t *b, int lp, int rp, lisp_addr_t *la, lisp_addr_t *ra,
        uint32_t vni);
void * vxlan_gpe_data_pull_hdr(lbuf_t *b);

uint32_t vxlan_gpe_hdr_get_vni(vxlan_gpe_hdr_t *hdr);

#define VXLAN_HDR_CAST(h_) ((vxlan_gpe_hdr_t *)(h_))
#define VXLAN_HDR_VNI_BIT(h_) (VXLAN_HDR_CAST((h_)))->vni_flag


#endif /* VXLAN_GPE_H_ */
