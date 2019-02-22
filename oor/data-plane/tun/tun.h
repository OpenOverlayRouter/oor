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

#ifndef TUN_H_
#define TUN_H_


#include "../ttable.h"
#include "../encapsulations/vxlan-gpe.h"
#include "../../lib/shash.h"
#include "../../liblisp/liblisp.h"


#define TUN_IFACE_NAME          "lispTun0"
#define TUN_RECEIVE_SIZE        2048


/*
 * From section 5.4.1 of LISP RFC (6830)
 *

 1 .  Define H to be the size, in* octets, of the outer header an ITR
 prepends to a packet.  This includes the UDP and LISP header
 lengths.
 
 2.  Define L to be the size, in octets, of the maximum-sized packet
 an ITR can send to an ETR without the need for the ITR or any
 intermediate routers to fragment the packet.
 
 3.  Define an architectural constant S for the maximum size of a
 packet, in octets, an ITR must receive so the effective MTU can
 be met.  That is, S = L - H.

 [...]

 This specification RECOMMENDS that L be defined as 1500.
 
 */

/* H = 40 (IPv6 header) + 8 (UDP header) + 8 (LISP header) + 4 (extra/safety) = 60 */

#define TUN_MTU                 1440 /* 1500 - 60 = 1440 */


/* Tun MN variables */

int tun_receive_fd;
int tun_ifindex;
uint8_t *tun_receive_buf;

lisp_addr_t * tun_get_default_output_address(int afi);
int tun_get_default_output_socket(int);

typedef struct iface iface_t;

typedef struct tun_dplane_data_{
    oor_encap_t encap_type;
    iface_t *default_out_iface_v4;
    iface_t *default_out_iface_v6;
    /* < char *eid -> glist_t <fwd_info_t *>> Used to find the fwd entries to be removed
     * of the data plane when there is a change with the mapping of the eid */
    shash_t *eid_to_dp_entries; //< char *eid -> glist_t <fwd_info_t *>>
    /* Hash table containg the forward info from a tupla */
    ttable_t ttable;
    /* List of allowed destination EID prefixes. Empty list is all Internet */
    glist_t *allowed_eid_prefixes;
}tun_dplane_data_t;

tun_dplane_data_t * tun_get_datap_data();
int tun_reset_all_fwd();

extern data_plane_struct_t dplane_tun;


#endif /* TUN_H_ */

