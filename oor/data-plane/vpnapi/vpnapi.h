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


#ifndef VPN_API_H_
#define VPN_API_H_

#include "../ttable.h"
#include "../../lib/shash.h"

typedef struct vpnapi_data_ {
    oor_encap_t encap_type;
    int tun_socket;
    int ipv4_data_socket;
    int ipv6_data_socket;
    /* < char *eid -> glist_t <fwd_info_t *>> Used to find the fwd entries to be removed
     * of the data plane when there is a change with the mapping of the eid */
    shash_t *eid_to_dp_entries; //< char *eid -> glist_t <fwd_info_t *>>
    /* Hash table containg the forward info from a tupla */
    ttable_t ttable;
} vpnapi_data_t;

vpnapi_data_t * vpnapi_get_datap_data();
int vpnapi_reset_all_fwd();
#endif /* VPN_API_H_ */
