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

#ifndef NETM_VPP_H_
#define NETM_VPP_H_

#include <stdint.h>

#define VPP_IPC_FILE "ipc:///tmp/oor-vpp-ipc"

typedef struct netm_vpp_data_ {
    void *zmq_context;
    void *zmq_socket;
} netm_vpp_data_t;


typedef enum vpp_netlink_msg_type_ {
    VPP_NEWADDR,
    VPP_DELADDR,
    VPP_NEWLINK,
    VPP_DELLINK,
    VPP_NEWROUTE,
    VPP_DELROUTE
} vpp_netlink_msg_type_e;


typedef struct vpp_nl_msg_{
    vpp_netlink_msg_type_e type;
    uint32_t len;
}vpp_nl_msg;

typedef struct{
    uint32_t ifi_index;
}vpp_nl_link_info;

typedef struct{
    uint8_t ifa_family;
    uint8_t ifa_prefixlen;
    uint32_t ifa_index;
}vpp_nl_addr_info;

#endif /* NETM_VPP_H_ */
