
/*
 * oor_ctrl.h - skeleton vpp engine plug-in header file 
 *
 * Copyright (c) <current-year> <your-organization>
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
 */
#ifndef __included_oor_ctrl_h__
#define __included_oor_ctrl_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#define OOR_IPC_FILE "ipc:///tmp/oor-vpp-ipc"


typedef enum netlink_msg_type_ {
    VPP_NEWADDR,
    VPP_DELADDR,
    VPP_NEWLINK,
    VPP_DELLINK,
    VPP_NEWROUTE,
    VPP_DELROUTE
} netlink_msg_type_e;

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    u32 sw_if_index;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    ethernet_main_t * ethernet_main;
} oor_ctrl_main_t;

typedef struct vpp_nl_msg_{
    netlink_msg_type_e type;
    u32 len;
}vpp_nl_msg;

typedef struct{
    u32 ifi_index;
}vpp_nl_link_info;

typedef struct{
    u8 ifa_family;
    u8 ifa_prefixlen;
    u32 ifa_index;
}vpp_nl_addr_info;

oor_ctrl_main_t oor_ctrl_main;

extern vlib_node_registration_t oor_ctrl_ipv4_node;
extern vlib_node_registration_t oor_ctrl_ipv6_node;

#define OOR_CTRL_PLUGIN_BUILD_VER "1.0"

#endif /* __included_oor_ctrl_h__ */
