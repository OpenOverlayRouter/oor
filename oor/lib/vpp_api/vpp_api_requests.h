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

#ifndef OOR_LIB_VPP_API_VPP_API_REQUESTS_H_
#define OOR_LIB_VPP_API_VPP_API_REQUESTS_H_

#include "../generic_list.h"
#include "../../fwd_policies/vpp_balancing/fwd_entry_vpp.h"

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/byte_order.h>


typedef struct
{
    /* vpe input queue */
    unix_shared_memory_queue_t *vl_input_queue;

    /* interface list */
    glist_t *iface_list;

    /* Address of the requested interface*/
    glist_t *ip_addr_lst; //<lisp_addr_t *>
    /* List of prefixes */
    glist_t *prefix_lst; //<lisp_addr_t *>
    /* Gateway */
    lisp_addr_t *gw;

    int table_id;
    int requested_ip_afi;

    /* our client index */
    uint32_t my_client_index;

    /* Main thread can spin (w/ timeout) here if needed */
    uint32_t async_mode;
    uint32_t async_errors;
    volatile uint32_t result_ready;
    volatile int32_t  retval;
    volatile uint32_t sw_if_index;

    /* Time is of the essence... */
    clib_time_t clib_time;
} vpp_api_main_t;

typedef struct
{
  u8 ip[16];
  u8 prefix_length;
} ip_address_details_t;

typedef struct
{
    uint32_t iface_index;
    char *iface_name;
    uint8_t status;
    uint8_t l2_address[8];
} vpp_api_iface_t;


#define MSG(T,t)                                \
do {                                            \
    vam->result_ready = 0;                      \
    mp = vl_msg_api_alloc_as_if_client(sizeof(*mp));  \
    memset (mp, 0, sizeof (*mp));               \
    mp->_vl_msg_id = ntohs (VL_API_##T);        \
    mp->client_index = vam->my_client_index;    \
} while(0);

#define MSG_PLUS(T,t,n)                         \
do {                                            \
    vam->result_ready = 0;                      \
    mp = vl_msg_api_alloc(sizeof(*mp)+(n));     \
    memset (mp, 0, sizeof (*mp));               \
    mp->_vl_msg_id = ntohs (VL_API_##T);        \
    mp->client_index = vam->my_client_index;    \
} while(0);

#define MSG_PLUGIN(T,t,n)                       \
do {                                            \
    vam->result_ready = 0;                      \
    mp = vl_msg_api_alloc(sizeof(*mp));         \
    memset (mp, 0, sizeof (*mp));               \
    mp->_vl_msg_id = ntohs (VL_API_##T + n);    \
    mp->client_index = vam->my_client_index;    \
} while(0);

/* VPP_SEND: send a message */
#define VPP_SEND (vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp))


extern vpp_api_main_t vpp_api_main;
extern vlib_main_t vlib_global_main;
extern vlib_main_t **vlib_mains;

/* vpp_wait: wait for results, with timeout */
int vpp_wait(vpp_api_main_t * vam);

clib_error_t *pkt_miss_plugin_register (vpp_api_main_t * vam);
clib_error_t *ctrl_plugin_register (vpp_api_main_t * vam);

int vpp_create_ap_iface(char *iface_name, uint8_t *mac);
int vpp_set_interface_unnumbered (uint32_t iface_index, int action);
int vpp_lisp_gpe_enable_disable(uint8_t enable_lisp_gpe);
int vpp_lisp_gpe_add_del_iface(uint32_t table, uint32_t vni, uint8_t action);
int vpp_lisp_eid_table_add_del_map (uint32_t table, uint32_t vni, uint8_t action);
int vpp_set_interface_status (uint32_t iface_indx, uint8_t status);
int vpp_oor_pkt_miss_enable_disable(char *iface_name, uint8_t enable_disable);
int vpp_oor_ctrl_enable_disable (char *iface_name, uint8_t enable_disable);
int vpp_oor_pkt_miss_native_route (lisp_addr_t *prefix, uint8_t is_add);
int vpp_oor_pkt_miss_drop_route (lisp_addr_t *prefix, uint8_t is_add, uint32_t table_id);
lisp_addr_t *vpp_oor_pkt_miss_get_default_route (int afi);
int vpp_lisp_gpe_add_del_fwd_entry (fwd_entry_vpp_t *fe, lisp_action_e action, uint8_t is_add);
int vpp_interface_get_table(uint32_t iface_index, uint8_t is_ipv6);
glist_t * vpp_ip_fib_prefixs(int afi);

static inline vpp_api_main_t *
vpp_api_main_get()
{
    return (&vpp_api_main);
}

void vat_api_hookup (vpp_api_main_t * vam);


#endif /* OOR_LIB_VPP_API_VPP_API_REQUESTS_H_ */
