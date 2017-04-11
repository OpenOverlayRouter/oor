
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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>

#include "../../defs.h"
#include "../../lib/oor_log.h"

/* Declare message IDs */
#include <oor_pkt_miss/oor_pkt_miss_msg_enum.h>
#include "vpp_api_requests.h"

/* define message structures */
#define vl_typedefs
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h>
#undef vl_printfun

#define vl_api_version(n,v) static u32 oor_pkt_miss_api_version=(v);
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h>
#undef vl_api_version

uint16_t pkt_miss_msg_id_base = ~0;


#define foreach_standard_reply_retval_handler   \
_(oor_pkt_miss_enable_disable_reply)            \
_(oor_pkt_miss_native_route_reply)              \
_(oor_pkt_miss_drop_route_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vpp_api_main_t * vam = vpp_api_main_get();      \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _


/* M: construct, but don't yet send a message */

#define M(T,t)                                      \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp));                         \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + pkt_miss_msg_id_base);          \
    mp->client_index = vam->my_client_index;                    \
} while(0);


/* S: send a message */
#define S (vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp))




int
vpp_oor_pkt_miss_enable_disable(char *iface_name, uint8_t enable_disable)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_oor_pkt_miss_enable_disable_t * mp;

    /* Construct the API message */
    M (OOR_PKT_MISS_ENABLE_DISABLE, oor_pkt_miss_enable_disable);
    memcpy (mp->host_if_name, iface_name, strlen(iface_name));
    mp->enable_disable = enable_disable;

    /* send it... */
    S;

    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not enable oor packet miss plugin");
        return (BAD);
    }
    return (GOOD);
}

int
vpp_oor_pkt_miss_native_route (lisp_addr_t *prefix, uint8_t is_add)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_oor_pkt_miss_native_route_t * mp;
    lisp_addr_t *ip_pref;
    int afi;

    ip_pref = lisp_addr_get_ip_pref_addr(prefix);
    afi = lisp_addr_ip_afi(ip_pref);

    /* Construct the API message */
    M(OOR_PKT_MISS_NATIVE_ROUTE, oor_pkt_miss_native_route);
    mp->is_add = is_add;
    mp->is_ipv6 = afi == AF_INET6 ? 1 : 0;
    mp->mask_len = lisp_addr_ip_get_plen(ip_pref);
    ip_addr_copy_to(mp->address, lisp_addr_ip_get_addr(ip_pref));

    /* send it... */
    S;

    /* Wait for a reply... */
    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not %s native route for prefix %s",
                is_add == ADD ? "add" : "rm",lisp_addr_to_char(prefix));
        return (BAD);
    }
    OOR_LOG(LDBG_3,"VPP %s native route for prefix %s",
            is_add == ADD ? "add" : "rm",lisp_addr_to_char(prefix));
    return (GOOD);
}

int
vpp_oor_pkt_miss_drop_route (lisp_addr_t *prefix, uint8_t is_add, uint32_t table_id)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_oor_pkt_miss_drop_route_t * mp;
    lisp_addr_t *ip_pref;
    int afi;

    ip_pref = lisp_addr_get_ip_pref_addr(prefix);
    afi = lisp_addr_ip_afi(ip_pref);
    /* Construct the API message */
    M(OOR_PKT_MISS_DROP_ROUTE, oor_pkt_miss_drop_route);
    mp->is_add = is_add;
    mp->is_ipv6 = afi == AF_INET6 ? 1 : 0;
    mp->mask_len = lisp_addr_ip_get_plen(ip_pref);
    ip_addr_copy_to(mp->address, lisp_addr_ip_get_addr(ip_pref));
    mp->table_id = table_id;

    /* send it... */
    S;

    /* Wait for a reply... */
    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not %s drop route for prefix %s from table %d",
                is_add == ADD ? "add" : "rm",
                lisp_addr_to_char(prefix), table_id);
        return (BAD);
    }
    OOR_LOG(LDBG_3,"VPP %s drop route for prefix %s from table %d",
                    is_add == ADD ? "add" : "rm",
                    lisp_addr_to_char(prefix), table_id);
    return (GOOD);
}

clib_error_t *
pkt_miss_plugin_register (vpp_api_main_t * vam)
{
    u8 * name;

    /* Ask the vpp engine for the first assigned message-id */

    name = format (0, "oor_pkt_miss_%08x%c", oor_pkt_miss_api_version, 0);
    pkt_miss_msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);
    vec_free(name);
    if (pkt_miss_msg_id_base != (uint16_t) ~0){
        vl_msg_api_set_handlers((VL_API_OOR_PKT_MISS_ENABLE_DISABLE_REPLY + pkt_miss_msg_id_base),     \
                "oor_pkt_miss_enable_disable_reply",                             \
                vl_api_oor_pkt_miss_enable_disable_reply_t_handler,              \
                vl_noop_handler,                                                 \
                vl_api_oor_pkt_miss_enable_disable_reply_t_endian,               \
                vl_api_oor_pkt_miss_enable_disable_reply_t_print,                \
                sizeof(vl_api_oor_pkt_miss_enable_disable_reply_t), 1);

        vl_msg_api_set_handlers((VL_API_OOR_PKT_MISS_NATIVE_ROUTE_REPLY + pkt_miss_msg_id_base),     \
                "oor_pkt_miss_native_route_reply",                             \
                vl_api_oor_pkt_miss_native_route_reply_t_handler,              \
                vl_noop_handler,                                               \
                vl_api_oor_pkt_miss_native_route_reply_t_endian,               \
                vl_api_oor_pkt_miss_native_route_reply_t_print,                \
                sizeof(vl_api_oor_pkt_miss_native_route_reply_t), 1);
        vl_msg_api_set_handlers((VL_API_OOR_PKT_MISS_DROP_ROUTE_REPLY + pkt_miss_msg_id_base),     \
                "oor_pkt_miss_drop_route_reply",                             \
                vl_api_oor_pkt_miss_drop_route_reply_t_handler,              \
                vl_noop_handler,                                               \
                vl_api_oor_pkt_miss_drop_route_reply_t_endian,               \
                vl_api_oor_pkt_miss_drop_route_reply_t_print,                \
                sizeof(vl_api_oor_pkt_miss_drop_route_reply_t), 1);
    }


    return 0;
}
