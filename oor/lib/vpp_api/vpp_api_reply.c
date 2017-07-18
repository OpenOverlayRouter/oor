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


#include "../mem_util.h"
#include "../oor_log.h"
#include "../../defs.h"
#include "../../liblisp/lisp_address.h"

#include <vppinfra/hash.h>


#include <vpp/api/vpe_msg_enum.h>

#include "vpp_api_requests.h"

/* define message structures */

#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun        /* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_printfun

#define vl_api_version(n,v) static u32 api_version=(v);
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h>
#undef vl_api_version

inline static vpp_api_iface_t *
vpp_api_iface_new()
{
    vpp_api_iface_t *iface = (vpp_api_iface_t *)xzalloc(sizeof(vpp_api_iface_t));
    return (iface);
}

inline static void
vpp_api_iface_free(vpp_api_iface_t *iface)
{
    if (iface->iface_name){
        free(iface->iface_name);
    }
    free (iface);
    iface = NULL;
}

#define foreach_standard_reply_retval_handler                   \
        _(sw_interface_set_flags_reply)                         \
        _(sw_interface_set_unnumbered_reply)                    \
        _(gpe_enable_disable_reply)                             \
        _(gpe_add_del_iface_reply)                         \
        _(gpe_add_del_fwd_entry_reply)

#define _(n)                                    \
        static void vl_api_##n##_t_handler (vl_api_##n##_t * mp)     \
        {                                           \
            vpp_api_main_t * vam = &vpp_api_main;   \
            uint32_t retval = ntohl(mp->retval);    \
            if (vam->async_mode) {                  \
                vam->async_errors += (retval < 0);  \
            } else {                                \
                vam->retval = retval;               \
                vam->result_ready = 1;              \
            }                                       \
        }
foreach_standard_reply_retval_handler;
#undef _

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */

#define foreach_vpp_api_reply_msg                                               \
        _(SW_INTERFACE_DETAILS, sw_interface_details)                           \
        _(SW_INTERFACE_SET_FLAGS_REPLY, sw_interface_set_flags_reply)           \
        _(SW_INTERFACE_SET_UNNUMBERED_REPLY,sw_interface_set_unnumbered_reply)  \
        _(CONTROL_PING_REPLY, control_ping_reply)                               \
        _(IP_ADDRESS_DETAILS, ip_address_details)                               \
        _(IP_FIB_DETAILS, ip_fib_details)                                       \
        _(IP6_FIB_DETAILS, ip6_fib_details)                                     \
        _(AF_PACKET_CREATE_REPLY, af_packet_create_reply)                       \
        _(GPE_ENABLE_DISABLE_REPLY, gpe_enable_disable_reply)                   \
        _(GPE_ADD_DEL_IFACE_REPLY, gpe_add_del_iface_reply)           \
        _(GPE_ADD_DEL_FWD_ENTRY_REPLY, gpe_add_del_fwd_entry_reply)   \
        _(SW_INTERFACE_GET_TABLE_REPLY, sw_interface_get_table_reply)



u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}


/********************** API REPLY HANDLER ***********************************/

static void
vl_api_control_ping_reply_t_handler(vl_api_control_ping_reply_t * mp)
{
    vpp_api_main_t *vam = &vpp_api_main;
    i32 retval = ntohl (mp->retval);
    if (vam->async_mode)
    {
        vam->async_errors += (retval < 0);
    }
    else
    {
        vam->retval = retval;
        vam->result_ready = 1;
    }
}

/*
 * Special-case: build the interface table, maintain
 * the next loopback sw_if_index vbl.
 */
static void
vl_api_sw_interface_details_t_handler(vl_api_sw_interface_details_t * mp)
{
    vpp_api_main_t *vam = &vpp_api_main;
    vpp_api_iface_t *iface = vpp_api_iface_new();

    iface->iface_index = ntohl(mp->sw_if_index);
    iface->iface_name = strdup((char *)format (0, "%s%c", mp->interface_name, 0));
    iface->status = (mp->admin_up_down == 1 && mp->link_up_down == 1) ? UP : FALSE;
    memcpy(iface->l2_address, mp->l2_address, sizeof(mp->l2_address));

    glist_add(iface,vam->iface_list);
}

static void
vl_api_ip_address_details_t_handler(vl_api_ip_address_details_t * mp)
{
    vpp_api_main_t *vam = &vpp_api_main;
    lisp_addr_t *addr;

    addr = lisp_addr_new_lafi(LM_AFI_IP);
    ip_addr_init(lisp_addr_ip(addr),  &mp->ip, vam->requested_ip_afi);
    lisp_addr_set_plen(addr,mp->prefix_length);
    glist_add(addr,vam->ip_addr_lst);
}


static void
vl_api_af_packet_create_reply_t_handler(vl_api_af_packet_create_reply_t * mp)
{
    vpp_api_main_t *vam = &vpp_api_main;
    i32 retval = ntohl (mp->retval);

    vam->retval = retval;
    vam->sw_if_index = ntohl (mp->sw_if_index);
    vam->result_ready = 1;
}

static void
vl_api_sw_interface_get_table_reply_t_handler(vl_api_sw_interface_get_table_reply_t * mp)
{
    vpp_api_main_t *vam = &vpp_api_main;

    vam->table_id = ntohl (mp->vrf_id);
    vam->retval = ntohl (mp->retval);
    vam->result_ready = 1;

}

#define vl_api_ip_fib_details_t_endian vl_noop_handler
#define vl_api_ip_fib_details_t_print vl_noop_handler

static void
vl_api_ip_fib_details_t_handler (vl_api_ip_fib_details_t * mp)
{
    vpp_api_main_t *vam = &vpp_api_main;
    lisp_addr_t *pref;

    pref = lisp_addr_new_lafi(LM_AFI_IPPREF);
    ip_addr_init(lisp_addr_ip(pref),  &mp->address, AF_INET);
    lisp_addr_set_plen(pref,mp->address_length);
    glist_add(pref,vam->prefix_lst);
}

#define vl_api_ip6_fib_details_t_endian vl_noop_handler
#define vl_api_ip6_fib_details_t_print vl_noop_handler

static void
vl_api_ip6_fib_details_t_handler (vl_api_ip6_fib_details_t * mp)
{
    vpp_api_main_t *vam = &vpp_api_main;
    lisp_addr_t *pref;

    pref = lisp_addr_new_lafi(LM_AFI_IPPREF);
    ip_addr_init(lisp_addr_ip(pref),  &mp->address, AF_INET6);
    lisp_addr_set_plen(pref,mp->address_length);
    glist_add(pref,vam->prefix_lst);
}


/***************************************************************************************/

#define _(N,n)                                  \
    static void vl_api_##n##_t_handler_uni      \
    (vl_api_##n##_t * mp)                       \
    {                                           \
        vl_api_##n##_t_handler(mp);             \
    }
foreach_vpp_api_reply_msg;
#undef _

void
vat_api_hookup (vpp_api_main_t * vam)
{
#define _(N,n)                                       \
        vl_msg_api_set_handlers(VL_API_##N, #n,      \
                vl_api_##n##_t_handler_uni,          \
                vl_noop_handler,                     \
                vl_api_##n##_t_endian,               \
                vl_api_##n##_t_print,                \
                sizeof(vl_api_##n##_t), 1);
    foreach_vpp_api_reply_msg;
#undef _
    vl_msg_api_set_first_available_msg_id (VL_MSG_FIRST_AVAILABLE);

    vam->iface_list = glist_new_managed((glist_del_fct)vpp_api_iface_free);
    vam->ip_addr_lst = glist_new_managed((glist_del_fct)lisp_addr_del);
    vam->prefix_lst = glist_new_managed((glist_del_fct)lisp_addr_del);
}



