
/*
 * oor_ctrl.c - skeleton vpp engine plug-in 
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

#include <arpa/inet.h>
#include <vnet/udp/udp.h>
#include <vnet/vnet.h>
#include <vnet/adj/adj_types.h>
#include <vnet/devices/af_packet/af_packet.h>
#include <vnet/plugin/plugin.h>
#include <oor_ctrl/oor_ctrl.h>
#include <vppinfra/error.h>
#include <zmq.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <oor_ctrl/oor_ctrl_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <oor_ctrl/oor_ctrl_all_api_h.h> 
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <oor_ctrl/oor_ctrl_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <oor_ctrl/oor_ctrl_all_api_h.h> 
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <oor_ctrl/oor_ctrl_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>



static clib_error_t * oor_link_up_down_function (vnet_main_t * vm, u32 hw_if_index, u32 flags);
static clib_error_t * oor_admin_up_down_function (vnet_main_t * vm, u32 sw_if_index, u32 flags);
void oor_ip4_add_del_interface_address (ip4_main_t * im, uword opaque, u32 sw_if_index,
        ip4_address_t * address, u32 address_length, u32 if_address_index, u32 is_delete);
void oor_ip6_add_del_interface_address (ip6_main_t * im, uword opaque, u32 sw_if_index,
        ip6_address_t * address, u32 address_length, u32 if_address_index, u32 is_delete);



/* List of message types that this plugin understands */

#define foreach_oor_ctrl_plugin_api_msg                           \
        _(OOR_CTRL_ENABLE_DISABLE, oor_ctrl_enable_disable)



/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = OOR_CTRL_PLUGIN_BUILD_VER,
    .description = "OOR Ctrl plugin",
};
/* *INDENT-ON* */


/* Action function shared between message handler and debug CLI */

int oor_ctrl_enable_disable (oor_ctrl_main_t * sm, u8 * host_if_name,
        int enable_disable)
{
    u8 hwaddr[6] = {0,0,0,0,0,0};
    vnet_sw_interface_t *si;
    u32 sw_if_index = ~0;
    u16 flags;
    int rv;

    clib_warning("OOR_CTRL: %s node", enable_disable ? "enable" : "disale");

    if (enable_disable){
        /* Create host-interface */
        rv = af_packet_create_if (sm->vlib_main, host_if_name, hwaddr, &sw_if_index);
        if (rv != 0  && rv != VNET_API_ERROR_SUBIF_ALREADY_EXISTS){
            return (VNET_API_ERROR_INVALID_INTERFACE);
        }
        /* Set interface status to UP */
        flags = VNET_SW_INTERFACE_FLAG_ADMIN_UP;
        vnet_sw_interface_set_flags (sm->vnet_main, sw_if_index, flags);
        /* Set interface to unnumbered */
        si = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
        si->flags |= VNET_SW_INTERFACE_FLAG_UNNUMBERED;
        si->unnumbered_sw_if_index = sw_if_index;
        ip4_sw_interface_enable_disable (sw_if_index, 1);
        ip6_sw_interface_enable_disable (sw_if_index, 1);
        /* Indicate plagin where to write received packets */
        sm->sw_if_index = sw_if_index;
        // LISP GPE is enabled in the pkt miss plugin

    }else {
        /* Remove unnumbered interface*/
        si = vnet_get_sw_interface (sm->vnet_main, sm->sw_if_index);
        si->flags &= ~(VNET_SW_INTERFACE_FLAG_UNNUMBERED);
        si->unnumbered_sw_if_index = (u32) ~ 0;
        ip4_sw_interface_enable_disable (sm->sw_if_index, 0);
        ip6_sw_interface_enable_disable (sm->sw_if_index, 0);
        /* Disable host-interface to send control packets to oor */
        sm->sw_if_index = ~0;
        /* Remove host interfaces */
        af_packet_delete_if (sm->vlib_main, host_if_name);
    }

    return 0;
}

static clib_error_t *
oor_ctrl_enable_disable_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
    oor_ctrl_main_t * sm = &oor_ctrl_main;
    u8 *host_if_name = NULL;
    int enable_disable = 1;
    int rv;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "disable")){
            enable_disable = 0;
        }else if (unformat (input, "%s", &host_if_name)){
            ;
        }else{
            break;
        }
    }

    if (host_if_name == NULL){
        return clib_error_return (0, "Please specify an interface...");
    }

    rv = oor_ctrl_enable_disable (sm, host_if_name, enable_disable);

    switch(rv) {
    case 0:
        break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
        return clib_error_return
                (0, "Invalid interface, only works on physical ports");
        break;

    case VNET_API_ERROR_UNIMPLEMENTED:
        return clib_error_return (0, "Device driver doesn't support redirection");
        break;

    default:
        return clib_error_return (0, "oor_ctrl_enable_disable returned %d",
                rv);
    }
    return 0;
}

VLIB_CLI_COMMAND (oor_ctrl_enable_disable_command, static) = {
        .path = "oor_ctrl enable-disable",
        .short_help ="oor_ctrl enable-disable <interface-name> [disable]",
        .function = oor_ctrl_enable_disable_command_fn,
};


/* API message handler */
static void vl_api_oor_ctrl_enable_disable_t_handler
(vl_api_oor_ctrl_enable_disable_t * mp)
{
    vl_api_oor_ctrl_enable_disable_reply_t * rmp;
    oor_ctrl_main_t * sm = &oor_ctrl_main;
    u8 *host_if_name = NULL;
    int rv;
    host_if_name = format (0, "%s", mp->host_if_name);
    vec_add1 (host_if_name, 0);
    rv = oor_ctrl_enable_disable (sm, host_if_name,(int) (mp->enable_disable));
    vec_free (host_if_name);

    REPLY_MACRO(VL_API_OOR_CTRL_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
oor_ctrl_plugin_api_hookup (vlib_main_t *vm)
{
    oor_ctrl_main_t * sm = &oor_ctrl_main;
#define _(N,n)                                                  \
        vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                #n,					\
                vl_api_##n##_t_handler,              \
                vl_noop_handler,                     \
                vl_api_##n##_t_endian,               \
                vl_api_##n##_t_print,                \
                sizeof(vl_api_##n##_t), 1);
    foreach_oor_ctrl_plugin_api_msg;
#undef _

    return 0;
}

#define vl_msg_name_crc_list
#include <oor_ctrl/oor_ctrl_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (oor_ctrl_main_t * sm, api_main_t *am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_oor_ctrl;
#undef _
}

static clib_error_t * oor_ctrl_init (vlib_main_t * vm)
{
    oor_ctrl_main_t * sm = &oor_ctrl_main;
    clib_error_t * error = 0;
    ip4_add_del_interface_address_callback_t cb4;
    ip6_add_del_interface_address_callback_t cb6;
    ip4_main_t * im4 = &ip4_main;
    ip6_main_t * im6 = &ip6_main;
    u8 * name;

    sm->vnet_main = vnet_get_main ();
    sm->sw_if_index = ~0;

    name = format (0, "oor_ctrl_%08x%c", api_version, 0);

    /* Ask for a correctly-sized block of API message decode slots */
    sm->msg_id_base = vl_msg_api_get_msg_ids
            ((char *) name, VL_MSG_FIRST_AVAILABLE);

    error = oor_ctrl_plugin_api_hookup (vm);
    /* Add our API messages to the global name_crc hash table */
    setup_message_id_table (sm, &api_main);

    vec_free(name);

    udp_register_dst_port (vm, UDP_DST_PORT_lisp_cp,
            oor_ctrl_ipv4_node.index, 1 /* is_ip4 */);
    udp_register_dst_port (vm, UDP_DST_PORT_lisp_cp,
            oor_ctrl_ipv6_node.index, 0 /* is_ip4 */);

    /* Register call back function of change of address */
    cb4.function = oor_ip4_add_del_interface_address;
    cb4.function_opaque = 0;
    vec_add1 (im4->add_del_interface_address_callbacks, cb4);

    cb6.function = oor_ip6_add_del_interface_address;
    cb6.function_opaque = 0;
    vec_add1 (im6->add_del_interface_address_callbacks, cb6);

    return error;
}

VLIB_INIT_FUNCTION (oor_ctrl_init);


/**** NETLINK notification functions ****/



VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (oor_link_up_down_function);

static clib_error_t *
oor_link_up_down_function (vnet_main_t * vm, u32 hw_if_index, u32 flags)
{
//  vpe_api_main_t *vam = &vpe_api_main;
//  vnet_hw_interface_t *hi = vnet_get_hw_interface (vm, hw_if_index);
//
//  if (vam->link_state_process_up)
//    vlib_process_signal_event (vam->vlib_main,
//                   link_state_process_node.index,
//                   API_LINK_STATE_EVENT, hi->sw_if_index);
    clib_warning("=> oor_link_up_down_function: Link %s", (flags == 1 ? "up" : "down"));
  return 0;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (oor_admin_up_down_function);

static clib_error_t *
oor_admin_up_down_function (vnet_main_t * vm, u32 sw_if_index, u32 flags)
{
    u8 sndbuf[1024];
    vpp_nl_msg *vpp_msg_h;
    vpp_nl_link_info *vpp_link_info;
    int nbytes, error;
    clib_warning("=> oor_admin_up_down_function: Link %s", (flags == 1 ? "up" : "down"));
    if (oor_ctrl_main.sw_if_index != ~0){
        void *zmq_context = zmq_ctx_new();
        void *zmq_sock = zmq_socket(zmq_context, ZMQ_PUSH);
        error = zmq_connect(zmq_sock, OOR_IPC_FILE);
        if (error != 0){
            clib_warning("oor_admin_up_down_function: Coudn't create ZMQ socket: %s",zmq_strerror (error));
            return (0);
        }

        memset(sndbuf, 0, 1024);
        vpp_msg_h = (vpp_nl_msg *)sndbuf;
        vpp_link_info = (vpp_nl_link_info *)(sndbuf + sizeof(vpp_nl_msg));

        if (flags == 1){
            vpp_msg_h->type = VPP_NEWLINK;
        }else{
            vpp_msg_h->type = VPP_DELLINK;
        }
        vpp_msg_h->len = sizeof(vpp_nl_msg) + sizeof(vpp_nl_link_info);
        vpp_link_info->ifi_index = sw_if_index;

        nbytes = zmq_send(zmq_sock,(void *)&sndbuf,vpp_msg_h->len,0);
        if (nbytes == -1){
            clib_warning("oor_admin_up_down_function: Error while ZMQ sending: %s",zmq_strerror (error));
        }
        zmq_close (zmq_sock);
        zmq_ctx_destroy (zmq_context);
    }
    return 0;
}

void
oor_ip4_add_del_interface_address (ip4_main_t * im,
        uword opaque,
        u32 sw_if_index,
        ip4_address_t * address,
        u32 address_length,
        u32 if_address_index,
        u32 is_delete)
{
    u8 sndbuf[1024];
    vpp_nl_msg *vpp_msg_h;
    vpp_nl_addr_info *vpp_addr_info;
    int nbytes, error;
    clib_warning("============>>>>> NEW ADDRESS");
    if (oor_ctrl_main.sw_if_index != ~0){

        void *zmq_context = zmq_ctx_new();
        void *zmq_sock = zmq_socket(zmq_context, ZMQ_PUSH);
        error = zmq_connect(zmq_sock, OOR_IPC_FILE);
        if (error != 0){
            clib_warning("oor_ip4_add_del_interface_address: Coudn't create ZMQ socket: %s",zmq_strerror (error));
            return;
        }

        memset(sndbuf, 0, 1024);
        vpp_msg_h = (vpp_nl_msg *)sndbuf;
        vpp_addr_info = (vpp_nl_addr_info *)(sndbuf + sizeof(vpp_nl_msg));

        if (is_delete == 1){
            vpp_msg_h->type = VPP_DELADDR;
        }else{
            vpp_msg_h->type = VPP_NEWADDR;
        }
        vpp_msg_h->len = sizeof(vpp_nl_msg) + sizeof(vpp_nl_addr_info) + sizeof (ip4_address_t);
        vpp_addr_info->ifa_family = AF_INET;
        vpp_addr_info->ifa_prefixlen = address_length;
        vpp_addr_info->ifa_index = sw_if_index;
        memcpy(sndbuf + sizeof(vpp_nl_msg) + sizeof(vpp_nl_addr_info), (u8 *)address, sizeof (ip4_address_t));

        nbytes = zmq_send(zmq_sock,(void *)&sndbuf,vpp_msg_h->len,0);
        if (nbytes == -1){
            clib_warning("oor_ip4_add_del_interface_address: Error while ZMQ sending: %s",zmq_strerror (error));
        }
        zmq_close (zmq_sock);
        zmq_ctx_destroy (zmq_context);
    }
    return;
}

void
oor_ip6_add_del_interface_address (ip6_main_t * im,
        uword opaque,
        u32 sw_if_index,
        ip6_address_t * address,
        u32 address_length,
        u32 if_address_index,
        u32 is_delete)
{
    u8 sndbuf[1024];
    vpp_nl_msg *vpp_msg_h;
    vpp_nl_addr_info *vpp_addr_info;
    int nbytes, error;
    if (oor_ctrl_main.sw_if_index != ~0){
        void *zmq_context = zmq_ctx_new();
        void *zmq_sock = zmq_socket(zmq_context, ZMQ_PUSH);
        error = zmq_connect(zmq_sock, OOR_IPC_FILE);
        if (error != 0){
            clib_warning("oor_ip4_add_del_interface_address: Coudn't create ZMQ socket: %s",zmq_strerror (error));
            return;
        }

        memset(sndbuf, 0, 1024);
        vpp_msg_h = (vpp_nl_msg *)sndbuf;
        vpp_addr_info = (vpp_nl_addr_info *)(sndbuf + sizeof(vpp_nl_msg));

        if (is_delete == 1){
            vpp_msg_h->type = VPP_DELADDR;
        }else{
            vpp_msg_h->type = VPP_NEWADDR;
        }
        vpp_msg_h->len = sizeof(vpp_nl_msg) + sizeof(vpp_nl_addr_info) + sizeof (ip6_address_t);
        vpp_addr_info->ifa_family = AF_INET6;
        vpp_addr_info->ifa_prefixlen = address_length;
        vpp_addr_info->ifa_index = sw_if_index;
        memcpy(sndbuf + sizeof(vpp_nl_msg) + sizeof(vpp_nl_addr_info), (u8 *)address, sizeof (ip6_address_t));

        nbytes = zmq_send(zmq_sock,(void *)&sndbuf,vpp_msg_h->len,0);
        if (nbytes == -1){
            clib_warning("oor_ip4_add_del_interface_address: Error while ZMQ sending: %s",zmq_strerror (error));
        }
        zmq_close (zmq_sock);
        zmq_ctx_destroy (zmq_context);
    }
    return;
}
