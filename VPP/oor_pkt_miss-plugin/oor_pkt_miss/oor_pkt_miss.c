
/*
 * oor_pkt_miss.c - skeleton vpp engine plug-in 
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

#include <vnet/vnet.h>
#include <vnet/devices/af_packet/af_packet.h>
#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe_tenant.h>
#include <vnet/fib/fib.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/plugin/plugin.h>
#include <oor_pkt_miss/oor_pkt_miss.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <oor_pkt_miss/oor_pkt_miss_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h> 
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h> 
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

int oor_pkt_miss_drop_route (int is_add, fib_prefix_t *prefix, u32 table_id);
int oor_pkt_miss_defaults_management_init(oor_pkt_miss_main_t * sm);
void oor_pkt_miss_enable_disable_src_route_check(int is_enable);
int oor_pkt_miss_defaults_management_uninit(oor_pkt_miss_main_t * sm);
int oor_pkt_miss_get_ipv4_gateway(ip46_address_t *gateway);
int oor_pkt_miss_get_ipv6_gateway(ip46_address_t *gateway);


/* List of message types that this plugin understands */

#define foreach_oor_pkt_miss_plugin_api_msg                     \
_(OOR_PKT_MISS_ENABLE_DISABLE, oor_pkt_miss_enable_disable)     \
_(OOR_PKT_MISS_NATIVE_ROUTE, oor_pkt_miss_native_route)         \
_(OOR_PKT_MISS_DROP_ROUTE, oor_pkt_miss_drop_route)             \
_(OOR_PKT_MISS_GET_DEFAULT_ROUTE, oor_pkt_miss_get_default_route)



/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = OOR_PKT_MISS_PLUGIN_BUILD_VER,
    .description = "OOR paket miss plugin",
};

/* Action function shared between message handler and debug CLI */

int oor_pkt_miss_enable_disable (oor_pkt_miss_main_t * sm, u8 * host_if_name,
        int enable_disable)
{
    u8 hwaddr[6] = {0,0,0,0,0,0};
    u32 sw_if_index = ~0;

    vnet_sw_interface_t *si;
    vnet_lisp_gpe_enable_disable_args_t lisp_gpe_args;
    char vpp_if_name[100];
    u16 flags;
    int rv;
    clib_warning("OOR_PKT_MISS: %s node", enable_disable ? "enable" : "disale");

    if (enable_disable){
        //oor_pkt_miss_enable_disable_src_route_check(0);
        /* Configure default gateway of the router for native forward entries */
        oor_pkt_miss_defaults_management_init(sm);
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
        /* Enable lisp data plane */
        lisp_gpe_args.is_en = 1;
        vnet_lisp_gpe_enable_disable (&lisp_gpe_args);
        /* Enable host-interface to send traffic to oor */
        sm->sw_if_index = sw_if_index;
    }else{
        /* Remove unnumbered interface*/
        si = vnet_get_sw_interface (sm->vnet_main, sm->sw_if_index);
        si->flags &= ~(VNET_SW_INTERFACE_FLAG_UNNUMBERED);
        si->unnumbered_sw_if_index = (u32) ~ 0;
        ip4_sw_interface_enable_disable (sm->sw_if_index, 0);
        ip6_sw_interface_enable_disable (sm->sw_if_index, 0);
        /* Disable host-interface to send traffic to oor */
        af_packet_delete_if (sm->vlib_main, host_if_name);
        sm->sw_if_index = ~0;
        /* Disable lisp data plane */
        lisp_gpe_tenant_l3_iface_unlock (0);
        lisp_gpe_args.is_en = 0;
        vnet_lisp_gpe_enable_disable (&lisp_gpe_args);
        /* Remove host interfaces */
        snprintf(vpp_if_name, sizeof (vpp_if_name), "%s%s", "host-",(char *)host_if_name);
        af_packet_delete_if (sm->vlib_main, (u8 *)vpp_if_name);
        /* Reinsert the default gateways */
        oor_pkt_miss_defaults_management_uninit(sm);
        //      oor_pkt_miss_enable_disable_src_route_check(1);
    }

    return 0;
}


static clib_error_t *
oor_pkt_miss_enable_disable_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
  oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
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
    
  rv = oor_pkt_miss_enable_disable (sm, host_if_name, enable_disable);

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
    return clib_error_return (0, "oor_pkt_miss_enable_disable returned %d",
                              rv);
  }
  return 0;
}

VLIB_CLI_COMMAND (oor_pkt_miss_enable_disable_command, static) = {
    .path = "oor_pkt_miss enable-disable",
    .short_help = "oor_pkt_miss enable-disable <interface-name> [disable]",
    .function = oor_pkt_miss_enable_disable_command_fn,
};

/* Action function shared between message handler and debug CLI */
int
oor_pkt_miss_native_route (oor_pkt_miss_main_t * sm, int is_add, fib_prefix_t *prefix)
{
    fib_route_path_t *rpaths = NULL, rpath;
    ip46_address_t *gateway;
    fib_protocol_t proto;
    u32 fib_index;


    if (prefix->fp_proto == FIB_PROTOCOL_IP4){
        proto = FIB_PROTOCOL_IP4;
        fib_index = ip4_fib_index_from_table_id(0);
        if (!sm->has_ipv4_gateway){
            clib_warning("OOR_PKT_MISS: Can not %s prefix via gateway. No IPv4 gateway detected",
                    is_add == 1 ? "add" : "remove");
            goto no_gateway;
        }
        gateway = &sm->ipv4_gateway;
        clib_warning("OOR_PKT_MISS: %s route to %s/%d via gateway",
                (is_add == 1 ? "Add":"Remove"),
                format (0, "%U", format_ip4_address, &(prefix[0].fp_addr.ip4)),
                prefix->fp_len);
    }else{
        proto = FIB_PROTOCOL_IP6;
        fib_index = ip6_fib_index_from_table_id(0);
        if (!sm->has_ipv6_gateway){
            clib_warning("OOR_PKT_MISS: Can not %s prefix via gateway. No IPv6 gateway detected",
                    is_add == 1 ? "add" : "remove");
            goto no_gateway;
        }
        gateway = &sm->ipv6_gateway;
        clib_warning("OOR_PKT_MISS: %s route to %s/%d via gateway",
                (is_add == 1 ? "Add":"Remove"),
                format (0, "%U", format_ip6_address, &(prefix[0].fp_addr.ip6)),
                prefix->fp_len);
    }


    memset (&rpath, 0, sizeof (rpath));

    rpath.frp_fib_index = 0;
    rpath.frp_weight = 1;
    rpath.frp_sw_if_index = ~0; // XXX to check
    rpath.frp_proto = proto;
    memcpy(&rpath.frp_addr,gateway, sizeof(ip46_address_t));
    vec_add1 (rpaths, rpath);

    if (is_add == 1){
        fib_table_entry_path_add2 (fib_index,
                &prefix[0],
                FIB_SOURCE_CLI,
                FIB_ENTRY_FLAG_NONE,
                &rpaths[0]); // Check if we could send directly rpath
    }else{
        fib_table_entry_delete (fib_index, &prefix[0], FIB_SOURCE_CLI);
    }
    return 0;
no_gateway:
    oor_pkt_miss_drop_route (is_add,prefix,0);
    return 0;
}


static clib_error_t *
oor_pkt_miss_native_route_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
    oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
    fib_prefix_t *prefixs = NULL, prefix;
    clib_error_t *error = 0;
    int is_add = 1;

    if (sm->sw_if_index == ~0){
        return clib_error_return (0, "OOR paket miss plugin is not enabled.");
    }
    memset(&prefix,0,sizeof(fib_prefix_t));

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "del")){
            is_add = 0;
        }else if (unformat (input, "add")){
            is_add = 1;
        }else if (unformat (input, "%U/%d",unformat_ip4_address, &prefix.fp_addr.ip4, &prefix.fp_len)){
            prefix.fp_proto = FIB_PROTOCOL_IP4;
            vec_add1 (prefixs, prefix);
        }else if (unformat (input, "%U/%d",unformat_ip6_address, &prefix.fp_addr.ip6, &prefix.fp_len)){
            prefix.fp_proto = FIB_PROTOCOL_IP6;
            vec_add1 (prefixs, prefix);
        }else{
            break;
        }
    }

    if (vec_len (prefixs) == 0){
        vec_free (prefixs);
        return clib_error_return (0, "expected ip4/ip6 destination address/length.");
    }

    oor_pkt_miss_native_route (sm, is_add, &prefixs[0]);

    return error;
}



VLIB_CLI_COMMAND (oor_pkt_miss_native_route_command, static) = {
        .path = "oor_pkt_miss native-route",
        .short_help = "oor_pkt_miss native-route [add|del] <dst-ip-addr>/<width>",
        .function = oor_pkt_miss_native_route_command_fn,
};

int
oor_pkt_miss_drop_route (int is_add, fib_prefix_t *prefix, u32 table_id)
{
    //fib_table_t *fib_table;
    u32 fib_index;
    const dpo_id_t *drop_dpo;

    if (prefix->fp_proto == FIB_PROTOCOL_IP4){
        fib_index = ip4_fib_index_from_table_id(table_id);
    }else{
        fib_index = ip6_fib_index_from_table_id(table_id);
    }

    if (is_add){
        drop_dpo = drop_dpo_get(fib_proto_to_dpo(prefix->fp_proto));
        fib_table_entry_special_dpo_add (fib_index,prefix,FIB_SOURCE_CLI,FIB_ENTRY_FLAG_EXCLUSIVE, drop_dpo);
    }else{
        fib_table_entry_delete (fib_index, &prefix[0], FIB_SOURCE_CLI);
    }

    return 0;
}



static clib_error_t *
oor_pkt_miss_drop_route_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
    oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
    fib_prefix_t *prefixs = NULL, prefix;
    clib_error_t *error = 0;
    int is_add = 1;
    u32 table_id = 0;

    if (sm->sw_if_index == ~0){
        return clib_error_return (0, "OOR paket miss plugin is not enabled.");
    }

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "del")){
            is_add = 0;
        }else if (unformat (input, "add")){
            is_add = 1;
        }else if (unformat (input, "%U/%d",unformat_ip4_address, &prefix.fp_addr.ip4, &prefix.fp_len)){
            prefix.fp_proto = FIB_PROTOCOL_IP4;
            vec_add1 (prefixs, prefix);
        }else if (unformat (input, "%U/%d",unformat_ip6_address, &prefix.fp_addr.ip6, &prefix.fp_len)){
            prefix.fp_proto = FIB_PROTOCOL_IP6;
            vec_add1 (prefixs, prefix);
        }else if (unformat (input,"table-id %d",&table_id)){

        }else{
            break;
        }
    }

    if (vec_len (prefixs) == 0){
        vec_free (prefixs);
        return clib_error_return (0, "expected ip4/ip6 destination address/length.");
    }

    oor_pkt_miss_drop_route (is_add, &prefixs[0], table_id);

    return error;
}



VLIB_CLI_COMMAND (oor_pkt_miss_drop_route_command, static) = {
        .path = "oor_pkt_miss drop-route",
        .short_help = "oor_pkt_miss drop-route [add|del] <dst-ip-addr>/<width> [table-id <n>]",
        .function = oor_pkt_miss_drop_route_command_fn,
};



static clib_error_t *
oor_pkt_miss_get_default_route_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
    oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
    ip46_address_t gateway;
    clib_error_t *error = 0;
    int is_ipv6 = 0;
    u8 *msg = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "ipv6")){
            is_ipv6 = 1;
        }else if (unformat (input, "ipv4")){
            is_ipv6 = 0;
        }else{
            break;
        }
    }

    if (sm->sw_if_index == ~0){
        if (is_ipv6){

            if (oor_pkt_miss_get_ipv6_gateway(&gateway) == 0){
                msg = format (msg, "IPv6 default gw: %U\n",format_ip6_address, &gateway.ip6);
                vlib_cli_output (vm, "%v", msg);
            }else{
                msg = format (msg, "IPv6 default gw: --\n");
                vlib_cli_output (vm, "%v", msg);
            }

        }else{
            if (oor_pkt_miss_get_ipv4_gateway(&gateway) == 0){
                msg = format (msg, "IPv4 default gw: %U\n",format_ip4_address, &gateway.ip4);
                vlib_cli_output (vm, "%v", msg);
            }else{
                msg = format (msg, "IPv4 default gw: --\n");
                vlib_cli_output (vm, "%v", msg);
            }
        }
    }else{
        if (is_ipv6){

            if (sm->has_ipv6_gateway){
                msg = format (msg, "IPv6 default gw: %U\n",format_ip6_address, &sm->ipv6_gateway.ip6);
                vlib_cli_output (vm, "%v", msg);
            }else{
                msg = format (msg, "IPv6 default gw: --\n");
                vlib_cli_output (vm, "%v", msg);
            }

        }else{
            if (sm->has_ipv4_gateway){
                msg = format (msg, "IPv4 default gw: %U\n",format_ip4_address, &sm->ipv4_gateway.ip4);
                vlib_cli_output (vm, "%v", msg);
            }else{
                msg = format (msg, "IPv4 default gw: --\n");
                vlib_cli_output (vm, "%v", msg);
            }
        }
    }

    return error;
}



VLIB_CLI_COMMAND (oor_pkt_miss_get_default_route_command, static) = {
        .path = "oor_pkt_miss get-default-route",
        .short_help = "oor_pkt_miss get-default-route [ipv4|ipv6]",
        .function = oor_pkt_miss_get_default_route_command_fn,
};


/* API message handler */
static void vl_api_oor_pkt_miss_enable_disable_t_handler
(vl_api_oor_pkt_miss_enable_disable_t * mp)
{
  vl_api_oor_pkt_miss_enable_disable_reply_t * rmp;
  oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
  u8 *host_if_name = NULL;
  int rv;

  host_if_name = format (0, "%s", mp->host_if_name);
  vec_add1 (host_if_name, 0);

  rv = oor_pkt_miss_enable_disable (sm, host_if_name,(int) (mp->enable_disable));
  vec_free (host_if_name);
  
  REPLY_MACRO(VL_API_OOR_PKT_MISS_ENABLE_DISABLE_REPLY);
}

static void vl_api_oor_pkt_miss_native_route_t_handler
(vl_api_oor_pkt_miss_native_route_t * mp)
{
    vl_api_oor_pkt_miss_native_route_reply_t * rmp;
    oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
    fib_prefix_t prefix;
    memset(&prefix,0,sizeof(fib_prefix_t));
    int rv;
    prefix.fp_proto = (mp->is_ipv6 == 1) ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;
    prefix.fp_len = mp->mask_len;
    if (mp->is_ipv6 == 0){
        memcpy(&prefix.fp_addr.ip4,mp->address,4);
    }else{
        memcpy(&prefix.fp_addr.ip6,mp->address,16);
    }

    oor_pkt_miss_native_route (sm,mp->is_add,&prefix);

    REPLY_MACRO(VL_API_OOR_PKT_MISS_NATIVE_ROUTE_REPLY);
}

static void vl_api_oor_pkt_miss_drop_route_t_handler
(vl_api_oor_pkt_miss_drop_route_t * mp)
{
    vl_api_oor_pkt_miss_drop_route_reply_t * rmp;
    oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
    fib_prefix_t prefix;
    int rv;
    prefix.fp_proto = (mp->is_ipv6 == 1) ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;
    prefix.fp_len = mp->mask_len;
    if (mp->is_ipv6 == 0){
        memcpy(&prefix.fp_addr.ip4,mp->address,4);
    }else{
        memcpy(&prefix.fp_addr.ip6,mp->address,16);
    }
    clib_warning("=====>>> Drop api");
    oor_pkt_miss_drop_route (mp->is_add,&prefix,mp->table_id);

    REPLY_MACRO(VL_API_OOR_PKT_MISS_DROP_ROUTE_REPLY);
}

static void vl_api_oor_pkt_miss_get_default_route_t_handler
(vl_api_oor_pkt_miss_get_default_route_t * mp)
{
    vl_api_oor_pkt_miss_get_default_route_reply_t * rmp;
    oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
    ip46_address_t gateway;
    int rv = 0;
    unix_shared_memory_queue_t *q =  vl_api_client_index_to_input_queue (mp->client_index);

    if (!q){
        return;
    }

    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = ntohs((VL_API_OOR_PKT_MISS_GET_DEFAULT_ROUTE_REPLY)+sm->msg_id_base);
    rmp->context = mp->context;


    if (sm->sw_if_index == ~0){
        if (mp->is_ipv6){
            rmp->is_ipv6 = 1;
            if (oor_pkt_miss_get_ipv6_gateway(&gateway) == 0){
                memcpy(rmp->address,&gateway.ip6,16);
                rmp->has_gateway = 1;
            }else{
                rmp->has_gateway = 0;
            }

        }else{
            rmp->is_ipv6 = 0;
            if (oor_pkt_miss_get_ipv4_gateway(&gateway) == 0){
                memcpy(rmp->address,&gateway.ip4,4);
                rmp->has_gateway = 1;
            }else{
                rmp->has_gateway = 0;
            }
        }
    }else{
        if (mp->is_ipv6){
            rmp->is_ipv6 = 1;
            if (sm->has_ipv6_gateway){
                memcpy(rmp->address,&sm->ipv6_gateway.ip6,16);
                               rmp->has_gateway = 1;
            }else{
                rmp->has_gateway = 0;
            }

        }else{
            rmp->is_ipv6 = 0;
            if (sm->has_ipv4_gateway){
                memcpy(rmp->address,&sm->ipv4_gateway.ip4,4);
                rmp->has_gateway = 1;
            }else{
                rmp->has_gateway = 0;
            }
        }
    }
    rmp->retval = ntohl(rv);

    vl_msg_api_send_shmem (q, (u8 *)&rmp);
}

/* Set up the API message handling tables */
static clib_error_t *
oor_pkt_miss_plugin_api_hookup (vlib_main_t *vm)
{
  oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_oor_pkt_miss_plugin_api_msg;
#undef _

    return 0;
}



/******** DEAFAULTS MANAGEMENT **********/

int
oor_pkt_miss_get_ipv4_gateway(ip46_address_t *gateway)
{
    ip4_address_t address;
    u32 mask_len = 0, fib_index;
    ip4_fib_t *fib;
    fib_node_index_t index = ~0;
    adj_index_t adj_inxex;
    ip_adjacency_t *adj;
    load_balance_t *lb_m, *lb_b;
    const dpo_id_t *dpo0, *dpo1, *dpo_fwd;
    int i=0, j=0, have_gw=0;

    fib_index = ip4_fib_index_from_table_id(0);
    if (fib_index == ~0){
        clib_warning("OOR_PKT_MISS: No default fib found");
        return (-1);
    }
    fib = ip4_fib_get(fib_index);

    memset(&address,0,sizeof(ip4_address_t));
    index = ip4_fib_table_lookup(fib, &address, mask_len);
    if (index == FIB_NODE_INDEX_INVALID){
        clib_warning("OOR_PKT_MISS: No default IPv4 gateway found");
        return (-2);
    }
    dpo_fwd = fib_entry_contribute_ip_forwarding(index);

    lb_m = load_balance_get (dpo_fwd->dpoi_index);

    for (i = 0; i < lb_m->lb_n_buckets; i++){
        dpo0 = load_balance_get_bucket_i (lb_m, i);
        if (dpo0->dpoi_type == DPO_LOAD_BALANCE){
            lb_b = load_balance_get (dpo0->dpoi_index);
            for (j = 0; j < lb_b->lb_n_buckets; j++){
                dpo1 = load_balance_get_bucket_i (lb_b, j);
                if (dpo1->dpoi_type == DPO_ADJACENCY  || dpo1->dpoi_type == DPO_ADJACENCY_INCOMPLETE){
                    adj_inxex = dpo1->dpoi_index;

                    if (ADJ_INDEX_INVALID == adj_inxex){
                        continue;
                    }

                    adj = ip_get_adjacency (&(ip4_main.lookup_main), adj_inxex);
                    memcpy (gateway,&(adj->sub_type.nbr.next_hop),sizeof(ip46_address_t));
                    clib_warning("OOR_PKT_MISS: IPv4 gateway: %s", format (0, "%U", format_ip4_address, &(adj->sub_type.nbr.next_hop.ip4)));
                    have_gw=1;
                    break;
                }
            }
            if (have_gw == 1){
                break;
            }
        }
    }
    if (have_gw == 0){
        clib_warning("OOR_PKT_MISS: No IPv4 gateway found");
        return (-4);
    }

    return (0);
}

int
oor_pkt_miss_ipv4_defaults_management_init(oor_pkt_miss_main_t * sm)
{
    /* Obtain default gateway */
    u32 fib_index;
    int ret;
    fib_prefix_t prefix;

    fib_index = ip4_fib_index_from_table_id(0);
    ret = oor_pkt_miss_get_ipv4_gateway(&sm->ipv4_gateway);
    if (ret == 0){
        sm->has_ipv4_gateway = 1;
    }else{
        return (ret);
    }

    /* Remove the gateway */

    memset(&prefix,0,sizeof(fib_prefix_t));
    prefix.fp_proto = FIB_PROTOCOL_IP4;
    /* Remove gateway */
    fib_table_entry_delete (fib_index, &prefix, FIB_SOURCE_CLI);

    return (0);
}

int
oor_pkt_miss_get_ipv6_gateway(ip46_address_t *gateway)
{
    /* Obtain default gateway */
    u32 fib_index;
    ip6_fib_t *fib;
    fib_node_index_t index = ~0;
    adj_index_t adj_inxex;
    ip_adjacency_t *adj;
    load_balance_t *lb_m, *lb_b;
    const dpo_id_t *dpo0, *dpo1 , *dpo_fwd;
    int i=0, j=0, have_gw=0;


    fib_index = ip6_fib_index_from_table_id(0);
    if (fib_index == ~0){
        clib_warning("OOR_PKT_MISS: No default fib found");
        return (-1);
    }

    fib = ip6_fib_get(fib_index);

    fib_prefix_t pfx_0_0 = {
            .fp_len = 128,
            .fp_proto = FIB_PROTOCOL_IP6,
            .fp_addr = {
                    .ip6 = {
                            .as_u64 = {
                                    [0] = 0,
                                    [1] = 0,
                            },
                    },
            }
    };

    index = fib_table_lookup(fib->index, &pfx_0_0);
    dpo_fwd = fib_entry_contribute_ip_forwarding(index);

    lb_m = load_balance_get (dpo_fwd->dpoi_index);

    for (i = 0; i < lb_m->lb_n_buckets; i++){
        dpo0 = load_balance_get_bucket_i (lb_m, i);

        if (dpo0->dpoi_type == DPO_LOAD_BALANCE){
            lb_b = load_balance_get (dpo0->dpoi_index);
            for (j = 0; j < lb_b->lb_n_buckets; j++){
                dpo1 = load_balance_get_bucket_i (lb_b, j);
                if (dpo1->dpoi_type == DPO_ADJACENCY || dpo1->dpoi_type == DPO_ADJACENCY_INCOMPLETE){
                    adj_inxex = dpo1->dpoi_index;

                    if (ADJ_INDEX_INVALID == adj_inxex){
                        continue;
                    }

                    adj = ip_get_adjacency (&(ip6_main.lookup_main), adj_inxex);
                    memcpy (gateway,&(adj->sub_type.nbr.next_hop),sizeof(ip46_address_t));
                    clib_warning("OOR_PKT_MISS: IPv6 gateway: %s", format (0, "%U", format_ip6_address, &(adj->sub_type.nbr.next_hop.ip6)));
                    have_gw=1;
                    break;
                }
            }
            if (have_gw == 1){
                break;
            }
        }
    }
    if (have_gw == 0){
        clib_warning("OOR_PKT_MISS: No IPv6 gateway found");
        return (-4);
    }
    return (0);
}



int
oor_pkt_miss_ipv6_defaults_management_init(oor_pkt_miss_main_t * sm)
{
    /* Obtain default gateway */
    int ret;
    fib_prefix_t prefix;
    u32 fib_index;

    fib_index = ip6_fib_index_from_table_id(0);
    ret = oor_pkt_miss_get_ipv6_gateway(&sm->ipv6_gateway);
    if (ret == 0){
        sm->has_ipv6_gateway = 1;
    }else{
        return (ret);
    }


    /* Remove the gateway */
    memset(&prefix,0,sizeof(fib_prefix_t));
    prefix.fp_proto = FIB_PROTOCOL_IP6;
    /* Remove gateway */
    fib_table_entry_delete (fib_index, &prefix, FIB_SOURCE_CLI);

    return (0);
}

int
oor_pkt_miss_defaults_management_init(oor_pkt_miss_main_t * sm)
{
    oor_pkt_miss_ipv4_defaults_management_init(sm);
    oor_pkt_miss_ipv6_defaults_management_init(sm);
    return (0);
}

int
oor_pkt_miss_defaults_management_uninit(oor_pkt_miss_main_t * sm)
{
    fib_prefix_t prefix;

    if (sm->has_ipv4_gateway){
        memset(&prefix,0,sizeof(fib_prefix_t));
        prefix.fp_proto = FIB_PROTOCOL_IP4;
        oor_pkt_miss_native_route (sm, 1, &prefix);
        memset (&sm->ipv4_gateway,0,sizeof(ip46_address_t));
        sm->has_ipv4_gateway = 0;
    }

    if (sm->has_ipv6_gateway){
        memset(&prefix,0,sizeof(fib_prefix_t));
        prefix.fp_proto = FIB_PROTOCOL_IP6;
        oor_pkt_miss_native_route (sm, 1, &prefix);
        memset (&sm->ipv6_gateway,0,sizeof(ip46_address_t));
        sm->has_ipv6_gateway = 0;
    }

    return (0);
}

/* Enable or disable the source path check */
// XXX It doesn't work for IPv6 in VPP 17.01. To be tested in new versions
void
oor_pkt_miss_enable_disable_src_route_check(int is_enable)
{
    u32 fib_index4, fib_index6;
    fib_prefix_t pfx4, pfx6;
    memset (&pfx4,0,sizeof(fib_prefix_t));
    pfx4.fp_proto = FIB_PROTOCOL_IP4;

    memset (&pfx6,0,sizeof(fib_prefix_t));
    pfx6.fp_proto = FIB_PROTOCOL_IP6;

    fib_index4 = ip4_fib_index_from_table_id(0);
    fib_index6 = ip6_fib_index_from_table_id(0);

    if (!is_enable){
        fib_table_entry_special_add (fib_index4,
                &pfx4,
                FIB_SOURCE_URPF_EXEMPT,
                FIB_ENTRY_FLAG_DROP);
        fib_table_entry_special_add (fib_index6,
                &pfx6,
                FIB_SOURCE_URPF_EXEMPT,
                FIB_ENTRY_FLAG_DROP);
    }
    else{
        fib_table_entry_special_remove (fib_index4,
                &pfx4, FIB_SOURCE_URPF_EXEMPT);
        fib_table_entry_special_remove (fib_index6,
                &pfx6, FIB_SOURCE_URPF_EXEMPT);
    }
}


#define vl_msg_name_crc_list
#include <oor_pkt_miss/oor_pkt_miss_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (oor_pkt_miss_main_t * sm, api_main_t *am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_oor_pkt_miss;
#undef _
}


static clib_error_t * oor_pkt_miss_init (vlib_main_t * vm)
{
  oor_pkt_miss_main_t * sm = &oor_pkt_miss_main;
  clib_error_t * error = 0;
  u8 * name;

  sm->vnet_main = vnet_get_main ();

  name = format (0, "oor_pkt_miss_%08x%c", api_version, 0);
  sm->sw_if_index = ~0;

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = oor_pkt_miss_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (oor_pkt_miss_init);
