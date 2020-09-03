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


#include <linux/rtnetlink.h>
#include "tun.h"
#include "tun_input.h"
#include "tun_output.h"
#include "../data-plane.h"
#include "../../oor_external.h"
#include "../../fwd_policies/fwd_policy.h"
#include "../../lib/interfaces_lib.h"
#include "../../lib/oor_log.h"
#include "../../lib/routing_tables_lib.h"

int tun_configure_data_plane(oor_dev_type_e dev_type, oor_encap_t encap_type, ...);
void tun_uninit_data_plane();
int tun_add_datap_iface_addr(iface_t *iface,int afi);
int tun_add_datap_iface_gw(iface_t *iface, int afi);
int tun_register_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map);
int tun_deregister_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map);

int configure_routing_to_tun_router(int afi);
int configure_routing_to_tun_mn(lisp_addr_t *eid_addr);
int remove_routing_to_tun_mn(lisp_addr_t *eid_addr);
int configure_routing_to_tun_mn(lisp_addr_t *eid_addr);
int tun_updated_route (int command, iface_t *iface, lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway);
int tun_updated_addr(iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr);
int tun_updated_link(iface_t *iface, int old_iface_index, int new_iface_index, int status);
void tun_process_new_gateway(iface_t *iface,lisp_addr_t *gateway);
void tun_process_rm_gateway(iface_t *iface,lisp_addr_t *gateway);

void tun_set_default_output_ifaces();
void tun_iface_remove_routing_rules(iface_t *iface);
int tun_rm_fwd_from_entry(lisp_addr_t *eid_prefix, uint8_t is_local);
tun_dplane_data_t * tun_dplane_data_new_init(oor_encap_t encap_type, glist_t *allowed_dst_eids);
void tun_dplane_data_free(tun_dplane_data_t *data);


data_plane_struct_t dplane_tun = {
        .datap_init = tun_configure_data_plane,
        .datap_uninit = tun_uninit_data_plane,
        .datap_add_iface_addr = tun_add_datap_iface_addr,
        .datap_add_iface_gw = tun_add_datap_iface_gw,
        .datap_register_lcl_mapping = tun_register_lcl_mapping,
        .datap_deregister_lcl_mapping = tun_deregister_lcl_mapping,
        .datap_input_packet = tun_process_input_packet,
        .datap_rtr_input_packet = tun_rtr_process_input_packet,
        .datap_output_packet = tun_output_recv,
        .datap_updated_route = tun_updated_route,
        .datap_updated_addr = tun_updated_addr,
        .datap_update_link = tun_updated_link,
        .datap_rm_fwd_from_entry = tun_rm_fwd_from_entry,
        .datap_reset_all_fwd = tun_reset_all_fwd,
        .datap_data = NULL
};

inline tun_dplane_data_t *
tun_get_datap_data()
{
    return ((tun_dplane_data_t *)dplane_tun.datap_data);
}

/*
 * tun_configure_data_plane not has variable list of parameters
 */
int
tun_configure_data_plane(oor_dev_type_e dev_type, oor_encap_t encap_type, ...)
{
    int (*cb_func)(sock_t *) = NULL;
    int ipv4_data_input_fd = -1;
    int ipv6_data_input_fd = -1;
    int data_port;
    va_list ap;
    glist_t *allowed_dst_eids;
    /* Get the extra parameter of the function */
    va_start(ap, encap_type);
    allowed_dst_eids = va_arg(ap, glist_t *);
    va_end(ap);

    /* Configure data plane */
    tun_receive_fd = create_tun_tap(TUN, TUN_IFACE_NAME, TUN_MTU);
    if (tun_receive_fd <= BAD){
        return (BAD);
    }
    tun_ifindex = if_nametoindex (TUN_IFACE_NAME);
    switch (dev_type){
    case MN_MODE:
        sockmstr_register_read_listener(smaster, tun_output_recv, NULL,tun_receive_fd);
        cb_func = tun_process_input_packet;
        break;
    case xTR_MODE:
        /* We add route tables for IPv4 and IPv6 even no EID exists for this afi*/
        /* Rules created for EID will redirect traffic to this table*/
        configure_routing_to_tun_router(AF_INET);
        configure_routing_to_tun_router(AF_INET6);
        sockmstr_register_read_listener(smaster, tun_output_recv, NULL,tun_receive_fd);
        cb_func = tun_process_input_packet;
        break;
    case RTR_MODE:
        cb_func = tun_rtr_process_input_packet;
        break;
    default:
        return (BAD);
    }

    switch (encap_type){
    case ENCP_LISP:
        data_port = LISP_DATA_PORT;
        break;
    case ENCP_VXLAN_GPE:
        data_port = VXLAN_GPE_DATA_PORT;
        break;
    default:
        return (BAD);
    }

    /* Generate receive sockets for data port (4341) */
    if (default_rloc_afi != AF_INET6) {
        ipv4_data_input_fd = open_data_raw_input_socket(AF_INET, data_port);
        sockmstr_register_read_listener(smaster, cb_func, NULL,
                ipv4_data_input_fd);
    }

    if (default_rloc_afi != AF_INET) {
        ipv6_data_input_fd = open_data_raw_input_socket(AF_INET6, data_port);
        sockmstr_register_read_listener(smaster, cb_func, NULL,
                ipv6_data_input_fd);
    }
    dplane_tun.datap_data = (void *)tun_dplane_data_new_init(encap_type, allowed_dst_eids);

    /* Select the default rlocs for output data packets and output control
     * packets */
    tun_set_default_output_ifaces();

    return (GOOD);
}

void
tun_uninit_data_plane()
{
    tun_dplane_data_t *data = (tun_dplane_data_t *)dplane_tun.datap_data;
    glist_entry_t *iface_it;
    iface_t *iface;

    if (data){
        /* Remove routes associated to each interface */
        glist_for_each_entry(iface_it, interface_list){
            iface = (iface_t *)glist_entry_data(iface_it);
            tun_iface_remove_routing_rules(iface);
        }
        tun_dplane_data_free(data);
    }
}

int
tun_add_datap_iface_addr(iface_t *iface, int afi)
{
    int sock;
    lisp_addr_t *addr;
    tun_dplane_data_t *data;
    int table = RULE_IFACE_BASE_TABLE_PRIORITY + iface->iface_index;

    data = (tun_dplane_data_t *)dplane_tun.datap_data;
    addr = iface_address(iface, afi);
    if (!addr  || lisp_addr_is_no_addr(addr)){
        return (BAD);
    }
    sock = open_ip_raw_socket(afi);
    bind_socket(sock, afi,addr,0);
    add_rule(afi, 0, table, table, RTN_UNICAST,addr, NULL, 0);

    switch (afi){
    case AF_INET:
        iface->out_socket_v4 = sock;
        if (data && !data->default_out_iface_v4){
            // It will only enter here when adding interfaces after init process
            tun_set_default_output_ifaces();
        }
        break;
    case AF_INET6:
        iface->out_socket_v6 = sock;
        if (data && !data->default_out_iface_v6){
            // It will only enter here when adding interfaces after init process
            tun_set_default_output_ifaces();
        }
        break;
    }

    return (GOOD);
}

int
tun_add_datap_iface_gw(iface_t *iface, int afi)
{
    lisp_addr_t *gw;
    int route_metric = 100;
    int table = RULE_IFACE_BASE_TABLE_PRIORITY + iface->iface_index;

    gw = iface_gateway(iface, afi);
    if (!gw  || lisp_addr_is_no_addr(gw)){
        return (BAD);
    }
    add_route(afi,iface->iface_index,NULL,NULL,gw,route_metric,table);

    return(GOOD);
}

int
tun_register_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map)
{
    lisp_addr_t *eid_ip_prefix = lisp_addr_get_ip_pref_addr(mapping_eid(map));
    int afi = lisp_addr_ip_afi(eid_ip_prefix);
    tun_dplane_data_t *data = dplane_tun.datap_data;
    glist_entry_t *it;
    lisp_addr_t *dst_eid_pref;

    if (afi == LM_AFI_NO_ADDR){
        return (BAD);
    }

    switch(dev_type){
    case xTR_MODE:
        /* Route to send dtraffic to TUN */
        if (glist_size(data->allowed_eid_prefixes) == 0){
            if (add_rule(afi,
                    0,
                    RULE_TO_LISP_TABLE_PRIORITY,
                    RULE_TO_LISP_TABLE_PRIORITY,
                    RTN_UNICAST,
                    eid_ip_prefix,
                    NULL,0)!=GOOD){
                return (BAD);
            }
        }else{
            glist_for_each_entry(it,data->allowed_eid_prefixes){
                dst_eid_pref = glist_entry_data(it);
                if (lisp_addr_ip_afi(dst_eid_pref) != afi){
                    continue;
                }
                if (add_rule(afi,
                        0,
                        RULE_TO_LISP_TABLE_PRIORITY,
                        RULE_TO_LISP_TABLE_PRIORITY,
                        RTN_UNICAST,
                        eid_ip_prefix,
                        dst_eid_pref,0)!=GOOD){
                    return (BAD);
                }
            }
        }
        /* Route to avoid to encapsulate traffic destined to the RLOC lan */
        if (add_rule(afi,
                0,
                RT_TABLE_MAIN,
                RULE_AVOID_LISP_TABLE_PRIORITY,
                RTN_UNICAST,
                NULL,
                eid_ip_prefix,
                0)!=GOOD){
            return (BAD);
        }
        break;
    case MN_MODE:
        configure_routing_to_tun_mn(eid_ip_prefix);
        break;
    case RTR_MODE:
    default:
        break;
    }
    return (GOOD);
}

int
tun_deregister_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map){
    lisp_addr_t *eid_ip_prefix = lisp_addr_get_ip_pref_addr(mapping_eid(map));
    int afi = lisp_addr_ip_afi(eid_ip_prefix);
    tun_dplane_data_t *data = dplane_tun.datap_data;
    glist_entry_t *it;
    lisp_addr_t *dst_eid_pref;

    if (afi == LM_AFI_NO_ADDR){
        return (BAD);
    }

    switch(dev_type){
    case xTR_MODE:
        /* Rm roule to send dtraffic to TUN */
        if (glist_size(data->allowed_eid_prefixes) == 0){
            if (del_rule(afi,
                    0,
                    RULE_TO_LISP_TABLE_PRIORITY,
                    RULE_TO_LISP_TABLE_PRIORITY,
                    RTN_UNICAST,
                    eid_ip_prefix,
                    NULL,0)!=GOOD){
                return (BAD);
            }
        }else{
            glist_for_each_entry(it,data->allowed_eid_prefixes){
                dst_eid_pref = glist_entry_data(it);
                if (lisp_addr_ip_afi(dst_eid_pref) != afi){
                    continue;
                }
                if (del_rule(afi,
                        0,
                        RULE_TO_LISP_TABLE_PRIORITY,
                        RULE_TO_LISP_TABLE_PRIORITY,
                        RTN_UNICAST,
                        eid_ip_prefix,
                        dst_eid_pref,0)!=GOOD){
                    return (BAD);
                }
            }
        }
        if (del_rule(afi,
                0,
                RT_TABLE_MAIN,
                RULE_AVOID_LISP_TABLE_PRIORITY,
                RTN_UNICAST,
                NULL,
                eid_ip_prefix,
                0)!=GOOD){
            return (BAD);
        }
        break;
    case MN_MODE:
        remove_routing_to_tun_mn(eid_ip_prefix);
        break;
    case RTR_MODE:
    default:
        break;
    }
    return (GOOD);
}

int
configure_routing_to_tun_mn(lisp_addr_t *eid_addr)
{

    tun_dplane_data_t *data = dplane_tun.datap_data;
    glist_entry_t *it;
    lisp_addr_t *dst_eid_pref;
    lisp_addr_t *src_eid_pref = NULL;
    uint32_t metric = 0;
    int afi = lisp_addr_ip_afi(eid_addr);
    if (afi == LM_AFI_NO_ADDR){
        return (BAD);
    }

    if (add_addr_to_iface(TUN_IFACE_NAME, eid_addr) != GOOD){
        return (BAD);
    }

    glist_for_each_entry(it,data->allowed_eid_prefixes){
        dst_eid_pref = glist_entry_data(it);
        if (lisp_addr_ip_afi(dst_eid_pref) != afi){
            continue;
        }
        if (add_route(afi,
                tun_ifindex,
                dst_eid_pref,
                src_eid_pref,
                NULL,
                metric,
                RT_TABLE_MAIN) != GOOD){
            remove_routing_to_tun_mn(eid_addr);
            return (BAD);
        }
    }


    return (GOOD);
}

int
remove_routing_to_tun_mn(lisp_addr_t *eid_addr)
{
    tun_dplane_data_t *data = dplane_tun.datap_data;
    glist_entry_t *it;
    lisp_addr_t *dst_eid_pref;
    lisp_addr_t *src_eid_pref = NULL;
    uint32_t metric = 0;
    int afi = lisp_addr_ip_afi(eid_addr);
    if (afi == LM_AFI_NO_ADDR){
        return (BAD);
    }

    if (del_addr_from_iface(TUN_IFACE_NAME, eid_addr) != GOOD){
        return (BAD);
    }

    glist_for_each_entry(it,data->allowed_eid_prefixes){
        dst_eid_pref = glist_entry_data(it);
        if (lisp_addr_ip_afi(dst_eid_pref) != afi){
            continue;
        }
        if (del_route(afi,
                tun_ifindex,
                dst_eid_pref,
                src_eid_pref,
                NULL,
                metric,
                RT_TABLE_MAIN) != GOOD){
            remove_routing_to_tun_mn(eid_addr);
            return (BAD);
        }
    }

    return (GOOD);
}

/*
* For router mode, add a new routing table with default route to tun interface. Using source routing,
* We send all traffic generated by EIDs to this table.
*/

int
configure_routing_to_tun_router(int afi)
{
    uint32_t iface_index = if_nametoindex(TUN_IFACE_NAME);

    return add_route(afi,iface_index,NULL,NULL,NULL,RULE_TO_LISP_TABLE_PRIORITY,RULE_TO_LISP_TABLE_PRIORITY);
}

int
tun_updated_route (int command, iface_t *iface, lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    /* We check if the new route message contains a destination. If
     * it is, then the gateway address is not a default route.
     * Discard it */

    if (command == ADD){
        if (lisp_addr_ip_afi(gateway) != LM_AFI_NO_ADDR
                && lisp_addr_ip_afi(dst_pref) == LM_AFI_NO_ADDR) {

            /* Check if the addres is a global address*/
            if (ip_addr_is_link_local(lisp_addr_ip(gateway)) == TRUE) {
                OOR_LOG(LDBG_3,"tun_update_route: the extractet address "
                        "from the netlink messages is a local link address: %s "
                        "discarded", lisp_addr_to_char(gateway));
                return (GOOD);
            }

            /* Process the new gateway */
            OOR_LOG(LDBG_1,  "tun_update_route: Process new gateway "
                    "associated to the interface %s:  %s", iface->iface_name,
                    lisp_addr_to_char(gateway));
            tun_process_new_gateway(iface,gateway);
        }
    }else{
        if (lisp_addr_ip_afi(gateway) != LM_AFI_NO_ADDR
                && lisp_addr_ip_afi(dst_pref) == LM_AFI_NO_ADDR) {

            /* Check if the addres is a global address*/
            if (ip_addr_is_link_local(lisp_addr_ip(gateway)) == TRUE) {
                OOR_LOG(LDBG_3,"tun_update_route: the extractet address "
                        "from the netlink messages is a local link address: %s "
                        "discarded", lisp_addr_to_char(gateway));
                return (GOOD);
            }

            /* Process the new gateway */
            OOR_LOG(LDBG_1,  "tun_update_route: Process remove gateway "
                    "associated to the interface %s:  %s", iface->iface_name,
                    lisp_addr_to_char(gateway));
            tun_process_rm_gateway(iface,gateway);
        }
    }

    return (GOOD);
}

int
tun_updated_addr(iface_t *iface, lisp_addr_t *old_addr, lisp_addr_t *new_addr)
{
    int old_addr_lafi,old_addr_ip_afi, new_addr_lafi,new_addr_ip_afi, table;
    int sckt;
    iface_t * def_iface = NULL;
    tun_dplane_data_t *data;

    data = (tun_dplane_data_t *)dplane_tun.datap_data;
    old_addr_lafi = lisp_addr_lafi(old_addr);
    new_addr_lafi = lisp_addr_lafi(new_addr);
    table = RULE_IFACE_BASE_TABLE_PRIORITY + iface->iface_index;


    /* Process if the address has been removed */
    if (new_addr_lafi == LM_AFI_NO_ADDR){
        old_addr_ip_afi = lisp_addr_ip_afi(old_addr);
        /* Close sockets associated with address */
        switch (old_addr_ip_afi) {
        case AF_INET:
            close (iface->out_socket_v4);
            iface->out_socket_v4 = 0;
            def_iface = data->default_out_iface_v4;
            break;
        case AF_INET6:
            close (iface->out_socket_v6);
            iface->out_socket_v6 = 0;
            def_iface = data->default_out_iface_v6;
            break;
        }
        if (def_iface == iface){
            OOR_LOG(LDBG_2, "Removed address from default interface. Recalculate new "
                    "output interface");
            tun_set_default_output_ifaces();
        }
        del_rule(old_addr_ip_afi, 0, table, table, RTN_UNICAST,
                        old_addr, NULL, 0);
        return (GOOD);
    }

    new_addr_ip_afi = lisp_addr_ip_afi(new_addr);

    /* Check if the detected change of address is the same. */
    if (lisp_addr_cmp(old_addr, new_addr) == 0) {
        OOR_LOG(LDBG_2, "tun_updated_addr: The change of address detected "
                "for interface %s doesn't affect (%s)", iface->iface_name,
                lisp_addr_to_char(new_addr));


        /* We must rebind the socket just in case the address is from a
         * virtual interface which has changed its interface number */
        switch (new_addr_ip_afi) {
        case AF_INET:
            bind_socket(iface->out_socket_v4, AF_INET, new_addr, 0);
            break;
        case AF_INET6:
            bind_socket(iface->out_socket_v6, AF_INET6,  new_addr, 0);
            break;
        }
        return (GOOD);
    }

    /* If interface was down during initial configuration process and now it
     * is up. Create sockets */
    if (old_addr_lafi == LM_AFI_NO_ADDR) {
        OOR_LOG(LDBG_2, "tun_updated_addr: Generating sockets for the initialized interface "
                "%s", lisp_addr_to_char(new_addr));

        switch(new_addr_ip_afi){
        case AF_INET:
            iface->out_socket_v4 = open_ip_raw_socket(AF_INET);
            sckt = iface->out_socket_v4;
            break;
        case AF_INET6:
            iface->out_socket_v6 = open_ip_raw_socket(AF_INET6);
            sckt = iface->out_socket_v6;
            break;
        default:
            /* basically to calm compiler and let the following fail for AF_INET7 */
            sckt=0;
            return BAD;
        }

        if (iface->status == UP) {
            /* If no default control interface, recalculate it */
            if ((data->default_out_iface_v4 == NULL && new_addr_ip_afi == AF_INET) ||
                    (data->default_out_iface_v6 == NULL && new_addr_ip_afi == AF_INET6)) {
                OOR_LOG(LDBG_2, "No default output interface. Recalculate new "
                        "output interface");
                tun_set_default_output_ifaces();
            }
        }
    }else{
        switch(new_addr_ip_afi){
        case AF_INET:
            sckt = iface->out_socket_v4;
            break;
        case AF_INET6:
            sckt = iface->out_socket_v6;
            break;
        default:
            /* basically to calm compiler and let the following fail for AF_INET7 */
            sckt=0;
            return BAD;
        }

        del_rule(new_addr_ip_afi, 0, table, table, RTN_UNICAST,
                old_addr, NULL, 0);
    }
    /* Rebind socket and add new routing */
    add_rule(new_addr_ip_afi, 0, table, table, RTN_UNICAST,
            new_addr, NULL, 0);

    bind_socket(sckt, new_addr_ip_afi, new_addr,0);

    return (GOOD);
}

int
tun_updated_link(iface_t *iface, int old_iface_index, int new_iface_index,
        int status)
{
    int old_table, new_table;
    tun_dplane_data_t *data;
    data = (tun_dplane_data_t *)dplane_tun.datap_data;
    old_table = RULE_IFACE_BASE_TABLE_PRIORITY + old_iface_index;
    new_table = RULE_IFACE_BASE_TABLE_PRIORITY + new_iface_index;

    /* In some OS when a virtual interface is removed and added again,
     * the index of the interface change. Search iface_t by the interface
     * name and update the index. */
    if (old_iface_index != new_iface_index){
        OOR_LOG(LDBG_2, "process_nl_new_link: The new index of the interface "
                "%s is: %d. Updating tables", iface->iface_name,
                iface->iface_index);

        /* Update routing tables and reopen sockets*/
        if (iface->ipv4_address && !lisp_addr_is_no_addr(iface->ipv4_address)) {
            del_rule(AF_INET, 0, old_table, old_table,
                    RTN_UNICAST, iface->ipv4_address, NULL, 0);
            add_rule(AF_INET, 0, new_table, new_table, RTN_UNICAST,
                    iface->ipv4_address, NULL, 0);
            close(iface->out_socket_v4);
            iface->out_socket_v4 = open_ip_raw_socket( AF_INET);
            bind_socket(iface->out_socket_v4, AF_INET, iface->ipv4_address, 0);
        }
        if (iface->ipv6_address && !lisp_addr_is_no_addr(iface->ipv6_address)) {
            del_rule(AF_INET6, 0, old_table, old_table,
                    RTN_UNICAST, iface->ipv6_address, NULL, 0);
            add_rule(AF_INET6, 0, new_table, new_table, RTN_UNICAST,
                    iface->ipv6_address, NULL, 0);
            close(iface->out_socket_v6);
            iface->out_socket_v6 = open_ip_raw_socket(AF_INET6);
            bind_socket(iface->out_socket_v6,AF_INET6, iface->ipv6_address, 0);
        }
    }

    if (data->default_out_iface_v4 == iface
            || data->default_out_iface_v6 == iface
            || data->default_out_iface_v4 == NULL
            || data->default_out_iface_v6 == NULL){
        OOR_LOG(LDBG_2,"Default output interface down. Recalculate new output "
                "interface");
        tun_set_default_output_ifaces();
    }

    return (GOOD);
}

void
tun_process_new_gateway(iface_t *iface,lisp_addr_t *gateway)
{
    lisp_addr_t **gw_addr = NULL;
    int afi = LM_AFI_NO_ADDR;
    int route_metric = 100;
    int table = RULE_IFACE_BASE_TABLE_PRIORITY + iface->iface_index;

    switch(lisp_addr_ip_afi(gateway)){
        case AF_INET:
            gw_addr = &(iface->ipv4_gateway);
            afi = AF_INET;
            break;
        case AF_INET6:
            gw_addr = &(iface->ipv6_gateway);
            afi = AF_INET6;
            break;
        default:
            return;
    }
    if (*gw_addr == NULL || lisp_addr_is_no_addr(*gw_addr)) { // The default gateway of this interface is not deffined yet
        lisp_addr_del(*gw_addr);
        *gw_addr = lisp_addr_new();
        lisp_addr_copy(*gw_addr,gateway);
    }else if (lisp_addr_cmp(*gw_addr, gateway) == 0){
        OOR_LOG(LDBG_3,"tun_process_new_gateway: the gatweay address has not changed: %s. Discard message.",
                            lisp_addr_to_char(gateway));
    }else{
        lisp_addr_copy(*gw_addr,gateway);
    }

    add_route(afi,iface->iface_index,NULL,NULL,gateway,route_metric,table);
}

void
tun_process_rm_gateway(iface_t *iface,lisp_addr_t *gateway)
{
    lisp_addr_t **gw_addr = NULL;
    int afi = LM_AFI_NO_ADDR;
    int route_metric = 100;
    int table = RULE_IFACE_BASE_TABLE_PRIORITY + iface->iface_index;


    switch(lisp_addr_ip_afi(gateway)){
        case AF_INET:
            gw_addr = &(iface->ipv4_gateway);
            afi = AF_INET;
            break;
        case AF_INET6:
            gw_addr = &(iface->ipv6_gateway);
            afi = AF_INET6;
            break;
        default:
            return;
    }

    if (*gw_addr == NULL || lisp_addr_is_no_addr(*gw_addr)){
        return;
    }

    del_route(afi,iface->iface_index,NULL,NULL,gateway,route_metric,table);
    lisp_addr_del(*gw_addr);
    *gw_addr = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
}

void
tun_set_default_output_ifaces()
{
    tun_dplane_data_t *data;
    data = (tun_dplane_data_t *)dplane_tun.datap_data;

    data->default_out_iface_v4 = get_any_output_iface(AF_INET);

    if (data->default_out_iface_v4 != NULL) {
       OOR_LOG(LDBG_2,"Default IPv4 data iface %s: %s\n",data->default_out_iface_v4->iface_name,
               lisp_addr_to_char(data->default_out_iface_v4->ipv4_address));
    }

    data->default_out_iface_v6 = get_any_output_iface(AF_INET6);
    if (data->default_out_iface_v6 != NULL) {
       OOR_LOG(LDBG_2,"Default IPv6 data iface %s: %s\n", data->default_out_iface_v6->iface_name,
               lisp_addr_to_char(data->default_out_iface_v6->ipv6_address));
    }

    if (!data->default_out_iface_v4 && !data->default_out_iface_v6){
        OOR_LOG(LCRIT,"NO OUTPUT IFACE: all the locators are down");
    }
}

lisp_addr_t *
tun_get_default_output_address(int afi)
{
    lisp_addr_t *addr = NULL;
    tun_dplane_data_t *data;
    data = (tun_dplane_data_t *)dplane_tun.datap_data;

    switch (afi) {
    case AF_INET:
        if (data->default_out_iface_v4 != NULL) {
            addr = data->default_out_iface_v4->ipv4_address;
        }
        break;
    case AF_INET6:
        if (data->default_out_iface_v6 != NULL) {
            addr = data->default_out_iface_v6->ipv6_address;
        }
        break;
    default:
        OOR_LOG(LDBG_2, "tun_get_default_output_address: AFI %s not valid", afi);
        return(NULL);
    }

    return(addr);
}

int
tun_get_default_output_socket(int afi)
{
    int out_socket = ERR_SOCKET;
    tun_dplane_data_t *data;
    data = (tun_dplane_data_t *)dplane_tun.datap_data;

    switch (afi) {
    case AF_INET:
        if (data->default_out_iface_v4 != NULL) {
            out_socket = data->default_out_iface_v4->out_socket_v4;
        }
        break;
    case AF_INET6:
        if (data->default_out_iface_v6 != NULL) {
            out_socket = data->default_out_iface_v6->out_socket_v6;
        }
        break;
    default:
        OOR_LOG(LDBG_2, "tun_get_default_output_socket: AFI %s not valid", afi);
        break;
    }

    return (out_socket);
}

void
tun_iface_remove_routing_rules(iface_t *iface)
{
    int table = RULE_IFACE_BASE_TABLE_PRIORITY + iface->iface_index;
    if (iface->ipv4_address && !lisp_addr_is_no_addr(iface->ipv4_address)) {
        if (iface->ipv4_gateway && !lisp_addr_is_no_addr(iface->ipv4_gateway)) {
            del_route(AF_INET, iface->iface_index, NULL, NULL,
                    iface->ipv4_gateway, 0, table);
        }

        del_rule(AF_INET, 0, table, table,
                RTN_UNICAST, iface->ipv4_address, NULL, 0);
    }
    if (iface->ipv6_address && !lisp_addr_is_no_addr(iface->ipv6_address)) {
        if (iface->ipv6_gateway && !lisp_addr_is_no_addr(iface->ipv6_gateway)) {
            del_route(AF_INET6, iface->iface_index, NULL, NULL,
                    iface->ipv6_gateway, 0, table);
        }
        del_rule(AF_INET6, 0, table, table,
                RTN_UNICAST, iface->ipv6_address, NULL, 0);
    }
}

int
tun_rm_fwd_from_entry(lisp_addr_t *eid_prefix, uint8_t is_local)
{
    char * eid_prefix_char = lisp_addr_to_char(eid_prefix);
    glist_t *fwd_tpl_list, *pxtr_fwd_tpl_list;
    glist_entry_t *tpl_it;
    fwd_info_t *fi;
    tun_dplane_data_t *data = (tun_dplane_data_t *)dplane_tun.datap_data;
    packet_tuple_t *tpl;


    if (is_local){
        return (tun_reset_all_fwd());
    }

    if (strcmp(eid_prefix_char,FULL_IPv4_ADDRESS_SPACE) == 0){ // Update of the PeTR list for IPv4 EIDs or RTR list
        OOR_LOG(LDBG_3, "tun_rm_fwd_from_entry: Removing all the forwarding entries association with the PeTRs for IPv4 EIDs");
        pxtr_fwd_tpl_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv4_ADDRESS_SPACE);
        if (!pxtr_fwd_tpl_list){
            return (GOOD);
        }
        /* Remove all the entries associated with the PxTR */

        while (glist_size(pxtr_fwd_tpl_list) > 0){
            tpl = (packet_tuple_t *)glist_first_data(pxtr_fwd_tpl_list);
            fi = ttable_lookup(&(data->ttable), tpl);
            // When we recurively call this function using the associated_entry we will execute "else" statement where we also
            // update the list of entries associated with PxTR.
            tun_rm_fwd_from_entry(fi->associated_entry,is_local);
        }
    }else if(strcmp(eid_prefix_char,FULL_IPv6_ADDRESS_SPACE) == 0){ // Update of the PeTR list for IPv6 EIDs or RTR list
        OOR_LOG(LDBG_3, "tun_rm_fwd_from_entry: Removing all the forwarding entries association with the PeTRs for IPv6 EIDs");
        pxtr_fwd_tpl_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv6_ADDRESS_SPACE);
        if (!pxtr_fwd_tpl_list){
            return (GOOD);
        }
        /* Remove all the entries associated with the PxTR */

        while (glist_size(pxtr_fwd_tpl_list) > 0){
            tpl = (packet_tuple_t *)glist_first_data(pxtr_fwd_tpl_list);
            fi = ttable_lookup(&(data->ttable), tpl);
            // When we recurively call this function using the associated_entry we will execute "else" statement where we also
            // update the list of entries associated with PxTR.
            tun_rm_fwd_from_entry(fi->associated_entry,is_local);
        }
    }else{
        OOR_LOG(LDBG_3, "tun_rm_fwd_from_entry: Removing all the forwarding entries association with the EID %s",eid_prefix_char);
        fwd_tpl_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,eid_prefix_char);
        if (!fwd_tpl_list){
            OOR_LOG(LDBG_2, "tun_rm_fwd_from_entry: Entry %s not found in the shasht!",eid_prefix_char);
            return (BAD);
        }
        /* Check if it is a negative entry in order to remove also from PxTRs list */
        tpl = (packet_tuple_t *)glist_first_data(fwd_tpl_list);
        fi = ttable_lookup(&(data->ttable), tpl);
        if (fi->neg_map_reply_act == ACT_NATIVE_FWD){ //negative mapping
            switch (lisp_addr_ip_afi(fi->associated_entry)){
            case AF_INET:
                pxtr_fwd_tpl_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv4_ADDRESS_SPACE);
                break;
            case AF_INET6:
                pxtr_fwd_tpl_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv6_ADDRESS_SPACE);
                break;
            default:
                OOR_LOG(LDBG_1, "tun_rm_fwd_from_entry: Associated entry is not IP");
                return (BAD);
            }
            glist_for_each_entry(tpl_it,fwd_tpl_list){
                tpl = (packet_tuple_t *)glist_entry_data(tpl_it);
                glist_remove_obj(tpl,pxtr_fwd_tpl_list);
            }
        }
        /* Remove associated entry from eid_to_dp_entries */
        shash_remove(data->eid_to_dp_entries, eid_prefix_char);
    }

    return (GOOD);
}

/* Remove all the fwd programmed in the data plane
 * Used when a change is produced in the local mappings */

int
tun_reset_all_fwd()
{
    tun_dplane_data_t *data = (tun_dplane_data_t *)dplane_tun.datap_data;

    shash_destroy(data->eid_to_dp_entries);
    data->eid_to_dp_entries = shash_new_managed((free_value_fn_t)glist_destroy);
    return (GOOD);
}

tun_dplane_data_t *
tun_dplane_data_new_init(oor_encap_t encap_type, glist_t *allowed_dst_eids)
{
    tun_dplane_data_t * data;
    data = xmalloc(sizeof(tun_dplane_data_t));
    if (!data){
        return (NULL);
    }
    data->encap_type = encap_type;
    data->eid_to_dp_entries = shash_new_managed((free_value_fn_t)glist_destroy);
    data->allowed_eid_prefixes = glist_clone(allowed_dst_eids, (glist_clone_obj)lisp_addr_clone);
    ttable_init(&(data->ttable));
    return (data);
}

void
tun_dplane_data_free(tun_dplane_data_t *data)
{
    if (!data){
        return;
    }
    shash_destroy(data->eid_to_dp_entries);
    glist_destroy(data->allowed_eid_prefixes);
    ttable_uninit(&(data->ttable));
    free(data);
}

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
