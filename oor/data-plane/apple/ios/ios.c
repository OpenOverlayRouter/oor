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

#include <stdarg.h>
#include <netdb.h>

#include "ios.h"
#include "ios_input.h"
#include "ios_output.h"
#include "../../data-plane.h"
#include "../../encapsulations/vxlan-gpe.h"
#include "../../../iface_list.h"
#include "../../../oor_external.h"
#include "../../../fwd_policies/fwd_policy.h"
#include "../../../lib/oor_log.h"
#include "../../../lib/util.h"
#include "../../../net_mgr/net_mgr.h"

int ios_init(oor_dev_type_e dev_type, oor_encap_t encap_type,...);
void ios_uninit();
int ios_add_datap_iface_addr(iface_t *iface, int afi);
int ios_add_datap_iface_gw(iface_t *iface, int afi);
int ios_register_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map);
int ios_deregister_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map);
int ios_updated_route(int command, iface_t *iface, lisp_addr_t *src_pref,
                         lisp_addr_t *dst_pref, lisp_addr_t *gw);
void ios_process_new_gateway(iface_t *iface,lisp_addr_t *gateway);
int ios_updated_addr(iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr);
int ios_update_link(iface_t *iface, int old_iface_index, int new_iface_index,
                       int status);
int ios_reset_sockets(int afi);
int ios_rm_fwd_from_entry(lisp_addr_t *eid_prefix, uint8_t is_local);
ios_data_t * ios_data_new_init(oor_encap_t encap_type, int tun_socket,
                                     int ipv4_data_socket, int ipv6_data_socket);
void ios_data_free(ios_data_t *data);

data_plane_struct_t dplane_apple = {
    .datap_init = ios_init,
    .datap_uninit = ios_uninit,
    .datap_add_iface_addr = ios_add_datap_iface_addr,
    .datap_add_iface_gw = ios_add_datap_iface_gw,
    .datap_register_lcl_mapping = ios_register_lcl_mapping,
    .datap_deregister_lcl_mapping = ios_deregister_lcl_mapping,
    .datap_input_packet = ios_process_input_packet,
    .datap_rtr_input_packet = ios_rtr_process_input_packet,
    .datap_output_packet = ios_output_recv2,
    .datap_updated_route = ios_updated_route,
    .datap_updated_addr = ios_updated_addr,
    .datap_update_link = ios_update_link,
    .datap_rm_fwd_from_entry = ios_rm_fwd_from_entry,
    .datap_reset_all_fwd = ios_reset_all_fwd,
    .datap_data = NULL
};

inline ios_data_t *
ios_get_datap_data()
{
    return ((ios_data_t *)dplane_apple.datap_data);
}

int
ios_init(oor_dev_type_e dev_type, oor_encap_t encap_type,...)
{
    int (*cb_func)(sock_t *) = NULL;
    int tun_socket, in_ipv4_data_socket, in_ipv6_data_socket, out_ipv4_data_socket, out_ipv6_data_socket;
    int data_port;
    
    //open socket to connect with TunnelProvider
    tun_socket = open_data_datagram_input_socket(AF_INET, 10001);
    sockmstr_register_read_listener(smaster, ios_output_recv2, NULL,tun_socket);
    
    switch (dev_type){
        case MN_MODE:
        case xTR_MODE:
            cb_func = ios_process_input_packet;
            break;
        case RTR_MODE:
            cb_func = ios_rtr_process_input_packet;
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
    }
    
    if (default_rloc_afi != AF_INET6){
        in_ipv4_data_socket = open_data_datagram_input_socket(AF_INET, data_port);
        sockmstr_register_read_listener(smaster, cb_func, NULL,in_ipv4_data_socket);
        out_ipv4_data_socket = open_data_datagram_output_socket(AF_INET,0);
    }else {
        in_ipv4_data_socket = ERR_SOCKET;
        out_ipv4_data_socket = ERR_SOCKET;
    }
    
    if (default_rloc_afi != AF_INET){
        in_ipv6_data_socket = open_data_datagram_input_socket(AF_INET6, data_port);
        sockmstr_register_read_listener(smaster, cb_func, NULL,in_ipv6_data_socket);
        out_ipv6_data_socket = open_data_datagram_output_socket(AF_INET6,0);
    }else {
        in_ipv6_data_socket = ERR_SOCKET;
        out_ipv6_data_socket = ERR_SOCKET;
    }
    
    dplane_apple.datap_data = (void *)ios_data_new_init(encap_type, tun_socket,
                                                            out_ipv4_data_socket, out_ipv6_data_socket);
    if (!(dplane_apple.datap_data)){
        return (BAD);
    }
    
    return (GOOD);
}

void
ios_uninit()
{
    ios_data_free(dplane_apple.datap_data);
}

int
ios_add_datap_iface_addr(iface_t *iface, int afi)
{
    return (GOOD);
}

int
ios_add_datap_iface_gw(iface_t *iface, int afi)
{
    return (GOOD);
}

int
ios_register_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map)
{
    return (GOOD);
}

int
ios_deregister_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map)
{
    return (GOOD);
}

int
ios_updated_route(int command, iface_t *iface, lisp_addr_t *src_pref,
                     lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    if (lisp_addr_ip_afi(gateway) != LM_AFI_NO_ADDR){
        if((lisp_addr_ip_afi(dst_pref) == LM_AFI_NO_ADDR ||
        laddr_is_full_space_pref(dst_pref))) {
            // Process the new gateway
            OOR_LOG(LDBG_1,  "ios_updated_route: Process new gateway "
                "associated to the interface %s:  %s", iface->iface_name,
                lisp_addr_to_char(gateway));
            ios_process_new_gateway(iface,gateway);
        }
        /* Sanity check in case we don't receive link status change */
        iface->status = net_mgr->netm_get_iface_status(iface->iface_name);
    }
    return (GOOD);
}

void
ios_process_new_gateway(iface_t *iface,lisp_addr_t *gateway)
{
    lisp_addr_t **gw_addr    = NULL;
    int afi;
    ios_data_t *data;
    uint8_t old_status;
    afi = lisp_addr_ip_afi(gateway);
    
    switch(afi){
        case AF_INET:
            gw_addr = &(iface->ipv4_gateway);
            break;
        case AF_INET6:
            gw_addr = &(iface->ipv6_gateway);
            break;
        default:
            return;
    }
    if (*gw_addr == NULL || lisp_addr_is_no_addr(*gw_addr)) { // The default gateway of this interface is not deffined yet
        lisp_addr_del (*gw_addr);
        *gw_addr = lisp_addr_new();
    }
    lisp_addr_copy(*gw_addr,gateway);
    
    data = (ios_data_t *)dplane_apple.datap_data;
    
    /* Recreate sockets */
    if (afi == AF_INET){
        ios_reset_sockets(AF_INET);
    }else{
        ios_reset_sockets(AF_INET6);
    }
}

int
ios_updated_addr(iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr)
{
    int new_addr_ip_afi;
    ios_data_t * data;

    data = (ios_data_t *)dplane_apple.datap_data;
    new_addr_ip_afi = lisp_addr_ip_afi(new_addr);
    
    /* Check if the detected change of address id the same. */
    if (lisp_addr_cmp(old_addr, new_addr) == 0) {
        OOR_LOG(LDBG_2, "ios_updated_addr: The change of address detected "
                "for interface %s doesn't affect", iface->iface_name);
        
        return (GOOD);
    };
    
    switch (new_addr_ip_afi){
        case AF_INET:
            ios_reset_sockets(AF_INET);
            break;
        case AF_INET6:
            ios_reset_sockets(AF_INET6);
            break;
        default:
            return (BAD);
    }
    
    return (GOOD);
}

int
ios_update_link(iface_t *iface, int old_iface_index, int new_iface_index, int status)
{
    ios_data_t * data;
    
    data = (ios_data_t *)dplane_apple.datap_data;
    
    if (default_rloc_afi != AF_INET6){
        ios_reset_sockets(AF_INET);
    }
    if (default_rloc_afi != AF_INET){
        ios_reset_sockets(AF_INET6);
    }
    return (GOOD);
}

int
ios_reset_sockets(int afi)
{
    sock_t *old_sock;
    ios_data_t * data;
    uint16_t src_port;
    int new_fd;

    data = (ios_data_t *)dplane_apple.datap_data;
    switch (data->encap_type){
    case ENCP_LISP:
        src_port = LISP_DATA_PORT;
        break;
    case ENCP_VXLAN_GPE:
        src_port = VXLAN_GPE_DATA_PORT;
        break;
    }
    
    /* Reset input socket */
    old_sock = sockmstr_register_get_by_bind_port(smaster,afi,src_port);

    OOR_LOG(LDBG_2,"reset_socket: Reset binded %s data socket", (afi == AF_INET) ? "IPv4" : "IPv6");
    new_fd = open_data_datagram_input_socket(afi,src_port);
    if (new_fd == ERR_SOCKET){
        OOR_LOG(LDBG_2,"ios_reset_socket: Error recreating the read socket");
        return (BAD);
    }

    sockmstr_register_read_listener(smaster,old_sock->recv_cb,old_sock->arg,new_fd);
    sockmstr_unregister_read_listenedr(smaster,old_sock);

    return (GOOD);
}

int
ios_rm_fwd_from_entry(lisp_addr_t *eid_prefix, uint8_t is_local)
{
    char * eid_prefix_char = lisp_addr_to_char(eid_prefix);
    glist_t *fwd_tpl_list, *pxtr_fwd_tpl_list;
    glist_entry_t *tpl_it;
    fwd_info_t *fi;
    ios_data_t *data = (ios_data_t *)dplane_apple.datap_data;
    packet_tuple_t *tpl;
    
    
    if (is_local){
        return (ios_reset_all_fwd());
    }
    
    if (strcmp(eid_prefix_char,FULL_IPv4_ADDRESS_SPACE) == 0){ // Update of the PeTR list for IPv4 EIDs or RTR list
        OOR_LOG(LDBG_3, "ios_rm_fwd_from_entry: Removing all the forwading entries association with the PeTRs for IPv4 EIDs");
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
            ios_rm_fwd_from_entry(fi->associated_entry,is_local);
        }
    }else if(strcmp(eid_prefix_char,FULL_IPv6_ADDRESS_SPACE) == 0){ // Update of the PeTR list for IPv6 EIDs or RTR list
        OOR_LOG(LDBG_3, "ios_rm_fwd_from_entry: Removing all the forwading entries association with the PeTRs for IPv6 EIDs");
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
            ios_rm_fwd_from_entry(fi->associated_entry,is_local);
        }
    }else{
        OOR_LOG(LDBG_3, "ios_rm_fwd_from_entry: Removing all the forwading entries association with the EID %s",eid_prefix_char);
        fwd_tpl_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,eid_prefix_char);
        if (!fwd_tpl_list){
            OOR_LOG(LDBG_1, "ios_rm_fwd_from_entry: Entry %s not found in the shasht!",eid_prefix_char);
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
                    OOR_LOG(LDBG_1, "ios_rm_fwd_from_entry: Associated entry is not IP");
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
ios_reset_all_fwd()
{
    ios_data_t *data = (ios_data_t *)dplane_apple.datap_data;
    
    shash_destroy(data->eid_to_dp_entries);
    data->eid_to_dp_entries = shash_new_managed((free_value_fn_t)glist_destroy);
    return (GOOD);
}

ios_data_t *
ios_data_new_init(oor_encap_t encap_type, int tun_socket,
                     int ipv4_data_socket, int ipv6_data_socket)
{
    ios_data_t * data;
    data = xmalloc(sizeof(ios_data_t));
    if (!data){
        return (NULL);
    }
    data->encap_type = encap_type;
    data->tun_socket = tun_socket;
    data->ipv4_data_socket = ipv4_data_socket;
    data->ipv6_data_socket = ipv6_data_socket;
    data->eid_to_dp_entries = shash_new_managed((free_value_fn_t)glist_destroy);
    
    ttable_init(&(data->ttable));
    
    return (data);
}

void
ios_data_free(ios_data_t *data)
{
    if (!data){
        return;
    }
    shash_destroy(data->eid_to_dp_entries);
    ttable_uninit(&(data->ttable));
    free(data);
}
