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
#include "vpnapi.h"
#include "vpnapi_input.h"
#include "vpnapi_output.h"
#include "../data-plane.h"
#include "../encapsulations/vxlan-gpe.h"
#include "../../iface_list.h"
#include "../../oor_external.h"
#include "../../oor_jni.h"
#include "../../fwd_policies/fwd_policy.h"
#include "../../lib/oor_log.h"
#include "../../net_mgr/net_mgr.h"

int vpnapi_init(oor_dev_type_e dev_type, oor_encap_t encap_type,...);
void vpnapi_uninit();
int vpnapi_add_datap_iface_addr(iface_t *iface, int afi);
int vpnapi_add_datap_iface_gw(iface_t *iface, int afi);
int vpnapi_register_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map);
int vpnapi_deregister_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map);
int vpnapi_updated_route(int command, iface_t *iface, lisp_addr_t *src_pref,
            lisp_addr_t *dst_pref, lisp_addr_t *gw);
void vpnapi_process_new_gateway(iface_t *iface,lisp_addr_t *gateway);
int vpnapi_updated_addr(iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr);
int vpnapi_update_link(iface_t *iface, int old_iface_index, int new_iface_index,
        int status);
int vpnapi_reset_socket(int fd, int afi);
int vpnapi_rm_fwd_from_entry(lisp_addr_t *eid_prefix, uint8_t is_local);
vpnapi_data_t * vpnapi_data_new_init(oor_encap_t encap_type, int tun_socket,
        int ipv4_data_socket, int ipv6_data_socket);
void vpnapi_data_free(vpnapi_data_t *data);

data_plane_struct_t dplane_vpnapi = {
        .datap_init = vpnapi_init,
        .datap_uninit = vpnapi_uninit,
        .datap_add_iface_addr = vpnapi_add_datap_iface_addr,
        .datap_add_iface_gw = vpnapi_add_datap_iface_gw,
        .datap_register_lcl_mapping = vpnapi_register_lcl_mapping,
        .datap_deregister_lcl_mapping = vpnapi_deregister_lcl_mapping,
        .datap_input_packet = vpnapi_process_input_packet,
        .datap_rtr_input_packet = vpnapi_rtr_process_input_packet,
        .datap_output_packet = vpnapi_output_recv,
        .datap_updated_route = vpnapi_updated_route,
        .datap_updated_addr = vpnapi_updated_addr,
        .datap_update_link = vpnapi_update_link,
        .datap_rm_fwd_from_entry = vpnapi_rm_fwd_from_entry,
        .datap_reset_all_fwd = vpnapi_reset_all_fwd,
        .datap_data = NULL
};

inline vpnapi_data_t *
vpnapi_get_datap_data()
{
    return ((vpnapi_data_t *)dplane_vpnapi.datap_data);
}

int
vpnapi_init(oor_dev_type_e dev_type, oor_encap_t encap_type,...)
{
    int (*cb_func)(sock_t *) = NULL;
    int tun_fd, ipv4_data_socket, ipv6_data_socket;
    va_list ap;
    int data_port;

    /* Get the extra parameter of the function */
    va_start(ap, encap_type);
    tun_fd = va_arg(ap, int);
    va_end(ap);

    sockmstr_register_read_listener(smaster, vpnapi_output_recv, NULL,tun_fd);

    switch (dev_type){
    case MN_MODE:
    case xTR_MODE:
        cb_func = vpnapi_process_input_packet;
        break;
    case RTR_MODE:
        cb_func = vpnapi_rtr_process_input_packet;
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
        ipv4_data_socket = open_data_datagram_input_socket(AF_INET, data_port);
        sockmstr_register_read_listener(smaster, cb_func, NULL,ipv4_data_socket);
        oor_jni_protect_socket(ipv4_data_socket);
    }else {
        ipv4_data_socket = ERR_SOCKET;
    }

    if (default_rloc_afi != AF_INET){
        ipv6_data_socket = open_data_datagram_input_socket(AF_INET6, data_port);
        sockmstr_register_read_listener(smaster, cb_func, NULL,ipv6_data_socket);
        oor_jni_protect_socket(ipv6_data_socket);
    }else {
        ipv6_data_socket = ERR_SOCKET;
    }

    dplane_vpnapi.datap_data = (void *)vpnapi_data_new_init(encap_type, tun_fd,
            ipv4_data_socket, ipv6_data_socket);
    if (!(dplane_vpnapi.datap_data)){
        return (BAD);
    }

    return (GOOD);
}

void
vpnapi_uninit()
{
    vpnapi_data_free(dplane_vpnapi.datap_data);
}

int
vpnapi_add_datap_iface_addr(iface_t *iface, int afi)
{
    return (GOOD);
}

int
vpnapi_add_datap_iface_gw(iface_t *iface, int afi)
{
    return (GOOD);
}

int
vpnapi_register_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map)
{
    return (GOOD);
}

int
vpnapi_deregister_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map)
{
    return (GOOD);
}

int
vpnapi_updated_route(int command, iface_t *iface, lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    if (lisp_addr_ip_afi(gateway) != LM_AFI_NO_ADDR
            && lisp_addr_ip_afi(dst_pref) == LM_AFI_NO_ADDR) {

        /* Check if the addres is a global address*/
        if (ip_addr_is_link_local(lisp_addr_ip(gateway)) == TRUE) {
            OOR_LOG(LDBG_3,"vpnapi_updated_route: the extractet address "
                    "from the netlink messages is a local link address: %s "
                    "discarded", lisp_addr_to_char(gateway));
            return (GOOD);
        }

        /* Process the new gateway */
        OOR_LOG(LDBG_1,  "vpnapi_updated_route: Process new gateway "
                "associated to the interface %s:  %s", iface->iface_name,
                lisp_addr_to_char(gateway));
        vpnapi_process_new_gateway(iface,gateway);
    }
    return (GOOD);
}

void
vpnapi_process_new_gateway(iface_t *iface,lisp_addr_t *gateway)
{
    lisp_addr_t **gw_addr    = NULL;
    int afi;
    vpnapi_data_t *data;

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
        lisp_addr_copy(*gw_addr,gateway);
    }else if (lisp_addr_cmp(*gw_addr, gateway) == 0){
        OOR_LOG(LDBG_3,"tun_process_new_gateway: the gatweay address has not changed: %s. Discard message.",
                            lisp_addr_to_char(gateway));
        return;
    }else{
        lisp_addr_copy(*gw_addr,gateway);
    }

    if (iface->status != UP){
        OOR_LOG(LDBG_1,"vpnapi_process_new_gateway: Probably the interface %s is UP "
                "but we didn't receive netlink indicating this. Checking it",
                iface->iface_name,iface->iface_name);
        iface->status = net_mgr->netm_get_iface_status(iface->iface_name);
    }

    data = (vpnapi_data_t *)dplane_vpnapi.datap_data;

    /* Recreate sockets */
    if (afi == AF_INET){
        vpnapi_reset_socket(data->ipv4_data_socket,AF_INET);
    }else{
        vpnapi_reset_socket(data->ipv6_data_socket,AF_INET6);
    }
}

int
vpnapi_updated_addr(iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr)
{
    int new_addr_ip_afi;
    vpnapi_data_t * data;

    data = (vpnapi_data_t *)dplane_vpnapi.datap_data;

    new_addr_ip_afi = lisp_addr_ip_afi(new_addr);

    /* Check if the detected change of address id the same. */
    if (lisp_addr_cmp(old_addr, new_addr) == 0) {
        OOR_LOG(LDBG_2, "vpnapi_updated_addr: The change of address detected "
                "for interface %s doesn't affect", iface->iface_name);

        return (GOOD);
    };

    switch (new_addr_ip_afi){
    case AF_INET:
        vpnapi_reset_socket(data->ipv4_data_socket, AF_INET);
        break;
    case AF_INET6:
        vpnapi_reset_socket(data->ipv6_data_socket, AF_INET6);
        break;
    default:
        return (BAD);
    }

    return (GOOD);
}

int
vpnapi_update_link(iface_t *iface, int old_iface_index, int new_iface_index, int status)
{
    vpnapi_data_t * data;

    data = (vpnapi_data_t *)dplane_vpnapi.datap_data;
    /* In some OS when a virtual interface is removed and added again,
     * the index of the interface change. Search iface_t by the interface
     * name and update the index. */
    if (old_iface_index != new_iface_index){
        OOR_LOG(LDBG_2, "vpnapi_update_link: The new index of the interface "
                "%s is: %d", iface->iface_name,iface->iface_index);
    }

    if (default_rloc_afi != AF_INET6){
        vpnapi_reset_socket(data->ipv4_data_socket, AF_INET);
    }
    if (default_rloc_afi != AF_INET){
        vpnapi_reset_socket(data->ipv6_data_socket, AF_INET6);
    }

    return (GOOD);
}

int
vpnapi_reset_socket(int fd, int afi)
{
    sock_t *old_sock;
    int new_fd;
    vpnapi_data_t * data;
    int src_port;

    data = (vpnapi_data_t *)dplane_vpnapi.datap_data;
    old_sock = sockmstr_register_get_by_fd(smaster,fd);

    switch (data->encap_type){
    case ENCP_LISP:
        src_port = LISP_DATA_PORT;
        break;
    case ENCP_VXLAN_GPE:
        src_port = VXLAN_GPE_DATA_PORT;
        break;
    }

    switch (afi){
    case AF_INET:
        OOR_LOG(LDBG_2,"reset_socket: Reset IPv4 data socket");
        new_fd = open_data_datagram_input_socket(AF_INET,src_port);
        if (new_fd == ERR_SOCKET){
            OOR_LOG(LDBG_2,"vpnapi_reset_socket: Error recreating the socket");
            return (BAD);
        }
        data->ipv4_data_socket = new_fd;
        break;
    case AF_INET6:
        OOR_LOG(LDBG_2,"reset_socket: Reset IPv6 data socket");
        new_fd = open_data_datagram_input_socket(AF_INET6,src_port);
        if (new_fd == ERR_SOCKET){
            OOR_LOG(LDBG_2,"vpnapi_reset_socket: Error recreating the socket");
            return (BAD);
        }
        data->ipv6_data_socket = new_fd;
        break;
    default:
        return (BAD);
    }
    sockmstr_register_read_listener(smaster,old_sock->recv_cb,old_sock->arg,new_fd);
    sockmstr_unregister_read_listenedr(smaster,old_sock);
    /* Protect the socket from loops in the system*/
    oor_jni_protect_socket(new_fd);

    return (GOOD);
}

int
vpnapi_rm_fwd_from_entry(lisp_addr_t *eid_prefix, uint8_t is_local)
{
    char * eid_prefix_char = lisp_addr_to_char(eid_prefix);
    glist_t *fwd_tpl_list, *pxtr_fwd_tpl_list;
    glist_entry_t *tpl_it;
    fwd_info_t *fi;
    vpnapi_data_t *data = (vpnapi_data_t *)dplane_vpnapi.datap_data;
    packet_tuple_t *tpl;


    if (is_local){
        return (vpnapi_reset_all_fwd());
    }

    if (strcmp(eid_prefix_char,FULL_IPv4_ADDRESS_SPACE) == 0){ // Update of the PeTR list for IPv4 EIDs or RTR list
        OOR_LOG(LDBG_3, "vpnapi_rm_fwd_from_entry: Removing all the forwading entries association with the PeTRs for IPv4 EIDs");
        pxtr_fwd_tpl_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv4_ADDRESS_SPACE);
        /* Remove all the entries associated with the PxTR */

        while (glist_size(pxtr_fwd_tpl_list) > 0){
            tpl = (packet_tuple_t *)glist_first_data(pxtr_fwd_tpl_list);
            fi = ttable_lookup(&(data->ttable), tpl);
            // When we recurively call this function using the associated_entry we will execute "else" statement where we also
            // update the list of entries associated with PxTR.
            vpnapi_rm_fwd_from_entry(fi->associated_entry,is_local);
        }
    }else if(strcmp(eid_prefix_char,FULL_IPv6_ADDRESS_SPACE) == 0){ // Update of the PeTR list for IPv6 EIDs or RTR list
        OOR_LOG(LDBG_3, "vpnapi_rm_fwd_from_entry: Removing all the forwading entries association with the PeTRs for IPv6 EIDs");
        pxtr_fwd_tpl_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv6_ADDRESS_SPACE);
        /* Remove all the entries associated with the PxTR */

        while (glist_size(pxtr_fwd_tpl_list) > 0){
            tpl = (packet_tuple_t *)glist_first_data(pxtr_fwd_tpl_list);
            fi = ttable_lookup(&(data->ttable), tpl);
            // When we recurively call this function using the associated_entry we will execute "else" statement where we also
            // update the list of entries associated with PxTR.
            vpnapi_rm_fwd_from_entry(fi->associated_entry,is_local);
        }
    }else{
        OOR_LOG(LDBG_3, "vpnapi_rm_fwd_from_entry: Removing all the forwading entries association with the EID %s",eid_prefix_char);
        fwd_tpl_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,eid_prefix_char);
        if (!fwd_tpl_list){
            OOR_LOG(LDBG_1, "vpnapi_rm_fwd_from_entry: Entry %s not found in the shasht!",eid_prefix_char);
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
                OOR_LOG(LDBG_1, "vpnapi_rm_fwd_from_entry: Associated entry is not IP");
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
vpnapi_reset_all_fwd()
{
    vpnapi_data_t *data = (vpnapi_data_t *)dplane_vpnapi.datap_data;

    shash_destroy(data->eid_to_dp_entries);
    data->eid_to_dp_entries = shash_new_managed((free_value_fn_t)glist_destroy);
    /* Insert entry for PeTRs */
    shash_insert(data->eid_to_dp_entries, strdup(FULL_IPv4_ADDRESS_SPACE), glist_new());
    shash_insert(data->eid_to_dp_entries, strdup(FULL_IPv6_ADDRESS_SPACE), glist_new());
    return (GOOD);
}

vpnapi_data_t *
vpnapi_data_new_init(oor_encap_t encap_type, int tun_socket,
        int ipv4_data_socket, int ipv6_data_socket)
{
    vpnapi_data_t * data;
    data = xmalloc(sizeof(vpnapi_data_t));
    if (!data){
        return (NULL);
    }
    data->encap_type = encap_type;
    data->tun_socket = tun_socket;
    data->ipv4_data_socket = ipv4_data_socket;
    data->ipv6_data_socket = ipv6_data_socket;
    data->eid_to_dp_entries = shash_new_managed((free_value_fn_t)glist_destroy);
    /* Insert entry for PeTRs */
    shash_insert(data->eid_to_dp_entries, strdup(FULL_IPv4_ADDRESS_SPACE), glist_new());
    shash_insert(data->eid_to_dp_entries, strdup(FULL_IPv6_ADDRESS_SPACE), glist_new());

    ttable_init(&(data->ttable));
    return (data);
}

void
vpnapi_data_free(vpnapi_data_t *data)
{
    if (!data){
        return;
    }
    shash_destroy(data->eid_to_dp_entries);
    ttable_uninit(&(data->ttable));
    free(data);
}
