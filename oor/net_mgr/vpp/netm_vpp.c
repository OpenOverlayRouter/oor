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

#include "netm_vpp.h"
#include "../net_mgr.h"
#include "../net_mgr_proc_fc.h"
#include "../../iface_list.h"
#include "../../lib/oor_log.h"
#include "../../lib/prefixes.h"
#include "../../lib/sockets.h"
#include "../../lib/util.h"
#include <vpp-api/vpe_msg_enum.h>
#include "../../lib/vpp_api/vpp_api_requests.h"

#define vl_typedefs
  #include <vpp-api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun        /* define message structures */
  #include <vpp-api/vpe_all_api_h.h>
#undef vl_endianfun


#include <zmq.h>

int vpp_netm_init();
void vpp_netm_uninit();
glist_t * vpp_get_ifaces_names();
lisp_addr_t * vpp_get_iface_addr(char *iface_name, int afi);
uint8_t vpp_get_iface_status(char *iface_name);
int vpp_get_iface_index(char *iface_name);
void vpp_get_iface_mac_addr(char *iface_name, uint8_t *mac);
char * vpp_get_iface_name_associated_with_prefix(lisp_addr_t * pref);
int vpp_reload_routes(uint32_t table, int afi);
shash_t * vpp_build_addr_to_if_name_hasht();
inline static netm_vpp_data_t * netm_vpp_data_new();
inline static void netm_vpp_data_free(netm_vpp_data_t * vpp_data);
int process_vpp_link_msg(struct sock *sl);
void vpp_process_link_change(vpp_nl_link_info *link_info, uint8_t status);
void vpp_process_addr_change(vpp_nl_addr_info *addr_info,uint8_t act);

net_mgr_class_t netm_vpp = {
        .netm_init = vpp_netm_init,
        .netm_uninit = vpp_netm_uninit,
        .netm_get_ifaces_names = vpp_get_ifaces_names,
        .netm_get_iface_index = vpp_get_iface_index,
        .netm_get_iface_addr = vpp_get_iface_addr,
        .netm_get_iface_status = vpp_get_iface_status,
        .netm_get_iface_mac_addr = vpp_get_iface_mac_addr,
        .netm_reload_routes = vpp_reload_routes,
        .netm_build_addr_to_if_name_hasht = vpp_build_addr_to_if_name_hasht,
        .netm_get_iface_associated_with_pref = vpp_get_iface_name_associated_with_prefix,
        .data = NULL
};

int
vpp_netm_init()
{
    netm_vpp_data_t *data = netm_vpp_data_new();
    int error;
    int fd,rc;
    size_t fd_size;

    data->zmq_context = zmq_ctx_new();
    data->zmq_socket = zmq_socket(data->zmq_context, ZMQ_PULL);
    error = zmq_bind(data->zmq_socket, VPP_IPC_FILE);

    if (error != 0){
        OOR_LOG(LDBG_1,"vpp_netm_init: Error while ZMQ binding on server: %s\n",zmq_strerror (errno));
        netm_vpp_data_free(data);
        return (BAD);
    }
    netm_vpp.data = data;
    OOR_LOG(LDBG_1,"vpp_netm_init: VPP network notification socket initiated using ZMQ\n");

    /* Get socket FD. When we receive an event in this socket, we should double check by checking
     * ZMQ_EVENTS option */

    fd_size = sizeof(int);
    rc = zmq_getsockopt(data->zmq_socket, ZMQ_FD, &fd, &fd_size);
    if (rc == -1){
        OOR_LOG(LDBG_1,"vpp_netm_init: Error while getting the fd of the ZMQ socket: %s\n",zmq_strerror (errno));
    }

    sockmstr_register_read_listener(smaster, process_vpp_link_msg, NULL,fd);
    return (GOOD);
}

void
vpp_netm_uninit()
{
    netm_vpp_data_t *data = (netm_vpp_data_t *)netm_vpp.data;
    if (!data){
        return;
    }
    zmq_close (data->zmq_socket);
    zmq_ctx_destroy (data->zmq_context);
    netm_vpp_data_free(data);
}


int
process_vpp_link_msg(struct sock *sl){
    uint8_t *buffer;
    int nbytes,rc;
    buffer = xzalloc(4096);
    netm_vpp_data_t *data = (netm_vpp_data_t *)netm_vpp.data;
    uint32_t events_flag;
    size_t fd_size;
    vpp_nl_msg *nl_msg;

    /* Check socket is ready to read */
    fd_size = sizeof(uint32_t);
    rc = zmq_getsockopt(data->zmq_socket, ZMQ_EVENTS, &events_flag, &fd_size);
    if (rc == -1){
        OOR_LOG(LDBG_1,"process_vpp_link_msg: Error while processing event type of ZMQ socket: %s\n",zmq_strerror (errno));
    }
    if (!(events_flag & ZMQ_POLLIN)){
        OOR_LOG(LDBG_3,"process_vpp_link_msg: ZMQ socket not ready to be read");
        return (GOOD);
    }
    /* Process the packet */
    nbytes = zmq_recv(data->zmq_socket, buffer, 4096, ZMQ_DONTWAIT);
    if (nbytes == -1){
        OOR_LOG(LERR,"process_vpp_link_msg: Error while ZMQ receiving: %s\n",zmq_strerror (errno));
        return (BAD);
    }

    nl_msg = (vpp_nl_msg *)buffer;


    switch(nl_msg->type){
    case VPP_NEWLINK:
        vpp_process_link_change((vpp_nl_link_info *)(buffer+sizeof(vpp_nl_msg)), UP);
        break;
    case VPP_DELLINK:
        vpp_process_link_change((vpp_nl_link_info *)(buffer+sizeof(vpp_nl_msg)), DOWN);
        break;
    case VPP_NEWADDR:
        vpp_process_addr_change((vpp_nl_addr_info *)(buffer+sizeof(vpp_nl_msg)), ADD);
        break;
    case VPP_DELADDR:
        vpp_process_addr_change((vpp_nl_addr_info *)(buffer+sizeof(vpp_nl_msg)), RM);
        break;
    default:
        OOR_LOG(LERR,"process_vpp_link_msg: Unknown message type\n");
    }

    return (GOOD);
}

void
vpp_process_link_change(vpp_nl_link_info *link_info, uint8_t status)
{
    OOR_LOG(LDBG_2, "vpp_process_link_change: Status of interface %d has changed to %s",
            link_info->ifi_index, status == UP ? "UP":"DOWN");

    nm_process_link_change(link_info->ifi_index, link_info->ifi_index, status);
}

void
vpp_process_addr_change(vpp_nl_addr_info *addr_info, uint8_t act)
{
    lisp_addr_t new_addr = { .lafi = LM_AFI_IP };

    switch (addr_info->ifa_family){
    case AF_INET:
        lisp_addr_ip_init(&new_addr, CO(addr_info,sizeof(vpp_nl_addr_info)), AF_INET);
        break;
    case AF_INET6:
        lisp_addr_ip_init(&new_addr, CO(addr_info,sizeof(vpp_nl_addr_info)), AF_INET6);
    }

    nm_process_address_change(act,addr_info->ifa_index, &new_addr);
}



glist_t *
vpp_get_ifaces_names()
{
    glist_t *iface_names = glist_new_managed((glist_del_fct)free);
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_sw_interface_dump_t *mp;
    glist_entry_t *iface_it;
    vpp_api_iface_t *iface_info;

    glist_remove_all(vam->iface_list);
    /* Get list of ethernets */
    MSG (SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, "Ether", sizeof (mp->name_filter) - 1);
    VPP_SEND;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t *mp;
        MSG (CONTROL_PING, control_ping);
        VPP_SEND;
    }

    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LERR,"vpp_get_ifaces_names: Couldn't obtain the list of interfaces");
        glist_destroy(iface_names);
        return (NULL);
    }

    glist_for_each_entry(iface_it,vam->iface_list){
        iface_info = (vpp_api_iface_t *)glist_entry_data(iface_it);
        glist_add(strdup(iface_info->iface_name),iface_names);
    }
    glist_remove_all(vam->iface_list);

    return (iface_names);
}

lisp_addr_t *
vpp_get_iface_addr(char *iface_name, int afi)
{
    vl_api_ip_address_dump_t *mp;
    vpp_api_main_t * vam = vpp_api_main_get();
    lisp_addr_t *addr;
    iface_t * iface;
    uint32_t iface_index;
    glist_entry_t *addr_it;

    glist_remove_all(vam->ip_addr_lst);
    iface = get_interface(iface_name);
    if (!iface){
        iface_index = vpp_get_iface_index(iface_name);
        if (iface_index == 0){
            OOR_LOG(LDBG_1,"vpp_get_iface_addr: Unknown interface %s",iface_name);
            return (lisp_addr_new_lafi(LM_AFI_NO_ADDR));
        }
    }else{
        iface_index = iface->iface_index;
    }

    MSG (IP_ADDRESS_DUMP, ip_address_dump);
    mp->sw_if_index = ntohl (iface_index);
    if (afi == AF_INET6){
        mp->is_ipv6 = 1;
    }
    vam->requested_ip_afi = afi;
    VPP_SEND;

    /* Use a control ping for synchronization */
    {
      vl_api_control_ping_t *mp;
      MSG (CONTROL_PING, control_ping);
      VPP_SEND;
    }
    if (vpp_wait(vam) == ERR_NO_REPLY){
        return (lisp_addr_new_lafi(LM_AFI_NO_ADDR));
    }

    glist_for_each_entry(addr_it,vam->ip_addr_lst){
        addr = (lisp_addr_t *)glist_entry_data(addr_it);
        lisp_addr_set_lafi(addr,LM_AFI_IP);
        if (ip_addr_is_link_local(lisp_addr_ip(addr)) == TRUE) {
            OOR_LOG(LDBG_2, "vpp_get_iface_addr: interface address from "
                    "%s discarded (%s)", iface_name, lisp_addr_to_char(addr));
        }else {
            return(lisp_addr_clone(addr));
        }
    }

    OOR_LOG(LDBG_2, "vpp_get_iface_addr: No %s RLOC configured for interface "
                       "%s\n", (afi == AF_INET) ? "IPv4" : "IPv6", iface_name);
    addr = lisp_addr_new_lafi(LM_AFI_NO_ADDR);

    return(addr);
}

uint8_t
vpp_get_iface_status(char *iface_name)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_sw_interface_dump_t *mp;
    vpp_api_iface_t *iface_info;

    glist_remove_all(vam->iface_list);
    /* Get list of ethernets */
    MSG (SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, iface_name, sizeof (mp->name_filter) - 1);
    VPP_SEND;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t *mp;
        MSG (CONTROL_PING, control_ping);
        VPP_SEND;
    }

    vpp_wait(vam);
    if (glist_size(vam->iface_list) == 0){
        OOR_LOG(LDBG_1,"vpp_get_iface_index: Unknown interface %s",iface_name);
        return (ERR_NO_EXIST);
    }
    iface_info = (vpp_api_iface_t *)glist_first_data(vam->iface_list);

    return (iface_info->status);
}

int
vpp_get_iface_index(char *iface_name)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_sw_interface_dump_t *mp;
    vpp_api_iface_t *iface_info;

    glist_remove_all(vam->iface_list);
    /* Get list of ethernets */
    MSG (SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, iface_name, sizeof (mp->name_filter) - 1);
    VPP_SEND;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t *mp;
        MSG (CONTROL_PING, control_ping);
        VPP_SEND;
    }

    vpp_wait(vam);
    if (glist_size(vam->iface_list) == 0){
        OOR_LOG(LDBG_1,"vpp_get_iface_index: Unknown interface %s",iface_name);
        return (0);
    }
    iface_info = (vpp_api_iface_t *)glist_first_data(vam->iface_list);

    return (iface_info->iface_index);
}

void
vpp_get_iface_mac_addr(char *iface_name, uint8_t *mac)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_sw_interface_dump_t *mp;
    vpp_api_iface_t *iface_info;

    glist_remove_all(vam->iface_list);
    /* Get list of ethernets */
    MSG (SW_INTERFACE_DUMP, sw_interface_dump);
    mp->name_filter_valid = 1;
    strncpy ((char *) mp->name_filter, iface_name, sizeof (mp->name_filter) - 1);
    VPP_SEND;

    /* Use a control ping for synchronization */
    {
        vl_api_control_ping_t *mp;
        MSG (CONTROL_PING, control_ping);
        VPP_SEND;
    }

    vpp_wait(vam);
    if (glist_size(vam->iface_list) == 0){
        OOR_LOG(LDBG_1,"vpp_get_iface_index: Unknown interface %s",iface_name);
        return;
    }
    iface_info = (vpp_api_iface_t *)glist_first_data(vam->iface_list);
    memcpy(mac, iface_info->l2_address, 6*sizeof(uint8_t));

    return;
}

char *
vpp_get_iface_name_associated_with_prefix(lisp_addr_t * pref)
{
    shash_t *addr_to_iface;
    glist_t *iface_addr_lst;
    glist_entry_t *addr_it;
    lisp_addr_t *iface_addr = lisp_addr_new();
    lisp_addr_t *ip_pref_addr = lisp_addr_get_ip_pref_addr(pref);
    char * iface_name = NULL;


    //XXX This process is not optim. VPP API not offer to obtain interface from IP
    addr_to_iface = vpp_build_addr_to_if_name_hasht();
    iface_addr_lst = shash_keys(addr_to_iface);
    glist_for_each_entry(addr_it,iface_addr_lst){
        lisp_addr_ip_from_char((char *)glist_entry_data(addr_it), iface_addr);
        if (pref_is_addr_part_of_prefix(iface_addr,ip_pref_addr) == TRUE){
            iface_name = strdup(shash_lookup(addr_to_iface, lisp_addr_to_char(iface_addr)));
            goto end;
        }
    }
    OOR_LOG(LERR,"VPP: Not found interface associated with prefix %s",lisp_addr_to_char(pref));

end:
   glist_destroy(iface_addr_lst);
   shash_destroy(addr_to_iface);
   lisp_addr_del(iface_addr);
   return (iface_name);
}


/*
 * Request to the kernel the routing table with the selected afi
 */
int
vpp_reload_routes(uint32_t table, int afi)
{

    return (GOOD);
}

shash_t *
vpp_build_addr_to_if_name_hasht()
{
    shash_t *ht;
    glist_t *iface_name_list;
    glist_entry_t *iface_name_it;
    char *iface_name;
    lisp_addr_t *addr;
    OOR_LOG(LDBG_2, "Building address to interface hash table");

    iface_name_list = vpp_get_ifaces_names();
    if (!iface_name_list){
        return (NULL);
    }

    ht = shash_new_managed((free_value_fn_t)free);

    glist_for_each_entry(iface_name_it,iface_name_list){
        iface_name = (char *)glist_entry_data(iface_name_it);
        addr = vpp_get_iface_addr(iface_name, AF_INET);
        if (!lisp_addr_is_no_addr(addr)){
            shash_insert(ht, strdup(lisp_addr_to_char(addr)), strdup(iface_name));
            OOR_LOG(LDBG_2, "Found interface %s with address %s", iface_name,
                    lisp_addr_to_char(addr));
        }
        lisp_addr_del (addr);


        addr = vpp_get_iface_addr(iface_name, AF_INET6);
        if (!lisp_addr_is_no_addr(addr)){
            shash_insert(ht, strdup(lisp_addr_to_char(addr)), strdup(iface_name));
            OOR_LOG(LDBG_2, "Found interface %s with address %s", iface_name,
                    lisp_addr_to_char(addr));
        }
        lisp_addr_del (addr);

    }

    return (ht);
}

inline static netm_vpp_data_t *
netm_vpp_data_new()
{
    return (xzalloc(sizeof(netm_vpp_data_t)));
}

inline static void
netm_vpp_data_free(netm_vpp_data_t * vpp_data)
{
    free(vpp_data);
}


