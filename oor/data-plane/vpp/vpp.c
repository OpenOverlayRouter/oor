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

#include "vpp.h"
#include "../data-plane.h"
#include "../../lib/interfaces_lib.h"
#include "../../lib/oor_log.h"
#include "../../lib/sockets.h"
#include "../../net_mgr/net_mgr.h"
#include "../../oor_external.h"
#include "../../control/oor_control.h"
#include "../../fwd_policies/fwd_policy.h"
#include "../../fwd_policies/vpp_balancing/fwd_entry_vpp.h"

#include <vpp/api/vpe_msg_enum.h>
#include "../../lib/vpp_api/vpp_api_requests.h"

#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun        /* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun


#include <errno.h>
#include  <fcntl.h>

static uint8_t pkt_recv_buf[TAP_VPP_BUFFER_SIZE];
static lbuf_t pkt_buf;

int vpp_init_data_plane(oor_ctrl_dev_t *ctrl_dev, oor_encap_t encap_type, ...);
void vpp_uninit_data_plane (oor_ctrl_t *ctrl);
int vpp_add_datap_iface_addr(iface_t *iface, int afi);
int vpp_add_datap_iface_gw(iface_t *iface, int afi);
int vpp_register_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map);
int vpp_deregister_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map);
int vpp_process_input_packet(sock_t *sl);
int vpp_rtr_process_input_packet(sock_t *sl);
int vpp_output_recv(sock_t *sl);
void vpp_remove_native_route(fwd_info_t *fi);
void vpp_remove_drop_route(fwd_info_t *fi);
void vpp_fwd_info_del(fwd_info_t *fi);
int vpp_updated_route(int command, iface_t *iface, lisp_addr_t *src_pref,
       lisp_addr_t *dst_pref, lisp_addr_t *gw);
int vpp_updated_addr(iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr);
int vpp_updated_link(iface_t *iface, int old_iface_index, int new_iface_index, int status);
int vpp_rm_fwd_from_entry(lisp_addr_t *eid_prefix, uint8_t local);
vpp_dplane_data_t * vpp_dplane_data_new();
int vpp_reset_all_fwd();

typedef void (*remove_fwd_entry_fn)(fwd_info_t *);

data_plane_struct_t dplane_vpp = {
        .datap_init = vpp_init_data_plane,
        .datap_uninit = vpp_uninit_data_plane,
        .datap_add_iface_addr = vpp_add_datap_iface_addr,
        .datap_add_iface_gw = vpp_add_datap_iface_gw,
        .datap_register_lcl_mapping = vpp_register_lcl_mapping,
        .datap_deregister_lcl_mapping = vpp_deregister_lcl_mapping,
        .datap_input_packet = vpp_process_input_packet,
        .datap_rtr_input_packet = vpp_rtr_process_input_packet,
        .datap_output_packet = vpp_output_recv,
        .datap_updated_route = vpp_updated_route,
        .datap_updated_addr = vpp_updated_addr,
        .datap_update_link = vpp_updated_link,
        .datap_rm_fwd_from_entry = vpp_rm_fwd_from_entry,
        .datap_reset_all_fwd = vpp_reset_all_fwd,
        .datap_data = NULL
};

int
vpp_init_data_plane(oor_ctrl_dev_t *ctrl_dev, oor_encap_t encap_type, ...)
{
    int vpp_data_fd = -1;

    if (encap_type == ENCP_VXLAN_GPE){
        OOR_LOG(LERR, "OOR with VPP data plane doesn't support VXLAN encapsulation yet");
    }

    /* Configure data plane */
    if ((vpp_data_fd = create_tun_tap(TAP,TAP_VPP_MISS_IFACE_NAME, TAP_MTU_VPP)) == BAD){
        return (BAD);
    }
    /* Enable oor pkt miss node in VPP */
    if (vpp_oor_pkt_miss_enable_disable(TAP_VPP_MISS_IFACE_NAME, TRUE)!=GOOD){
        OOR_LOG(LERR,"VPP: Could not initiate oor packet miss plugin. Check /var/log/syslog for more details");
        return (BAD);
    }
    OOR_LOG(LDBG_2,"VPP: Enabled oor packet miss plugin.");

    sockmstr_register_read_listener(smaster, vpp_output_recv, ctrl_dev, vpp_data_fd);

    dplane_vpp.datap_data = vpp_dplane_data_new();

    return (GOOD);
}

void
vpp_uninit_data_plane (oor_ctrl_t *ctrl)
{
    vpp_dplane_data_t *data = (vpp_dplane_data_t *)dplane_vpp.datap_data;

    if (data){
        shash_destroy(data->eid_to_dp_entries);
        shash_destroy(data->iid_lst);
        free(data);
        /* Enable oor pkt miss node in VPP */
        vpp_oor_pkt_miss_enable_disable(TAP_VPP_MISS_IFACE_NAME, FALSE);
    }

}

int
vpp_add_datap_iface_addr(iface_t *iface, int afi)
{
    return (GOOD);
}

int
vpp_add_datap_iface_gw(iface_t *iface, int afi)
{
    return (GOOD);
}

int
vpp_register_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map)
{
    lisp_addr_t *eid_addr = mapping_eid(map);
    lisp_addr_t *eid_pref;
    int table_id = 0,vni = 0;
    char vni_str[9];
    vpp_dplane_data_t *data = (vpp_dplane_data_t *)dplane_vpp.datap_data;
    glist_t *iid_eids_lst;
    char * iface_name;
    int iface_index;


    /* XXX The user should add the EID interface to the vni table before
     * starting OOR (before assigning IPs to the interface):
     * # vppctl set interface ip table <iface_name> <vni>
     */
    if (lisp_addr_is_iid(eid_addr)){
        eid_pref = lisp_addr_get_ip_pref_addr(eid_addr);
        vni = lcaf_iid_get_iid(lisp_addr_get_lcaf(eid_addr));
        /* Check if the interface is associated with the table of the VNI */
        iface_name = net_mgr->netm_get_iface_associated_with_pref(eid_addr);
        if (!iface_name){
            return (BAD);
        }
        iface_index = net_mgr->netm_get_iface_index(iface_name);
        table_id = vpp_interface_get_table(iface_index,
                lisp_addr_ip_afi(eid_pref) == AF_INET ? 0 : 1);

        if (table_id != vni){
            OOR_LOG(LERR,"VPP: Interface should be associated to the table of VNI. " \
                    "This process should be done before configuring addresses of the interface");
            return (BAD);
        }
    }

    sprintf(vni_str, "%d",vni);
    /* Check if we already have configured this iid */
    iid_eids_lst = shash_lookup(data->iid_lst,vni_str);
    if (!iid_eids_lst){
        iid_eids_lst = glist_new();
        glist_add(eid_addr,iid_eids_lst);
        shash_insert(data->iid_lst,strdup(vni_str),iid_eids_lst);
        /* Configure IID in data plane */
        vpp_lisp_gpe_add_del_iface(table_id, vni, ADD);
        if (vni != 0){
            vpp_lisp_eid_table_add_del_map (table_id, vni, ADD);
        }
    }else{
        glist_add(eid_addr,iid_eids_lst);
        return (GOOD);
    }


    return (GOOD);
}

int
vpp_deregister_lcl_mapping(oor_dev_type_e dev_type, mapping_t *map)
{
    lisp_addr_t *eid_addr = mapping_eid(map);
    int table_id = 0,vni = 0;
    char vni_str[9];
    vpp_dplane_data_t *data = (vpp_dplane_data_t *)dplane_vpp.datap_data;
    glist_t *iid_eids_lst;

    if (!data){
        return (GOOD);
    }

    vpp_reset_all_fwd();

    if (lisp_addr_is_iid(eid_addr)){
        vni = lcaf_iid_get_iid(lisp_addr_get_lcaf(eid_addr));
        table_id = vni;
    }
    sprintf(vni_str, "%d",vni);

    /* Check if we have to unregistered this iid from the dataplane */
    iid_eids_lst = shash_lookup(data->iid_lst,vni_str);
    if (!iid_eids_lst){
        OOR_LOG(LDBG_1,"vpp_deregister_lcl_mapping: It should never happen");
        return (BAD);
    }
    if(glist_size(iid_eids_lst) > 1){
        /* We don't remove IID from data plane. There are other eids using it */
        glist_remove_obj(eid_addr, iid_eids_lst);
        return(GOOD);
    }
    shash_remove(data->iid_lst, vni_str);
    if (vni != 0){
        vpp_lisp_eid_table_add_del_map (table_id, vni, RM);
    }
    vpp_lisp_gpe_add_del_iface(table_id, vni, RM);

    return (GOOD);
}

int
vpp_process_input_packet(sock_t *sl)
{
    return (GOOD);
}

int
vpp_rtr_process_input_packet(sock_t *sl)
{
    return (GOOD);
}

int
associate_fwd_info_with_eid(fwd_info_t *fi, vpp_dplane_data_t *dp_data, remove_fwd_entry_fn rm_fwd_entry_fn)
{
    glist_t *fwd_info_list;

    fwd_info_list = (glist_t *)shash_lookup(dp_data->eid_to_dp_entries,lisp_addr_to_char(fi->associated_entry));
    if (!fwd_info_list){
        fwd_info_list = glist_new_managed((glist_del_fct)rm_fwd_entry_fn);
        shash_insert(dp_data->eid_to_dp_entries, strdup(lisp_addr_to_char(fi->associated_entry)), fwd_info_list);
    }
    glist_add(fi,fwd_info_list);

    return (GOOD);
}

int
associate_fwd_info_with_petrs(fwd_info_t *fi, vpp_dplane_data_t *dp_data)
{
    glist_t *pxtr_fwd_info_list;

    switch (lisp_addr_ip_afi(fi->associated_entry)){
    case AF_INET:
        pxtr_fwd_info_list = (glist_t *)shash_lookup(dp_data->eid_to_dp_entries,FULL_IPv4_ADDRESS_SPACE);
        break;
    case AF_INET6:
        pxtr_fwd_info_list = (glist_t *)shash_lookup(dp_data->eid_to_dp_entries,FULL_IPv6_ADDRESS_SPACE);
        break;
    default:
        OOR_LOG(LDBG_3, "vpp_output_recv: Forwarding to PeTR is only for IP EIDs. It should never reach here");
        return (BAD);
    }
    glist_add(fi,pxtr_fwd_info_list);

    return (GOOD);
}

int
vpp_output_recv(sock_t *sl)
{
    packet_tuple_t tpl;
    fwd_info_t *fi;
    fwd_entry_vpp_t *fe;
    vpp_dplane_data_t *dp_data = (vpp_dplane_data_t *)dplane_vpp.datap_data;
    lbuf_t buff;
    uint8_t mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, TAP_VPP_BUFFER_SIZE);
    lbuf_reserve(&pkt_buf, LBUF_STACK_OFFSET);

    if (sock_recv(sl->fd, &pkt_buf) != GOOD) {
        OOR_LOG(LWRN, "OUTPUT: Error while reading from tun!");
        return (BAD);
    }
    buff = pkt_buf;
    lbuf_reset_ip(&pkt_buf);
    if (pkt_parse_5_tuple(&pkt_buf, &tpl) != GOOD) {
        return (BAD);
    }
    /* XXX The correct IID is updated in ctrl_get_forwarding_info */
    tpl.iid = 0;

    OOR_LOG(LDBG_3, "OUTPUT: Received packet miss from data plane for %s", pkt_tuple_to_char(&tpl));

    fi = (fwd_info_t *)ctrl_get_forwarding_info(&tpl);
    if (!fi){
        return (BAD);
    }

    if (!(fi->dp_conf_inf)){
        if (fi->neg_map_reply_act == ACT_NATIVE_FWD){
            /* Configure the native route through the gateway */
            vpp_oor_pkt_miss_native_route(fi->associated_entry,ADD);
            /* Associate eid with fwd_info */
            associate_fwd_info_with_eid(fi, dp_data, (remove_fwd_entry_fn) vpp_remove_native_route);
            goto resend;
        }
        return (BAD);
    }

    fe = (fwd_entry_vpp_t *)(fi->dp_conf_inf);

    /* Associate eid with fwd_info */
    switch(fi->neg_map_reply_act){
    case ACT_NATIVE_FWD:
        /* Associate eid with petrs */
        associate_fwd_info_with_petrs(fi,dp_data);
        break;
    case ACT_NO_ACTION:
        if (glist_size(fe->loc_pair_lst) == 0){
            /* Negative mappings with no PeTRs available */
            /* Configure a route to drop the packets to this destination prefix */
            vpp_oor_pkt_miss_drop_route(fi->associated_entry,ADD,tpl.iid);
            /* Associate eid with fwd_info and petrs */
            associate_fwd_info_with_eid(fi, dp_data, (remove_fwd_entry_fn) vpp_remove_drop_route);
            associate_fwd_info_with_petrs(fi,dp_data);
            goto resend;
        }
        break;
    case ACT_DROP:
        /* Configure a route to drop the packets to this destination prefix */
        vpp_oor_pkt_miss_drop_route(fi->associated_entry,ADD,tpl.iid);
        /* Associate eid with fwd_info */
        associate_fwd_info_with_eid(fi, dp_data, (remove_fwd_entry_fn) vpp_remove_drop_route);
        goto resend;
    default:
        OOR_LOG(LDBG_1,"vpp_output_recv: Unknown action");
        return (BAD);
    }
    associate_fwd_info_with_eid(fi, dp_data, (remove_fwd_entry_fn) vpp_fwd_info_del);

    /* Configure vpp data plane*/
    vpp_lisp_gpe_add_del_fwd_entry(fe,fi->neg_map_reply_act,ADD);


resend:
    /* Reinsert the packet to VPP in order to reduce the number of packets lost */
    pkt_push_eth(&buff, mac, mac, ETH_P_IP);
    if (write(sl->fd, lbuf_data(&buff), lbuf_size(&buff)) < 0 ){
        OOR_LOG(LDBG_2, "write error: %s\n ", strerror(errno));
        return(BAD);
    }
    return (GOOD);
}

void
vpp_remove_native_route(fwd_info_t *fi)
{
    vpp_oor_pkt_miss_native_route(fi->associated_entry,RM);
    fwd_info_del(fi);
}

void
vpp_remove_drop_route(fwd_info_t *fi)
{
    uint32_t table_id = 0;
    if (lisp_addr_is_iid(fi->associated_entry)){
        table_id = lcaf_iid_get_iid(lisp_addr_get_lcaf(fi->associated_entry));
    }
    vpp_oor_pkt_miss_drop_route(fi->associated_entry,RM,table_id);
    fwd_info_del(fi);
}

void vpp_fwd_info_del(fwd_info_t *fi)
{
    vpp_lisp_gpe_add_del_fwd_entry((fwd_entry_vpp_t *)(fi->dp_conf_inf),fi->neg_map_reply_act,RM);
    fwd_info_del(fi);
}

int
vpp_updated_route(int command, iface_t *iface, lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gw)
{
    return (GOOD);
}

int
vpp_updated_addr(iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr)
{
    return (GOOD);
}


int
vpp_updated_link(iface_t *iface, int old_iface_index, int new_iface_index, int status)
{
    return (GOOD);
}

int
vpp_rm_fwd_from_entry(lisp_addr_t *eid_prefix, uint8_t local)
{
    char * eid_prefix_char = lisp_addr_to_char(eid_prefix);
    glist_t *fwd_info_list, *pxtr_fwd_info_list;
    glist_entry_t *fi_it;
    fwd_entry_vpp_t *fe;
    fwd_info_t *fi;
    vpp_dplane_data_t *data = (vpp_dplane_data_t *)dplane_vpp.datap_data;

    if (local){
        vpp_reset_all_fwd();
        return (GOOD);
    }

    if (strcmp(eid_prefix_char,FULL_IPv4_ADDRESS_SPACE) == 0){ // Update of the PeTR list for IPv4 EIDs or RTR list
        pxtr_fwd_info_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv4_ADDRESS_SPACE);
        // Remove all the entries associated with the PxTR
        while (glist_size(pxtr_fwd_info_list) > 0){
            fi = (fwd_info_t *)glist_first_data(pxtr_fwd_info_list);
            // When we recurively call this function using the associated_entry we will execute "else" statement where we also
            // update the list of entries associated with PxTR.
            vpp_rm_fwd_from_entry(fi->associated_entry,local);
        }
    }else if (strcmp(eid_prefix_char,FULL_IPv6_ADDRESS_SPACE) == 0){ // Update of the PeTR list for IPv6 EIDs or RTR list
        pxtr_fwd_info_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv6_ADDRESS_SPACE);
        // Remove all the entries associated with the PxTR
        while (glist_size(pxtr_fwd_info_list) > 0){
            fi = (fwd_info_t *)glist_first_data(pxtr_fwd_info_list);
            // When we recursively call this function using the associated_entry we will execute "else" statement where we also
            // update the list of entries associated with PxTR.
            vpp_rm_fwd_from_entry(fi->associated_entry,local);
        }
    }else{
        fwd_info_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,eid_prefix_char);
        if (!fwd_info_list){
            OOR_LOG(LDBG_2, "vpp_rm_fwd_from_entry: Entry %s not found in the shasht!",eid_prefix_char);
            return (BAD);
        }
        /* Check if it is a negative entry in order to remove also from PxTRs list */
        fi = (fwd_info_t *)glist_first_data(fwd_info_list);
        fe = (fwd_entry_vpp_t *)(fi->dp_conf_inf);
        if (fi->dp_conf_inf &&
                (fi->neg_map_reply_act == ACT_NATIVE_FWD || //Negative mapping with PeTRs
                (fi->neg_map_reply_act == ACT_NO_ACTION && glist_size(fe->loc_pair_lst) == 0))){ // negative mapping without PeTRs
            switch (lisp_addr_ip_afi(fi->associated_entry)){
            case AF_INET:
                pxtr_fwd_info_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv4_ADDRESS_SPACE);
                break;
            case AF_INET6:
                pxtr_fwd_info_list = (glist_t *)shash_lookup(data->eid_to_dp_entries,FULL_IPv6_ADDRESS_SPACE);
                break;
            default:
                OOR_LOG(LDBG_1, "vpp_rm_fwd_from_entry: Associated entry is not IP");
                return (BAD);
            }
            /* Remove each fwd_info associated to the eid_prefix from the PeTR list */
            glist_for_each_entry(fi_it,fwd_info_list){
                fi = (fwd_info_t *)glist_entry_data(fi_it);
                glist_remove_obj(fi,pxtr_fwd_info_list);
            }
        }

        /* Remove associated entry from eid_to_dp_entries -> This will remove the list of fwd_info_list
         * associated with the eid_prefix. The list is a managed list initialized with a remove function */
        shash_remove(data->eid_to_dp_entries, eid_prefix_char);
    }

    return (GOOD);
}

/* Remove all the fwd programmed in the data plane
 * Used when a change is produced in the local mappings */

int
vpp_reset_all_fwd()
{
    vpp_dplane_data_t *data = (vpp_dplane_data_t *)dplane_vpp.datap_data;
    shash_destroy(data->eid_to_dp_entries);
    data->eid_to_dp_entries = shash_new_managed((free_value_fn_t)glist_destroy);
    /* Insert entry for PeTRs */
    shash_insert(data->eid_to_dp_entries, strdup(FULL_IPv4_ADDRESS_SPACE), glist_new());
    shash_insert(data->eid_to_dp_entries, strdup(FULL_IPv6_ADDRESS_SPACE), glist_new());
    return (GOOD);
}

vpp_dplane_data_t *
vpp_dplane_data_new()
{
    vpp_dplane_data_t * data;
    data = xmalloc(sizeof(vpp_dplane_data_t));
    data->eid_to_dp_entries = shash_new_managed((free_value_fn_t)glist_destroy);
    /* Insert entry for PeTRs */
    shash_insert(data->eid_to_dp_entries, strdup(FULL_IPv4_ADDRESS_SPACE), glist_new());
    shash_insert(data->eid_to_dp_entries, strdup(FULL_IPv6_ADDRESS_SPACE), glist_new());
    data->iid_lst = shash_new_managed((free_value_fn_t)glist_destroy);
    return (data);
}
