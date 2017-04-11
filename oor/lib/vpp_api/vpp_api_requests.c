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

#include "vpp_api_requests.h"

#include "../generic_list.h"
#include "../oor_log.h"
#include "../../defs.h"


#include <vpp-api/vpe_msg_enum.h>

#define vl_typedefs
#include <vpp-api/vpe_all_api_h.h>
#undef vl_typedefs


#define vl_endianfun        /* define message structures */
#include <vpp-api/vpe_all_api_h.h>
#undef vl_endianfun



void
vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...)
{
    clib_warning ("BUG");
}



int
vpp_wait(vpp_api_main_t * vam)
{
    f64 timeout;

    timeout = clib_time_now (&vam->clib_time) + 1.0;
    while (clib_time_now (&vam->clib_time) < timeout) {
        if (vam->result_ready == 1) {
            return (vam->retval);
        }
    }
    return(ERR_NO_REPLY);
}

int
vpp_create_ap_iface(char *iface_name, uint8_t *mac)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_af_packet_create_t *mp;

    MSG (AF_PACKET_CREATE, af_packet_create);
    memcpy (mp->host_if_name, iface_name, strlen(iface_name));
    memcpy (mp->hw_addr,mac,6);
    mp->use_random_hw_addr = 1;
    VPP_SEND;
    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not create interface HOST-%s associated with interface %s"
                , iface_name, iface_name);
        return (0);
    }

    return (vam->sw_if_index);
}

int
vpp_set_interface_status (uint32_t iface_index, uint8_t status)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_sw_interface_set_flags_t *mp;

    MSG (SW_INTERFACE_SET_FLAGS, sw_interface_set_flags);
    mp->sw_if_index = ntohl (iface_index);
    mp->admin_up_down = status;
    mp->link_up_down = status;
    VPP_SEND;
    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not set status for interface %d", iface_index);
        return (BAD);
    }
    return (GOOD);
}

int
vpp_set_interface_unnumbered (uint32_t iface_index, int action)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_sw_interface_set_unnumbered_t *mp;

    MSG (SW_INTERFACE_SET_UNNUMBERED, sw_interface_set_unnumbered);

    mp->sw_if_index = ntohl (iface_index);
    mp->unnumbered_sw_if_index = ntohl (iface_index);
    mp->is_add = action;

    VPP_SEND;
    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not set interface %d as unnumbered", iface_index);
        return (BAD);
    }
    return (GOOD);
}

int
vpp_lisp_gpe_enable_disable(uint8_t enable_lisp_gpe)
{
    /* OOR_CTRL plugin enables lisp */
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_lisp_gpe_enable_disable_t *mp;

    /* Construct the API message */
    MSG (LISP_GPE_ENABLE_DISABLE, lisp_gpe_enable_disable);
    mp->is_en = 1;

    /* send it... */
    VPP_SEND;
    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not %s lisp gpe", enable_lisp_gpe ? "enable" : "disable");
        return (BAD);
    }
    return (GOOD);
}

int
vpp_lisp_gpe_add_del_iface(uint32_t table, uint32_t vni, uint8_t action)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_lisp_gpe_add_del_iface_t *mp;
    /* Construct the API message */
    MSG (LISP_GPE_ADD_DEL_IFACE, lisp_gpe_add_del_iface);

    mp->is_add = action;
    mp->dp_table = table;
    mp->is_l2 = FALSE;
    mp->vni = vni;

    /* send it... */
    VPP_SEND;

    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not %s lisp gpe interface for vni %d",
                action == ADD ? "add" : "remove", vni);
        return (BAD);
    }
    OOR_LOG(LDBG_2,"VPP: LISP gpe interface associated with VNI %d has been %s",
            vni, action == ADD ? "added" : "removed");

    return (GOOD);
}

/**
 * Add/delete mapping between vni and vrf
 */
int
vpp_lisp_eid_table_add_del_map (uint32_t table, uint32_t vni, uint8_t action)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_lisp_eid_table_add_del_map_t *mp;

    MSG (LISP_EID_TABLE_ADD_DEL_MAP, lisp_eid_table_add_del_map);

    mp->is_add = action;
    mp->vni = htonl (vni);
    mp->dp_table = htonl (table);
    mp->is_l2 = FALSE;

    /* send */
    VPP_SEND;

    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not %s lisp gpe interface associated with VNI %d",
                action == ADD ? "map" : "unmap",vni);
        return (BAD);
    }
    OOR_LOG(LDBG_2,"VPP: LISP gpe interface associated with VNI %d has been %s",
            vni, action == ADD ? "mapped" : "unmapped");

    return (GOOD);
}

typedef struct rloc_{
    uint8_t is_ip4; /**< is locator an IPv4 address? */
    uint8_t weight;   /**< locator weight */
    uint8_t addr[16]; /**< IPv4/IPv6 address */
}__attribute__ ((__packed__)) rloc_t;

void
vpp_write_rloc(void *buff, lisp_addr_t *addr, uint8_t weight)
{
    rloc_t *vpp_rloc = buff;

    vpp_rloc->is_ip4 = lisp_addr_ip_afi(addr) == AF_INET ? 1 : 0;
    vpp_rloc->weight = weight;
    ip_addr_copy_to(vpp_rloc->addr, lisp_addr_ip(addr));
}


int
vpp_lisp_gpe_add_del_fwd_entry (fwd_entry_vpp_t *fe, lisp_action_e action, uint8_t is_add)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_lisp_gpe_add_del_fwd_entry_t *mp;
    lisp_addr_t *src_eid, *dst_eid;
    vpp_loct_pair * vpp_pair;
    glist_entry_t * pairs_it;
    int vni=0, ctr=0;

    src_eid = lisp_addr_get_ip_pref_addr(fe->seid);
    dst_eid = lisp_addr_get_ip_pref_addr(fe->deid);
    vni = fe->iid;

    /* Construct the API message */
    MSG_PLUS (LISP_GPE_ADD_DEL_FWD_ENTRY, lisp_gpe_add_del_fwd_entry,
            sizeof (rloc_t) * glist_size(fe->loc_pair_lst)*2);

    mp->is_add = is_add;
    ip_addr_copy_to(mp->lcl_eid, lisp_addr_ip(src_eid));
    ip_addr_copy_to(mp->rmt_eid, lisp_addr_ip(dst_eid));
    mp->eid_type = lisp_addr_ip_afi(dst_eid) == AF_INET ? 0 : 1;
    mp->lcl_len = lisp_addr_ip_get_plen(src_eid);
    mp->rmt_len = lisp_addr_ip_get_plen(dst_eid);
    mp->action = action;
    mp->vni = htonl(vni);
    mp->dp_table = htonl(vni);

    mp->loc_num = htonl(glist_size(fe->loc_pair_lst)*2);
    if (mp->loc_num != 0)
    {
        glist_for_each_entry(pairs_it,fe->loc_pair_lst){
            vpp_pair = (vpp_loct_pair *)glist_entry_data(pairs_it);
            vpp_write_rloc(CO(mp->locs,sizeof(rloc_t)*ctr), vpp_pair->srloc, 0);
            ctr++;
        }
        ctr = 0;
        glist_for_each_entry(pairs_it,fe->loc_pair_lst){
            vpp_pair = (vpp_loct_pair *)glist_entry_data(pairs_it);
            vpp_write_rloc(CO(mp->locs,sizeof(rloc_t)*(ctr + glist_size(fe->loc_pair_lst))), vpp_pair->drloc, vpp_pair->weight);
            ctr++;
        }
    }
    /* send */
    VPP_SEND;

    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not add forward entry");
        return (BAD);
    }

    return (GOOD);
}

int
vpp_interface_get_table(uint32_t iface_index, uint8_t is_ipv6)
{
    vpp_api_main_t * vam = vpp_api_main_get();
    vl_api_sw_interface_get_table_t *mp;

    MSG (SW_INTERFACE_GET_TABLE, sw_interface_get_table);
    mp->sw_if_index = htonl (iface_index);
    mp->is_ipv6 = is_ipv6;

    VPP_SEND;
    if (vpp_wait(vam) == ERR_NO_REPLY){
        OOR_LOG(LWRN,"VPP could not get table associated with interface %s");
        return (ERR_NO_EXIST);
    }

    return (vam->table_id);
}
