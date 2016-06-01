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

#include <unistd.h>
#include <linux/rtnetlink.h>

#include "oor_control.h"
#include "oor_ctrl_device.h"
#include "../data-plane/data-plane.h"
#include "../lib/oor_log.h"
#include "../lib/routing_tables_lib.h"
#include "../lib/mem_util.h"



static void set_rlocs(oor_ctrl_t *ctrl);

static void
set_rlocs(oor_ctrl_t *ctrl)
{
    iface_t *iface;
    glist_entry_t *iface_it;

    glist_remove_all(ctrl->rlocs);
    glist_remove_all(ctrl->ipv4_rlocs);
    glist_remove_all(ctrl->ipv6_rlocs);
    ctrl->supported_afis = NO_AFI_SUPPOT;

    glist_for_each_entry(iface_it,interface_list){
        iface = (iface_t *)glist_entry_data(iface_it);
        if (iface->ipv4_address && !lisp_addr_is_no_addr(iface->ipv4_address)) {
            glist_add_tail(iface->ipv4_address, ctrl->ipv4_rlocs);
            glist_add_tail(iface->ipv4_address, ctrl->rlocs);
        }
        if (iface->ipv6_address && !lisp_addr_is_no_addr(iface->ipv6_address)) {
            glist_add_tail(iface->ipv6_address, ctrl->ipv6_rlocs);
            glist_add_tail(iface->ipv6_address, ctrl->rlocs);
        }
    }

    if (glist_size(ctrl->ipv4_rlocs) > 0){
    	ctrl->supported_afis = ctrl->supported_afis | IPv4_SUPPORT;
    }
    if (glist_size(ctrl->ipv6_rlocs) > 0){
    	ctrl->supported_afis = ctrl->supported_afis | IPv6_SUPPORT;
    }
}

oor_ctrl_t *
ctrl_create()
{
    oor_ctrl_t *ctrl = xzalloc(sizeof(oor_ctrl_t));
    if (ctrl == NULL){
        return (NULL);
    }
    ctrl->devices = glist_new_managed((glist_del_fct)ctrl_dev_destroy);
    ctrl->rlocs = glist_new();
    ctrl->ipv4_rlocs = glist_new();
    ctrl->ipv6_rlocs = glist_new();
    ctrl->control_data_plane = control_dp_select();

    OOR_LOG(LINF, "Control created!");

    return (ctrl);
}

void
ctrl_destroy(oor_ctrl_t *ctrl)
{
    if (ctrl == NULL){
        return;
    }
    glist_destroy(ctrl->devices);
    glist_destroy(ctrl->rlocs);
    glist_destroy(ctrl->ipv4_rlocs);
    glist_destroy(ctrl->ipv6_rlocs);
    if (ctrl->control_data_plane != NULL){
        ctrl->control_data_plane->control_dp_uninit(ctrl);
    }

    free(ctrl);
    OOR_LOG(LDBG_1,"Lisp controler destroyed");
}

void
ctrl_init(oor_ctrl_t *ctrl)
{
    ctrl->control_data_plane->control_dp_init(ctrl,smaster);
    set_rlocs(ctrl);

    OOR_LOG(LDBG_1, "Control initialized");
}

void
ctrl_update_iface_info(oor_ctrl_t *ctrl)
{
    glist_entry_t *     iface_it    = NULL;
    iface_t *           iface       = NULL;
    uint8_t             new_ifaces  = FALSE;

    glist_for_each_entry(iface_it,interface_list){
        iface = (iface_t *)glist_entry_data(iface_it);
        if (iface->ipv4_address && !lisp_addr_is_no_addr(iface->ipv4_address)){
            if (glist_contain_using_cmp_fct(iface->ipv4_address, ctrl->ipv4_rlocs, (glist_cmp_fct)lisp_addr_cmp) == FALSE){
                new_ifaces = TRUE;
                break;
            }
        }
        if (iface->ipv6_address && !lisp_addr_is_no_addr(iface->ipv6_address)){
            if (glist_contain_using_cmp_fct(iface->ipv6_address, ctrl->ipv6_rlocs, (glist_cmp_fct)lisp_addr_cmp) == FALSE){
                new_ifaces = TRUE;
                break;
            }
        }
    }
    if (new_ifaces == TRUE){
        set_rlocs(ctrl);
        request_route_table(RT_TABLE_MAIN,AF_INET);
        request_route_table(RT_TABLE_MAIN,AF_INET6);
    }
}

void
ctrl_if_addr_update(oor_ctrl_t *ctrl,iface_t *iface, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr)
{
    oor_ctrl_dev_t *dev;

    dev = glist_first_data(ctrl->devices);

    ctrl->control_data_plane->control_dp_updated_addr(ctrl, iface, old_addr, new_addr);

    /* TODO: should store and pass updated rloc in the future
     * The old, and current solution is to keep a mapping between mapping_t
     * and iface to identify mapping_t(s) for which SMRs have to be sent. In
     * the future this should be decoupled and only the affected RLOC should
     * be passed to ctrl_dev */
    ctrl_dev_if_addr_update(dev, iface->iface_name, old_addr,new_addr, iface_status(iface));
    set_rlocs(ctrl);
}

void
ctrl_if_link_update(oor_ctrl_t *ctrl, iface_t *iface, int old_iface_index,
        int new_iface_index, int status)
{
    oor_ctrl_dev_t *dev;

    dev = glist_first_data(ctrl->devices);

    ctrl->control_data_plane->control_dp_update_link(ctrl, iface, old_iface_index, new_iface_index, status);
    ctrl_dev_if_link_update(dev, iface->iface_name, iface_status(iface));
    set_rlocs(ctrl);
}


void
ctrl_route_update(oor_ctrl_t *ctrl, int command, iface_t *iface,lisp_addr_t *src,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    oor_ctrl_dev_t *dev;

    dev = glist_first_data(ctrl->devices);
    ctrl->control_data_plane->control_dp_updated_route(ctrl, command, iface, src, dst_pref, gateway);
    ctrl_dev_route_update(dev, command, iface->iface_name, src, dst_pref, gateway);
    set_rlocs(ctrl);
}

lisp_addr_t *
ctrl_default_rloc(oor_ctrl_t *ctrl, int afi)
{
    return (ctrl->control_data_plane->control_dp_get_default_addr(ctrl,afi));
}
/*
 * Return the default control rlocs in a list that shoud be released
 * by the user.
 * @param ctrl Lisp controler to be used
 * @return glist_t * with the lisp_addr_t * of the default rlocs
 */
glist_t *
ctrl_default_rlocs(oor_ctrl_t * ctrl)
{
    lisp_addr_t *addr;

    glist_t *   dflt_rlocs  = glist_new();
    if (dflt_rlocs == NULL){
        return (NULL);
    }

    addr = ctrl->control_data_plane->control_dp_get_default_addr(ctrl,AF_INET);
    if (addr != NULL){
        glist_add(addr, dflt_rlocs);
    }

    addr = ctrl->control_data_plane->control_dp_get_default_addr(ctrl,AF_INET6);
    if (addr != NULL){
        glist_add(addr, dflt_rlocs);
    }
    return (dflt_rlocs);
}

glist_t *
ctrl_rlocs(oor_ctrl_t *ctrl){
	return (ctrl->rlocs);
}

glist_t *
ctrl_rlocs_with_afi(oor_ctrl_t *c, int afi)
{
    switch(afi) {
    case AF_INET:
        return(c->ipv4_rlocs);
    case AF_INET6:
        return(c->ipv6_rlocs);
    }
    return(NULL);
}

inline int
ctrl_supported_afis(oor_ctrl_t *ctrl)
{
	return (ctrl->supported_afis);
}

fwd_info_t *
ctrl_get_forwarding_info(packet_tuple_t *tuple)
{
    oor_ctrl_dev_t *dev;
    dev = glist_first_data(lctrl->devices);
    return (ctrl_dev_get_fwd_entry(dev, tuple));
}

int
ctrl_register_device(oor_ctrl_t *ctrl, oor_ctrl_dev_t *dev)
{
    char *device;
    device = ctrl_dev_type_to_char(dev->mode);
    OOR_LOG(LINF, "Device working in mode %s registering with control",
            device);
    glist_add(dev, ctrl->devices);
    return(GOOD);
}

int
ctrl_register_eid_prefix(oor_ctrl_dev_t *dev, lisp_addr_t *eid_prefix)
{
    oor_dev_type_e dev_type = dev->mode;
    if (dev_type == xTR_MODE || dev_type == MN_MODE || dev_type == RTR_MODE){
        data_plane->datap_add_eid_prefix(dev_type,eid_prefix);
    }else{
        OOR_LOG(LDBG_1, "Current version only supports the registration in control of "
                        "EID prefixes from xTRs and MNs");
    }

    return (GOOD);
}

int
ctrl_unregister_eid_prefix(oor_ctrl_dev_t *dev, lisp_addr_t *eid_prefix)
{
    oor_dev_type_e dev_type = dev->mode;

    if (dev_type == xTR_MODE || dev_type == MN_MODE || dev_type == RTR_MODE){
        data_plane->datap_remove_eid_prefix(dev_type,eid_prefix);
    }else{
        OOR_LOG(LDBG_1, "Current version only supports the unregistration in control of "
                "EID prefixes from xTRs");
    }

    return (GOOD);
}


/*
 * Multicast Interface to end-hosts
 */

void
multicast_join_channel(lisp_addr_t *src, lisp_addr_t *grp)
{
    lisp_addr_t *mceid = lisp_addr_build_mc(src, grp);
    /* re_join_channel(mceid); */
    lisp_addr_del(mceid);
}

void
multicast_leave_channel(lisp_addr_t *src, lisp_addr_t *grp)
{
    lisp_addr_t *mceid = lisp_addr_build_mc(src, grp);
    /* re_leave_channel(mceid); */
    lisp_addr_del(mceid);
}

