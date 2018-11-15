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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#ifndef __APPLE__
#include <linux/rtnetlink.h>
#endif

#include "oor_control.h"
#include "oor_ctrl_device.h"
#include "../data-plane/data-plane.h"
#include "../lib/oor_log.h"
#include "../lib/routing_tables_lib.h"
#include "../lib/mem_util.h"
#include "../net_mgr/net_mgr.h"

#define MAX_BUF_SIZE 2048

static void set_rlocs(oor_ctrl_t *ctrl);
int ctrl_recv_locl_msg(sock_t *sl);

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
    int pipefd[2];
    oor_ctrl_t *ctrl = xzalloc(sizeof(oor_ctrl_t));
    if (ctrl == NULL){
        return (NULL);
    }
    ctrl->devices = glist_new_managed((glist_del_fct)ctrl_dev_destroy);
    ctrl->rlocs = glist_new();
    ctrl->ipv4_rlocs = glist_new();
    ctrl->ipv6_rlocs = glist_new();
    ctrl->control_data_plane = control_dp_select();
    /* Create a pipe to notify new local ctrl_msg */
    if (pipe(pipefd) == -1) {
        OOR_LOG(LERR, "Error opening control notification pipe: %s (%d)", strerror(errno),errno);
        return (NULL);
    }
    sockmstr_register_read_listener(smaster, ctrl_recv_locl_msg, ctrl,pipefd[0]);
    ctrl->ctrl_notify_fd = pipefd[1];
    ctrl->recv_local_ctrl_msg_lst = glist_new_managed((glist_del_fct)ctrl_local_msg_del);

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
    close(ctrl->ctrl_notify_fd);
    glist_destroy(ctrl->recv_local_ctrl_msg_lst);
    free(ctrl);
    OOR_LOG(LDBG_1,"Lisp controller destroyed");
}

void
ctrl_run_devices(oor_ctrl_t *ctrl)
{
    glist_entry_t *dev_it;
    oor_ctrl_dev_t *dev;

    glist_for_each_entry(dev_it,ctrl->devices){
        dev = (oor_ctrl_dev_t *)glist_entry_data(dev_it);
        ctrl_dev_run(dev);
    }
}

ctrl_local_msg *
ctrl_local_msg_new_init(lbuf_t *buf, uconn_t uc, oor_ctrl_dev_t *dst_dev)
{
    ctrl_local_msg * ctrl_msg = xmalloc(sizeof(ctrl_local_msg));
    if (!ctrl_msg){
        return (NULL);
    }
    ctrl_msg->buf = lbuf_clone(buf);
    ctrl_msg->uc = uc;
    ctrl_msg->dst_dev = dst_dev;

    return (ctrl_msg);
}

void
ctrl_local_msg_del(ctrl_local_msg *ctrl_msg)
{
    lbuf_del(ctrl_msg->buf);
    free(ctrl_msg);
}

int
ctrl_init(oor_ctrl_t *ctrl)
{
    if (ctrl->control_data_plane->control_dp_init(ctrl,smaster)!= GOOD){
        OOR_LOG(LERR, "Could not initialize control plane");
        return (BAD);
    }

    set_rlocs(ctrl);
    OOR_LOG(LDBG_1, "Control initialized");

    return (GOOD);
}

int
ctrl_send_msg(oor_ctrl_dev_t *dev, lbuf_t *b, uconn_t *uc, oor_dev_type_e dst_dev_type)
{
    oor_ctrl_t *ctrl = dev->ctrl;
    oor_ctrl_dev_t *aux_dev;
    oor_dev_type_e type;
    glist_entry_t *dev_it;
    lisp_addr_t *src_addr;
    uconn_t rev_uc;
    ctrl_local_msg *ctrl_msg;

    if (glist_size(ctrl->devices) > 1 && dst_dev_type != NO_MODE ){
        /* Check if the destination address is local */
        // TODO Find a more optimal way to check if the destination of the packet
        // is the same host
        src_addr = net_mgr->netm_get_src_addr_to(&uc->ra);
        if (lisp_addr_cmp(src_addr, &uc->ra) == 0){
            lisp_addr_del(src_addr);
            glist_for_each_entry(dev_it, ctrl->devices){
                aux_dev = (oor_ctrl_dev_t *)glist_entry_data(dev_it);
                type = ctrl_dev_mode(aux_dev);
                if (ctrl_dev_is_tr(type)){
                    type = TR_MODE;
                }
                if (type == dst_dev_type){
                    OOR_LOG(LDBG_2,"Sending message to local configured device: %s",
                            ctrl_dev_type_to_char(ctrl_dev_mode(aux_dev)));
                    if (lisp_addr_is_no_addr(&uc->la)){
                        uconn_init(&rev_uc, uc->rp, uc->lp, &uc->ra,&uc->ra);
                    }else{
                        uconn_init(&rev_uc, uc->rp, uc->lp, &uc->ra,&uc->la);
                    }
                    ctrl_msg = ctrl_local_msg_new_init(b,rev_uc,aux_dev);
                    glist_add_tail(ctrl_msg,ctrl->recv_local_ctrl_msg_lst);
                    /* Notify system we have a packet to be processed. It is better to not process
                     * directly here */
                    write (ctrl->ctrl_notify_fd,"1",sizeof("1"));
                    return (GOOD);
                }
            }
            OOR_LOG(LWRN, "The ctrl message is the for local device but it is not configured as a %s ",ctrl_dev_type_to_char(dst_dev_type));
            return (BAD);
        }
        lisp_addr_del(src_addr);
    }

    return (send_msg(dev, b, uc));
}

void
ctrl_recv_msg(oor_ctrl_t *ctrl, lbuf_t *b, uconn_t *uc)
{
    glist_entry_t *dev_it;
    oor_ctrl_dev_t *dev;
    // XXX Check type of message and if they need to be sent to each device

    glist_for_each_entry(dev_it,ctrl->devices){
        dev = (oor_ctrl_dev_t *)glist_entry_data(dev_it);
        OOR_LOG(LDBG_1,"==> Start processing received message by %s",ctrl_dev_type_to_char(ctrl_dev_mode(dev)));
        ctrl_dev_recv(dev, b, uc);
        OOR_LOG(LDBG_1,"==> End processing received message by %s",ctrl_dev_type_to_char(ctrl_dev_mode(dev)));
    }
    return;
}

/* Process messages that should be locally delivered */
int
ctrl_recv_locl_msg(sock_t *sl)
{
    oor_ctrl_t *ctrl;
    char buf[MAX_BUF_SIZE];
    ctrl_local_msg *ctrl_msg;


    ctrl = sl->arg;
    read(sl->fd, buf, MAX_BUF_SIZE);
    while ((ctrl_msg = glist_pull(ctrl->recv_local_ctrl_msg_lst))){
        ctrl_dev_recv(ctrl_msg->dst_dev,ctrl_msg->buf, &(ctrl_msg->uc));
        ctrl_local_msg_del(ctrl_msg);
    }
    return (GOOD);
}

#ifndef __APPLE__
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
        net_mgr->netm_reload_routes(RT_TABLE_MAIN,AF_INET);
        net_mgr->netm_reload_routes(RT_TABLE_MAIN,AF_INET6);
    }

}
#endif

void
ctrl_if_addr_update(oor_ctrl_t *ctrl,iface_t *iface, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr)
{
    oor_ctrl_dev_t *dev;
    glist_entry_t *dev_it;

    ctrl->control_data_plane->control_dp_updated_addr(ctrl, iface, old_addr, new_addr);

    /* TODO: should store and pass updated rloc in the future
     * The old, and current solution is to keep a mapping between mapping_t
     * and iface to identify mapping_t(s) for which SMRs have to be sent. In
     * the future this should be decoupled and only the affected RLOC should
     * be passed to ctrl_dev */
    glist_for_each_entry(dev_it,ctrl->devices){
        dev = (oor_ctrl_dev_t *)glist_entry_data(dev_it);
        ctrl_dev_if_addr_update(dev, iface->iface_name, old_addr,new_addr, iface_status(iface));
    }
    set_rlocs(ctrl);
}

void
ctrl_if_link_update(oor_ctrl_t *ctrl, iface_t *iface, int old_iface_index,
        int new_iface_index, int status)
{
    oor_ctrl_dev_t *dev;
    glist_entry_t *dev_it;

    ctrl->control_data_plane->control_dp_update_link(ctrl, iface, old_iface_index, new_iface_index, status);
    glist_for_each_entry(dev_it,ctrl->devices){
        dev = (oor_ctrl_dev_t *)glist_entry_data(dev_it);
        ctrl_dev_if_link_update(dev, iface->iface_name, status);
    }
    set_rlocs(ctrl);
}


void
ctrl_route_update(oor_ctrl_t *ctrl, int command, iface_t *iface,lisp_addr_t *src,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    oor_ctrl_dev_t *dev;
    glist_entry_t *dev_it;

    ctrl->control_data_plane->control_dp_updated_route(ctrl, command, iface, src, dst_pref, gateway);
    glist_for_each_entry(dev_it,ctrl->devices){
        dev = (oor_ctrl_dev_t *)glist_entry_data(dev_it);
        ctrl_dev_route_update(dev, command, iface->iface_name, src, dst_pref, gateway);
    }
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
 * @param ctrl Lisp controller to be used
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
    // XXX To check if we support more than one TR per device
    oor_ctrl_dev_t *dev = ctrl_get_tr_device(lctrl);
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
ctrl_register_mapping_dp(oor_ctrl_dev_t *dev, mapping_t *map)
{
    oor_dev_type_e dev_type = dev->mode;
    int res = GOOD;

    if (dev_type == xTR_MODE || dev_type == MN_MODE || dev_type == RTR_MODE){
        res = data_plane->datap_register_lcl_mapping(dev_type,map);
    }else{
        OOR_LOG(LDBG_1, "Current version only supports the registration in control of "
                        "EID prefixes from xTRs and MNs");
    }

    return (res);
}

int
ctrl_unregister_mapping_dp(oor_ctrl_dev_t *dev, mapping_t *map)
{
    oor_dev_type_e dev_type = ctrl_dev_mode(dev);

    if (data_plane){
        if (dev_type == xTR_MODE || dev_type == MN_MODE || dev_type == RTR_MODE){
            data_plane->datap_deregister_lcl_mapping(dev_type,map);
        }else{
            OOR_LOG(LDBG_1, "Current version only supports the unregistration in control of "
                    "EID prefixes from xTRs");
        }
    }
    return (GOOD);
}

int
ctrl_datap_rm_fwd_from_entry(lisp_addr_t *eid_prefix, uint8_t is_local)
{
    return (data_plane->datap_rm_fwd_from_entry(eid_prefix, is_local));
}

int
ctrl_datap_reset_all_fwd()
{
    return (data_plane->datap_reset_all_fwd());
}

uint8_t
ctrl_has_compatible_devices(oor_ctrl_t *c)
{
    glist_entry_t *dev_it;
    oor_ctrl_dev_t *dev;
    uint8_t tr_configured = FALSE;
    oor_dev_type_e dev_type;


    glist_for_each_entry(dev_it, c->devices){
        dev = (oor_ctrl_dev_t *)glist_entry_data(dev_it);
        dev_type = ctrl_dev_mode(dev);
        if (ctrl_dev_is_tr(dev_type)){
            if (!tr_configured){
                tr_configured = TRUE;
            }else{
                OOR_LOG(LERR, "Only one tunnel router is allowed for device");
                return (FALSE);
            }
        }
    }
    return (TRUE);
}

uint8_t
ctrl_is_tr_configured(oor_ctrl_t *c)
{
    glist_entry_t *dev_it;
    oor_ctrl_dev_t *dev;

    glist_for_each_entry(dev_it, c->devices){
        dev = (oor_ctrl_dev_t *)glist_entry_data(dev_it);
        if (ctrl_dev_is_tr(ctrl_dev_mode(dev))){
            return (TRUE);
        }
    }
    return (FALSE);
}

oor_ctrl_dev_t *
ctrl_get_tr_device(oor_ctrl_t *c)
{
    glist_entry_t *dev_it;
    oor_ctrl_dev_t *dev;

    glist_for_each_entry(dev_it, c->devices){
        dev = (oor_ctrl_dev_t *)glist_entry_data(dev_it);
        if (ctrl_dev_is_tr(ctrl_dev_mode(dev))){
            return (dev);
        }
    }
    return (NULL);
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

