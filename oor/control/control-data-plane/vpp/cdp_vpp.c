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

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/ether.h>
#include <unistd.h>

#include "cdp_vpp.h"

#include "../../../lib/vpp_api/vpp_api_requests.h"
#include "../control-data-plane.h"
#include "../../lib/interfaces_lib.h"
#include "../../lib/oor_log.h"
#include "../../oor_control.h"
#include "../../oor_ctrl_device.h"

int
vpp_control_dp_init(oor_ctrl_t *ctrl,...);
void
vpp_control_dp_uninit (oor_ctrl_t *ctrl);
int
vpp_control_dp_add_iface_addr(oor_ctrl_t *ctrl,iface_t *iface, int afi);
int
vpp_control_dp_add_iface_gw(oor_ctrl_t *ctrl,iface_t *iface, int afi);
int
vpp_control_dp_recv_msg(sock_t *sl);
int
vpp_control_dp_send_msg(oor_ctrl_t *ctrl, lbuf_t *buff, uconn_t *udp_conn);
lisp_addr_t *
vpp_control_dp_get_default_addr(oor_ctrl_t *ctrl, int afi);
inline lisp_addr_t *
vpp_control_dp_get_default_ctrl_address(vpp_ctr_dplane_data_t * data, int afi);
int
vpp_control_dp_updated_route(oor_ctrl_t *ctrl, int command, iface_t *iface,
        lisp_addr_t *src_pref,lisp_addr_t *dst_pref, lisp_addr_t *gw);
void
vpp_control_dp_process_new_gateway(oor_ctrl_t *ctrl, iface_t *iface,
        lisp_addr_t *gateway);
int
vpp_control_dp_updated_addr(oor_ctrl_t *ctrl, iface_t *iface,
        lisp_addr_t *old_addr,lisp_addr_t *new_addr);
int
vpp_control_dp_update_link(oor_ctrl_t *ctrl, iface_t *iface,
        int old_iface_index, int new_iface_index, int status);

void
vpp_control_dp_set_default_ctrl_ifaces(vpp_ctr_dplane_data_t * data);

/*  Process a received control message */
int
vpp_control_dp_recv_msg(sock_t *sl);


control_dplane_struct_t control_dp_vpp = {
        .control_dp_init = vpp_control_dp_init,
        .control_dp_uninit = vpp_control_dp_uninit,
        .control_dp_add_iface_addr = vpp_control_dp_add_iface_addr,
        .control_dp_add_iface_gw = vpp_control_dp_add_iface_gw,
        .control_dp_recv_msg = vpp_control_dp_recv_msg,
        .control_dp_send_msg = vpp_control_dp_send_msg,
        .control_dp_get_default_addr = vpp_control_dp_get_default_addr,
        .control_dp_updated_route = vpp_control_dp_updated_route,
        .control_dp_updated_addr = vpp_control_dp_updated_addr,
        .control_dp_update_link = vpp_control_dp_update_link,
        .control_dp_data = NULL
};

int tap_fd = 0;
uint8_t mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int
vpp_control_dp_init(oor_ctrl_t *ctrl,...)
{
    vpp_ctr_dplane_data_t *data;

    /* Configure data plane */
    if ((tap_fd = create_tun_tap(TAP,TAP_CTRL_IFACE_NAME,TAP_MTU_CTRL_VPP)) == BAD){
        return (BAD);
    }
    /* Enable oor control node in VPP */
    if (vpp_oor_ctrl_enable_disable(TAP_CTRL_IFACE_NAME, TRUE)!= GOOD){
        OOR_LOG(LERR,"VPP: Could not initiate oor ctrl plugin. Check /var/log/syslog for more details");
        return (BAD);
    }
    OOR_LOG(LDBG_1,"VPP: Enabled OOR Ctrl plugin");

    /* Register socket */
    sockmstr_register_read_listener(smaster, vpp_control_dp_recv_msg, ctrl,tap_fd);

    data = (vpp_ctr_dplane_data_t *)xmalloc(sizeof(vpp_ctr_dplane_data_t));
    if (!data){
        return (BAD);
    }
    control_dp_vpp.control_dp_data = (void *)data;
    vpp_control_dp_set_default_ctrl_ifaces(data);
    return (GOOD);
}

void
vpp_control_dp_uninit (oor_ctrl_t *ctrl)
{
    vpp_ctr_dplane_data_t *data = (vpp_ctr_dplane_data_t *)control_dp_vpp.control_dp_data;

    /* Disable oor control node in VPP */
    if (vpp_oor_ctrl_enable_disable(TAP_CTRL_IFACE_NAME, FALSE)!= GOOD){
        OOR_LOG(LERR,"VPP: Could not disable oor ctrl plugin. Check /var/log/syslog for more details");
    }else{
        OOR_LOG(LDBG_1,"VPP: Disable OOR Ctrl plugin");
    }

    if (data){
        free(data);
        /* Disable oor pkt miss node in VPP */
       // vpp_oor_ctrl_enable_disable(TAP_CTRL_IFACE_NAME, FALSE);
    }
}

int
vpp_control_dp_add_iface_addr(oor_ctrl_t *ctrl,iface_t *iface, int afi)
{
    vpp_ctr_dplane_data_t * cdp_data = control_dp_vpp.control_dp_data;

    switch (afi){
    case AF_INET:
        if (cdp_data && !cdp_data->default_ctrl_iface_v4){
            // It will only enter here when adding interfaces after init process
            vpp_control_dp_set_default_ctrl_ifaces(cdp_data);
        }
        break;
    case AF_INET6:
        if (cdp_data && !cdp_data->default_ctrl_iface_v6){
            // It will only enter here when adding interfaces after init process
            vpp_control_dp_set_default_ctrl_ifaces(cdp_data);
        }
        break;
    default:
        break;
    }

    return (GOOD);
}

int
vpp_control_dp_add_iface_gw(oor_ctrl_t *ctrl,iface_t *iface, int afi)
{
    return (GOOD);
}

/*  Process a received control message */
int
vpp_control_dp_recv_msg(sock_t *sl)
{
    uconn_t uc;
    lbuf_t *b;
    oor_ctrl_t *ctrl;
    oor_ctrl_dev_t *dev;
    packet_tuple_t tpl;

    ctrl = sl->arg;
    /* Only one device supported for now */
    dev = glist_first_data(ctrl->devices);

    b = lisp_msg_create_buf();

    if (sock_recv(sl->fd, b) != GOOD) {
        OOR_LOG(LDBG_1, "Couldn't read socket. Discarding packet!");
        lbuf_del(b);
        return (BAD);
    }
    /* Remove ethernet header (TAP interface) */
    pkt_pull_eth(b);

    lbuf_reset_ip(b);

    if (pkt_parse_5_tuple(b, &tpl) != GOOD) {
        return (BAD);
    }

    if (tpl.protocol != IPPROTO_UDP || tpl.dst_port != LISP_CONTROL_PORT){
       return(BAD);
    }

    uconn_from_5_tuple(&tpl, &uc, 1);

    /* Remove IP and UDP header */
    pkt_pull_ip(b);
    pkt_pull_udp(b);

    lbuf_reset_lisp(b);
    OOR_LOG(LDBG_1, "Received %s, IP: %s -> %s, UDP: %d -> %d",
            lisp_msg_hdr_to_char(b), lisp_addr_to_char(&uc.ra),
            lisp_addr_to_char(&uc.la), uc.rp, uc.lp);

    /* direct call of ctrl device
     * TODO: check type to decide where to send msg*/
    ctrl_dev_recv(dev, b, &uc);


    lbuf_del(b);

    return (GOOD);
}


int
vpp_control_dp_send_msg(oor_ctrl_t *ctrl, lbuf_t *buff, uconn_t *udp_conn)
{
    int ret,dst_afi;
    ip_addr_t *src_addr, *dst_addr;
    lisp_addr_t *ctrl_addr;

    if (lisp_addr_lafi(&udp_conn->ra) != LM_AFI_IP) {
        OOR_LOG(LDBG_2, "vpp_control_dp_send_msg: Destination address %s of UDP connection is not a IP. "
                "Discarding!", lisp_addr_to_char(&udp_conn->ra));
        return(BAD);
    }

    if (lisp_addr_lafi(&udp_conn->la) != LM_AFI_IP) {
        dst_afi = lisp_addr_ip_afi(&udp_conn->ra);
        ctrl_addr = vpp_control_dp_get_default_ctrl_address(control_dp_vpp.control_dp_data, dst_afi);
        if (!ctrl_addr) {
            OOR_LOG(LERR, "vpp_control_dp_send_msg: No %s control address found, send aborted!",
                    (dst_afi == AF_INET) ? "IPv4" : "IPv6");
            return(ERR_SOCKET);
        }
        /* Use as local address the default control address */
        lisp_addr_copy(&udp_conn->la, ctrl_addr);
    }

    src_addr = lisp_addr_ip(&udp_conn->la);
    dst_addr = lisp_addr_ip(&udp_conn->ra);

    if (ip_addr_afi(src_addr) != ip_addr_afi(dst_addr)) {
        OOR_LOG(LDBG_2, "vpp_control_dp_send_msg: src %s and dst %s of UDP connection have "
                "different IP AFI. Discarding!", ip_addr_to_char(src_addr),
                ip_addr_to_char(dst_addr));
        return(BAD);
    }

    pkt_push_udp_and_ip(buff, udp_conn->lp, udp_conn->rp, src_addr, dst_addr);
    if (lisp_addr_ip_afi(&udp_conn->la) == AF_INET){
        pkt_push_eth(buff, mac, mac, ETH_P_IP);
    }else{
        pkt_push_eth(buff, mac, mac, ETH_P_IPV6);
    }
    lbuf_reset_eth(buff);

    ret = write(tap_fd, lbuf_data(buff), lbuf_size(buff));



    if (ret < 0) {
        OOR_LOG(LDBG_1, "Failed to send contrl message from RLOC: %s -> %s",
                lisp_addr_to_char(&udp_conn->la), lisp_addr_to_char(&udp_conn->ra));
        return(BAD);
    } else {
        OOR_LOG(LDBG_1, "Sent control message IP: %s -> %s UDP: %d -> %d",
                lisp_addr_to_char(&udp_conn->la), lisp_addr_to_char(&udp_conn->ra),
                udp_conn->lp, udp_conn->rp);
        return(GOOD);
    }

    return (GOOD);
}

lisp_addr_t *
vpp_control_dp_get_default_addr(oor_ctrl_t *ctrl, int afi)
{
    vpp_ctr_dplane_data_t * data;
    data = (vpp_ctr_dplane_data_t *)control_dp_vpp.control_dp_data;

    return (vpp_control_dp_get_default_ctrl_address(data,afi));
}


inline lisp_addr_t *
vpp_control_dp_get_default_ctrl_address(vpp_ctr_dplane_data_t * data, int afi)
{
    lisp_addr_t *address = NULL;
    switch (afi){
    case AF_INET:
        if (data->default_ctrl_iface_v4 != NULL){
            address = data->default_ctrl_iface_v4->ipv4_address;
        }
        break;
    case AF_INET6:
        if (data->default_ctrl_iface_v6 != NULL){
            address = data->default_ctrl_iface_v6->ipv6_address;
        }
        break;
    default:
        OOR_LOG(LDBG_2,"vpp_control_dp_get_default_ctrl_address: Unsupported afi: %d",afi);
        break;
    }
    return (address);
}

int
vpp_control_dp_updated_route(oor_ctrl_t *ctrl, int command, iface_t *iface,
        lisp_addr_t *src_pref,lisp_addr_t *dst_pref, lisp_addr_t *gw)
{
    return (GOOD);
}

void
vpp_control_dp_process_new_gateway(oor_ctrl_t *ctrl, iface_t *iface,
        lisp_addr_t *gateway)
{

}

int
vpp_control_dp_updated_addr(oor_ctrl_t *ctrl, iface_t *iface,
        lisp_addr_t *old_addr,lisp_addr_t *new_addr)
{
    int addr_afi;
    vpp_ctr_dplane_data_t * data;
    data = (vpp_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;

    /* If no default control, recalculate it */
    if (iface->status == UP) {
        addr_afi = lisp_addr_ip_afi(new_addr);
        if ((data->default_ctrl_iface_v4 == NULL && addr_afi == AF_INET) ||
                (data->default_ctrl_iface_v6 == NULL && addr_afi == AF_INET6)) {
            OOR_LOG(LDBG_2, "No default control interface. Recalculate new "
                    "control interface");
            vpp_control_dp_set_default_ctrl_ifaces(data);
        }
    }

    return (GOOD);
}

int
vpp_control_dp_update_link(oor_ctrl_t *ctrl, iface_t *iface,
        int old_iface_index, int new_iface_index, int status)
{
    vpp_ctr_dplane_data_t * data;
    data = (vpp_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;

    /* If the affected interface is the default control or output iface,
     * recalculate it */

    if (data->default_ctrl_iface_v4 == iface
            || data->default_ctrl_iface_v6 == iface
            || data->default_ctrl_iface_v4 == NULL
            || data->default_ctrl_iface_v6 == NULL){
        OOR_LOG(LDBG_2,"Default control interface down. Recalculate new control"
                " interface");
        vpp_control_dp_set_default_ctrl_ifaces(data);
    }

    return (GOOD);
}

void
vpp_control_dp_set_default_ctrl_ifaces(vpp_ctr_dplane_data_t * data)
{
    data->default_ctrl_iface_v4 = get_any_output_iface(AF_INET);
    if (data->default_ctrl_iface_v4 != NULL) {
       OOR_LOG(LDBG_2,"Default IPv4 control iface %s: %s\n",
               data->default_ctrl_iface_v4->iface_name,
               lisp_addr_to_char(data->default_ctrl_iface_v4->ipv4_address));
    }

    data->default_ctrl_iface_v6 = get_any_output_iface(AF_INET6);
    if (data->default_ctrl_iface_v6 != NULL) {
        OOR_LOG(LDBG_2,"Default IPv6 control iface %s: %s\n",
                data->default_ctrl_iface_v6->iface_name,
                lisp_addr_to_char(data->default_ctrl_iface_v6->ipv6_address));
    }

    if (!data->default_ctrl_iface_v4 && !data->default_ctrl_iface_v6) {
        OOR_LOG(LERR, "NO CONTROL IFACE: all the locators are down");

    }
}

