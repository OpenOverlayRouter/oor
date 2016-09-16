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

#include "cdp_tun.h"
#include "../control-data-plane.h"
#include "../../oor_control.h"
#include "../../oor_ctrl_device.h"
#include "../../../iface_list.h"
#include "../../../lib/oor_log.h"

/***************************** FUNCTIONS DECLARATION *************************/

int
tun_control_dp_init(oor_ctrl_t *ctrl, ...);
void
tun_control_dp_uninit (oor_ctrl_t *ctrl);
int
tun_control_dp_add_iface_addr(oor_ctrl_t *ctrl,iface_t *iface, int afi);
int
tun_control_dp_recv_msg(sock_t *sl);
int
tun_control_dp_send_msg(oor_ctrl_t *ctrl, lbuf_t *buff, uconn_t *udp_conn);
lisp_addr_t * tun_control_dp_get_default_addr(oor_ctrl_t *ctrl, int afi);
int
tun_control_dp_updated_route(oor_ctrl_t *ctrl, int command, iface_t *iface,
        lisp_addr_t *src_pref, lisp_addr_t *dst_pref, lisp_addr_t *gw);
int
tun_control_dp_updated_addr(oor_ctrl_t *ctrl, iface_t *iface,lisp_addr_t *old_addr,
        lisp_addr_t *new_addr);
int
tun_control_dp_update_link(oor_ctrl_t *ctrl, iface_t *iface, int old_iface_index,
        int new_iface_index, int status);
void
tun_control_dp_set_default_ctrl_ifaces(tun_ctr_dplane_data_t * data);
iface_t *
tun_control_dp_get_default_ctrl_iface(tun_ctr_dplane_data_t * data, int afi);
lisp_addr_t *
tun_control_dp_get_default_ctrl_address(tun_ctr_dplane_data_t * data, int afi);
int
tun_control_dp_get_default_ctrl_socket(tun_ctr_dplane_data_t * data,int afi);
int
tun_control_dp_get_output_ctrl_sock(tun_ctr_dplane_data_t * data, uconn_t *udp_conn);

control_dplane_struct_t control_dp_tun = {
        .control_dp_init = tun_control_dp_init,
        .control_dp_uninit = tun_control_dp_uninit,
        .control_dp_add_iface_addr = tun_control_dp_add_iface_addr,
        .control_dp_recv_msg = tun_control_dp_recv_msg,
        .control_dp_send_msg = tun_control_dp_send_msg,
        .control_dp_get_default_addr = tun_control_dp_get_default_addr,
        .control_dp_updated_route = tun_control_dp_updated_route,
        .control_dp_updated_addr = tun_control_dp_updated_addr,
        .control_dp_update_link = tun_control_dp_update_link,
        .control_dp_data = NULL
};

/********************************** FUNCTIONS ********************************/

int
tun_control_dp_init(oor_ctrl_t *ctrl, ...)
{
    int socket;
    tun_ctr_dplane_data_t * data;

    /* Generate receive sockets for control port (4342)*/
    if (default_rloc_afi != AF_INET6) {
        socket = open_control_input_socket(AF_INET);
        sockmstr_register_read_listener(smaster, tun_control_dp_recv_msg, ctrl,socket);
    }

    if (default_rloc_afi != AF_INET) {
        socket = open_control_input_socket(AF_INET6);
        sockmstr_register_read_listener(smaster, tun_control_dp_recv_msg, ctrl,socket);
    }

    data = (tun_ctr_dplane_data_t *)xmalloc(sizeof(tun_ctr_dplane_data_t));
    ctrl->control_data_plane->control_dp_data = (void *)data;
    tun_control_dp_set_default_ctrl_ifaces(data);

    return (GOOD);
}


void
tun_control_dp_uninit (oor_ctrl_t *ctrl)
{
    tun_ctr_dplane_data_t * data;
    data = (tun_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;

    free(data);
}

int
tun_control_dp_add_iface_addr(oor_ctrl_t *ctrl,iface_t *iface, int afi)
{
    tun_ctr_dplane_data_t * cdp_data = control_dp_tun.control_dp_data;
    switch (afi){
    case AF_INET:
        if (cdp_data && !cdp_data->default_ctrl_iface_v4){
            // It will only enter here when adding interfaces after init process
            tun_control_dp_set_default_ctrl_ifaces(cdp_data);
        }
        break;
    case AF_INET6:
        if (cdp_data && !cdp_data->default_ctrl_iface_v6){
            // It will only enter here when adding interfaces after init process
            tun_control_dp_set_default_ctrl_ifaces(cdp_data);
        }
        break;
    default:
        break;
    }

    return (GOOD);
}

/*  Process a LISP protocol message sitting on
 *  socket s with address family afi */
int
tun_control_dp_recv_msg(sock_t *sl)
{
    uconn_t uc;
    lbuf_t *b;
    oor_ctrl_t *ctrl;
    oor_ctrl_dev_t *dev;

    ctrl = sl->arg;
    /* Only one device supported for now */
    dev = glist_first_data(ctrl->devices);

    uc.lp = LISP_CONTROL_PORT;

    b = lisp_msg_create_buf();

    if (sock_ctrl_recv(sl->fd, b, &uc) != GOOD) {
        OOR_LOG(LDBG_1, "Couldn't retrieve socket information"
                "for control message! Discarding packet!");
        lbuf_del(b);
        return (BAD);
    }

    if (lbuf_size(b) < 4){
        OOR_LOG(LDBG_3, "Received a non LISP message in the "
                "control port! Discarding packet!");
        return (BAD);
    }

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
tun_control_dp_send_msg(oor_ctrl_t *ctrl, lbuf_t *buff, uconn_t *udp_conn)
{
    int ret;
    int sock;
    ip_addr_t *src_addr, *dst_addr;

    if (lisp_addr_lafi(&udp_conn->ra) != LM_AFI_IP) {
        OOR_LOG(LDBG_2, "tun_control_dp_send_msg: Destination address %s of UDP connection is not a IP. "
                "Discarding!", lisp_addr_to_char(&udp_conn->ra));
        return(BAD);
    }

    sock = tun_control_dp_get_output_ctrl_sock(
            (tun_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data, udp_conn);
    if (sock == ERR_SOCKET){
        return (BAD);
    }

    src_addr = lisp_addr_ip(&udp_conn->la);
    dst_addr = lisp_addr_ip(&udp_conn->ra);

    if (ip_addr_afi(src_addr) != ip_addr_afi(dst_addr)) {
        OOR_LOG(LDBG_2, "tun_control_dp_send_msg: src %s and dst %s of UDP connection have "
                "different IP AFI. Discarding!", ip_addr_to_char(src_addr),
                ip_addr_to_char(dst_addr));
        return(BAD);
    }

    pkt_push_udp_and_ip(buff, udp_conn->lp, udp_conn->rp, src_addr, dst_addr);

    ret = send_raw_packet(sock, lbuf_data(buff), lbuf_size(buff), dst_addr);


    if (ret != GOOD) {
        OOR_LOG(LDBG_1, "Failed to send contrl message from RLOC: %s -> %s",
                lisp_addr_to_char(&udp_conn->la), lisp_addr_to_char(&udp_conn->ra));
        return(BAD);
    } else {
        OOR_LOG(LDBG_1, "Sent control message IP: %s -> %s UDP: %d -> %d",
                lisp_addr_to_char(&udp_conn->la), lisp_addr_to_char(&udp_conn->ra),
                udp_conn->lp, udp_conn->rp);
        return(GOOD);
    }
}

lisp_addr_t *
tun_control_dp_get_default_addr(oor_ctrl_t *ctrl, int afi)
{
    lisp_addr_t *addr = NULL;
    tun_ctr_dplane_data_t * data;
    data = (tun_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;

    switch (afi){
    case AF_INET:
        if (data->default_ctrl_iface_v4 != NULL){
            addr = iface_address(data->default_ctrl_iface_v4,AF_INET);
        }
        break;
    case AF_INET6:
        if (data->default_ctrl_iface_v6 != NULL){
            addr = iface_address(data->default_ctrl_iface_v6,AF_INET6);
        }
        break;
    default:
        OOR_LOG(LDBG_2,"tun_control_dp_get_default_addr: Unsupported afi: %d",afi);
        break;
    }

    return (addr);
}

int
tun_control_dp_updated_route(oor_ctrl_t *ctrl, int command, iface_t *iface,
        lisp_addr_t *src_pref, lisp_addr_t *dst_pref, lisp_addr_t *gw)
{
    return (GOOD);
}

int
tun_control_dp_updated_addr(oor_ctrl_t *ctrl, iface_t *iface,lisp_addr_t *old_addr,
        lisp_addr_t *new_addr)
{
    int addr_afi;
    tun_ctr_dplane_data_t * data;
    data = (tun_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;

    /* If no default control, recalculate it */
    if (iface->status == UP) {
        addr_afi = lisp_addr_ip_afi(new_addr);
        if ((data->default_ctrl_iface_v4 == NULL && addr_afi == AF_INET) ||
                (data->default_ctrl_iface_v6 == NULL && addr_afi == AF_INET6)) {
            OOR_LOG(LDBG_2, "No default control interface. Recalculate new "
                    "control interface");
            tun_control_dp_set_default_ctrl_ifaces(data);
        }
    }

    return (GOOD);
}

int
tun_control_dp_update_link(oor_ctrl_t *ctrl, iface_t *iface, int old_iface_index,
        int new_iface_index, int status)
{
    tun_ctr_dplane_data_t * data;
    data = (tun_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;

    /* If the affected interface is the default control or output iface,
     * recalculate it */

    if (data->default_ctrl_iface_v4 == iface
            || data->default_ctrl_iface_v6 == iface
            || data->default_ctrl_iface_v4 == NULL
            || data->default_ctrl_iface_v6 == NULL){
        OOR_LOG(LDBG_2,"Default control interface down. Recalculate new control"
                " interface");
        tun_control_dp_set_default_ctrl_ifaces(data);
    }

    return (GOOD);
}


void
tun_control_dp_set_default_ctrl_ifaces(tun_ctr_dplane_data_t * data)
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

iface_t *
tun_control_dp_get_default_ctrl_iface(tun_ctr_dplane_data_t * data, int afi)
{
    iface_t *iface = NULL;

    switch (afi){
    case AF_INET:
        iface = data->default_ctrl_iface_v4;
        break;
    case AF_INET6:
        iface = data->default_ctrl_iface_v6;
        break;
    default:
        //arnatal TODO: syslog
        iface = NULL;
        break;
    }

    return (iface);
}

lisp_addr_t *
tun_control_dp_get_default_ctrl_address(tun_ctr_dplane_data_t * data, int afi)
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
        break;
    }
    return (address);
}

int
tun_control_dp_get_default_ctrl_socket(tun_ctr_dplane_data_t * data, int afi)
{
    int socket = ERR_SOCKET;
    switch (afi){
    case AF_INET:
        if (data->default_ctrl_iface_v4 != NULL){
            socket = data->default_ctrl_iface_v4->out_socket_v4;
        }
        break;
    case AF_INET6:
        if (data->default_ctrl_iface_v6 != NULL){
            socket = data->default_ctrl_iface_v6->out_socket_v6;
        }
        break;
    default:
        socket = ERR_SRC_ADDR;
        break;
    }

    return (socket);
}

int
tun_control_dp_get_output_ctrl_sock(tun_ctr_dplane_data_t * data,
        uconn_t *udp_conn)
{
    int sock, dst_afi;
    lisp_addr_t *ctrl_addr;
    iface_t *iface;

    dst_afi = lisp_addr_ip_afi(&udp_conn->ra);
    /* If no local address specified, use the default one */
    if (lisp_addr_is_no_addr(&udp_conn->la)) {
        ctrl_addr = tun_control_dp_get_default_ctrl_address(data, dst_afi);
        if (!ctrl_addr) {
            OOR_LOG(LERR, "tun_control_dp_get_output_ctrl_sock: No %s control address found, send aborted!",
                    (dst_afi == AF_INET) ? "IPv4" : "IPv6");
            return(ERR_SOCKET);
        }
        /* Use as local address the default control address */
        lisp_addr_copy(&udp_conn->la, ctrl_addr);
        sock = tun_control_dp_get_default_ctrl_socket(data,dst_afi);
    } else {
        iface = get_interface_with_address(&udp_conn->la);
        if (iface != NULL) {
            sock = iface_socket(iface, dst_afi);
        } else {
            OOR_LOG(LDBG_2, "tun_control_dp_get_output_ctrl_sock: No interface found with local address %s. Using default one!",
                    lisp_addr_to_char(&udp_conn->la));
            ctrl_addr = tun_control_dp_get_default_ctrl_address(data, dst_afi);
            if (!ctrl_addr) {
                OOR_LOG(LERR, "tun_control_dp_get_output_ctrl_sock: No control address found, send aborted!");
                return(ERR_SOCKET);
            }
            /* Use as local address the default control address */
            lisp_addr_copy(&udp_conn->la, ctrl_addr);
            sock = tun_control_dp_get_default_ctrl_socket(data,dst_afi);
        }
    }

    if (sock < 0) {
        OOR_LOG(LERR, "No output socket found, send aborted!");
        return(ERR_SOCKET);
    }

    return (sock);
}
