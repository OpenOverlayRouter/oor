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
#include <netdb.h>
#include <sys/socket.h>
#include <syslog.h>

#include "cdp_ios.h"
#include "../../control-data-plane.h"
#include "../../../oor_control.h"
#include "../../../oor_ctrl_device.h"
#include "../../../../iface_list.h"
#include "../../../../lib/oor_log.h"
#include "../../../../lib/util.h"

/***************************** FUNCTIONS DECLARATION *************************/

int
ios_control_dp_init(oor_ctrl_t *ctrl, ...);
void
ios_control_dp_uninit (oor_ctrl_t *ctrl);
int
ios_control_dp_add_iface_addr(oor_ctrl_t *ctrl,iface_t *iface, int afi);
int
ios_control_dp_recv_msg(sock_t *sl);
int
ios_control_dp_send_msg(oor_ctrl_t *ctrl, lbuf_t *buff, uconn_t *udp_conn);
lisp_addr_t * ios_control_dp_get_default_addr(oor_ctrl_t *ctrl, int afi);
int ios_control_dp_add_iface_gw(oor_ctrl_t *ctrl,iface_t *iface, int afi);
int
ios_control_dp_updated_route(oor_ctrl_t *ctrl, int command, iface_t *iface,
                             lisp_addr_t *src_pref, lisp_addr_t *dst_pref, lisp_addr_t *gw);
void ios_control_dp_process_new_gateway(oor_ctrl_t *ctrl, iface_t *iface,
                            lisp_addr_t *gateway);
int
ios_control_dp_updated_addr(oor_ctrl_t *ctrl, iface_t *iface,lisp_addr_t *old_addr,
                            lisp_addr_t *new_addr);
int
ios_control_dp_update_link(oor_ctrl_t *ctrl, iface_t *iface, int old_iface_index,
                           int new_iface_index, int status);
int
ios_control_dp_reset_socket(ios_ctr_dplane_data_t * data, int fd, int afi);

control_dplane_struct_t control_dp_apple = {
    .control_dp_init = ios_control_dp_init,
    .control_dp_uninit = ios_control_dp_uninit,
    .control_dp_add_iface_addr = ios_control_dp_add_iface_addr,
    .control_dp_add_iface_gw = ios_control_dp_add_iface_gw,
    .control_dp_recv_msg = ios_control_dp_recv_msg,
    .control_dp_send_msg = ios_control_dp_send_msg,
    .control_dp_get_default_addr = ios_control_dp_get_default_addr,
    .control_dp_updated_route = ios_control_dp_updated_route,
    .control_dp_updated_addr = ios_control_dp_updated_addr,
    .control_dp_update_link = ios_control_dp_update_link,
    .control_dp_data = NULL
};

/********************************** FUNCTIONS ********************************/

#ifdef __APPLE__
#define IPV6_RECVPKTINFO 61
#define IPV6_PKTINFO 46
#define IPV6_HOPLIMIT 47
#endif

int
ios_control_dp_init(oor_ctrl_t *ctrl, ...) {
    ios_ctr_dplane_data_t * data;
    sock_t *sock;
    
    data = (ios_ctr_dplane_data_t *)xmalloc(sizeof(ios_ctr_dplane_data_t));
    ctrl->control_data_plane->control_dp_data = (void *)data;
    
    /* Generate receive sockets for control port (4342)*/
    if (default_rloc_afi != AF_INET6) {
        data->ipv4_ctrl_socket = open_control_input_socket(AF_INET);
        sockmstr_register_read_listener(smaster, ios_control_dp_recv_msg, ctrl,data->ipv4_ctrl_socket);
        /* Socket to send Encap Map Register using src port 4341 */
        sock = sockmstr_register_get_by_bind_port(smaster, AF_INET, LISP_DATA_PORT);
        if (sock != NULL){
            data->ipv4_data_socket = sock_fd(sock);
        }
    }
    
    if (default_rloc_afi != AF_INET) {
        data->ipv6_ctrl_socket = open_control_input_socket(AF_INET6);
        sockmstr_register_read_listener(smaster, ios_control_dp_recv_msg, ctrl,data->ipv6_ctrl_socket);
    }
    
    return (GOOD);
}

void
ios_control_dp_uninit (oor_ctrl_t *ctrl) {
    ios_ctr_dplane_data_t * data;
    data = (ios_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;
    
    free(data);
}

int
ios_control_dp_add_iface_addr(oor_ctrl_t *ctrl,iface_t *iface, int afi) {
    return (GOOD);
}

int
ios_control_dp_recv_msg(sock_t *sl) {
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
ios_control_dp_send_msg(oor_ctrl_t *ctrl, lbuf_t *buff, uconn_t *udp_conn) {
    
    int ret;
    int sock;
    ip_addr_t *src_addr, *dst_addr;
    ios_ctr_dplane_data_t * data;
    
    data = (ios_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;
    
    
    if (lisp_addr_lafi(&udp_conn->ra) != LM_AFI_IP) {
        OOR_LOG(LDBG_2, "ios_control_dp_send_msg: Destination address %s of UDP connection is not a IP. "
                "Discarding!", lisp_addr_to_char(&udp_conn->ra));
        return(BAD);
    }
    
    src_addr = lisp_addr_ip(&udp_conn->la);
    dst_addr = lisp_addr_ip(&udp_conn->ra);
    
    if (!lisp_addr_is_no_addr(&udp_conn->la) &&  (ip_addr_afi(src_addr) != ip_addr_afi(dst_addr))) {
        OOR_LOG(LDBG_2, "ios_control_dp_send_msg: src %s and dst %s of UDP connection have "
                "different IP AFI. Discarding!", ip_addr_to_char(src_addr),
                ip_addr_to_char(dst_addr));
        return(BAD);
    }
    
    switch (ip_addr_afi(dst_addr)){
        case AF_INET:
            if (udp_conn->lp == LISP_CONTROL_PORT){
                sock = data->ipv4_ctrl_socket;
            }else{
                sock = data->ipv4_data_socket;
            }
            break;
        case AF_INET6:
            sock = data->ipv6_ctrl_socket;
            break;
        default:
            return (BAD);
    }

    ret = send_datagram_packet (sock, lbuf_data(buff), lbuf_size(buff), &udp_conn->ra, udp_conn->rp);
    
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

lisp_addr_t * ios_control_dp_get_default_addr(oor_ctrl_t *ctrl, int afi) {
    iface_t *iface;
    lisp_addr_t *addr = NULL;
    
    iface = get_any_output_iface(afi);
    if (iface != NULL){
        addr = iface_address(iface, afi);
    }
    
    return (addr);
}

int ios_control_dp_add_iface_gw(oor_ctrl_t *ctrl,iface_t *iface, int afi) {
    return (GOOD);
}

int
ios_control_dp_updated_route(oor_ctrl_t *ctrl, int command, iface_t *iface,
                             lisp_addr_t *src_pref, lisp_addr_t *dst_pref, lisp_addr_t *gw) {
    /* Check if the updated route is a gateway */
    if (lisp_addr_ip_afi(gw) != LM_AFI_NO_ADDR
        && (lisp_addr_ip_afi(dst_pref) == LM_AFI_NO_ADDR ||
            laddr_is_full_space_pref(dst_pref))) {
        ios_control_dp_process_new_gateway(ctrl,iface,gw);
    }
    
    return (GOOD);
}

void
ios_control_dp_process_new_gateway(oor_ctrl_t *ctrl, iface_t *iface,
                                      lisp_addr_t *gateway)
{
    int afi;
    ios_ctr_dplane_data_t * data;
    
    afi = lisp_addr_ip_afi(gateway);
    data = (ios_ctr_dplane_data_t *)(ctrl->control_data_plane->control_dp_data);
    
    /* Gatway is updated in data plane process */
    
    /* Recreate sockets */
    switch(afi){
        case AF_INET:
            ios_control_dp_reset_socket(data, data->ipv4_ctrl_socket,AF_INET);
            break;
        case AF_INET6:
            ios_control_dp_reset_socket(data, data->ipv6_ctrl_socket,AF_INET6);
            break;
        default:
            return;
    }
}
        

int
ios_control_dp_updated_addr(oor_ctrl_t *ctrl, iface_t *iface,
                               lisp_addr_t *old_addr,lisp_addr_t *new_addr)
{
    int addr_afi;
    ios_ctr_dplane_data_t * data;
    
    data = (ios_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;
    if (lisp_addr_is_no_addr(new_addr)){
        return(GOOD);
    }
    addr_afi = lisp_addr_ip_afi(new_addr);
    
    /* Check if the detected change of address is the same. */
    if (lisp_addr_cmp(old_addr, new_addr) == 0) {
        OOR_LOG(LDBG_2, "ios_control_dp_updated_addr: The change of address detected "
                "for interface %s doesn't affect", iface->iface_name);
        return (GOOD);
    };
    
    switch (addr_afi){
        case AF_INET:
            ios_control_dp_reset_socket(data, data->ipv4_ctrl_socket, AF_INET);
            break;
        case AF_INET6:
            ios_control_dp_reset_socket(data, data->ipv6_ctrl_socket, AF_INET6);
            break;
        default:
            return (BAD);
    }
    
    return (GOOD);
}

int
ios_control_dp_update_link(oor_ctrl_t *ctrl, iface_t *iface,
                              int old_iface_index, int new_iface_index, int status)
{		
    ios_ctr_dplane_data_t * data;
    data = (ios_ctr_dplane_data_t *)ctrl->control_data_plane->control_dp_data;
    
    if (default_rloc_afi != AF_INET6){
        ios_control_dp_reset_socket(data, data->ipv4_ctrl_socket, AF_INET);
    }
    if (default_rloc_afi != AF_INET){
        ios_control_dp_reset_socket(data, data->ipv6_ctrl_socket, AF_INET6);
    }
    
    return (GOOD);
}


int
ios_control_dp_reset_socket(ios_ctr_dplane_data_t * data, int fd, int afi)
{
    sock_t *old_sock, *data_sock;
    int new_fd;
    void *ctrl;
    int (*cb_func)(struct sock *);
    old_sock = sockmstr_register_get_by_fd(smaster,fd);
    if (!old_sock){
        OOR_LOG(LWRN,"ios_control_dp_reset_socket: Couldn't reset socket with fd %d. Socket not found ", fd);
        return (BAD);
    }
    ctrl = old_sock->arg;
    cb_func = old_sock->recv_cb;
    sockmstr_unregister_read_listenedr(smaster,old_sock);
    
    switch (afi){
        case AF_INET:
            OOR_LOG(LDBG_2,"reset_socket: Reset IPv4 control socket\n");
            new_fd = open_control_input_socket(AF_INET);
            if (new_fd == ERR_SOCKET){
                OOR_LOG(LWRN,"ios_control_dp_reset_socket: Error recreating the socket");
                return (BAD);
            }
            data->ipv4_ctrl_socket = new_fd;
            
            /* The data socket has probably changed too. Refresh it */
            data_sock =  sockmstr_register_get_by_bind_port (smaster, AF_INET, LISP_DATA_PORT);
            if (data_sock != NULL){
                data->ipv4_data_socket = sock_fd(data_sock);
            }
            break;
        case AF_INET6:
            OOR_LOG(LDBG_2,"reset_socket: Reset IPv6 control socket\n");
            new_fd = open_control_input_socket(AF_INET6);
            if (new_fd == ERR_SOCKET){
                OOR_LOG(LWRN,"ios_control_dp_reset_socket: Error recreating the socket");
                return (BAD);
            }
            data->ipv6_ctrl_socket = new_fd;
            break;
        default:
            return (BAD);
    }
    sockmstr_register_read_listener(smaster,cb_func,ctrl,new_fd);
    return (GOOD);
}
