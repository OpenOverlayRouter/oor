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

#ifndef CONTROL_DATA_PLANE_H_
#define CONTROL_DATA_PLANE_H_

#include "../../liblisp/liblisp.h"

typedef struct iface iface_t;
typedef struct uconn uconn_t;
typedef struct sock sock_t;

/* functions to manipulate routing */
typedef struct control_dplane_struct {
    int (*control_dp_init)(oor_ctrl_t *ctrl, ...);
    void (*control_dp_uninit)(oor_ctrl_t *ctrl);
    int (*control_dp_add_iface_addr)(oor_ctrl_t *ctrl, iface_t *iface, int afi);
    int (*control_dp_add_iface_gw)(oor_ctrl_t *ctrl, iface_t *iface, int afi);
    int (*control_dp_recv_msg)(sock_t *sl);
    int (*control_dp_send_msg)(oor_ctrl_t *ctrl, lbuf_t *buf, uconn_t *udp_conn);
    lisp_addr_t *(*control_dp_get_default_addr)(oor_ctrl_t *ctrl, int afi);
    int (*control_dp_updated_route)(oor_ctrl_t *ctrl, int command, iface_t *iface, lisp_addr_t *src_pref,
            lisp_addr_t *dst_pref, lisp_addr_t *gw);
    int (*control_dp_updated_addr)(oor_ctrl_t *ctrl, iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr);
    int (*control_dp_update_link)(oor_ctrl_t *ctrl, iface_t *iface, int old_iface_index, int new_iface_index, int status);
    void *control_dp_data;
} control_dplane_struct_t;

control_dplane_struct_t *
control_dp_select();

extern control_dplane_struct_t control_dp_tun;
extern control_dplane_struct_t control_dp_vpnapi;
extern control_dplane_struct_t control_dp_vpp;
extern control_dplane_struct_t control_dp_apple;

#endif /* CONTROL_DATA_PLANE_H_ */
