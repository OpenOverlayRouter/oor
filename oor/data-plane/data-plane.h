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

#ifndef DATA_PLANE_H_
#define DATA_PLANE_H_

#include "../liblisp/liblisp.h"
typedef struct iface iface_t;
typedef struct sock sock_t;

/* functions to manipulate routing */
typedef struct data_plane_struct {
    int (*datap_init)(oor_dev_type_e dev_type, oor_encap_t encap_type,  ...);
    void (*datap_uninit)();
    int (*datap_add_iface_addr)(iface_t *iface, int afi);
    int (*datap_add_eid_prefix)(oor_dev_type_e dev_type, lisp_addr_t *eid_prefix);
    int (*datap_remove_eid_prefix)(oor_dev_type_e dev_type, lisp_addr_t *eid_prefix);
    int (*datap_input_packet)(sock_t *sl);
    int (*datap_rtr_input_packet)(sock_t *sl);
    int (*datap_output_packet)(sock_t *sl);
    int (*datap_updated_route)(int command, iface_t *iface, lisp_addr_t *src_pref,
            lisp_addr_t *dst_pref, lisp_addr_t *gw);
    int (*datap_updated_addr)(iface_t *iface,lisp_addr_t *old_addr,lisp_addr_t *new_addr);
    int (*datap_update_link)(iface_t *iface, int old_iface_index, int new_iface_index, int status);

    void *datap_data;
} data_plane_struct_t;

void data_plane_select();

extern data_plane_struct_t dplane_tun;
extern data_plane_struct_t dplane_vpnapi;


#endif /* DATA_PLANE_H_ */
