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

#ifndef LISPD_CONTROL_H_
#define LISPD_CONTROL_H_

#include "../iface_list.h"
#include "../lib/sockets.h"
#include "../liblisp/liblisp.h"
#include "control-data-plane/control-data-plane.h"

#define NO_AFI_SUPPOT  	0
#define IPv4_SUPPORT	1
#define IPv6_SUPPORT	2

typedef struct lisp_ctrl lisp_ctrl_t;

struct lisp_ctrl {
    glist_t *devices;
    /* move ctrl interface here */

    int supported_afis;

    glist_t *rlocs;
    glist_t *ipv4_rlocs;
    glist_t *ipv6_rlocs;
    control_dplane_struct_t *control_data_plane;
};

lisp_ctrl_t *ctrl_create();
void ctrl_destroy(lisp_ctrl_t *ctrl);
void ctrl_init(lisp_ctrl_t *ctrl);

void ctrl_update_iface_info(lisp_ctrl_t *ctrl);


lisp_addr_t *ctrl_default_rloc(lisp_ctrl_t *c, int afi);
/*
 * Return the default control rlocs in a list that shoud be released
 * by the user.
 * @param ctrl Lisp controler to be used
 * @return glist_t * with the lisp_addr_t * of the default rlocs
 */
glist_t *ctrl_default_rlocs(lisp_ctrl_t * ctrl);
glist_t *ctrl_rlocs(lisp_ctrl_t *ctrl);
glist_t *ctrl_rlocs_with_afi(lisp_ctrl_t *c, int afi) ;
inline int ctrl_supported_afis(lisp_ctrl_t *ctrl);

void ctrl_if_addr_update(lisp_ctrl_t *, iface_t *, lisp_addr_t *,
        lisp_addr_t *);
void ctrl_if_link_update(lisp_ctrl_t *ctrl, iface_t *iface, int old_iface_index,
        int new_iface_index, int status);
void ctrl_route_update(lisp_ctrl_t *ctrl, int command, iface_t *iface,lisp_addr_t *src_pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway);
fwd_info_t *ctrl_get_forwarding_info(packet_tuple_t *);
int ctrl_register_device(lisp_ctrl_t *ctrl, lisp_ctrl_dev_t *dev);

int ctrl_register_eid_prefix(lisp_ctrl_dev_t *dev, lisp_addr_t *eid_prefix);

int ctrl_unregister_eid_prefix(lisp_ctrl_dev_t *dev, lisp_addr_t *eid_prefix);


void multicast_join_channel(lisp_addr_t *src, lisp_addr_t *grp);
void multicast_leave_channel(lisp_addr_t *src, lisp_addr_t *grp);

#endif /* LISPD_CONTROL_H_ */
