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


#include "../oor_external.h"
#include "../lib/packets.h"
#include "../lib/sockets.h"
#include "oor_ctrl_device.h"


static ctrl_dev_class_t *reg_ctrl_dev_cls[4] = {
        &xtr_ctrl_class,
        &ms_ctrl_class,
        &xtr_ctrl_class,/* RTR */
        &xtr_ctrl_class,/* MN */
};

inline oor_dev_type_e
lisp_ctrl_dev_mode(oor_ctrl_dev_t *dev){
    return dev->mode;
}
inline oor_ctrl_t *
lisp_ctrl_dev_get_ctrl_t(oor_ctrl_dev_t *dev){
    return dev->ctrl;
}

static ctrl_dev_class_t *
ctrl_dev_class_find(oor_dev_type_e type)
{
    return(reg_ctrl_dev_cls[type]);
}

int
ctrl_dev_recv(oor_ctrl_dev_t *dev, lbuf_t *b, uconn_t *uc)
{
    return(dev->ctrl_class->recv_msg(dev, b, uc));
}

void
ctrl_dev_run(oor_ctrl_dev_t *dev)
{
    dev->ctrl_class->run(dev);
}

int
ctrl_dev_create(oor_dev_type_e type, oor_ctrl_dev_t **devp)
{
    oor_ctrl_dev_t *dev;
    ctrl_dev_class_t *class;

    *devp = NULL;

    /* find type of device */
    class = ctrl_dev_class_find(type);
    dev = class->alloc();
    dev->mode =type;
    dev->ctrl_class = class;
    dev->ctrl_class->construct(dev);
    ctrl_dev_set_ctrl(dev, lctrl);
    *devp = dev;
    return(GOOD);
}

void
ctrl_dev_destroy(oor_ctrl_dev_t *dev)
{
    if (!dev) {
        return;
    }

    dev->ctrl_class->destruct(dev);
    dev->ctrl_class->dealloc(dev);
}

int
send_msg(oor_ctrl_dev_t *dev, lbuf_t *b, uconn_t *uc)
{
    return(dev->ctrl->control_data_plane->control_dp_send_msg(dev->ctrl, b, uc));
}

int
ctrl_dev_if_link_update(oor_ctrl_dev_t *dev, char *iface_name, uint8_t status)
{
    return(dev->ctrl_class->if_link_update(dev, iface_name, status));

}

int
ctrl_dev_if_addr_update(oor_ctrl_dev_t *dev, char *iface_name, lisp_addr_t *old_addr,
        lisp_addr_t *new_addr, uint8_t status)
{
    return(dev->ctrl_class->if_addr_update(dev, iface_name, old_addr, new_addr, status));
}

int
ctrl_dev_route_update(oor_ctrl_dev_t *dev, int command, char *iface_name ,lisp_addr_t *pref,
        lisp_addr_t *dst_pref, lisp_addr_t *gateway)
{
    return(dev->ctrl_class->route_update(dev,command,iface_name,pref,dst_pref,gateway));
}

fwd_info_t *
ctrl_dev_get_fwd_entry(oor_ctrl_dev_t *dev, packet_tuple_t *tuple)
{
    return(dev->ctrl_class->get_fwd_entry(dev, tuple));
}

inline oor_dev_type_e
ctrl_dev_mode(oor_ctrl_dev_t *dev)
{
    return (dev->mode);
}

inline oor_ctrl_t *
ctrl_dev_ctrl(oor_ctrl_dev_t *dev)
{
    return (dev->ctrl);
}

int
ctrl_dev_set_ctrl(oor_ctrl_dev_t *dev, oor_ctrl_t *ctrl)
{
    dev->ctrl = ctrl;
    ctrl_register_device(ctrl, dev);
    return(GOOD);
}

char *
ctrl_dev_type_to_char(oor_dev_type_e type)
{
    static char device[15];
    *device='\0';
    switch (type){
    case xTR_MODE:
        strcpy(device,"xTR");
        break;
    case MS_MODE:
        strcpy(device,"Map Server");
        break;
    case RTR_MODE:
        strcpy(device,"RTR");
        break;
    case MN_MODE:
        strcpy(device,"Mobile Node");
        break;
    default:
        strcpy(device,"Unknown");
        break;
    }
    return (device);
}
