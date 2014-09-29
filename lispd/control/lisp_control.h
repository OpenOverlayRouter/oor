/*
 * lispd_control.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#ifndef LISPD_CONTROL_H_
#define LISPD_CONTROL_H_

#include "sockets.h"
#include "liblisp.h"
#include "iface_list.h"

typedef struct lisp_ctrl lisp_ctrl_t;

struct lisp_ctrl {
    glist_t *devices;
    /* move ctrl interface here */

    int ipv4_control_input_fd;
    int ipv6_control_input_fd;

    glist_t *rlocs;
    glist_t *ipv4_rlocs;
    glist_t *ipv6_rlocs;
    glist_t *default_rlocs;
};

lisp_ctrl_t *ctrl_create();
void ctrl_destroy(lisp_ctrl_t *ctrl);
void ctrl_init(lisp_ctrl_t *ctrl);

int ctrl_recv_msg(struct sock *sl);
int ctrl_send_msg(lisp_ctrl_t *, lbuf_t *, uconn_t *);


glist_t *ctrl_default_rlocs(lisp_ctrl_t *c);
lisp_addr_t *ctrl_default_rloc(lisp_ctrl_t *c, int afi);
glist_t *ctrl_rlocs(lisp_ctrl_t *c, int afi) ;

void ctrl_if_addr_update(lisp_ctrl_t *, iface_t *, lisp_addr_t *,
        lisp_addr_t *);
void ctrl_if_status_update(lisp_ctrl_t *, iface_t *);
fwd_entry_t *ctrl_get_forwarding_entry(packet_tuple_t *);
int ctrl_register_device(lisp_ctrl_t *ctrl, lisp_ctrl_dev_t *dev);


void multicast_join_channel(lisp_addr_t *src, lisp_addr_t *grp);
void multicast_leave_channel(lisp_addr_t *src, lisp_addr_t *grp);

#endif /* LISPD_CONTROL_H_ */
