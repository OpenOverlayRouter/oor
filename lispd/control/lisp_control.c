/*
 * lispd_control.c
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

#include <unistd.h>

#include "lisp_control.h"
#include "lisp_ctrl_device.h"
#include "lispd_info_nat.h"
#include "iface_list.h"
#include "util.h"
#include "lmlog.h"


static void set_default_rlocs(lisp_ctrl_t *ctrl);
static void set_rlocs(lisp_ctrl_t *ctrl);

static void
set_default_rlocs(lisp_ctrl_t *ctrl)
{
    glist_remove_all(ctrl->default_rlocs);
    if (default_ctrl_iface_v4
        && lisp_addr_is_ip(default_ctrl_iface_v4->ipv4_address)) {
        glist_add(default_ctrl_iface_v4->ipv4_address, ctrl->default_rlocs);
    }

    if (default_ctrl_iface_v6
        && lisp_addr_is_ip(default_ctrl_iface_v6->ipv6_address)) {
        glist_add_tail(default_ctrl_iface_v6->ipv6_address,
                ctrl->default_rlocs);
    }

    glist_entry_t *it;
    LMLOG(DBG_2, "Recomputing default interfaces");
    glist_for_each_entry(it, ctrl->default_rlocs) {
        LMLOG(DBG_2, "  Default iface: %s",
                lisp_addr_to_char(glist_entry_data(it)));
    }
}

static void
set_rlocs(lisp_ctrl_t *ctrl)
{
    iface_list_elt_t *iface_elt;
    iface_t *iface;

    glist_remove_all(ctrl->ipv4_rlocs);
    glist_remove_all(ctrl->ipv6_rlocs);

    iface_elt = head_interface_list;
    while (iface_elt) {
        iface = iface_elt->iface;
        if (!lisp_addr_is_no_addr(iface->ipv4_address)) {
            glist_add_tail(iface->ipv4_address, ctrl->ipv4_rlocs);
        }
        if (!lisp_addr_is_no_addr(iface->ipv6_address)) {
            glist_add_tail(iface->ipv6_address, ctrl->ipv6_rlocs);
        }

        iface_elt = iface_elt->next;
    }

    set_default_rlocs(ctrl);
}

lisp_ctrl_t *
ctrl_create()
{
    lisp_ctrl_t *ctrl = xzalloc(sizeof(lisp_ctrl_t));
    ctrl->devices = glist_new();
    ctrl->default_rlocs = glist_new();
    ctrl->ipv4_rlocs = glist_new();
    ctrl->ipv6_rlocs = glist_new();

    LMLOG(LINF, "Control initialized!");

    return (ctrl);
}

void
ctrl_destroy(lisp_ctrl_t *ctrl)
{
    glist_destroy(ctrl->devices);
    glist_destroy(ctrl->default_rlocs);
    glist_destroy(ctrl->ipv4_rlocs);
    glist_destroy(ctrl->ipv6_rlocs);

    close(ctrl->ipv4_control_input_fd);
    close(ctrl->ipv6_control_input_fd);
    free(ctrl);
}

void
ctrl_init(lisp_ctrl_t *ctrl)
{
    set_default_ctrl_ifaces();

    /* Generate receive sockets for control (4342) and data port (4341) */
    if (default_rloc_afi == -1 || default_rloc_afi == AF_INET) {
        ctrl->ipv4_control_input_fd = open_control_input_socket(AF_INET);
        sockmstr_register_read_listener(smaster, ctrl_recv_msg, ctrl,
                ctrl->ipv4_control_input_fd);
    }

    if (default_rloc_afi == -1 || default_rloc_afi == AF_INET6) {
        ctrl->ipv6_control_input_fd = open_control_input_socket(AF_INET6);
        sockmstr_register_read_listener(smaster, ctrl_recv_msg, ctrl,
                ctrl->ipv6_control_input_fd);
    }

    set_rlocs(ctrl);

    LMLOG(DBG_1, "Control initialized");
}

/*  Process a LISP protocol message sitting on
 *  socket s with address family afi */
int
ctrl_recv_msg(sock_t *sl)
{
    uconn_t uc;
    lbuf_t *b;
    lisp_ctrl_t *ctrl;
    lisp_ctrl_dev_t *dev;

    ctrl = sl->arg;
    /* Only one device supported for now */
    dev = glist_first_data(ctrl->devices);

    uc.lp = LISP_CONTROL_PORT;

    b = lisp_msg_create_buf();

    if (sock_ctrl_recv(sl->fd, b, &uc) != GOOD) {
        LMLOG(DBG_1, "Couldn't retrieve socket information"
                "for control message! Discarding packet!");
        return (BAD);
    }

    lbuf_reset_lisp(b);

    LMLOG(DBG_1, "Received %s, IP: %s -> %s, UDP: %d -> %d",
            lisp_msg_hdr_to_char(b), lisp_addr_to_char(&uc.ra),
            lisp_addr_to_char(&uc.la), uc.rp, uc.lp);

    /* direct call of ctrl device
     * TODO: check type to decide where to send msg*/
    ctrl_dev_recv(dev, b, &uc);

    lbuf_del(b);

    return (GOOD);
}

int
ctrl_send_msg(lisp_ctrl_t *ctrl, lbuf_t *b, uconn_t *uc)
{
    int ret;

    if (lisp_addr_afi(&uc->ra) != LM_AFI_IP) {
        LMLOG(DBG_2, "ctrl_send_msg: dst %s of UDP connection not IP. "
                "Discarding!", lisp_addr_to_char(&uc->la),
                lisp_addr_to_char(&uc->ra));
        return(BAD);
    }

    ret = sock_ctrl_send(uc, b);

    if (ret != GOOD) {
        LMLOG(DBG_1, "FAILED TO SEND \n From RLOC: %s -> %s",
                lisp_addr_to_char(&uc->la), lisp_addr_to_char(&uc->ra));
        return(BAD);
    } else {
        LMLOG(DBG_1, "Sent message IP: %s -> %s UDP: %d -> %d",
                lisp_addr_to_char(&uc->la), lisp_addr_to_char(&uc->ra),
                uc->lp, uc->rp);
        return(GOOD);
    }
}

/* TODO: should change to get_updated_interfaces */
int
ctrl_get_mappings_to_smr(lisp_ctrl_t *ctrl, glist_t *mappings_to_smr)
{
    iface_list_elt_t *iface_list = NULL;
    mapping_t *m;
    iface_map_list_t *mlist;
    glist_entry_t *it;

    iface_list = ifaces_list_head();

    while (iface_list) {
        if ((iface_list->iface->status_changed == TRUE)
                || (iface_list->iface->ipv4_changed == TRUE)
                || (iface_list->iface->ipv6_changed == TRUE)) {
            mlist = iface_list->iface->head_mappings_list;
            while (mlist != NULL) {
                if (iface_list->iface->status_changed == TRUE
                        || (iface_list->iface->ipv4_changed == TRUE
                                && mlist->use_ipv4_address == TRUE)
                        || (iface_list->iface->ipv6_changed == TRUE
                                && mlist->use_ipv6_address == TRUE)) {
                    m = mlist->mapping;

                    glist_for_each_entry(it, mappings_to_smr) {
                        if (glist_entry_data(it) == m) {
                            break;
                        }
                    }

                    if (glist_entry_data(it) != m) {
                        glist_add(m, mappings_to_smr);
                    }
                }
                mlist = mlist->next;
            }
        }

        iface_list->iface->status_changed = FALSE;
        iface_list->iface->ipv4_changed = FALSE;
        iface_list->iface->ipv6_changed = FALSE;
        iface_list = iface_list->next;
    }

    return (GOOD);
}

void
ctrl_if_addr_update(lisp_ctrl_t *ctrl, iface_t *iface, lisp_addr_t *old,
        lisp_addr_t *new)
{
    lisp_ctrl_dev_t *dev;

    dev = glist_first_data(ctrl->devices);

    /* Check if the new address is behind NAT */
    if (nat_aware == TRUE) {
        /* TODO : To be modified when implementing NAT per multiple
         * interfaces */
        nat_status = UNKNOWN;
        if (iface->status == UP) {
            /* TODO: fix nat
            initial_info_request_process(); */
        }
    }

    /* TODO: should store and pass updated rloc in the future
     * The old, and current solution is to keep a mapping between mapping_t
     * and iface to identify mapping_t(s) for which SMRs have to be sent. In
     * the future this should be decoupled and only the affected RLOC should
     * be passed to ctrl_dev */
    ctrl_if_event(dev);
    set_rlocs(ctrl);
}

void
ctrl_if_status_update(lisp_ctrl_t *ctrl, iface_t *iface)
{
    lisp_ctrl_dev_t *dev;
    dev = glist_first_data(ctrl->devices);
    ctrl_if_event(dev);
    set_rlocs(ctrl);
}

glist_t *
ctrl_default_rlocs(lisp_ctrl_t *c)
{
    return (c->default_rlocs);
}

glist_t *
ctrl_rlocs(lisp_ctrl_t *c, int afi)
{
    switch(afi) {
    case AF_INET:
        return(c->ipv4_rlocs);
    case AF_INET6:
        return(c->ipv6_rlocs);
    }
    return(NULL);
}

lisp_addr_t *
ctrl_default_rloc(lisp_ctrl_t *c, int afi)
{
    lisp_addr_t *loc = NULL;
    if (lisp_addr_ip_afi(glist_first_data(c->default_rlocs)) == afi) {
        loc = glist_first_data(c->default_rlocs);
    } else if (lisp_addr_ip_afi(glist_last_data(c->default_rlocs)) == afi) {
        loc = glist_last_data(c->default_rlocs);
    }
    return (loc);
}

fwd_entry_t *
ctrl_get_forwarding_entry(packet_tuple_t *tuple)
{
    lisp_ctrl_dev_t *dev;
    dev = glist_first_data(lctrl->devices);
    return (ctrl_dev_get_fwd_entry(dev, tuple));
}

int
ctrl_register_device(lisp_ctrl_t *ctrl, lisp_ctrl_dev_t *dev)
{
    LMLOG(LINF, "Device working in mode %d registering with control", dev->mode);
    glist_add(dev, ctrl->devices);
    return(GOOD);
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

