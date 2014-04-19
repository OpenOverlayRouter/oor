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

#include "lispd_control.h"
#include <lispd_external.h>
#include "lispd_info_nat.h"
#include <lbuf.h>
#include <cksum.h>

/* only one instance for now */
lisp_ctrl_t *ctrl = lisp_ctrl_create();

lisp_ctrl_t *
lisp_ctrl_create() {
    lisp_ctrl_t *ctrl = calloc(1, sizeof(lisp_ctrl_t));
    ctrl->devices = glist_new_managed(lisp_ctrl_destroy);
    return(ctrl);
}

void
lisp_ctrl_destroy(lisp_ctrl_t *ctrl) {
    glist_del(ctrl->devices);
    free(ctrl);
}


/*  Process a LISP protocol message sitting on
 *  socket s with address family afi */
int
process_lisp_ctr_msg(struct sock *sl) {

    lisp_msg *msg;
    uconn_t uc;
    struct lbuf *packet;
    uint8_t type;
    lisp_msg_type_t type;

    uc.rp = LISP_CONTROL_PORT;

    packet = lbuf_new(MAX_IP_PKT_LEN);
    if (sock_recv(sl->fd, packet, &uc) != GOOD) {
        lmlog(DBG_1, "Couldn't retrieve socket information"
                "for control message! Discarding packet!");
        return (BAD);
    }

    lisp_msg_parse_type(packet, &type);

    /* direct call of ctrl device
     * TODO: check type to decide where to send msg*/
    ctrl_dev_handle_msg(ctrl_dev, packet, &uc);

    lbuf_del(packet);

    return (GOOD);
}

int
ctrl_send_msg(lisp_ctrl_t *ctrl, lbuf_t *b, uconn_t *uc) {
    int sk;
    int dst_afi = lisp_addr_ip_afi(&uc->ra);
    lispd_iface_elt *iface;

    if (lisp_addr_afi(&uc->rp) != LM_AFI_IP) {
        lmlog(DBG_1, "sock_send: dst % of UDP connection is not IP. "
                "Discarding!", lisp_addr_to_char(&uc->ra));
        return(BAD);
    }

    /* FIND the socket where to output the packet
     * TODO: sockmgr should deal with this, once it's
     *       implemented */
    if (lisp_addr_afi(uc->la) == LM_AFI_NO_ADDR) {
        lisp_addr_copy(&uc->la, get_default_ctrl_address(dst_afi));
        sk =  get_default_ctrl_socket(dst_afi);
    } else {
        iface = get_interface_with_address(&uc->la);
        if (iface) {
            sk = get_iface_socket(iface, dst_afi);
        } else {
            sk = get_default_ctrl_socket(dst_afi);
        }
    }

    return(sock_send(sk, b, uc));
}

/* TODO: should change to get_updated_interfaces */
int
ctrl_get_mappings_to_smr(lisp_ctrl_t *ctrl, mapping_t **mappings_to_smr, int *mcount) {
    iface_list_elt *iface_list = NULL;
    mapping_t *m;
    iface_mappings_list *mlist;
    int mappings_ctr, ctr, nb_mappings;

    iface_list = get_head_interface_list();

    while (iface_list) {
        if ((iface_list->iface->status_changed == TRUE)
             || (iface_list->iface->ipv4_changed == TRUE)
             || (iface_list->iface->ipv6_changed == TRUE)) {
            mlist = iface_list->iface->head_mappings_list;
            while (mlist != NULL && mappings_ctr < nb_mappings) {
                if (iface_list->iface->status_changed == TRUE
                    || (iface_list->iface->ipv4_changed == TRUE && mlist->use_ipv4_address == TRUE)
                    || (iface_list->iface->ipv6_changed == TRUE && mlist->use_ipv6_address == TRUE)) {
                    m = mlist->mapping;
                    for (ctr=0; ctr< mappings_ctr; ctr++) {
                        if (mappings_to_smr[ctr] == m) {
                            break;
                        }
                    }
                    if (mappings_to_smr[ctr] != m) {
                        mappings_to_smr[mappings_ctr] = m;
                        mappings_ctr ++;
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
    *mcount = mappings_ctr;
    return(GOOD);
}

void
ctrl_if_addr_update(lispd_iface_elt *iface, lisp_addr_t *old) {

    /* Check if the new address is behind NAT */
    if(nat_aware==TRUE){
        // TODO : To be modified when implementing NAT per multiple interfaces
        nat_status = UNKNOWN;
        if (iface->status == UP){
            initial_info_request_process();
        }
    }

    /* TODO: should store and pass updated rloc in the future
     * The old, and current solution is to keep a mapping between mapping_t
     * and iface to identify mapping_t(s) for which SMRs have to be sent. In
     * the future this should be decoupled and only the affected RLOC should
     * be passed to ctrl_dev */
    ctrl_dev_program_smr();
}

void
ctrl_if_status_update() {
    ctrl_dev_program_smr();
}

/*
 * Multicast Interface to end-hosts
 */

void multicast_join_channel(lisp_addr_t *src, lisp_addr_t *grp) {
    lisp_addr_t *mceid = lisp_addr_build_mc(src, grp);
    re_join_channel(mceid);
    lisp_addr_del(mceid);
}

void multicast_leave_channel(lisp_addr_t *src, lisp_addr_t *grp) {
    lisp_addr_t *mceid = lisp_addr_build_mc(src, grp);
    re_leave_channel(mceid);
    lisp_addr_del(mceid);
}

