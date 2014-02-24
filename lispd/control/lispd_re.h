/*
 * lispd_re_control.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Various routines to manage the list of interfaces.
 *
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 *    Florin Coras   <fcoras@ac.upc.edu>
 *
 */

#ifndef LISPD_RE_CONTROL_H_
#define LISPD_RE_CONTROL_H_

#include "lispd_remdb.h"
#include <lispd_mapping.h>
#include <lisp_messages.h>

#define MCASTMIN4   0xE0000000
#define MCASTMAX4   0xEFFFFFFF

int re_join_channel(lisp_addr_t *mceid);
int re_leave_channel(lisp_addr_t *mceid);

int re_recv_join_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair);


int re_recv_leave_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair);
int re_send_leave_ack();

int re_send_join_request(mapping_t *ch_mapping);
int re_recv_join_ack(lisp_addr_t *eid, uint32_t nonce);

int re_send_leave_request(lisp_addr_t *mceid);
int re_recv_leave_ack(lisp_addr_t *eid, uint32_t nonce);


re_upstream_t        *re_get_upstream(lisp_addr_t *eid);
remdb_t             *re_get_jib(lisp_addr_t *mcaddr);

glist_t    *re_get_orlist(lisp_addr_t *addr);


//lisp_addr_t *re_build_mceid(lisp_addr_t *src, lisp_addr_t *grp);


//int mrsignaling_recv_mrequest(
//        uint8_t *offset,
//        lisp_addr_t *src_eid,
//        lisp_addr_t *local_rloc,
//        lisp_addr_t *remote_rloc,
//        uint16_t    dport,
//        uint64_t    nonce);
//
//int mrsignaling_send_mreply(
//        lispd_mapping_elt *registered_mapping,
//        lisp_addr_t *local_rloc,
//        lisp_addr_t *remote_rloc,
//        uint16_t dport,
//        uint64_t nonce,
//        mrsignaling_flags_t mc_flags);

//void mrsignaling_set_flags_in_pkt(uint8_t *offset, mrsignaling_flags_t mc_flags);
//int mrsignaling_recv_mreply(mapping_record *record,  uint64_t nonce);


#endif /* LISPD_RE_CONTROL_H_ */
