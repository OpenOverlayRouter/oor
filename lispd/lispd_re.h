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

#include "defs_re.h"

int re_join_channel(ip_addr_t *src, ip_addr_t *grp);
int re_leave_channel(ip_addr_t *src, ip_addr_t *grp);

int re_process_join_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair, mrsignaling_flags_t *mc_flags);
int re_process_leave_request(lisp_addr_t *ch, lisp_addr_t *rloc_pair);
int re_send_join_request(lisp_addr_t *mceid);
lispd_generic_list_t *re_get_orlist(mc_addr_t *addr);

lisp_addr_t *re_build_mceid(ip_addr_t *src, ip_addr_t *grp);

void multicast_join_channel(ip_addr_t *src, ip_addr_t *grp);
void multicast_leave_channel(ip_addr_t *src, ip_addr_t *grp);
int mrsignaling_process_mreq_message(uint8_t **offset, mrsignaling_flags_t *mc_flags);
int mrsignaling_process_mrep_message(uint8_t **offset, mrsignaling_flags_t *mc_flags);



#endif /* LISPD_RE_CONTROL_H_ */
