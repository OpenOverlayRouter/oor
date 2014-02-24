/*
 * lispd_control.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2012 Cisco Systems, Inc, 2012. All rights reserved.
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

#include <defs.h>
#include <lispd_sockets.h>
#include <lisp_xtr.h>
#include <lisp_ms.h>
#include <lisp_rtr.h>



int process_lisp_ctr_msg(struct sock *sl);


void multicast_join_channel(lisp_addr_t *src, lisp_addr_t *grp);
void multicast_leave_channel(lisp_addr_t *src, lisp_addr_t *grp);

#endif /* LISPD_CONTROL_H_ */
