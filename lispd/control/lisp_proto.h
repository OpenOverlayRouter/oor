/*
 * lisp_proto.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
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

#ifndef LISP_PROTO_H_
#define LISP_PROTO_H_

#include <liblisp.h>
#include <lisp_ctrl_device.h>

/* Generic timer argument that includes the device as parameter. As a rule,
 * both 'dev' and 'data' should be pointers to existing data structure that
 * don't require the caller to free them */
typedef struct timer_arg_t_ {
    void *dev;
    void *data;
} timer_arg_t;

int process_map_notify(lisp_ctrl_dev_t *, lbuf_t *);
void send_all_smr(lisp_ctrl_dev_t *);
int send_smr_invoked_map_request(lisp_ctrl_dev_t *, mcache_entry_t *);

int build_and_send_map_reg(lisp_ctrl_dev_t *, mapping_t *, char *,
        lisp_key_type_t );

int program_smr(lisp_ctrl_dev_t *, int time);
int program_map_register(lisp_ctrl_dev_t *dev, int time);
int map_register_process();

#endif /* LISP_PROTO_H_ */
