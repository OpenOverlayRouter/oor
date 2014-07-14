/*
 * lispd_smr.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Write a message to /var/log/syslog
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
 *    Albert López       <alopez@ac.upc.edu>
 *
 */
#ifndef LISPD_SMR_H_
#define LISPD_SMR_H_

#include "lispd_timers.h"

typedef struct _timer_smr_retry_arg{
    lispd_mapping_list   *mapping_list;
    int                  retries;
} timer_smr_retry_arg;

/*
 * Send a solicit map request for each rloc of all eids in the map cahce database
 */
void init_smr(
        timer *timer_elt,
        void  *arg);

/*
 * Send initial Map Register associated to the SMR process
 * We notify to the mapping system the change of mapping
 */
int smr_send_map_reg(lispd_mapping_elt *mapping);

/*
 * Send a map request smr invoked and reprogram the timer to retransmit in case
 * no receive answer.
 */
int solicit_map_request_reply(
        timer *t,
        void *arg);

/*
 * Send a solicit map request of the mapping for each rloc of all eids in the map cahce database
 */
int smr_send_map_req(lispd_mapping_elt *mapping);

/*
 * Free memory of a timer_smr_retry_arg structure
 */
void free_timer_smr_retry_arg(timer_smr_retry_arg *timer_arg);

#endif /*LISPD_SMR_H_*/
