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

/*
 * Send a solicit map request for each proxy itr and rlocs of all eids of the map cahce
 */
void init_smr();

/*
 * Send a map request smr invoked and reprogram the timer to retransmit in case
 * no receive answer.
 */
void solicit_map_request_reply(timer *t, void *arg);

#endif /*LISPD_SMR_H_*/
