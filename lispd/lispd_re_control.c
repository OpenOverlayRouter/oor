/*
 * lispd_re_control.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Necessary logic to handle incoming map replies.
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
 *    Florin Coras  <fcoras@ac.upc.edu>
 *
 */

#include "defs_re.h"

void join_re_channel(lisp_addr_t src, lisp_addr_t group){
    printf("------ > Request to JOIN RE channel (%s, %s). Still not implemented! \n",
            get_char_from_lisp_addr_t(src), get_char_from_lisp_addr_t(group));
}

void leave_re_channel(lisp_addr_t src, lisp_addr_t group){
    printf("------ > Request to LEAVE RE channel (%s, %s). Still not implemented! \n",
            get_char_from_lisp_addr_t(src), get_char_from_lisp_addr_t(group));
}
