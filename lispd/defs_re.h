/*
 * defs_re.c
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

#ifndef DEFS_RE_H_
#define DEFS_RE_H_

//#include "lispd_lib.h"
#include "lispd_re.h"

//#include "lispd_afi.h"
#include "defs.h"




#define MCASTMIN4   0xE0000000
#define MCASTMAX4   0xEFFFFFFF

/* foreach for old lists */
#define list_for_each_old(pos, head) \
    for (pos = (head)->next; pos != (NULL); \
            pos = pos->next)



#endif /* DEFS_RE_H_ */
