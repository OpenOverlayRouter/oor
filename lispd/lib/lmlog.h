/*
 * lmlog.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Write log messages
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
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 *    Florin Coras <fcoras@ac.upc.edu>
 *
 */

#ifndef LMLOG_H_
#define LMLOG_H_

#include "../lispd_external.h"

extern int debug_level;

/* If these set of defines is modified, check the function is_loggable() */

#define LISP_LOG_CRIT        1       /* critical conditions -> Exit program */
#define LISP_LOG_ERR         2       /* error conditions -> Not exit but should be considered by user */
#define LISP_LOG_WARNING     3       /* warning conditions -> Low level errors. Program doesn't finish */
#define LISP_LOG_INFO        4       /* informational -> Initial configuration, SMRs, interface change status*/
#define LISP_LOG_DEBUG_1     5       /* low debug-level messages -> Control message */
#define LISP_LOG_DEBUG_2     6       /* medium debug-level messages -> Errors in received packets. Wrong AFI, ...  */
#define LISP_LOG_DEBUG_3     7       /* high debug-level messages -> Log for each received or generated packet */

#define LCRIT    1
#define LERR     2
#define LWRN     3
#define LINF     4
#define DBG_1   5
#define DBG_2   6
#define DBG_3   7



#define LMLOG(...) LLOG(__VA_ARGS__)

#define LLOG(level__, ...)                  \
    do {                                    \
        if (is_loggable(level__)) {         \
            llog(level__, __VA_ARGS__);     \
        }                                   \
    } while (0)

void llog(int lisp_log_level, const char *format, ...);


/* True if log_level is enough to print results */
static inline int is_loggable(int log_level)
{
    if (log_level < LISP_LOG_DEBUG_1)
        return (1);
    else if (log_level <= LISP_LOG_INFO + debug_level)
        return (1);
    return (0);
}


#endif /*LMLOG_H_*/
