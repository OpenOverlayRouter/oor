/*
 * lispd_syslog.c
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
 *    David Meyer       <dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

#include "lispd_external.h"

void set_up_syslog(void)
{

    setlogmask(LOG_UPTO(LOG_INFO));
    openlog(LISPD, LOG_CONS, LOG_USER);
 
    if (!daemonize) {           /* print it to the user if not a daemon */
        setlogmask(LOG_UPTO(LOG_DEBUG));
        openlog(LISPD, LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
    }

    syslog(LOG_INFO, "Starting up...");

}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
