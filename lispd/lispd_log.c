/*
 * lispd_log.c
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
 *    Alberto Rodriguez Natal <arnatal@ac.ucp.edu>
 *
 */

#include "lispd_external.h"
#include <syslog.h>
#include <stdarg.h>

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

// For reference purpose
//
// #define LOG_EMERG       0       /* system is unusable */
// #define LOG_ALERT       1       /* action must be taken immediately */
// #define LOG_CRIT        2       /* critical conditions */
// #define LOG_ERR         3       /* error conditions */
// #define LOG_WARNING     4       /* warning conditions */
// #define LOG_NOTICE      5       /* normal but significant condition */
// #define LOG_INFO        6       /* informational */
// #define LOG_DEBUG       7       /* debug-level messages */



void lispd_log_msg(int log_level, const char *format, ...)
{
    va_list args;
    char *log_name; /* To store the log level in string format for printf output */
    

    
    va_start (args, format);


    if (daemonize == TRUE){     /* syslog output */
        
        vsyslog(log_level,format,args);
        
    }else{                      /* printf output */

        switch (log_level){
            case LOG_EMERG:
                log_name = "EMERG";
                break;
            case LOG_ALERT:
                log_name = "ALERT";
                break;
            case LOG_CRIT:
                log_name = "CRIT";
                break;
            case LOG_ERR:
                log_name = "ERR";
                break;
            case LOG_WARNING:
                log_name = "WARNING";
                break;
            case LOG_NOTICE:
                log_name = "NOTICE";
                break;
            case LOG_INFO:
                log_name = "INFO";
                break;
            case LOG_DEBUG:
                log_name = "DEBUG";
                break;
        }

        printf("%s: ",log_name);
        vfprintf(stdout,format,args);
        printf("\n");
        
    }

    va_end (args);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
