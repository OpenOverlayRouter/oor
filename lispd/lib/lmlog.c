/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "lmlog.h"
#ifdef ANDROID
#include <android/log.h>
#endif

FILE *fp = NULL;

inline void lispd_log(int log_level, char *log_name, const char *format,
        va_list args);


void
llog(int lisp_log_level, const char *format, ...)
{
    va_list args;
    char *log_name; /* To store the log level in string format for printf output */
    int log_level;

    va_start(args, format);

    switch (lisp_log_level){
    case LCRIT:
        log_name = "CRIT";
        log_level = LOG_CRIT;
        lispd_log(log_level, log_name, format, args);
        break;
    case LERR:
        log_name = "ERR";
        log_level = LOG_ERR;
        lispd_log(log_level, log_name, format, args);
        break;
    case LWRN:
        log_name = "WARNING";
        log_level = LOG_WARNING;
        lispd_log(log_level, log_name, format, args);
        break;
    case LINF:
        log_name = "INFO";
        log_level = LOG_INFO;
        lispd_log(log_level, log_name, format, args);
        break;
    case LDBG_1:
        if (debug_level > 0){
            log_name = "DEBUG";
            log_level = LOG_DEBUG;
            lispd_log(log_level, log_name, format, args);
        }
        break;
    case LDBG_2:
        if (debug_level > 1){
            log_name = "DEBUG-2";
            log_level = LOG_DEBUG;
            lispd_log(log_level, log_name, format, args);
        }
        break;
    case LDBG_3:
        if (debug_level > 2){
            log_name = "DEBUG-3";
            log_level = LOG_DEBUG;
            lispd_log(log_level, log_name, format, args);
        }
        break;
    default:
        log_name = "LOG";
        log_level = LOG_INFO;
        lispd_log(log_level, log_name, format, args);
        break;
    }


    va_end (args);
}

inline void
lispd_log(int log_level, char *log_name, const char *format,
        va_list args)
{
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

#ifdef ANDROID
    __android_log_vprint(ANDROID_LOG_INFO, "LISPmob-C ==>", format,args);

    if (fp != NULL){
        fprintf(fp,"[%d/%d/%d %d:%d:%d] %s: ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, log_name);
        vfprintf(fp,format,args);
        fprintf(fp,"\n");
        fflush(fp);
    }else{
        vsyslog(log_level,format,args);
    }
#else
    if (daemonize){
        if (fp != NULL){
            fprintf(fp,"[%d/%d/%d %d:%d:%d] %s: ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, log_name);
            vfprintf(fp,format,args);
            fprintf(fp,"\n");
            fflush(fp);
        }else{
            vsyslog(log_level,format,args);
        }
    }else{
        printf("[%d/%d/%d %d:%d:%d] %s: ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, log_name);
        vfprintf(stdout,format,args);
        printf("\n");
    }
#endif
}

void
open_log_file(char *log_file)
{
    if (log_file == NULL){
        return;
    }
    /* Overwrite log file in each start */
    fp = freopen(log_file, "w", stderr);
    if (fp == NULL){
        LMLOG(LERR,"Couldn't open the log file %s: %s. Using  syslog",
                log_file, strerror(errno));
    }
}

void
close_log_file()
{
    if (fp != NULL){
        fclose (fp);
    }
}
