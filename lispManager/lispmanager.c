/*
 * lispmanager.c
 *
 * Simple wrapper code to start/stop lispd and
 * install/remove the kernel module. Called
 * via the lisp app or from the command-line.
 *
 * Options:
 *
 * lispmanager [start|stop] stops or starts the lispd process
 * lispmanager [install|remove] installs or removes the kernel module
 *
 *
 * Copyright (C) 2009-2012 Cisco Systems, Inc, 2012. All rights reserved.
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
 *    Chris White       <chris@logicalelegance.com>
 *    David Meyer       <dmm@cisco.com>
 *
 */

//#include "lispmanager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *daemonCommand = "/system/bin/lispd -Df /sdcard/lispd.conf";
const char *killCommand = "/system/bin/kill -15";
const char *lockFilename = "/sdcard/lispd.lock";
const char *procCheckCommand = "/system/xbin/pgrep -nl lispd";

int startDaemon(void)
{
    int status;
    printf("Starting lisp daemon\n");
    status = system(daemonCommand);
    printf("\n");
    return(status);
}

int stopDaemon(void)
{
    FILE *lockFile = fopen(lockFilename, "r");
    int pid;
    char killstring[128];
    int status;

    if (!lockFile) {
        printf("lispd is already not running.\n");
        return(-1);
    }
    fscanf(lockFile, "%d", &pid);
    sprintf(killstring, "%s %d", killCommand, pid);
    status = system(killstring);
    printf("\n");
    return(status);
}

void getStatus(void)
{
    FILE *procPipe;
    char  statusString[128];

    procPipe = popen(procCheckCommand, "r");

    if (!procPipe) {
        printf("Failed to execute pgrep.\n");
        exit(-1);
    }
    memset(statusString, 0, 128);
    fgets(statusString, 128, procPipe);
    if (strstr(statusString, "lispd")) {
        printf("lispd: running.\n");
        exit(0);
    }

    printf("lispd: not running.\n");
    exit(1);
}

int main(int argc, char **argv)
{

    if (argc != 2) {
        printf("Usage: \n");
        printf("lispmanager [start|stop]: stops or starts the lispd process\n");
        printf("lispmanager status: displays lisp process status.\n");
        exit(-1);
    }

    if (!strncmp(argv[1], "start", 5)) {
        exit(startDaemon());
    } else if (!strncmp(argv[1], "stop", 4)) {
        exit(stopDaemon());
    } else if (!strncmp(argv[1], "status", 6)) {
        getStatus();
    } else {
        exit(-1);
    }
    exit(0);
    return 0;
}
