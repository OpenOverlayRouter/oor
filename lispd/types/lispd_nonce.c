/*
 * lispd_nonce.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send registration messages for each database mapping to
 * configured map-servers.
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
 *    Albert Lopez      <alopez@ac.upc.edu>
 */

#include "lispd_nonce.h"
#include <time.h>


/*
 *      requires librt
 */

uint64_t build_nonce(int seed)
{

    uint64_t            nonce;
    uint32_t            nonce_lower;
    uint32_t            nonce_upper;
    struct timespec     ts;

    /*
     * Put nanosecond clock in lower 32-bits and put an XOR of the nanosecond
     * clock with the seond clock in the upper 32-bits.
     */

    clock_gettime(CLOCK_MONOTONIC,&ts);
    nonce_lower = ts.tv_nsec;
    nonce_upper = ts.tv_sec ^ htonl(nonce_lower);

    /*
     * OR in a caller provided seed to the low-order 32-bits.
     */
    nonce_lower |= seed;

    /*
     * Return 64-bit nonce.
     */
    nonce = nonce_upper;
    nonce = (nonce << 32) | nonce_lower;
    return(nonce);
}



nonces_list *new_nonces_list()
{
    nonces_list *nonces;
    if ((nonces = (nonces_list*)malloc(sizeof(nonces_list))) == NULL) {
        lispd_log_msg(LISP_LOG_WARNING, "new_nonces_list: Unable to allocate memory for nonces_list: %s", strerror(errno));
        return (NULL);
    }

    memset(nonces,0,sizeof(nonces_list));

    return (nonces);
}

/*
 * Return true if nonce is found in the nonces list
 */

int check_nonce(
        nonces_list     *nonces,
        uint64_t        nonce){
    int i;
    if (nonces == NULL)
        return (BAD);
    for (i=0;i<nonces->retransmits;i++){
        if (nonces->nonce[i] == nonce){
            return (GOOD);
        }
    }
    return (BAD);
}


/*
 * lisp_print_nonce
 *
 * Print 64-bit nonce in 0x%08x-0x%08x format.
 */
void lispd_print_nonce (
        uint64_t    nonce,
        int         log_level)
{
    uint32_t lower;
    uint32_t upper;

    lower = nonce & 0xffffffff;
    upper = (nonce >> 32) & 0xffffffff;
    lispd_log_msg(log_level,"nonce: 0x%08x-0x%08x\n", htonl(upper), htonl(lower));
}

char * get_char_from_nonce (uint64_t nonce)
{
    static char         nonce_char[2][21];
    static unsigned int i;
    uint32_t            lower          = 0;
    uint32_t            upper          = 0;

    /* Hack to allow more than one addresses per printf line. Now maximum = 2 */
    i++;
    i = i % 2;

    lower = nonce & 0xffffffff;
    upper = (nonce >> 32) & 0xffffffff;
    sprintf(nonce_char[i] , "0x%08x-0x%08x", htonl(upper), htonl(lower));

    return (nonce_char[i]);
}


