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

#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <time.h>

#include "lisp_nonce.h"
#include "../lib/lmlog.h"
#include "../lib/util.h"


/*  Generates a nonce random number. Requires librt */
uint64_t
nonce_build(int seed)
{

    uint64_t nonce;
    uint32_t nonce_lower;
    uint32_t nonce_upper;
    struct timespec ts;

    /*
     * Put nanosecond clock in lower 32-bits and put an XOR of the nanosecond
     * clock with the seond clock in the upper 32-bits.
     */

    clock_gettime(CLOCK_MONOTONIC, &ts);
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
    return (nonce);
}

uint64_t
nonce_build_time()
{
    return(nonce_build((unsigned int) time(NULL)));
}

nonces_list_t *
nonces_list_new()
{
    nonces_list_t *nonces;
    nonces = xzalloc(sizeof(nonces_list_t));
    return (nonces);
}

/* Return true if nonce is found in the nonces list */
int
nonce_check(nonces_list_t *nonces, uint64_t nonce)
{
    int i;
    if (nonces == NULL){
        return (BAD);
    }
    for (i = 0; i < nonces->retransmits; i++) {
        if (nonces->nonce[i] == nonce) {
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
void
lispd_print_nonce(uint64_t nonce, int log_level)
{
    uint32_t lower;
    uint32_t upper;

    lower = nonce & 0xffffffff;
    upper = (nonce >> 32) & 0xffffffff;
    LMLOG(log_level, "nonce: 0x%08x-0x%08x\n", htonl(upper), htonl(lower));
}

char *
nonce_to_char(uint64_t nonce)
{
    static char nonce_char[2][21];
    static unsigned int i;

    /* Hack to allow more than one addresses per printf line. Now maximum = 2 */
    i++;
    i = i % 2;
    *nonce_char[i] = '\0';
    sprintf(nonce_char[i], "%#" PRIx64, nonce);

    return (nonce_char[i]);
}

