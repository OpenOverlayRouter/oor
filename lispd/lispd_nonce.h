/*
 * lispd_nonce.h
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

#ifndef LISPD_NONCE_H_
#define LISPD_NONCE_H_

#include "lispd.h"

typedef struct{
    uint8_t     retransmits;
    uint64_t    nonce[LISPD_MAX_NONCES_LIST];
}nonces_list;



/*
 *      Generates a nonce random number
 *      requires librt
 */

uint64_t build_nonce(int seed);


/*
 * Create and reserve space for a nonces_lits structure
 */
nonces_list *new_nonces_list();

/*
 * Return true if nonce is found in the nonces list
 */

int check_nonce(nonces_list   *nonces, uint64_t nonce);


/*
 * Print 64-bit nonce in 0x%08x-0x%08x format.
 */
void lispd_print_nonce (uint64_t nonce);

#endif /* LISPD_NONCE_H_ */
