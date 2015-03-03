/*
 * lisp_data.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
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
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#ifndef LISP_DATA_H_
#define LISP_DATA_H_

//#include "stdint.h"
#include "../lib/util.h"

 /* LISP data packet header */

 typedef struct lisphdr {
     #ifdef __LITTLE_ENDIAN_BITFIELD
     uint8_t rflags:3;
     uint8_t instance_id:1;
     uint8_t map_version:1;
     uint8_t echo_nonce:1;
     uint8_t lsb:1;
     uint8_t nonce_present:1;
     #else
     uint8_t nonce_present:1;
     uint8_t lsb:1;
     uint8_t echo_nonce:1;
     uint8_t map_version:1;
     uint8_t instance_id:1;
     uint8_t rflags:3;
     #endif
     uint8_t nonce[3];
     uint32_t lsb_bits;
 } lisphdr_t;

/* LISP Data header structure */
typedef struct lisp_data_hdr {
#ifdef LITTLE_ENDIANS
    uint8_t rflags:3;
    uint8_t instance_id:1;
    uint8_t map_version:1;
    uint8_t echo_nonce:1;
    uint8_t lsb:1;
    uint8_t nonce_present:1;
#else
    uint8_t nonce_present:1;
    uint8_t lsb:1;
    uint8_t echo_nonce:1;
    uint8_t map_version:1;
    uint8_t instance_id:1;
    uint8_t rflags:3;
#endif
    uint8_t nonce[3];
    uint32_t lsb_bits;
} lisp_data_hdr_t;


void lisp_data_hdr_init(lisphdr_t *lhdr);

#endif /* LISP_DATA_H_ */
