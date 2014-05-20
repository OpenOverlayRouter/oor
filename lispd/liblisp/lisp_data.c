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


#include "lisp_data.h"

void
lisp_data_hdr_init(lisphdr_t *lhdr)
{
    lhdr->echo_nonce = 0;
    lhdr->lsb = 0;
    lhdr->lsb_bits = 0;
    lhdr->map_version = 0;
    lhdr->nonce[0] = 0;
    lhdr->nonce[1] = 0;
    lhdr->nonce[2] = 0;
    lhdr->nonce_present = 0;
    lhdr->rflags = 0;
}
