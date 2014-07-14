/*
 * hmac.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Implementation for UDP checksum.
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
 *    Albert López   <alopez@ac.upc.edu>
 *
 */

#ifndef HMAC_H_
#define HMAC_H_

#include <stdint.h>

uint16_t get_auth_data_len(uint8_t key_id);

int complete_auth_fields(uint8_t key_id,
                         char *key,
                         void *packet,
                         int pckt_len,
                         void *auth_data_pos);

int check_auth_field(uint8_t key_id,
                     char *key,
                     void *packet,
                     int pckt_len,
                     void *auth_data_pos);

#endif /* HMAC_H_ */
