/*
 * lispd_afi.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
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
 *
 */
#ifndef LISPD_AFI_H_
#define LISPD_AFI_H_

#include "lispd.h"
#include "lispd_local_db.h"

/*
 * Reads the address information from the packet and fill the lispd_identifier_elt element
 */
int pkt_process_eid_afi(char  **offset, lispd_identifier_elt *identifier);

/*
 * Reads the address information from the packet and fill the lispd_locator_elt element
 */
int pkt_process_rloc_afi(char  **offset, lispd_locator_elt *locator);

#endif /*LISPD_AFI_H_*/
