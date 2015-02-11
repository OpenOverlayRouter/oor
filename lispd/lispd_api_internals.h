/*
 * lispd_api.h
 *
 * This file is part of LISPmob implementation. It defines the API to
 * interact with LISPmob internals.
 *
 * Copyright (C) The LISPmob project, 2014. All rights reserved.
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
 */

#include "lispd_api.h"


/* API main loop */
void lmapi_loop(lmapi_connection_t *conn);

/* Initialize API system (server) */
int lmapi_init_server(lmapi_connection_t *conn);


