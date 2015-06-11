/*
 * lispd_api_netconf.h
 *
 * This file is part of the LISPmob implementation.
 * It connects the LISPmob API to NETCONF
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

#include "../lispd/defs.h"
#include "../lispd/lispd_api.h"

int lmapi_nc_node_accessed(lmapi_connection_t *conn, int dev, int trgt, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error);
