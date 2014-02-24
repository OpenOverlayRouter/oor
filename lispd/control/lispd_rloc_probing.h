/*
 * lispd_rloc_probing.h
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
 *    Albert López      <alopez@ac.upc.edu>
 *
 */

#ifndef LISPD_RLOC_PROBING_H_
#define LISPD_RLOC_PROBING_H_

#include "lispd_locator.h"
#include "lispd_map_cache_db.h"

typedef struct _timer_rloc_prob_argument{
    mapping_t   *mapping;
    locator_t   *locator;
} timer_rloc_probe_argument;



timer_rloc_probe_argument *new_timer_rloc_probe_argument(
        mapping_t       *mapping,
        locator_t       *locator);

int rloc_probing(
    timer *t,
    void *arg);

/*
 * Program RLOC probing for each locator of the mapping
 */

void programming_rloc_probing(mapping_t *mapping);

/*
 * Program RLOC probing for each proxy-ETR
 */

void programming_petr_rloc_probing();

#endif /*LISPD_RLOC_PROBING_H_*/
