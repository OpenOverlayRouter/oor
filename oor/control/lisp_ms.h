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

#ifndef LISP_MS_H_
#define LISP_MS_H_

#include "oor_ctrl_device.h"
#include "../lib/lisp_site.h"


static int Default_Registered_Ttl = 1440;
static int Default_Configured_Not_Registered_Ttl = 1;
static int Default_Negative_Referral_Ttl = 15;


typedef struct _lisp_ms {
    oor_ctrl_dev_t super;    /* base "class" */

    /* ms members */
    mdb_t *lisp_sites_db;
    mdb_t *reg_sites_db;
} lisp_ms_t;

/* ms interface */
int ms_add_lisp_site_prefix(lisp_ms_t *ms, lisp_site_prefix_t *site);
int ms_add_registered_site_prefix(lisp_ms_t *dev, mapping_t *sp);
void ms_dump_configured_sites(lisp_ms_t *dev, int log_level);
void ms_dump_registered_sites(lisp_ms_t *dev, int log_level);

#endif /* LISP_MS_H_ */
