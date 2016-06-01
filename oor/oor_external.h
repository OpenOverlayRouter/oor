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

#ifndef OOR_EXTERNAL_H_
#define OOR_EXTERNAL_H_

#include "defs.h"

extern char *config_file;
extern int daemonize;
extern int default_rloc_afi;

extern sockmstr_t *smaster;
extern int netlink_fd;
extern oor_ctrl_dev_t *ctrl_dev;
extern oor_ctrl_t *lctrl;
extern data_plane_struct_t *data_plane;

extern void exit_cleanup();
extern htable_nonces_t *nonces_ht;
extern htable_ptrs_t *ptrs_to_timers_ht;

#endif /*OOR_EXTERNAL_H_*/

/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
