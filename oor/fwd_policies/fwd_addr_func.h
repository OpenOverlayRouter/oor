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

#ifndef OOR_FWD_POLICIES_FWD_ADDR_FUNC_H_
#define OOR_FWD_POLICIES_FWD_ADDR_FUNC_H_

#include "../liblisp/lisp_address.h"

lisp_addr_t *laddr_get_fwd_ip_addr(lisp_addr_t *addr,
        glist_t *locl_rlocs_addr);


#endif /* OOR_FWD_POLICIES_FWD_ADDR_FUNC_H_ */
