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
