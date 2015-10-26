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

#ifndef LISPD_NONCE_H_
#define LISPD_NONCE_H_

#include "../defs.h"

typedef struct {
    uint8_t retransmits;
    uint64_t nonce[LISPD_MAX_RETRANSMITS + 1];
} nonces_list_t;


uint64_t nonce_build(int seed);
uint64_t nonce_build_time();
nonces_list_t *nonces_list_new();
int nonce_check(nonces_list_t *nonces, uint64_t nonce);
void lispd_print_nonce(uint64_t nonce, int log_level);
char *nonce_to_char(uint64_t nonce);

#endif /* LISPD_NONCE_H_ */
