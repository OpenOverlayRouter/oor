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

#ifndef HMAC_H_
#define HMAC_H_

#include <stdint.h>

#define SHA1_AUTH_DATA_LEN         20
#define SHA256_AUTH_DATA_LEN       32

int complete_auth_fields(uint8_t key_id, const char *key, void *packet, size_t pckt_len,
        void *auth_data_pos);

int check_auth_field(uint8_t key_id, const char *key, void *packet, size_t pckt_len,
        void *auth_data_pos);

#endif /* HMAC_H_ */
