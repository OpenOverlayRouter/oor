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

#include "util.h"
//#include "defs.h"
#include "oor_log.h"
//#include "sockets.h"


static void
out_of_memory(void)
{
    OOR_LOG(LCRIT, "virtual memory exhausted");
    abort();
}

void *
xcalloc(size_t count, size_t size)
{
    void *p = count && size ? calloc(count, size) : malloc(1);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

void *
xzalloc(size_t size)
{
    return xcalloc(1, size);
}

void *
xmalloc(size_t size)
{
    void *p = malloc(size ? size : 1);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

void *
xrealloc(void *p, size_t size)
{
    p = realloc(p, size ? size : 1);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

void *
xmemdup(const void *p_, size_t size)
{
    void *p = xmalloc(size);
    memcpy(p, p_, size);
    return p;
}

char *
xmemdup0(const char *p_, size_t length)
{
    char *p = xmalloc(length + 1);
    memcpy(p, p_, length);
    p[length] = '\0';
    return p;
}

char *
xstrdup(const char *s)
{
    return xmemdup0(s, strlen(s));
}

void
lm_assert_failure(const char *where, const char *function,
                   const char *condition)
{
    /* Prevent an infinite loop (or stack overflow) in case VLOG_ABORT happens
     * to trigger an assertion failure of its own. */
    static int reentry = 0;

    switch (reentry++) {
    case 0:
        OOR_LOG(LCRIT, "%s: assertion %s failed in %s()",
                where, condition, function);
        abort();

    case 1:
        fprintf(stderr, "%s: assertion %s failed in %s()",
                where, condition, function);
        abort();

    default:
        abort();
    }
}

static inline int
convert_hex_char_to_byte (char val)
{
    val = (char)toupper (val);

    switch (val){
    case '0':
        return (0);
    case '1':
        return (1);
    case '2':
        return (2);
    case '3':
        return (3);
    case '4':
        return (4);
    case '5':
        return (5);
    case '6':
        return (6);
    case '7':
        return (7);
    case '8':
        return (8);
    case '9':
        return (9);
    case 'A':
        return (10);
    case 'B':
        return (11);
    case 'C':
        return (12);
    case 'D':
        return (13);
    case 'E':
        return (14);
    case 'F':
        return (15);
    default:
        return (-1);
    }
}

int
convert_hex_string_to_bytes(char *hex, uint8_t *bytes, int bytes_len)
{
    int         ctr = 0;
    char        hex_digit[2];
    int         partial_byte[2] = {0,0};

    while (hex[ctr] != '\0' && ctr <= bytes_len * 2) {
        ctr++;
    }
    if (hex[ctr] != '\0' && ctr != bytes_len * 2) {
        return (BAD);
    }

    for (ctr = 0; ctr < bytes_len; ctr++) {
        hex_digit[0] = hex[ctr * 2];
        hex_digit[1] = hex[ctr * 2 + 1];
        partial_byte[0] = convert_hex_char_to_byte(hex_digit[0]);
        partial_byte[1] = convert_hex_char_to_byte(hex_digit[1]);
        if (partial_byte[0] == -1 || partial_byte[1] == -1) {
            OOR_LOG(LDBG_2, "convert_hex_string_to_bytes: Invalid hexadecimal"
                    " number");
            return (BAD);
        }
        bytes[ctr] = partial_byte[0] * 16 + partial_byte[1];
    }
    return (GOOD);
}


