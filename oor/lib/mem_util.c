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

#include "mem_util.h"
#include "oor_log.h"


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
