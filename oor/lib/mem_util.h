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

#ifndef MEM_UTIL_H_
#define MEM_UTIL_H_

#include <endian.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../defs.h"
//#include "../elibs/ovs/ovs_util.h"

/* Determine endianness */
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
#define BIG_ENDIANS  2
#elif defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN
#define LITTLE_ENDIANS 1
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _BIG_ENDIAN
#define BIG_ENDIANS  2
#elif defined(_BYTE_ORDER) && _BYTE_ORDER == _LITTLE_ENDIAN
#define LITTLE_ENDIANS 1
#elif defined(BYTE_ORDR) && BYTE_ORDER == BIG_ENDIAN
#define BIG_ENDIANS  2
#elif defined(BYTE_ORDER) && BYTE_ORDER == LITTLE_ENDIAN
#define LITTLE_ENDIANS 1
#elif defined(__386__)
#define LITTLE_ENDIANS 1
#else
# error "Can't determine endianness"
#endif



/* Calculate Offset: Try not to make dumb mistakes with  pointer arithmetic */
#define CO(addr,len) (((uint8_t *) addr + len))

/* sockaddr length */
#define SA_LEN(a) ((a == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#define ARRAY_SIZE(x) ((sizeof x) / (sizeof *x))



/* compile attributes */
#define NO_RETURN __attribute__((__noreturn__))
#define LM_LIKELY(CONDITION) __builtin_expect(!!(CONDITION), 1)
#define LM_UNLIKELY(CONDITION) __builtin_expect(!!(CONDITION), 0)


/* Expands to a string that looks like "<file>:<line>", e.g. "tmp.c:10".
 *
 * See http://c-faq.com/ansi/stringize.html for an explanation of STRINGIZE and
 * STRINGIZE2. */
#define SOURCE_LOCATOR __FILE__ ":" STRINGIZE(__LINE__)
#define STRINGIZE(ARG) STRINGIZE2(ARG)
#define STRINGIZE2(ARG) #ARG

#define BOLD "\033[1m"
#define RESET "\033[0m"

/* Like the standard assert macro, except:
 *
 *   - Writes the failure message to the log.
 *
 *   - Not affected by NDEBUG. */
#define lm_assert(CONDITION)                                           \
    if (!LM_LIKELY(CONDITION)) {                                       \
        lm_assert_failure(SOURCE_LOCATOR, __func__, #CONDITION);       \
    }
void lm_assert_failure(const char *, const char *, const char *) NO_RETURN;

void *xmalloc(size_t size);
void *xzalloc(size_t size);
void *xcalloc(size_t count, size_t size);
void *xrealloc(void *p, size_t size);
void *xmemdup(const void *p_, size_t size);
char *xmemdup0(const char *p_, size_t length);
char *xstrdup(const char *s);

#endif /* MEM_UTIL_H_ */
