/*
 * util.h
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2012 Cisco Systems, Inc, 2012. All rights reserved.
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
 * As the name goes, this is a set of useful macros and functions. An
 * important source of inspiration was util.h in the ovs project
 * http://openvswitch.org/
 *
 * Written or modified by:
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <stddef.h>
#include <stdint.h>

/* Calculate Offset: Try not to make dumb mistakes with  pointer arithmetic */
#define CO(addr,len) (((uint8_t *) addr + len))

/* sockaddr length */
#define SA_LEN(a) ((a == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

/*  names for where the udp checksum goes */
#ifdef BSD
#define udpsum(x) x->uh_sum
#else
#define udpsum(x) x->check
#endif

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif


/* compile attributes */
#define NO_RETURN __attribute__((__noreturn__))
#define LM_LIKELY(CONDITION) __builtin_expect(!!(CONDITION), 1)
#define LM_UNLIKELY(CONDITION) __builtin_expect(!!(CONDITION), 0)


/* Given a pointer-typed lvalue OBJECT, expands to a pointer type that may be
 * assigned to OBJECT. */
#ifdef __GNUC__
#define TYPEOF(OBJECT) typeof(OBJECT)
#else
#define TYPEOF(OBJECT) void *
#endif

/* Given OBJECT of type pointer-to-structure, expands to the offset of MEMBER
 * within an instance of the structure.
 *
 * The GCC-specific version avoids the technicality of undefined behavior if
 * OBJECT is null, invalid, or not yet initialized.  This makes some static
 * checkers (like Coverity) happier.  But the non-GCC version does not actually
 * dereference any pointer, so it would be surprising for it to cause any
 * problems in practice.
 */
#ifdef __GNUC__
#define OBJECT_OFFSETOF(OBJECT, MEMBER) offsetof(typeof(*(OBJECT)), MEMBER)
#else
#define OBJECT_OFFSETOF(OBJECT, MEMBER) \
    ((char *) &(OBJECT)->MEMBER - (char *) (OBJECT))
#endif

/* Given POINTER, the address of the given MEMBER in a STRUCT object, returns
   the STRUCT object. */
#define CONTAINER_OF(POINTER, STRUCT, MEMBER)                           \
        ((STRUCT *) (void *) ((char *) (POINTER) - offsetof (STRUCT, MEMBER)))

/* Given POINTER, the address of the given MEMBER within an object of the type
 * that that OBJECT points to, returns OBJECT as an assignment-compatible
 * pointer type (either the correct pointer type or "void *").  OBJECT must be
 * an lvalue.
 *
 * This is the same as CONTAINER_OF except that it infers the structure type
 * from the type of '*OBJECT'. */
#define OBJECT_CONTAINING(POINTER, OBJECT, MEMBER)                      \
    ((TYPEOF(OBJECT)) (void *)                                      \
     ((char *) (POINTER) - OBJECT_OFFSETOF(OBJECT, MEMBER)))

/* Given POINTER, the address of the given MEMBER within an object of the type
 * that that OBJECT points to, assigns the address of the outer object to
 * OBJECT, which must be an lvalue.
 *
 * Evaluates to (void) 0 as the result is not to be used. */
#define ASSIGN_CONTAINER(OBJECT, POINTER, MEMBER) \
    ((OBJECT) = OBJECT_CONTAINING(POINTER, OBJECT, MEMBER), (void) 0)


/* Casts 'pointer' to 'type' and issues a compiler warning if the cast changes
 * anything other than an outermost "const" or "volatile" qualifier.
 *
 * The cast to int is present only to suppress an "expression using sizeof
 * bool" warning from "sparse" (see
 * http://permalink.gmane.org/gmane.comp.parsers.sparse/2967). */
#define CONST_CAST(TYPE, POINTER)                               \
    ((void) sizeof ((int) ((POINTER) == (TYPE) (POINTER))),     \
     (TYPE) (POINTER))


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


int convert_hex_string_to_bytes(char *hex, uint8_t *bytes, int bytes_len);

#endif /* UTIL_H_ */
