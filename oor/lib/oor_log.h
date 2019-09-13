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

#ifndef OOR_LOG_H_
#define OOR_LOG_H_

#include "../oor_external.h"

extern int debug_level;

/* If these set of defines is modified, check the function is_loggable() */

#define LCRIT   1   /* critical conditions -> Exit program */
#define LERR    2   /* error conditions -> Not exit but should be considered by user */
#define LWRN    3   /* warning conditions -> Low level errors. Program doesn't finish */
#define LINF    4   /* informational -> Initial configuration, SMRs, interface change status*/
#define LDBG_1  5   /* low debug-level messages -> Control message */
#define LDBG_2  6   /* medium debug-level messages -> Errors in received packets. Wrong AFI, ...  */
#define LDBG_3  7   /* high debug-level messages -> Log for each received or generated packet */
#define LDBG_4  8   /* ultra high debug-level used to print packets  */



#define OOR_LOG(...) LLOG(__VA_ARGS__)

#define LLOG(level__, ...)                  \
do {                                    \
if (is_loggable(level__)) {         \
llog(level__, __VA_ARGS__);     \
}                                   \
} while (0)

void llog(int oor_log_level, const char *format, ...);
void open_log_file(char *log_file);
void close_log_file();


/* True if log_level is enough to print results */
static inline int
is_loggable(int log_level)
{
    if (log_level < LDBG_1)
        return (TRUE);
    else if (log_level <= LINF + debug_level)
        return (TRUE);
    return (FALSE);
}

void hexDump(const char *desc, const void *data, const int len, int log_level);


#endif /*OOR_LOG_H_*/
