/*
 * Shamelessly copied (and slightly modified) from glib.c
 *
 * Modified by the GLib Team and others 1997-1999.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/.
 */


#ifndef HASH_H_
#define HASH_H_

int g_str_equal(const void * v1, const void * v2);
unsigned int g_str_hash(const void * v);

int g_int_equal(const void * v1, const void * v2);
unsigned int g_int_hash(const void * v);

int g_int64_equal(const void * v1, const void * v2);
unsigned int g_int64_hash(const void * v);

int g_double_equal(const void * v1, const void * v2);
unsigned int g_double_hash(const void * v);

unsigned int g_direct_hash(const void * v);
int g_direct_equal(const void * v1, const void * v2);


#endif /* HASH_H_ */
