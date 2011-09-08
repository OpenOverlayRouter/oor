/*
 * lisp_slab.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Initialize/destroy and support for the slab allocator
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 * Written or modified by:
 *    David Meyer       <dmm@.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */


#include "tables.h"
#include "lisp_mod.h"

#ifdef	USE_LISP_SLAB_ALLOCATOR
struct kmem_cache *lisp_map_cache;		/* map cache */
struct kmem_cache *lisp_map_cache_loctype;	/* mc locators */
struct kmem_cache *lisp_database;		/* database */
struct kmem_cache *lisp_database_loctype;	/* db locators */

int init_lisp_caches(void)
{
    lisp_map_cache = kmem_cache_create("lisp_map_cache_t",
				       sizeof(lisp_map_cache_t), 
				       0,                  
				       SLAB_HWCACHE_ALIGN, 
				       NULL);              
    if (lisp_map_cache == NULL) {
	printk(KERN_INFO "Couldn't create lisp_map_cache_t cache\n");
	return (0);
    }

    lisp_map_cache_loctype = kmem_cache_create("lisp_map_cache_loc_t",
				       sizeof(lisp_map_cache_loc_t), 
				       0,                  
				       SLAB_HWCACHE_ALIGN, 
				       NULL);              
    if (lisp_map_cache_loctype == NULL) {
	printk(KERN_INFO "Couldn't create lisp_map_cache_loc_t cache\n");
	return (0);
    }

    lisp_database = kmem_cache_create("lisp_database_entry_t",
				       sizeof(lisp_database_entry_t), 
				       0,                  
				       SLAB_HWCACHE_ALIGN, 
				       NULL);              
    if (lisp_database == NULL) {
	printk(KERN_INFO "Couldn't create lisp_database_entry_t cache\n");
	return (0);
    }

    lisp_database_loctype = kmem_cache_create("lisp_database_loc_t",
				       sizeof(lisp_database_loc_t), 
				       0,                  
				       SLAB_HWCACHE_ALIGN, 
				       NULL);              
    if (lisp_database_loctype == NULL) {
	printk(KERN_INFO "Couldn't create lisp_database_loc_t cache\n");
	return (0);
    }

    return(1);
}

void delete_lisp_caches(void)
{
    teardown_trees();

    if (lisp_map_cache)
	kmem_cache_destroy(lisp_map_cache);
    if (lisp_map_cache_loctype)
	kmem_cache_destroy(lisp_map_cache_loctype);
    if (lisp_database)
	kmem_cache_destroy(lisp_database);
    if (lisp_database_loctype)
	kmem_cache_destroy(lisp_database_loctype);
    return;
}

#endif

