/*
 * map_local_entry.c
 *
 *  Created on: 04/12/2014
 *      Author: albert
 */
#include "map_local_entry.h"
#include "lmlog.h"
#include "defs.h"

map_local_entry_t *map_local_entry_new()
{
	map_local_entry_t *mle = NULL;
	mle = xzalloc(sizeof(map_local_entry_t));

	return (mle);
}

map_local_entry_t *map_local_entry_new_init(mapping_t *map)
{
	map_local_entry_t *mle = NULL;
	mle = xzalloc(sizeof(map_local_entry_t));

	mle->mapping = map;

	return (mle);
}

void map_local_entry_init(
		map_local_entry_t *mle,
		mapping_t *map)
{
	mle->mapping = map;
}

void map_local_entry_del(map_local_entry_t *mle)
{
	mapping_del(mle->mapping);
	// TODO alopez free fwd_info;
	free(mle);
}

void map_local_entry_dump(
		map_local_entry_t *mle,
		int log_level)
{
	// TODO
	lmlog(log_level,mapping_to_char(mle->mapping));
}
