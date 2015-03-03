/*
 * map_local_entry.h
 *
 *  Created on: 04/12/2014
 *      Author: albert
 */

#ifndef MAP_LOCAL_ENTRY_H_
#define MAP_LOCAL_ENTRY_H_

#include "../liblisp/lisp_mapping.h"

typedef void (*fwd_info_del_fct)(void *);

typedef struct map_local_entry_ {
    mapping_t *         mapping;
    void *              fwd_info;
    fwd_info_del_fct    fwd_inf_del;
} map_local_entry_t;

map_local_entry_t *map_local_entry_new();
map_local_entry_t *map_local_entry_new_init(mapping_t *map);
void map_local_entry_init(
		map_local_entry_t *mle,
		mapping_t *map);

void map_local_entry_del(map_local_entry_t *mle);
void map_local_entry_dump(
		map_local_entry_t *mle,
		int log_level);
char * map_local_entry_to_char(map_local_entry_t *mle);


inline mapping_t *map_local_entry_mapping(map_local_entry_t *mle);
inline void map_local_entry_set_mapping(
		map_local_entry_t *mle,
		mapping_t *map);
inline void *map_local_entry_fwd_info(map_local_entry_t *mle);
inline void map_local_entry_set_fwd_info(
		map_local_entry_t *mle,
		void *fwd_info,
		fwd_info_del_fct fwd_del_fct);

inline lisp_addr_t *map_local_entry_eid(map_local_entry_t *mle);



#endif /* MAP_LOCAL_ENTRY_H_ */
