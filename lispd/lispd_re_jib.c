/*
 * lispd_re_jib.c
 *
 *  Created on: Oct 27, 2013
 *      Author: florin
 */

#include "defs_re.h"

int free_lispd_locators_list(lispd_locators_list *loc_list) {
    /* fcoras: actually the locators list will be a pointer
     * to the list saved in the mapping, so DO NOT free
     * Since the lispd_generic_list calls free if no
     * free function is defined, I define this just as a
     * placeholder
     */

    /*
     * TODO fcoras: decide if not better to copy the locator lists
     */
    return(GOOD);
}

lispd_jib_t *lispd_new_jib() {
    lispd_jib_t     *jib    = NULL;
    jib =  generic_list_new(NULL, free_lispd_locators_list);
    return(jib);
}

lispd_generic_list_t *jib_get_orlist(lispd_jib_t *jib) {
    lispd_generic_list_t        *orlist     = NULL;
    lispd_jib_entry_t           *jibentry   = NULL;
    lispd_generic_list_entry_t  *it         = NULL;

    orlist = generic_list_new(NULL, free_lispd_locators_list);

    generic_list_for_each_entry(it,jib){
        /* Ugly but should do for now. Just take the first locator */
        jibentry = (lispd_jib_entry_t *)generic_list_entry_get_data(it);
        generic_list_add(jibentry->locators->locator, orlist);
    }

    return(orlist);
}

void jib_add_locator_list(lispd_locators_list *loc_list, lispd_jib_t *jib) {

    lispd_jib_entry_t *jibentry;

    assert(jib);
    assert(loc_list);

    jibentry = calloc(1, sizeof(lispd_jib_entry_t));
    jibentry->locators = loc_list;
//    jibentry->timer = smth;

    generic_list_add(jibentry, jib);
}

void jib_del_locator_list(lispd_locators_list *loc_list, lispd_jib_t *jib) {
    lispd_generic_list_entry_t      *it         = NULL;
    lispd_jib_entry_t               *jibentry;

    generic_list_for_each_entry(it,jib) {
        jibentry = (lispd_jib_entry_t *)generic_list_entry_get_data(it);
        if (lisp_addr_compare(jibentry->locators->locator, loc_list->locator))
            lispd_generic_list_del(it, jib);
    }
}

inline uint32_t jib_size(lispd_jib_t *jib) {
    return(generic_list_size(jib));
}
