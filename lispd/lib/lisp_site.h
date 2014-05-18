
#ifndef LISP_SITE_H_
#define LISP_SITE_H_

#include <lisp_message_fields.h>
#include <lisp_address.h>

typedef struct _lisp_site_prefix {
    lisp_addr_t         *eid_prefix;
    uint32_t            iid;
    uint8_t             proxy_reply;
    uint8_t             accept_more_specifics;
    lisp_key_type_e       key_type;
    char                *key;
    uint8_t             merge;
} lisp_site_prefix;

lisp_site_prefix *lisp_site_prefix_init(lisp_addr_t *eid_prefix, uint32_t iid,
        int key_type, char *key, uint8_t more_specifics, uint8_t proxy_reply, uint8_t merge);
void lisp_site_prefix_del(lisp_site_prefix *sp);

static inline lisp_addr_t *lsite_prefix(lisp_site_prefix *ls) {
    return(ls->eid_prefix);
}
#endif /* LISP_SITE_H_ */
