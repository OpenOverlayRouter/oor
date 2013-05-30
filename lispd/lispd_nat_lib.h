
#include "lispd_info_nat.h"


int inet2lispafi(int afi);

lisp_addr_t extract_lisp_address(void *ptr);

void free_lisp_addr_list(lispd_addr_list_t * list);

int check_auth_field(int key_id,
                     char *key,
                     void *packet,
                     int pckt_len,
                     void *auth_data_pos,
                     int auth_data_len);

lisp_addr_t *select_best_rtr_from_rtr_list(lispd_addr_list_t *rtr_rloc_list);

int compare_lisp_addresses(lisp_addr_t * add1,
                           lisp_addr_t * add2);

lisp_addr_t *get_current_locator(void);

int add_rtr_as_default_in_map_cache(lisp_addr_t * rtr_add);

int get_auth_data_len(int key_id);

int complete_auth_fields(int key_id,
                         uint16_t * key_id_pos,
                         char *key,
                         void *packet,
                         int pckt_len,
                         void *auth_data_pos);

int compute_sha1_hmac(char *key,
                      void *packet,
                      int pckt_len,
                      void *auth_data_pos,
                      int auth_data_len);

int build_and_send_ecm_map_register(lispd_mapping_elt *mapping_elt,
                                    int proxy_reply,
                                    lisp_addr_t *inner_addr_from,
                                    lisp_addr_t *inner_addr_dest,
                                    unsigned int inner_port_from,
                                    unsigned int inner_port_dest,
                                    lisp_addr_t *outer_addr_from,
                                    lisp_addr_t *outer_addr_dest,
                                    unsigned int outer_port_from,
                                    unsigned int outer_port_dest,
                                    int key_id,
                                    char *key);

void nat_info_request(void);