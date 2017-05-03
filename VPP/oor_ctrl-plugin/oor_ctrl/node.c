
/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
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
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <oor_ctrl/oor_ctrl.h>


typedef struct {
  u32 next_index;
  u32 sw_if_index;
} oor_ctrl_trace_t;

/* packet trace format function */
static u8 * format_oor_ctrl_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  oor_ctrl_trace_t * t = va_arg (*args, oor_ctrl_trace_t *);
  
  s = format (s, "OOR_CTRL: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}

vlib_node_registration_t oor_ctrl_ipv4_node;
vlib_node_registration_t oor_ctrl_ipv6_node;

#define foreach_oor_ctrl_error \
_(LISPD, "LISP control packets processed")

typedef enum {
#define _(sym,str) OOR_CTRL_ERROR_##sym,
  foreach_oor_ctrl_error
#undef _
  OOR_CTRL_N_ERROR,
} oor_ctrl_error_t;

static char * oor_ctrl_error_strings[] = {
#define _(sym,string) string,
  foreach_oor_ctrl_error
#undef _
};

typedef enum {
  OOR_CTRL_NEXT_INTERFACE_OUTPUT,
  OOR_CTRL_N_NEXT,
} oor_ctrl_next_t;



static uword
oor_ctrl_ipv4_node_fn (vlib_main_t * vm,
        vlib_node_runtime_t * node,
        vlib_frame_t * frame)
{
    u32 n_left_from, * from, * to_next;
    u32 pkts_swapped = 0;
    oor_ctrl_main_t *sm = &oor_ctrl_main;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    while (n_left_from > 0)
    {
        u32 n_left_to_next_drop;

        vlib_get_next_frame (vm, node, OOR_CTRL_NEXT_INTERFACE_OUTPUT,
                to_next, n_left_to_next_drop);
        while (n_left_from > 0 && n_left_to_next_drop > 0)
        {
            u32 bi0;
            vlib_buffer_t * b0;

            bi0 = from[0];
            from += 1;
            n_left_from -= 1;
            to_next[0] = bi0;
            to_next += 1;
            n_left_to_next_drop -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            vlib_buffer_advance (b0, -(word) (sizeof(udp_header_t)+ sizeof(ip4_header_t) + sizeof(ethernet_header_t)));

            vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm->sw_if_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }
        }

        vlib_put_next_frame (vm, node, OOR_CTRL_NEXT_INTERFACE_OUTPUT, n_left_to_next_drop);
    }

    vlib_node_increment_counter (vm, oor_ctrl_ipv4_node.index, OOR_CTRL_ERROR_LISPD, pkts_swapped);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (oor_ctrl_ipv4_node) = {
  .function = oor_ctrl_ipv4_node_fn,
  .name = "oor_ctrl_ipv4_node",
  .vector_size = sizeof (u32),
  .format_trace = format_oor_ctrl_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(oor_ctrl_error_strings),
  .error_strings = oor_ctrl_error_strings,

  .n_next_nodes = OOR_CTRL_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [OOR_CTRL_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};


static uword
oor_ctrl_ipv6_node_fn (vlib_main_t * vm,
        vlib_node_runtime_t * node,
        vlib_frame_t * frame)
{
    u32 n_left_from, * from, * to_next;
    u32 pkts_swapped = 0;
    oor_ctrl_main_t *sm = &oor_ctrl_main;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    while (n_left_from > 0)
    {
        u32 n_left_to_next_drop;

        vlib_get_next_frame (vm, node, OOR_CTRL_NEXT_INTERFACE_OUTPUT,
                to_next, n_left_to_next_drop);
        while (n_left_from > 0 && n_left_to_next_drop > 0)
        {
            u32 bi0;
            vlib_buffer_t * b0;

            bi0 = from[0];
            from += 1;
            n_left_from -= 1;
            to_next[0] = bi0;
            to_next += 1;
            n_left_to_next_drop -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            vlib_buffer_advance (b0, -(word) (sizeof(udp_header_t)+ sizeof(ip6_header_t) + sizeof(ethernet_header_t)));

            vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm->sw_if_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {

            }
        }

        vlib_put_next_frame (vm, node, OOR_CTRL_NEXT_INTERFACE_OUTPUT, n_left_to_next_drop);
    }

    vlib_node_increment_counter (vm, oor_ctrl_ipv6_node.index, OOR_CTRL_ERROR_LISPD, pkts_swapped);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (oor_ctrl_ipv6_node) = {
  .function = oor_ctrl_ipv6_node_fn,
  .name = "oor_ctrl_ipv6_node",
  .vector_size = sizeof (u32),
  .format_trace = format_oor_ctrl_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(oor_ctrl_error_strings),
  .error_strings = oor_ctrl_error_strings,

  .n_next_nodes = OOR_CTRL_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [OOR_CTRL_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};



