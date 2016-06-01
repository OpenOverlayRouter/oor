# Android makefile for Open Overaly Router

LOCAL_PATH:= $(call my-dir)
LOCAL_PATH2:= $(call my-dir)
subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, confuse_android ))
include $(subdirs)	

LOCAL_PATH:= $(LOCAL_PATH2)/../../oor
include $(CLEAR_VARS)
LOCAL_SRC_FILES = \
config/oor_config_confuse.c    \
		  config/oor_config_functions.c  \
   		  control/oor_control.c          \
		  control/oor_ctrl_device.c      \
		  control/oor_local_db.c         \
		  control/oor_map_cache.c        \
		  control/lisp_xtr.c             \
		  control/lisp_ms.c              \
		  control/control-data-plane/control-data-plane.c    \
		  control/control-data-plane/tun/cdp_tun.c           \
		  data-plane/data-plane.c        \
		  data-plane/encapsulations/vxlan-gpe.c              \
		  data-plane/tun/tun.c           \
		  data-plane/tun/tun_input.c     \
		  data-plane/tun/tun_output.c    \
		  elibs/mbedtls/md.c             \
		  elibs/mbedtls/sha1.c           \
		  elibs/mbedtls/sha256.c         \
		  elibs/mbedtls/md_wrap.c        \
		  elibs/patricia/patricia.c      \
		  fwd_policies/fwd_policy.c	     \
		  fwd_policies/flow_balancing/fb_addr_func.c         \
		  fwd_policies/flow_balancing/flow_balancing.c       \
		  liblisp/liblisp.c              \
		  liblisp/lisp_address.c         \
		  liblisp/lisp_data.c            \
		  liblisp/lisp_ip.c              \
		  liblisp/lisp_lcaf.c            \
		  liblisp/lisp_locator.c         \
		  liblisp/lisp_mapping.c         \
		  liblisp/lisp_messages.c        \
		  liblisp/lisp_message_fields.c  \
		  lib/cksum.c                    \
		  lib/generic_list.c             \
		  lib/hmac.c                     \
		  lib/iface_locators.c           \
		  lib/int_table.c                \
		  lib/lbuf.c                     \
		  lib/lisp_site.c                \
		  lib/oor_log.c                  \
		  lib/mapping_db.c               \
		  lib/map_cache_entry.c          \
		  lib/map_local_entry.c		     \
          lib/mem_util.c	    	     \
          lib/nonces_table.c             \
          lib/packets.c                  \
          lib/pointers_table.c           \
		  lib/prefixes.c                 \
		  lib/routing_tables_lib.c       \
		  lib/sockets.c                  \
		  lib/sockets-util.c             \
		  lib/shash.c                    \
		  lib/timers.c                   \
          lib/timers_utils.c             \
		  lib/ttable.c                   \
		  lib/util.c                     \
		  cmdline.c                      \
		  iface_list.c                   \
		  iface_mgmt.c                   \
		  oor.c                          

LOCAL_CFLAGS += -g -DANDROID
LOCAL_C_INCLUDES += $(LOCAL_PATH2)/zeromq3-x/include 
LOCAL_LDLIBS := -llog
LOCAL_STATIC_LIBRARIES := libconfuse
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_MODULE = oor
include $(BUILD_EXECUTABLE)


