# Android makefile for lispmob

LOCAL_PATH:= $(call my-dir)
LOCAL_PATH2:= $(call my-dir)
subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, confuse_android )) \
	$(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, zeromq3-x/src ))
include $(subdirs)	

LOCAL_PATH:= $(LOCAL_PATH2)/../../lispd
include $(CLEAR_VARS)
LOCAL_SRC_FILES = \
		  control/lisp_control.c         \
		  control/lisp_ctrl_device.c     \
		  control/lisp_local_db.c        \
		  control/lisp_map_cache.c       \
		  control/lisp_xtr.c             \
		  control/lisp_ms.c              \
		  control/control-data-plane/control-data-plane.c    \
		  control/control-data-plane/vpnapi/cdp_vpnapi.c     \
		  data-plane/data-plane.c        \
		  data-plane/vpnapi/vpnapi.c     \
		  data-plane/vpnapi/vpnapi_input.c                   \
		  data-plane/vpnapi/vpnapi_output.c                  \
		  elibs/libcfu/cfu.c             \
		  elibs/libcfu/cfuhash.c         \
		  elibs/libcfu/cfustring.c       \
		  elibs/mbedtls/md.c             \
		  elibs/mbedtls/sha1.c           \
		  elibs/mbedtls/sha256.c         \
		  elibs/mbedtls/md_wrap.c        \
		  elibs/patricia/patricia.c      \
		  fwd_policies/fwd_policy.c	     \
		  fwd_policies/flow_balancing/fb_lisp_addr_func.c    \
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
		  liblisp/lisp_nonce.c           \
		  lib/cksum.c                    \
		  lib/generic_list.c             \
		  lib/hmac.c                     \
		  lib/iface_locators.c           \
		  lib/lbuf.c                     \
		  lib/lisp_site.c                \
		  lib/lmlog.c                    \
		  lib/mapping_db.c               \
		  lib/map_cache_entry.c          \
		  lib/map_local_entry.c			 \
		  lib/prefixes.c                 \
		  lib/routing_tables_lib.c       \
		  lib/packets.c                  \
		  lib/sockets.c                  \
		  lib/sockets-util.c             \
		  lib/shash.c                    \
		  lib/timers.c                   \
		  lib/ttable.c                   \
		  lib/util.c                     \
		  cmdline.c                      \
		  iface_list.c                   \
		  iface_mgmt.c                   \
		  lispd.c                        \
		  lispd_config_confuse.c         \
		  lispd_config_functions.c       \
		  lispd_api.c                    

LOCAL_CFLAGS += -g -DANDROID
LOCAL_C_INCLUDES += $(LOCAL_PATH2)/zeromq3-x/include 
LOCAL_LDLIBS := -llog
LOCAL_STATIC_LIBRARIES := libconfuse zeromq
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_MODULE = lispd
include $(BUILD_EXECUTABLE)


