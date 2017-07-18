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
		  data-plane/ttable.c            \
		  data-plane/encapsulations/vxlan-gpe.c              \
		  data-plane/tun/tun.c           \
		  data-plane/tun/tun_input.c     \
		  data-plane/tun/tun_output.c    \
		  elibs/mbedtls/md.c             \
		  elibs/mbedtls/sha1.c           \
		  elibs/mbedtls/sha256.c         \
		  elibs/mbedtls/md_wrap.c        \
		  elibs/patricia/patricia.c      \
		  fwd_policies/balancing_locators.c                  \
          fwd_policies/fwd_addr_func.c   \
          fwd_policies/fwd_policy.c	     \
          fwd_policies/fwd_utils.c	     \
		  fwd_policies/flow_balancing/flow_balancing.c       \
		  fwd_policies/flow_balancing/fwd_entry_tuple.c      \
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
		  lib/interfaces_lib.c	         \
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
		  lib/util.c                     \
		  net_mgr/net_mgr.c              \
          net_mgr/net_mgr_proc_fc.c      \
          net_mgr/kernel/netm_kernel.c   \
          net_mgr/kernel/iface_mgmt.c    \
		  cmdline.c                      \
		  iface_list.c                   \
		  oor.c

LOCAL_CFLAGS += -g -DANDROID  
#-fPIE
#LOCAL_LDFLAGS += -fPIE -pie
LOCAL_C_INCLUDES += $(LOCAL_PATH2)/zeromq3-x/include 
LOCAL_LDLIBS := -llog
LOCAL_STATIC_LIBRARIES := libconfuse
LOCAL_MODULE = oorexec

include $(BUILD_EXECUTABLE)

all:
	mv $(LOCAL_PATH2)/../libs/armeabi/oorexec $(LOCAL_PATH2)/../libs/armeabi/liboorexec.so
	mv $(LOCAL_PATH2)/../libs/arm64-v8a/oorexec $(LOCAL_PATH2)/../libs/arm64-v8a/liboorexec.so
	mv $(LOCAL_PATH2)/../libs/armeabi-v7a/oorexec $(LOCAL_PATH2)/../libs/armeabi-v7a/liboorexec.so
	mv $(LOCAL_PATH2)/../libs/mips/oorexec $(LOCAL_PATH2)/../libs/mips/liboorexec.so
	mv $(LOCAL_PATH2)/../libs/mips64/oorexec $(LOCAL_PATH2)/../libs/mips64/liboorexec.so
	mv $(LOCAL_PATH2)/../libs/x86/oorexec $(LOCAL_PATH2)/../libs/x86/liboorexec.so
	mv $(LOCAL_PATH2)/../libs/x86_64/oorexec $(LOCAL_PATH2)/../libs/x86_64/liboorexec.so


