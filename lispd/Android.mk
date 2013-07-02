# Android makefile for lispmob

ifneq ($(TARGET_SIMULATOR),true)
LOCAL_PATH:= $(call my-dir)

etc_dir := $(TARGET_OUT)/etc/lispd

subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, \
	confuse_android/ ))

include $(CLEAR_VARS)
LOCAL_SRC_FILES = cmdline.c lispd.c lispd_config.c lispd_log.c	\
		  lispd_lib.c lispd_map_register.c		\
		  patricia/patricia.c cksum.c lispd_map_request.c	\
		  lispd_map_reply.c \
		  lispd_iface_list.c lispd_map_notify.c lispd_pkt_lib.c \
		  lispd_timers.c lispd_local_db.c lispd_map_cache_db.c \
		  lispd_afi.c lispd_nonce.c lispd_rloc_probing.c \
		  lispd_smr.c lispd_tun.c lispd_input.c lispd_output.c lispd_sockets.c 
LOCAL_C_FLAGS += -g
LOCAL_C_INCLUDES := external/openssl/include/
LOCAL_STATIC_LIBRARIES := libconfuse
LOCAL_SHARED_LIBRARIES := libcutils libssl libcrypto
LOCAL_MODULE = lispd
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(subdirs) 
endif
