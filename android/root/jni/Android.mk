# Android makefile for lispmob

LOCAL_PATH:= $(call my-dir)
LOCAL_PATH2:= $(LOCAL_PATH)
subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, /confuse_android )) 
	
include $(subdirs)	

LOCAL_PATH:= $(LOCAL_PATH2)/../../lispd
include $(CLEAR_VARS)
LOCAL_SRC_FILES = \
			cksum.c \
			cmdline.c \
		  	lispd_afi.c \
			lispd_config.c \
			lispd_external.c \
			lispd_iface_list.c \
			lispd_iface_mgmt.c \
			lispd_info_nat.c \
			lispd_info_reply.c \
			lispd_info_request.c \
			lispd_input.c \
			lispd_lib.c \
			lispd_local_db.c \
			lispd_locator.c	\
			lispd_log.c	\
			lispd_map_cache_db.c \
			lispd_map_cache.c \
			lispd_map_notify.c \
			lispd_map_referral.c \
		  	lispd_map_register.c \
		  	lispd_map_reply.c \
		  	lispd_map_request.c	\
		  	lispd_mapping.c \
		  	lispd_nonce.c \
		  	lispd_output.c \
		  	lispd_pkt_lib.c \
		  	lispd_referral_cache.c \
		  	lispd_referral_cache_db.c \
		  	lispd_rloc_probing.c \
		  	lispd_routing_tables_lib.c \
		  	lispd_smr.c \
		  	lispd_sockets.c \
		  	lispd_timers.c \
		  	lispd_tun.c \
		  	lispd.c \
		  	hmac/hmac.c \
		  	hmac/hmac-sha1.c \
		  	patricia/patricia.c

LOCAL_CFLAGS += -g -DANDROID
LOCAL_LDLIBS := -llog
LOCAL_STATIC_LIBRARIES := libconfuse 
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_MODULE = lispd
include $(BUILD_EXECUTABLE)


