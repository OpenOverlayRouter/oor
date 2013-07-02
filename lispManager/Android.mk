# Android makefile for lispd module

ifneq ($(TARGET_SIMULATOR),true)
LOCAL_PATH:= $(call my-dir)

etc_dir := $(TARGET_OUT)/etc/lispd

subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, \
         \
))

include $(CLEAR_VARS)
LOCAL_SRC_FILES = lispmanager.c

LOCAL_C_FLAGS += -g
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_MODULE = lispmanager
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

include $(subdirs) 
endif
