LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_C_INCLUDES += config.h
LOCAL_SRC_FILES:= src/lexer.c src/confuse.c

LOCAL_CFLAGS+=-DHAVE_CONFIG_H -Dlinux 
LOCAL_MODULE:= libconfuse

include $(BUILD_STATIC_LIBRARY)

