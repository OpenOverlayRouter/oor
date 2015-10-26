# Android makefile for lispd module

ifneq ($(TARGET_SIMULATOR),true)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_SRC_FILES:= confuse.c lexer.c
LOCAL_MODULE:= libconfuse
include $(BUILD_STATIC_LIBRARY)
endif
