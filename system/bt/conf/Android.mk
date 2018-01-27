LOCAL_PATH := $(call my-dir)

# Bluetooth bt_stack.conf config file
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := bt_stack.conf
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/bluetooth
LOCAL_MODULE_TAGS := optional
ifeq ($(MTK_BT_LOG_MODE_CUSTOMIZED), yes)
# add "MTK stack config" to bt_stack.conf
LOCAL_SRC_FILES := bt_stack.conf
else #($(MTK_BT_LOG_MODE_CUSTOMIZED), no)
# rename original bt_stack.conf to bt_stack_origin.conf
LOCAL_SRC_FILES := bt_stack_origin.conf
endif
include $(BUILD_PREBUILT)

$(info MTK_BT_STACK - MTK_BT_LOG_MODE_CUSTOMIZED in conf: $(MTK_BT_LOG_MODE_CUSTOMIZED))
ifeq ($(MTK_BT_LOG_MODE_CUSTOMIZED), yes)
# Support bt_stack.conf override
# Include bt_stack.conf.sqc, bt_stack.conf.debug
include $(CLEAR_VARS)
LOCAL_MODULE := bt_stack.conf.sqc
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/bluetooth
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(LOCAL_MODULE)
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := bt_stack.conf.debug
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/bluetooth
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(LOCAL_MODULE)
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := bt_stack.conf.usertrial
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/bluetooth
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(LOCAL_MODULE)
include $(BUILD_PREBUILT)
endif

# Bluetooth bt_did.conf config file
# ========================================================
include $(CLEAR_VARS)
LOCAL_MODULE := bt_did.conf
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/bluetooth
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(LOCAL_MODULE)
include $(BUILD_PREBUILT)

