#define LOG_TAG "hci_dump"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "bt_types.h"
#include "btcore/include/module.h"
#include "osi/include/allocator.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "osi/include/thread.h"
#include "hcidefs.h"
#include "hci_data_dump.h"
#include "stack_config.h"

// If DBG_LOG_ENABLE is TRUE, it will print the debugging log of
// hci_raw_dump to trace or tune how HCI data is parsed.
// MUST set it FALSE when to check in.
#define DBG_LOG_ENABLE FALSE

// if DBG_NEED_VALIDATE_CONST_DATA_FORMAT is TURE, it will validate
// some formatting of the pre-defined const data.
// MUST set it FALSE when to check in.
#define DBG_NEED_VALIDATE_CONST_DATA_FORMAT FALSE

// if FILTER_FW_PICUS_LOG_EVENT is TRUE, it will filter out controller's
// log event "0xff" with sub-event code "0x50"
#define FILTER_FW_PICUS_LOG_EVENT TRUE

#if DBG_LOG_ENABLE == TRUE
#define DBG_LOG_TAG "debug_"LOG_TAG
#define DBG_LOG(tag, fmt, args...)    LOG_INFO(DBG_LOG_TAG, fmt, ##args)
#else
#define DBG_LOG(tag, fmt, args...)    ((void)0)
#endif

#define LOG_TAG_CMD LOG_TAG"_cmd"
#define LOG_TAG_EVT LOG_TAG"_evt"

// if HCI_HIDE_SECURITY_DATA is TRUE, it will hide security data like
// link key or passkey when to print HCI log to main log
#define HCI_HIDE_SECURITY_DATA TRUE

/**
 * Print HCI command/event to main log
 */
#define INDENT_LEVEL_0  0
#define INDENT_LEVEL_1  1
#define INDENT_LEVEL_2  2
#define INDENT_LEVEL_3  3
#define INDENT_LEVEL_4  4
const static char *LINE_INDENT[] = {
    "",
    "    ",
    "        ",
    "            ",
    "                ",
};

// The max parameter count in Spec is 24, and here add 6 for dynamic buffer
#define MAX_HCI_PARAM_NUM (24 + 6)

// public log buffer that is used to print command/event's extra data which is
// beyond the length in command/event packet.
static char log_buf[255*3] = {0};

// define HCI command's OGF
#define HCI_CMD_GRP_LINK_CONTROL                  0x01
#define HCI_CMD_GRP_LINK_POLICY                   0x02
#define HCI_CMD_GRP_CONTROLLER_BASEBAND           0x03
#define HCI_CMD_GRP_INFORMATIONAL_PARAMETERS      0x04
#define HCI_CMD_GRP_STATUS_PARAMETERS             0x05
#define HCI_CMD_GRP_TESTING                       0x06
#define HCI_CMD_GRP_LE_CONTROLLER                 0x08
#define HCI_CMD_GRP_VENDOR_SPECIFIC               0x3f

// Declare the special display index
// These index should be by HCI command/event parameters whose display_type
// is "TEXT_SPECIAL_DISPLAY_PARAM".
#define SCAN_ENABLE                                             1
#define INQUIRY_SCAN_TYPE                                       4
#define INQUIRY_MODE                                            5
#define PAGE_SCAN_TYPE                                         11
#define VOICE_SETTING                                          12
#define PIN_TYPE                                               13
#define AUTHENTICATION_ENABLE                                  16
#define HOLD_MODE_ACTIVITY                                     17
#define LINK_POLICY_SETTING                                    18
#define SYNCHRONOUS_FLOW_CONTROL_ENABLE                        22
#define ERRONEOUS_DATA_REPORTING                               25
#define LOCATION_DOMAIN_AWARE                                  29
#define LOCATION_DOMAIN_OPTIONS                                31
#define LOCATION_OPTIONS                                       32
#define FLOW_CONTROL_MODE                                      33
#define LE_SUPPORTED_HOST                                      34
#define SECURE_CONNECTIONS_HOST_SUPPORT                        39

#define PAGE_SCAN_REPETITION_MODE                             100
#define LAP_IAC                                               101
#define PACKET_TYPE_ACL                                       102
#define PACKET_TYPE_SCO                                       103
#define SIMPLE_PAIRING_MODE                                   104
#define SIMPLE_PAIRING_DEBUG_MODE                             105
#define FEC_REQUIRED                                          106
#define RSSI                                                  107
#define DELETE_ALL_FLAG                                       108

// LE parameters
#define LE_META_EVENT_ADVERTISING_REPORT_EVENT_TYPE           200
#define LE_META_EVENT_ADVERTISING_REPORT_ADDRESS_TYPE         201
#define ADVERTISING_TYPE                                      202
#define ADVERTISING_ENABLE                                    203
#define LE_SCAN_TYPE                                          204
#define LE_SCAN_ENABLE                                        205
#define FILTER_DUPLICATES                                     206
#define ADDRESS_TYPE                                          207
#define OWN_ADDRESS_TYPE                                      208
#define PEER_IDENTITY_ADDRESS_TYPE                            209
#define PEER_ADDRESS_TYPE                                     210

// Special case
#define SECURITY_KEY_TYPE                                     301
#define SECURITY_PASSKEY_TYPE                                 302

// HCI command/event parameter's display types
// we print HCI command/event parameter according to the display type
// it declares.
typedef enum {
  INT_HEX = 0x01,
  INT_DEC,
  INT_HANDLE,
  SEQ_HEX,
  SEQ_CHAR,
  TIME_CLK1,  // 0.625ms
  TIME_CLK2,  // 1.25ms
  TIME_CLK5,  // 10ms
  TIME_CLK12, // 12.8s
  TEXT_REASON_STATUS_CODE,
  TEXT_BD_ADDR,
  TEXT_SPECIAL_DISPLAY_PARAM,
} HCI_PARAM_DISPLAY_TYPE;

typedef struct _HCI_PARAMETER {
  /*
   * The HCI command/event parameter's name defined in HCI Spec Vol2: PartE Chapter 7
   */
  const char * name;
  /*
   * This variable indicates the length of this HCI command/event parameter.
   * if its value is >=0, it is the parameter length.
   * if its value is <0, it means the parameter length refer to the value,
   *     which is defined in another parameter.
   *     The negative value is the relevant index based on current parameter.
   */
  int length;
  /*
   * Some parameter may repeat according to another parameter's definition,
   * such as BD_ADDR and Link_Key in HCI_Write_Stored_Link_Key command.
   *
   * This variable indicates the next "repeat_param_num" parameters would be
   * repeated, the repeat times is the value of this parameter.
   */
  int repeat_param_num;

  /*
   * HCI command/event type
   * if it is number including uint8_t, uint16_t, uint24_t, uint32_t, the value
   * would be parsed and printed in whole.
   * if it is sequence, it will be printed as sequence like "0x01 0x02 0x03".
   */
  HCI_PARAM_DISPLAY_TYPE display_type;
  /*
   * 0~42, are HCI configuration parameters defined in HCI Spec Vol2: PartE
   *       Chapter 6 HCI Configuration Parameters
   * 100+, are other parameters that we want to show in detail.
   */
  int index_of_special_display_param;
} HCI_PARAMETER_REPR;

typedef struct _HCI_UNIT {
  const char * name;
  uint16_t opcode;
  size_t parameter_count;
  HCI_PARAMETER_REPR parameter[MAX_HCI_PARAM_NUM];
  size_t return_parameter_count;
  HCI_PARAMETER_REPR return_parameter[MAX_HCI_PARAM_NUM];
} HCI_UNIT_REPR;

typedef HCI_UNIT_REPR HCI_COMMAND_REPR;
typedef HCI_UNIT_REPR HCI_EVENT_REPR;

#define LING_CONTROL_NUM 69
const HCI_COMMAND_REPR HCI_LINK_CONTROL_COMMANDS[LING_CONTROL_NUM + 1] = {
    [0x0001] = {
        .name = "HCI_Inquiry",
        .opcode = 0x0401,
        .parameter_count = 3,
        .parameter = {
            {.name = "LAP",
                .length = 3,
                .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
                .index_of_special_display_param = LAP_IAC,
            },
            {.name = "Inquiry_Length",
                .length = 1,
                .display_type = TIME_CLK12,
            },
            {.name = "Num_Responses",
                .length = 1,
                .display_type = INT_DEC,
            },
        },
        .return_parameter_count = 0,
    },
    [0x0002] = {
        .name = "HCI_Inquiry_Cancel",
        .opcode = 0x0402,
        .parameter_count = 0,
        .return_parameter_count = 1,
        .return_parameter = {
            {.name = "Status",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            }
        },
    },
    [0x0003] = {
        .name = "HCI_Periodic_Inquiry_Mode",
        .opcode = 0x0403,
        .parameter_count = 5,
        .parameter = {
            {.name = "Max_Period_Length",
                .length = 2,
                .display_type = TIME_CLK12,
            },
            {.name = "Min_Period_Length",
                .length = 2,
                .display_type = TIME_CLK12,
            },
            {.name = "LAP",
                .length = 3,
                .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
                .index_of_special_display_param = LAP_IAC,
            },
            {.name = "Inquiry_Length",
                .length = 1,
                .display_type = TIME_CLK12,
            },
            {.name = "Num_Responses",
                .length = 1,
                .display_type = INT_DEC,
            },
        },
        .return_parameter_count = 1,
        .return_parameter = {
            {.name = "Status",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            },
        }
    },
    [0x0004] = {
        .name = "HCI_Exit_Periodic_Inquiry_Mode",
        .opcode = 0x0404,
        .parameter_count = 0,
        .return_parameter_count = 1,
        .return_parameter = {
            {.name = "Status",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            },
        },
    },
    [0x0005] = {
        .name = "HCI_Create_Connection",
        .opcode = 0x0405,
        .parameter_count = 6,
        .parameter = {
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
            {.name = "Packet_Type",
                .length = 2,
                .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
                .index_of_special_display_param = PACKET_TYPE_ACL,
            },
            {.name = "Page_Scan_Repetition_Mode",
                .length = 1,
                .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
                .index_of_special_display_param = PAGE_SCAN_REPETITION_MODE,
            },
            {.name = "Reserved",
                .length = 1,
                .display_type = INT_HEX,
            },
            {.name = "Clock_Offset",
                .length = 2,
                .display_type = INT_HEX,
            },
            {.name = "Allow_Role_Switch",
                .length = 1,
                .display_type = INT_HEX,
            },
        },
        .return_parameter_count = 0,
    },
    [0x0006] = {
        .name = "HCI_Disconnect",
        .opcode = 0x0406,
        .parameter_count = 2,
        .parameter = {
            {.name = "Connection_Handle",
                .length = 2,
                .display_type = INT_HANDLE,
            },
            {.name = "Reason",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            },
        },
    },
    [0x0008] = {
        .name = "HCI_Create_Connection_Cancel",
        .opcode = 0x0408,
        .parameter_count = 1,
        .parameter = {
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
        },
        .return_parameter_count = 2,
        .return_parameter = {
            {.name = "Status",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            },
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
        },
    },
    [0x0009] = {
        .name = "HCI_Accept_Connection_Request",
        .opcode = 0x0409,
        .parameter_count = 2,
        .parameter = {
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
            {.name = "Role",
                .length = 1,
                .display_type = INT_HEX,
            },
        },
        .return_parameter_count = 0,
    },
    [0x000A] = {
        .name = "HCI_Reject_Connection_Request",
        .opcode = 0x040A,
        .parameter_count = 2,
        .parameter = {
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
            {.name = "Reason",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            },
        },
        .return_parameter_count = 0,
    },
    [0x000B] = {
        .name = "HCI_Link_Key_Request_Reply",
        .opcode = 0x040B,
        .parameter_count = 2,
        .parameter = {
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
            {.name = "Link_Key",
                .length = 16,
                .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
                .index_of_special_display_param = SECURITY_KEY_TYPE,
            },
        },
        .return_parameter_count = 2,
        .return_parameter = {
            {.name = "Status",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            },
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
        },
    },
    [0x000C] = {
        .name = "HCI_Link_Key_Request_Negative_Reply",
        .opcode = 0x040C,
        .parameter_count = 1,
        .parameter = {
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
        },
        .return_parameter_count = 2,
        .return_parameter = {
            {.name = "Status",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            },
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
        },
    },
    [0x000D] = {
        .name = "HCI_PIN_Code_Request_Reply",
        .opcode = 0x040D,
        .parameter_count = 3,
        .parameter = {
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
            {.name = "PIN_Code_Length",
                .length = 1,
                .display_type = INT_DEC,
            },
            {.name = "PIN_Code",
                .length = 16,
                .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
                .index_of_special_display_param = SECURITY_KEY_TYPE,
            },
        },
        .return_parameter_count = 2,
        .return_parameter = {
            {.name = "Status",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            },
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
        },
    },
    [0x000E] = {
        .name = "HCI_PIN_Code_Request_Negative_Reply",
        .opcode = 0x040E,
        .parameter_count = 1,
        .parameter = {
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
        },
        .return_parameter_count = 2,
        .return_parameter = {
            {.name = "Status",
                .length = 1,
                .display_type = TEXT_REASON_STATUS_CODE,
            },
            {.name = "BD_ADDR",
                .length = 6,
                .display_type = TEXT_BD_ADDR,
            },
        },
    },
    [0x000F] = {
        .name = "HCI_Change_Connection_Packet_Type",
        .opcode = 0x040F,
        .parameter_count = 2,
        .parameter = {
            {.name = "Connection_Handle",
                .length = 2,
                .display_type = INT_HANDLE,
            },
            {.name = "Packet_Type",
                .length = 2,
                .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
                .index_of_special_display_param = PACKET_TYPE_ACL,
            },
        },
        .return_parameter_count = 0,
    },
    [0x0011] = {
      .name = "HCI_Authentication_Requested",
      .opcode = 0x0411,
      .parameter_count = 1,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0013] = {
      .name = "HCI_Set_Connection_Encryption",
      .opcode = 0x0413,
      .parameter_count = 2,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Encryption_Enable",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0015] = {
      .name = "HCI_Change_Connection_Link_Key",
      .opcode = 0x0415,
      .parameter_count = 1,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0017] = {
      .name = "HCI_Master_Link_Key",
      .opcode = 0x0417,
      .parameter_count = 1,
      .parameter = {
          {.name = "Key_Flag",
              .length = 1,
              .display_type = INT_HEX,
          }
      },
      .return_parameter_count = 0,
    },
    [0x0019] = {
      .name = "HCI_Remote_Name_Request",
      .opcode = 0x0419,
      .parameter_count = 4,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Page_Scan_Repetition_Mode",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PAGE_SCAN_REPETITION_MODE,
          },
          {.name = "Reserved",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Clock_Offset",
              .length = 2,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x001A] = {
      .name = "HCI_Remote_Name_Request_Cancel",
      .opcode = 0x041A,
      .parameter_count = 1,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x001B] = {
      .name = "HCI_Read_Remote_Supported_Features",
      .opcode = 0x041B,
      .parameter_count = 1,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
      },
      .return_parameter_count = 0,
    },
    [0x001C] = {
      .name = "HCI_Read_Remote_Extended_Features",
      .opcode = 0x041C,
      .parameter_count = 2,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Page Number",
              .length = 1,
              .display_type = INT_DEC,
          },
      },
      .return_parameter_count = 0,
    },
    [0x001D] = {
      .name = "HCI_Read_Remote_Version_Information",
      .opcode = 0x041D,
      .parameter_count = 1,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
      },
      .return_parameter_count = 0,
    },
    [0x001F] = {
      .name = "HCI_Read_Clock_Offset",
      .opcode = 0x041F,
      .parameter_count = 1,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0020] = {
      .name = "HCI_Read_LMP_Handle",
      .opcode = 0x0420,
      .parameter_count = 1,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0028] = {
      .name = "HCI_Setup_Synchronous_Connection",
      .opcode = 0x0428,
      .parameter_count = 7,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Transmit_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Receive_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Max_Latency",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Voice_Setting",
              .length = 2,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = VOICE_SETTING,
          },
          {.name = "Retransmission_Effort",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Packet_Type",
              .length = 2,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PACKET_TYPE_SCO,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0029] = {
      .name = "HCI_Accept_Synchronous_Connection_Request",
      .opcode = 0x0429,
      .parameter_count = 7,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Transmit_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Receive_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Max_Latency",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Voice_Setting",
              .length = 2,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = VOICE_SETTING,
          },
          {.name = "Retransmission_Effort",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Packet_Type",
              .length = 2,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PACKET_TYPE_SCO,
          },
      },
      .return_parameter_count = 0,
    },
    [0x002A] = {
      .name = "HCI_Reject_Synchronous_Connection_Request",
      .opcode = 0x042A,
      .parameter_count = 2,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Reason",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
      },
      .return_parameter_count = 0,
    },
    [0x002B] = {
      .name = "HCI_IO_Capability_Request_Reply",
      .opcode = 0x042B,
      .parameter_count = 4,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "IO_Capability",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "OOB_Data_Present",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Authentication_Requirements",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x002C] = {
      .name = "HCI_User_Confirmation_Request_Reply",
      .opcode = 0x042C,
      .parameter_count = 1,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x002D] = {
      .name = "HCI_User_Confirmation_Request_Negative_Reply",
      .opcode = 0x042D,
      .parameter_count = 1,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x002E] = {
      .name = "HCI_User_Passkey_Request_Reply",
      .opcode = 0x042E,
      .parameter_count = 2,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Numeric_Value",
              .length = 4,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x002F] = {
      .name = "HCI_User_Passkey_Request_Negative_Reply",
      .opcode = 0x042F,
      .parameter_count = 1,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x0030] = {
      .name = "HCI_Remote_OOB_Data_Request_Reply",
      .opcode = 0x0430,
      .parameter_count = 3,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "C",
              .length = 16,
              .display_type = SEQ_HEX,
          },
          {.name = "R",
              .length = 16,
              .display_type = SEQ_HEX,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x0033] = {
      .name = "HCI_Remote_OOB_Data_Request_Negative_Reply",
      .opcode = 0x0433,
      .parameter_count = 1,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x0034] = {
      .name = "HCI_IO_Capability_Request_Negative_Reply",
      .opcode = 0x0434,
      .parameter_count = 1,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Reason",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x0035] = {
      .name = "HCI_Create_Physical_Link",
      .opcode = 0x0435,
      .parameter_count = 4,
      .parameter = {
          {.name = "Physical_Link_Handle",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Dedicated_AMP_Key_Length",
              .length = 1,
              .display_type = INT_DEC,
          },
          {.name = "Dedicated_AMP_Key_Type",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Dedicated_AMP_Key", //variable length
              .length = -2,
              .display_type = SEQ_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0036] = {
      .name = "HCI_Accept_Physical_Link",
      .opcode = 0x0436,
      .parameter_count = 4,
      .parameter = {
          {.name = "Physical_Link_Handle",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Dedicated_AMP_Key_Length",
              .length = 1,
              .display_type = INT_DEC,
          },
          {.name = "Dedicated_AMP_Key_Type",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Dedicated_AMP_Key", // variable length
              .length = -2,
              .display_type = SEQ_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0037] = {
      .name = "HCI_Disconnect_Physical_Link",
      .opcode = 0x0437,
      .parameter_count = 2,
      .parameter = {
          {.name = "Physical_Link_Handle",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Reason",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0038] = {
      .name = "HCI_Create_Logical_Link",
      .opcode = 0x0438,
      .parameter_count = 3,
      .parameter = {
          {.name = "Physical_Link_Handle",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Tx_Flow_Spec",
              .length = 16,
              .display_type = SEQ_HEX,
          },
          {.name = "Rx_Flow_Spec",
              .length = 16,
              .display_type = SEQ_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0039] = {
      .name = "HCI_Accept_Logical_Link",
      .opcode = 0x0439,
      .parameter_count = 3,
      .parameter = {
          {.name = "Physical_Link_Handle",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Tx_Flow_Spec",
              .length = 16,
              .display_type = SEQ_HEX,
          },
          {.name = "Rx_Flow_Spec",
              .length = 16,
              .display_type = SEQ_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x003A] = {
      .name = "HCI_Disconnect_Logical_Link",
      .opcode = 0x043A,
      .parameter_count = 1,
      .parameter = {
          {.name = "Logical_Link_Handle",
              .length = 2,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x003B] = {
      .name = "HCI_Logical_Link_Cancel",
      .opcode = 0x043B,
      .parameter_count = 2,
      .parameter = {
          {.name = "Physical_Link_Handle",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Tx_Flow_Spec_ID",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 3,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "Physical_Link_Handle",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Tx_Flow_Spec_ID",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
    },
    [0x003C] = {
      .name = "HCI_Flow_Spec_Modify",
      .opcode = 0x043C,
      .parameter_count = 3,
      .parameter = {
          {.name = "Handle",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Tx_Flow_Spec",
              .length = 16,
              .display_type = SEQ_HEX,
          },
          {.name = "Rx_Flow_Spec",
              .length = 16,
              .display_type = SEQ_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x003D] = {
      .name = "HCI_Enhanced_Setup_Synchronous_Connection",
      .opcode = 0x043D,
      .parameter_count = 24,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Transmit_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Receive_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Transmit_Coding_Format",
              .length = 5,
              .display_type = SEQ_HEX,
          },
          {.name = "Receive_Coding_Format",
              .length = 5,
              .display_type = SEQ_HEX,
          },
          {.name = "Transmit_Codec_Frame_Size",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Receive_Codec_Frame_Size",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Input_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Output_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Input_Coding_Format",
              .length = 5,
              .display_type = SEQ_HEX,
          },
          {.name = "Output_Coding_Format",
              .length = 5,
              .display_type = SEQ_HEX,
          },
          {.name = "Input_Coded_Data_Size",
              .length = 2,
              .display_type = INT_DEC,
          },
          {.name = "Output_Coded_Data_Size",
              .length = 2,
              .display_type = INT_DEC,
          },
          {.name = "Input_PCM_Data_Format",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Output_PCM_Data_Format",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Input_PCM_Sample_Payload_MSB_Position",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Output_PCM_Sample_Payload_MSB_Position",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "InputData_Path",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Output_Data_Path",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Input_Transport_Unit_Size",
              .length = 1,
              .display_type = INT_DEC,
          },
          {.name = "Output_Transport_Unit_Size",
              .length = 1,
              .display_type = INT_DEC,
          },
          {.name = "Max_Latency",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Packet_Type",
              .length = 2,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PACKET_TYPE_SCO,
          },
          {.name = "Retransmission_Effort",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x003E] = {
      .name = "HCI_Enhanced_Accept_Synchronous_Connection_Request",
      .opcode = 0x043E,
      .parameter_count = 24,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Transmit_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Receive_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Transmit_Coding_Format",
              .length = 5,
              .display_type = SEQ_HEX,
          },
          {.name = "Receive_Coding_Format",
              .length = 5,
              .display_type = SEQ_HEX,
          },
          {.name = "Transmit_Codec_Frame_Size",
              .length = 2,
              .display_type = INT_DEC,
          },
          {.name = "Receive_Codec_Frame_Size",
              .length = 2,
              .display_type = INT_DEC,
          },
          {.name = "Input_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Output_Bandwidth",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Input_Coding_Format",
              .length = 5,
              .display_type = SEQ_HEX,
          },
          {.name = "Output_Coding_Format",
              .length = 5,
              .display_type = SEQ_HEX,
          },
          {.name = "Input_Coded_Data_Size",
              .length = 2,
              .display_type = INT_DEC,
          },
          {.name = "Output_Coded_Data_Size",
              .length = 2,
              .display_type = INT_DEC,
          },
          {.name = "Input_PCM_Data_Format",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Output_PCM_Data_Format",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Input_PCM_Sample_Payload_MSB_Position",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Output_PCM_Sample_Payload_MSB_Position",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "InputData_Path",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Output_Data_Path",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Input_Transport_Unit_Size",
              .length = 1,
              .display_type = INT_DEC,
          },
          {.name = "Output_Transport_Unit_Size",
              .length = 1,
              .display_type = INT_DEC,
          },
          {.name = "Max_Latency",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Packet_Type",
              .length = 2,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PACKET_TYPE_SCO,
          },
          {.name = "Retransmission_Effort",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x003F] = {
      .name = "HCI_Truncated_Page",
      .opcode = 0x043F,
      .parameter_count = 3,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Page_Scan_Repetition_Mode",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PAGE_SCAN_REPETITION_MODE,
          },
          {.name = "Clock_Offset",
              .length = 2,
              .display_type = SEQ_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0040] = {
      .name = "HCI_Truncated_Page_Cancel",
      .opcode = 0x0440,
      .parameter_count = 1,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    [0x0041] = {
      .name = "HCI_Set_Connectionless_Slave_Broadcast",
      .opcode = 0x0441,
      .parameter_count = 7,
      .parameter = {
          {.name = "Enable",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "LT_ADDR",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "LPO_Allowed",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Packet_Type",
              .length = 2,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PACKET_TYPE_ACL,
          },
          {.name = "Interval_Min",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Interval_Max",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "CSB_supervisionTO",
              .length = 2,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 3,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "LT_ADDR",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Interval",
              .length = 2,
              .display_type = INT_HEX,
          },
      },
    },
    [0x0042] = {
      .name = "HCI_Set_Connectionless_Slave_Broadcast_Receive",
      .opcode = 0x0442,
      .parameter_count = 12,
      .parameter = {
          {.name = "Enable",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "LT_ADDR",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Interval",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Clock_Offset",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "Next_Connectionless_Slave_Broadcast_Clock",
              .length = 4,
              .display_type = INT_HEX,
          },
          {.name = "CSB_supervisionTO",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Remote_Timing_Accuracy",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Skip",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Packet_Type",
              .length = 2,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PACKET_TYPE_ACL,
          },
          {.name = "AFH_Channel_Map",
              .length = 10,
              .display_type = SEQ_HEX,
          },
      },
      .return_parameter_count = 3,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "LT_ADDR",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
    },
    [0x0043] = {
      .name = "HCI_Start_Synchronization_Train",
      .opcode = 0x0443,
      .parameter_count = 0,
      .return_parameter_count = 0,
    },
    [0x0044] = {
      .name = "HCI_ Receive_Synchronization_Train",
      .opcode = 0x0444,
      .parameter_count = 4,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "synchronization_scanTO",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Sync_Scan_Window",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Sync_Scan_Interval",
              .length = 2,
              .display_type = INT_HEX,
          },
      },
      .return_parameter_count = 0,
    },
    [0x0045] = {
      .name = "HCI_Remote_OOB_Extended_Data_Request_Reply",
      .opcode = 0x0445,
      .parameter_count = 5,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "C_192",
              .length = 16,
              .display_type = SEQ_HEX,
          },
          {.name = "R_192",
              .length = 16,
              .display_type = SEQ_HEX,
          },
          {.name = "C_256",
              .length = 16,
              .display_type = SEQ_HEX,
          },
          {.name = "R_256",
              .length = 16,
              .display_type = SEQ_HEX,
          },
      },
      .return_parameter_count = 2,
      .return_parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
      },
    },
    };

#define LINK_POLICY_NUM 17
const HCI_COMMAND_REPR HCI_LINK_POLICY_COMMANDS[LINK_POLICY_NUM + 1] = {
  [0x0001] = {
    .name = "HCI_Hold_Mode",
    .opcode = 0x0801,
    .parameter_count = 3,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Hold_Mode_Max_Interval",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Hold_Mode_Min_Interval",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 0,
  },
  [0x0003] = {
    .name = "HCI_Sniff_Mode",
    .opcode = 0x0803,
    .parameter_count = 5,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Sniff_Max_Interval",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Sniff_Min_Interval",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Sniff_Attempt",
            .length = 2,
            .display_type = TIME_CLK2,
        },
        {.name = "Sniff_Timeout",
            .length = 2,
            .display_type = TIME_CLK2,
        },
    },
    .return_parameter_count = 0,
  },
  [0x0004] = {
    .name = "HCI_Exit_Sniff_Mode",
    .opcode = 0x0804,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 0,
    .return_parameter = {},
  },
  [0x0005] = {
    .name = "HCI_Park_State",
    .opcode = 0x0805,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 0,
    .return_parameter = {},
  },
  [0x0006] = {
    .name = "HCI_Exit_Park_State",
    .opcode = 0x0806,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 0,
    .return_parameter = {},
  },
  [0x0007] = {
    .name = "HCI_QoS_Setup",
    .opcode = 0x0807,
    .parameter_count = 7,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Flags",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Service_Type",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Token_Rate",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Peak_Bandwidth",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Latency",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Delay_Variation",
            .length = 4,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 0,
  },
  [0x0009] = {
    .name = "HCI_Role_Discovery",
    .opcode = 0x0809,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Current_Role",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x000B] = {
    .name = "HCI_Switch_Role",
    .opcode = 0x080B,
    .parameter_count = 2,
    .parameter = {
        {.name = "BD_ADDR",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
        {.name = "Role",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 0,
  },
  [0x000C] = {
    .name = "HCI_Read_Link_Policy_Settings",
    .opcode = 0x080C,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Link_Policy_Settings",
            .length = 2,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LINK_POLICY_SETTING,
        },
    },
  },
  [0x000D] = {
    .name = "HCI_Write_Link_Policy_Settings",
    .opcode = 0x080D,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Link_Policy_Settings",
            .length = 2,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LINK_POLICY_SETTING,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x000E] = {
    .name = "HCI_Read_Default_Link_Policy_Settings",
    .opcode = 0x080E,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Default_Link_Policy_Settings",
            .length = 2,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LINK_POLICY_SETTING,
        },
    },
  },
  [0x000F] = {
    .name = "HCI_Write_Default_Link_Policy_Settings",
    .opcode = 0x080F,
    .parameter_count = 1,
    .parameter = {
        {.name = "Default_Link_Policy_Settings",
            .length = 2,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LINK_POLICY_SETTING,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0010] = {
    .name = "HCI_Flow_Specification",
    .opcode = 0x0810,
    .parameter_count = 8,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Flags",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Flow_direction",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Service_Type",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Token Rate",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Token Bucket Size",
            .length = 4,
            .display_type = INT_DEC,
        },
        {.name = "Peak_Bandwidth",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Access Latency",
            .length = 4,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 0,
  },
  [0x0011] = {
    .name = "HCI_Sniff_Subrating",
    .opcode = 0x0811,
    .parameter_count = 4,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Maximum_Latency",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Minimum_Remote_Timeout",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Minimum_Local_Timeout",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  };

#define CONTROLLER_BASEBAND_NUM 129
const HCI_COMMAND_REPR HCI_CONTROLLER_BASEBAND_COMMANDS[CONTROLLER_BASEBAND_NUM + 1] = {
  [0x0001] = {
    .name = "HCI_Set_Event_Mask",
    .opcode = 0x0C01,
    .parameter_count = 1,
    .parameter = {
        {.name = "Event_Mask",
            .length = 8,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0003] = {
    .name = "HCI_Reset",
    .opcode = 0x0C03,
    .parameter_count = 0,
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0005] = {
    .name = "HCI_Set_Event_Filter",
    .opcode = 0x0C05,
    .parameter_count = 1,
    .parameter = {
        {.name = "Filter_Type",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0008] = {
    .name = "HCI_Flush",
    .opcode = 0x0C08,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x0009] = {
    .name = "HCI_Read_PIN_Type",
    .opcode = 0x0C09,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "PIN_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PIN_TYPE,
        },
    },
  },
  [0x000A] = {
    .name = "HCI_Write_PIN_Type",
    .opcode = 0x0C0A,
    .parameter_count = 1,
    .parameter = {
        {.name = "PIN_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PIN_TYPE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x000B] = {
    .name = "HCI_Create_New_Unit_Key",
    .opcode = 0x0C0B,
    .parameter_count = 0,
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x000D] = {
    .name = "HCI_Read_Stored_Link_Key",
    .opcode = 0x0C0D,
    .parameter_count = 2,
    .parameter = {
        {.name = "BD_ADDR",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
        {.name = "Read_All_Flag",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Max_Num_Keys",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "Max_Keys_Read",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0011] = {
    .name = "HCI_Write_Stored_Link_Key", // Repeat Parameter
    .opcode = 0x0C11,
    .parameter_count = 3,
    .parameter = {
        {.name = "Num_Keys_To_Write",
            .length = 1,
            .repeat_param_num = 2,
            .display_type = INT_DEC,
        },
        {.name = "BD_ADDR",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
        {.name = "Link_Key",
            .length = 16,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SECURITY_KEY_TYPE,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Num_Keys_Written",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
  },
  [0x0012] = {
    .name = "HCI_Delete_Stored_Link_Key",
    .opcode = 0x0C12,
    .parameter_count = 2,
    .parameter = {
        {.name = "BD_ADDR",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
        {.name = "Delete_All_Flag",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = DELETE_ALL_FLAG,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Num_Keys_Deleted",
            .length = 2,
            .display_type = INT_DEC,
        },
    },
  },
  [0x0013] = {
    .name = "HCI_Write_Local_Name",
    .opcode = 0x0C13,
    .parameter_count = 1,
    .parameter = {
        {.name = "Local_Name",
            .length = 248,
            .display_type = SEQ_CHAR,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0014] = {
    .name = "HCI_Read_Local_Name",
    .opcode = 0x0C14,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Local_Name",
            .length = 248,
            .display_type = SEQ_CHAR,
        },
    },
  },
  [0x0015] = {
    .name = "HCI_Read_Connection_Accept_Timeout",
    .opcode = 0x0C15,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Conn_Accept_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
  },
  [0x0016] = {
    .name = "HCI_Write_Connection_Accept_Timeout",
    .opcode = 0x0C16,
    .parameter_count = 1,
    .parameter = {
        {.name = "Conn_Accept_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0017] = {
    .name = "HCI_Read_Page_Timeout",
    .opcode = 0x0C17,
    .parameter_count = 0,
    .return_parameter_count = 0,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Page_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
  },
  [0x0018] = {
    .name = "HCI_Write_Page_Timeout",
    .opcode = 0x0C18,
    .parameter_count = 1,
    .parameter = {
        {.name = "Page_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0019] = {
    .name = "HCI_Read_Scan_Enable",
    .opcode = 0x0C19,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Scan_Enable",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SCAN_ENABLE,
        },
    },
  },
  [0x001A] = {
    .name = "HCI_Write_Scan_Enable",
    .opcode = 0x0C1A,
    .parameter_count = 1,
    .parameter = {
        {.name = "Scan_Enable",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SCAN_ENABLE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x001B] = {
    .name = "HCI_Read_Page_Scan_Activity",
    .opcode = 0x0C1B,
    .parameter_count = 0,
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Page_Scan_Interval",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Page_Scan_Window",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
  },
  [0x001C] = {
    .name = "HCI_Write_Page_Scan_Activity",
    .opcode = 0x0C1C,
    .parameter_count = 2,
    .parameter = {
        {.name = "Page_Scan_Interval",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Page_Scan_Window",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x001D] = {
    .name = "HCI_Read_Inquiry_Scan_Activity",
    .opcode = 0x0C1D,
    .parameter_count = 0,
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Inquiry_Scan_Interval",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Inquiry_Scan_Window",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
  },
  [0x001E] = {
    .name = "HCI_Write_Inquiry_Scan_Activity",
    .opcode = 0x0C1E,
    .parameter_count = 2,
    .parameter = {
        {.name = "Inquiry_Scan_Interval",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Inquiry_Scan_Window",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x001F] = {
    .name = "HCI_Read_Authentication_Enable",
    .opcode = 0x0C1F,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Authentication_Enable",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = AUTHENTICATION_ENABLE,
        },
    },
  },
  [0x0020] = {
    .name = "HCI_Write_Authentication_Enable",
    .opcode = 0x0C20,
    .parameter_count = 1,
    .parameter = {
        {.name = "Authentication_Enable",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = AUTHENTICATION_ENABLE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0023] = {
    .name = "HCI_Read_Class_of_Device",
    .opcode = 0x0C23,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Class_of_Device",
            .length = 3,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0024] = {
    .name = "HCI_Write_Class_of_Device",
    .opcode = 0x0C24,
    .parameter_count = 1,
    .parameter = {
        {.name = "Class_of_Device",
            .length = 3,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0025] = {
    .name = "HCI_Read_Voice_Setting",
    .opcode = 0x0C25,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Voice_Setting",
            .length = 2,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = VOICE_SETTING,
        },
    },
  },
  [0x0026] = {
    .name = "HCI_Write_Voice_Setting",
    .opcode = 0x0C26,
    .parameter_count = 1,
    .parameter = {
        {.name = "Voice_Setting",
            .length = 2,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = VOICE_SETTING,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0027] = {
    .name = "HCI_Read_Automatic_Flush_Timeout",
    .opcode = 0x0C27,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Flush_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
  },
  [0x0028] = {
    .name = "HCI_Write_Automatic_Flush_Timeout",
    .opcode = 0x0C28,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Flush_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x0029] = {
    .name = "HCI_Read_Num_Broadcast_Retransmissions",
    .opcode = 0x0C29,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Num_Broadcast_Retransmissions",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
  },
  [0x002A] = {
    .name = "HCI_Write_Num_Broadcast_Retransmissions",
    .opcode = 0x0C2A,
    .parameter_count = 1,
    .parameter = {
        {.name = "Num_Broadcast_Retransmissions",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x002B] = {
    .name = "HCI_Read_Hold_Mode_Activity",
    .opcode = 0x0C2B,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Hold_Mode_Activity",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = HOLD_MODE_ACTIVITY,
        },
    },
  },
  [0x002C] = {
    .name = "HCI_Write_Hold_Mode_Activity",
    .opcode = 0x0C2C,
    .parameter_count = 1,
    .parameter = {
        {.name = "Hold_Mode_Activity",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = HOLD_MODE_ACTIVITY,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x002D] = {
    .name = "HCI_Read_Transmit_Power_Level",
    .opcode = 0x0C2D,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Type",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Transmit_Power_Level",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x002E] = {
    .name = "HCI_Read_Synchronous_Flow_Control_Enable",
    .opcode = 0x0C2E,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Synchronous_Flow_Control_Enable",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SYNCHRONOUS_FLOW_CONTROL_ENABLE,
        },
    },
  },
  [0x002F] = {
    .name = "HCI_Write_Synchronous_Flow_Control_Enable",
    .opcode = 0x0C2F,
    .parameter_count = 1,
    .parameter = {
        {.name = "Synchronous_Flow_Control_Enable",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SYNCHRONOUS_FLOW_CONTROL_ENABLE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0031] = {
    .name = "HCI_Set_Controller_To_Host_Flow_Control",
    .opcode = 0x0C31,
    .parameter_count = 1,
    .parameter = {
        {.name = "Flow_Control_Enable",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0033] = {
    .name = "HCI_Host_Buffer_Size",
    .opcode = 0x0C33,
    .parameter_count = 4,
    .parameter = {
        {.name = "Host_ACL_Data_Packet_Length",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "Host_Synchronous_Data_Packet_Length",
            .length = 1,
            .display_type = INT_DEC,
        },
        {.name = "Host_Total_Num_ACL_Data_Packets",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "Host_Total_Num_Synchronous_Data_Packets",
            .length = 2,
            .display_type = INT_DEC,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0035] = {
    .name = "HCI_Host_Number_Of_Completed_Packets",  // repeat parameter
    .opcode = 0x0C35,
    .parameter_count = 3,
    .parameter = {
        {.name = "Number_Of_Handles",
            .length = 1,
            .display_type = INT_DEC,
            .repeat_param_num = 2,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Host_Num_Of_Complete_Packets",
            .length = 2,
            .display_type = INT_DEC,
        },
    },
    .return_parameter_count = 0,
  },
  [0x0036] = {
    .name = "HCI_Read_Link_Supervision_Timeout",
    .opcode = 0x0C36,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Link_Supervision_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
  },
  [0x0037] = {
    .name = "HCI_Write_Link_Supervision_Timeout",
    .opcode = 0x0C37,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Link_Supervision_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x0038] = {
    .name = "HCI_Read_Number_Of_Supported_IAC",
    .opcode = 0x0C38,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Num_Support_IAC",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
  },
  [0x0039] = {
    .name = "HCI_Read_Current_IAC_LAP", // repeat parameter
    .opcode = 0x0C39,
    .parameter_count = 0,
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Num_Current_IAC",
            .length = 1,
            .display_type = INT_DEC,
            .repeat_param_num = 1,
        },
        {.name = "IAC_LAP",
            .length = 3,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LAP_IAC,
        },
    },
  },
  [0x003A] = {
    .name = "HCI_Write_Current_IAC_LAP", // repeat parameter
    .opcode = 0x0C3A,
    .parameter_count = 2,
    .parameter = {
        {.name = "Num_Current_IAC",
            .length = 1,
            .display_type = INT_DEC,
            .repeat_param_num = 1,
        },
        {.name = "IAC_LAP",
            .length = 3,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LAP_IAC,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x003F] = {
    .name = "Set_AFH_Host_Channel_Classification",
    .opcode = 0x0C3F,
    .parameter_count = 1,
    .parameter = {
        {.name = "AFH_Host_Channel_Classification",
            .length = 10,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0042] = {
    .name = "HCI_Read_Inquiry_Scan_Type",
    .opcode = 0x0C42,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Inquiry_Scan_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = INQUIRY_SCAN_TYPE,
        },
    },
  },
  [0x0043] = {
    .name = "HCI_Write_Inquiry_Scan_Type",
    .opcode = 0x0C43,
    .parameter_count = 1,
    .parameter = {
        {.name = "Inquiry_Scan_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = INQUIRY_SCAN_TYPE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0044] = {
    .name = "HCI_Read_Inquiry_Mode",
    .opcode = 0x0C44,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Inquiry_Mode",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = INQUIRY_MODE,
        },
    },
  },
  [0x0045] = {
    .name = "HCI_Write_Inquiry_Mode",
    .opcode = 0x0C45,
    .parameter_count = 1,
    .parameter = {
        {.name = "Inquiry_Mode",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = INQUIRY_MODE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0046] = {
    .name = "HCI_Read_Page_Scan_Type",
    .opcode = 0x0C46,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Page_Scan_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PAGE_SCAN_TYPE,
        },
    },
  },
  [0x0047] = {
    .name = "HCI_Write_Page_Scan_Type",
    .opcode = 0x0C47,
    .parameter_count = 1,
    .parameter = {
        {.name = "Page_Scan_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PAGE_SCAN_TYPE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0048] = {
    .name = "Read_AFH_Channel_Assessment_Mode",
    .opcode = 0x0C48,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "AFH_Channel_Assessment_Mode",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0049] = {
    .name = "Write_AFH_Channel_Assessment_Mode",
    .opcode = 0x0C49,
    .parameter_count = 1,
    .parameter = {
        {.name = "AFH_Channel_Assessment_Mode",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0051] = {
    .name = "HCI_Read_Extended_Inquiry_Response",
    .opcode = 0x0C51,
    .parameter_count = 0,
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "FEC_Required",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = FEC_REQUIRED,
        },
        {.name = "Extended_Inquiry_Response",
            .length = 240,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0052] = {
    .name = "HCI_Write_Extended_Inquiry_Response",
    .opcode = 0x0C52,
    .parameter_count = 2,
    .parameter = {
        {.name = "FEC_Required",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = FEC_REQUIRED,
        },
        {.name = "Extended_Inquiry_Response",
            .length = 240,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0053] = {
    .name = "HCI_Refresh_Encryption_Key",
    .opcode = 0x0C53,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 0,
  },
  [0x0055] = {
    .name = "HCI_Read_Simple_Pairing_Mode",
    .opcode = 0x0C55,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Simple_Pairing_Mode",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SIMPLE_PAIRING_MODE,
        },
    },
  },
  [0x0056] = {
    .name = "HCI_Write_Simple_Pairing_Mode",
    .opcode = 0x0C56,
    .parameter_count = 1,
    .parameter = {
        {.name = "Simple_Pairing_Mode",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SIMPLE_PAIRING_MODE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0057] = {
    .name = "HCI_Read_Local_OOB_Data",
    .opcode = 0x0C57,
    .parameter_count = 0,
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "C",
            .length = 16,
            .display_type = SEQ_HEX,
        },
        {.name = "R",
            .length = 16,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0058] = {
    .name = "HCI_Read_Inquiry_Response_Transmit_Power_Level",
    .opcode = 0x0C58,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "TX_Power",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0059] = {
    .name = "HCI_Write_Inquiry_Transmit_Power_Level",
    .opcode = 0x0C59,
    .parameter_count = 1,
    .parameter = {
        {.name = "TX_Power",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x005A] = {
    .name = "HCI_Read_Default_Erroneous_Data_Reporting",
    .opcode = 0x0C5A,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Erroneous_Data_Reporting",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = ERRONEOUS_DATA_REPORTING,
        },
    },
  },
  [0x005B] = {
    .name = "HCI_Write_Default_Erroneous_Data_Reporting",
    .opcode = 0x0C5B,
    .parameter_count = 1,
    .parameter = {
        {.name = "Erroneous_Data_Reporting",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = ERRONEOUS_DATA_REPORTING,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x005F] = {
    .name = "HCI_Enhanced_Flush",
    .opcode = 0x0C5F,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Packet_Type",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 0,
  },
  [0x0060] = {
    .name = "HCI_Send_Keypress_Notification",
    .opcode = 0x0C60,
    .parameter_count = 2,
    .parameter = {
        {.name = "BD_ADDR",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
        {.name = "Notification_Type",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "BD_ADDR",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
    },
  },
  [0x0061] = {
    .name = "HCI_Read_Logical_Link_Accept_Timeout",
    .opcode = 0x0C61,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Logical_Link_Accept_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
  },
  [0x0062] = {
    .name = "HCI_Write_Logical_Link_Accept_Timeout",
    .opcode = 0x0C62,
    .parameter_count = 1,
    .parameter = {
        {.name = "Logical_Link_Accept_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0063] = {
    .name = "HCI_Set_Event_Mask_Page_2",
    .opcode = 0x0C63,
    .parameter_count = 1,
    .parameter = {
        {.name = "Event_Mask_Page_2",
            .length = 8,
            .display_type = SEQ_HEX,
        },

    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0064] = {
    .name = "HCI_Read_Location_Data",
    .opcode = 0x0C64,
    .parameter_count = 0,
    .return_parameter_count = 5,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Location_Domain_Aware",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LOCATION_DOMAIN_AWARE,
        },
        {.name = "Location_Domain",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Location_Domain_Options",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LOCATION_DOMAIN_OPTIONS,
        },
        {.name = "Location_Options",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LOCATION_OPTIONS,
        },
    },
  },
  [0x0065] = {
    .name = "HCI_Write_Location_Data",
    .opcode = 0x0C65,
    .parameter_count = 4,
    .parameter = {
        {.name = "Location_Domain_Aware",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LOCATION_DOMAIN_AWARE,
        },
        {.name = "Location_Domain",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Location_Domain_Options",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LOCATION_DOMAIN_OPTIONS,
        },
        {.name = "Location_Options",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LOCATION_OPTIONS,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0066] = {
    .name = "HCI_Read_Flow_Control_Mode",
    .opcode = 0x0C66,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Flow_Control_Mode",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = FLOW_CONTROL_MODE,
        },
    },
  },
  [0x0067] = {
    .name = "HCI_Write_Flow_Control_Mode",
    .opcode = 0x0C67,
    .parameter_count = 1,
    .parameter = {
        {.name = "Flow_Control_Mode",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = FLOW_CONTROL_MODE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0068] = {
    .name = "HCI_Read_Enhance_Transmit_Power_Level",
    .opcode = 0x0C68,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Type",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 5,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Transmit_Power_Level_GFSK",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Transmit_Power_Level_DQPSK",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Transmit_Power_Level_8DPSK",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0069] = {
    .name = "HCI_Read_Best_Effort_Flush_Timeout",
    .opcode = 0x0C69,
    .parameter_count = 1,
    .parameter = {
        {.name = "Logical_Link_Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Best_Effort_Flush_Timeout",
            .length = 4,
            .display_type = INT_HEX,
        },
    },
  },
  [0x006A] = {
    .name = "HCI_Write_Best_Effort_Flush_Timeout",
    .opcode = 0x0C6A,
    .parameter_count = 2,
    .parameter = {
        {.name = "Logical_Link_Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Best_Effort_Flush_Timeout",
            .length = 4,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x006B] = {
    .name = "HCI_Short_Range_Mode",
    .opcode = 0x0C6B,
    .parameter_count = 2,
    .parameter = {
        {.name = "Physical_Link_Handle",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Short_Range_Mode",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 0,
  },
  [0x006C] = {
    .name = "HCI_Read_LE_Host_Support",
    .opcode = 0x0C6C,
    .parameter_count = 0,
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "LE_Supported_Host",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LE_SUPPORTED_HOST,
        },
        {.name = "Simultaneous_LE_Host",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x006D] = {
    .name = "HCI_Write_LE_Host_Support",
    .opcode = 0x0C6D,
    .parameter_count = 2,
    .parameter = {
        {.name = "LE_Supported_Host",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LE_SUPPORTED_HOST,
        },
        {.name = "Simultaneous_LE_Host",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x006E] = {
    .name = "HCI_Set_MWS_Channel_Parameters",
    .opcode = 0x0C6E,
    .parameter_count = 6,
    .parameter = {
        {.name = "MWS_Channel_Enable",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "MWS_RX_Center_Frequency",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_TX_Center_Frequency",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_RX_Channel_Bandwidth",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_TX_Channel_Bandwidth",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_Channel_Type",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x006F] = {
    .name = "HCI_Set_External_Frame_Configuration", // repeat parameter
    .opcode = 0x0C6F,
    .parameter_count = 6,
    .parameter = {
        {.name = "Ext_Frame_Duration",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Ext_Frame_Sync_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Ext_Frame_Sync_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Ext_Num_Periods",
            .length = 1,
            .display_type = INT_DEC,
            .repeat_param_num = 1,
        },
        {.name = "Period_Duration",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Period_Type",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0070] = {
    .name = "HCI_Set_MWS_Signaling",
    .opcode = 0x0C70,
    .parameter_count = 15,
    .parameter = {
        {.name = "MWS_RX_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_RX_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_RX_Deassert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_RX_Deassert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_TX_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_TX_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_TX_Deassert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_TX_Deassert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_Pattern_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_Pattern_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_Inactivity_Duration_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_Inactivity_Duration_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_Scan_Frequency_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_Scan_Frequency_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_Priority_Assert_Offset_Requeset",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 17,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Bluetooth_RX_Priority_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Bluetooth_RX_Priority_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Bluetooth_RX_Priority_Deassert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Bluetooth_RX_Priority_Deassert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "802_RX_Priority_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "802_RX_Priority_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "802_RX_Priority_Deassert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "802_RX_Priority_Deassert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Bluetooth_TX_Priority_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Bluetooth_TX_Priority_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Bluetooth_TX_Priority_Deassert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Bluetooth_TX_Priority_Deassert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "802_TX_Priority_Assert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "802_TX_Priority_Assert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "802_TX_Priority_Deassert_Offset",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "802_TX_Priority_Deassert_Jitter",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0071] = {
    .name = "HCI_Set_MWS_Transport_Layer",
    .opcode = 0x0C71,
    .parameter_count = 3,
    .parameter = {
        {.name = "Transport_Layer",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "To_MWS_Baud_Rate",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "From_MWS_Baud_Rate",
            .length = 4,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0072] = {
    .name = "HCI_Set_MWS_Scan_Frequency_Table", // repeat parameter
    .opcode = 0x0C72,
    .parameter_count = 3,
    .parameter = {
        {.name = "Num_Scan_Frequencies",
            .length = 1,
            .display_type = INT_DEC,
            .repeat_param_num = 2,
        },
        {.name = "Scan_Frequency_Low",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Scan_Frequency_High",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0073] = {
    .name = "HCI_Set_MWS_PATTERN_Configuration", // repeat parameter
    .opcode = 0x0C73,
    .parameter_count = 4,
    .parameter = {
        {.name = "MWS_PATTERN_Index",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "MWS_PATTERN_NumIntervals",
            .length = 1,
            .display_type = INT_DEC,
            .repeat_param_num = 2,
        },
        {.name = "MWS_PATTERN_IntervalDuration",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "MWS_PATTERN_IntervalType",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0074] = {
    .name = "HCI_Set_Reserved_LT_ADDR",
    .opcode = 0x0C74,
    .parameter_count = 1,
    .parameter = {
        {.name = "LT_ADDR",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "LT_ADDR",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0075] = {
    .name = "HCI_Delete_Reserved_LT_ADDR",
    .opcode = 0x0C75,
    .parameter_count = 1,
    .parameter = {
        {.name = "LT_ADDR",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "LT_ADDR",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0076] = {
    .name = "HCI_Set_Connectionless_Slave_Broadcast_Data", //variable
    .opcode = 0x0C76,
    .parameter_count = 4,
    .parameter = {
        {.name = "LT_ADDR",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Fragment",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Data_Length",
            .length = 1,
            .display_type = INT_DEC,
        },
        {.name = "Data",
            .length = -1,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "LT_ADDR",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0077] = {
    .name = "HCI_Read_Synchronization_Train_Parameters",
    .opcode = 0x0C77,
    .parameter_count = 0,
    .return_parameter_count = 4,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Sync_Train_Interval",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "synchronization_trainTO",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Service_Data",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0078] = {
    .name = "HCI_Write_Synchronization_Train_Parameters",
    .opcode = 0x0C78,
    .parameter_count = 4,
    .parameter = {
        {.name = "Interval_Min",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Interval_Max",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "synchronization_trainTO",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Service_Data",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Sync_Train_Interval",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0079] = {
    .name = "HCI_Read_Secure_Connections_Host_Support",
    .opcode = 0x0C79,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Secure_Connections_Host_Support",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SECURE_CONNECTIONS_HOST_SUPPORT,
        },
    },
  },
  [0x007A] = {
    .name = "HCI_Write_Secure_Connections_Host_Support",
    .opcode = 0x0C7A,
    .parameter_count = 1,
    .parameter = {
        {.name = "Secure_Connections_Host_Support",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SECURE_CONNECTIONS_HOST_SUPPORT,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x007B] = {
    .name = "HCI_Read_Authenticated_Payload_Timeout",
    .opcode = 0x0C7B,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Authenticated_Payload_Timeout",
            .length = 2,
            .display_type = TIME_CLK5,
        },
    },
  },
  [0x007C] = {
    .name = "HCI_Write_Authenticated_Payload_Timeout",
    .opcode = 0x0C7C,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Authenticated_Payload_Timeout",
            .length = 2,
            .display_type = TIME_CLK5,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x007D] = {
    .name = "HCI_Read_Local_OOB_Extended_Data",
    .opcode = 0x0C7D,
    .parameter_count = 0,
    .return_parameter_count = 5,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "C_192",
            .length = 16,
            .display_type = SEQ_HEX,
        },
        {.name = "R_192",
            .length = 16,
            .display_type = SEQ_HEX,
        },
        {.name = "C_256",
            .length = 16,
            .display_type = SEQ_HEX,
        },
        {.name = "R_256",
            .length = 16,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x007E] = {
    .name = "HCI_Read_Extended_Page_Timeout",
    .opcode = 0x0C7E,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Extended_Page_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
  },
  [0x007F] = {
    .name = "HCI_Write_Extended_Page_Timeout",
    .opcode = 0x0C7F,
    .parameter_count = 1,
    .parameter = {
        {.name = "Extended_Page_Timeout",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0080] = {
    .name = "HCI_Read_Extended_Inquiry_Length",
    .opcode = 0x0C80,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Extended_Inquiry_Length",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
  },
  [0x0081] = {
    .name = "HCI_Write_Extended_Inquiry_Length",
    .opcode = 0x0C81,
    .parameter_count = 1,
    .parameter = {
        {.name = "Extended_Inquiry_Length",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  };

#define INFORMATIONAL_PARAMETERS_NUM 11
const HCI_COMMAND_REPR HCI_INFORMATIONAL_PARAMETERS[INFORMATIONAL_PARAMETERS_NUM + 1] = {
  [0x0001] = {
    .name = "HCI_Read_Local_Version_Information",
    .opcode = 0x1001,
    .parameter_count = 0,
    .return_parameter_count = 6,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "HCI_Version",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "HCI_Revision",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "LMP/PAL_Version",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Manufacturer_Name",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "LMP/PAL_Subversion",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0002] = {
    .name = "HCI_Read_Local_Supported_Commands",
    .opcode = 0x1002,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Supported_Commands",
            .length = 64,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0003] = {
    .name = "HCI_Read_Local_Supported_Features",
    .opcode = 0x1003,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "LMP_Features",
            .length = 8,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0004] = {
    .name = "HCI_Read_Local_Extended_Features",
    .opcode = 0x1004,
    .parameter_count = 1,
    .parameter = {
        {.name = "Page_Number",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
    .return_parameter_count = 4,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Page_Number",
            .length = 1,
            .display_type = INT_DEC,
        },
        {.name = "Maximum_Page_Number",
            .length = 1,
            .display_type = INT_DEC,
        },
        {.name = "Extended_LMP_Features",
            .length = 8,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0005] = {
    .name = "HCI_Read_Buffer_Size",
    .opcode = 0x1005,
    .parameter_count = 0,
    .return_parameter_count = 5,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "HC_ACL_Data_Packet_Length",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "HC_Synchronous_Data_Length",
            .length = 1,
            .display_type = INT_DEC,
        },
        {.name = "HC_Total_Num_ACL_Data_Packets",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "HC_Total_Num_Synchronous_Data_Packets",
            .length = 2,
            .display_type = INT_DEC,
        },
    },
  },
  [0x0009] = {
    .name = "HCI_Read_BD_ADDR",
    .opcode = 0x1009,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "BD_ADDR",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
    },
  },
  [0x000A] = {
    .name = "HCI_Read_Data_Block_Size",
    .opcode = 0x100A,
    .parameter_count = 0,
    .return_parameter_count = 4,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Max_ACL_Data_Packet_Length",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "Data_Block_Length",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "Total_Num_Data_Blocks",
            .length = 2,
            .display_type = INT_DEC,
        },
    },
  },
  [0x000B] = {
    .name = "HCI_Read_Local_Supported_Codecs", // repeat parameter
    .opcode = 0x100B,
    .parameter_count = 0,
    .return_parameter_count = 5,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Number_of_Supported_Codecs",
            .length = 1,
            .display_type = INT_DEC,
            .repeat_param_num = 1,
        },
        {.name = "Supported_Codecs",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Number_of_Supported_Vendor_Specific_Codecs",
            .length = 1,
            .display_type = INT_DEC,
            .repeat_param_num = 1,
        },
        {.name = "Vendor_Specific_Codecs",
            .length = 4,
            .display_type = INT_HEX,
        },
    },
  },
  };

#define STATUS_PARAMETERS_NUM 13
const HCI_COMMAND_REPR HCI_STATUS_PARAMETERS[STATUS_PARAMETERS_NUM + 1] = {
  [0x0001] = {
    .name = "HCI_Read_Failed_Contact_Counter",
    .opcode = 0x1401,
    .parameter_count = 1,
    .parameter = {
        {.name = "Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Failed_Contact_Counter",
            .length = 2,
            .display_type = INT_DEC,
        },
    },
  },
  [0x0002] = {
    .name = "HCI_Reset_Failed_Contact_Counter",
    .opcode = 0x1402,
    .parameter_count = 1,
    .parameter = {
        {.name = "Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0003] = {
    .name = "HCI_Read_Link_Quality",
    .opcode = 0x1403,
    .parameter_count = 1,
    .parameter = {
        {.name = "Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Link_Quality",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0005] = {
    .name = "HCI_Read_RSSI",
    .opcode = 0x1405,
    .parameter_count = 1,
    .parameter = {
        {.name = "Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Handle",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "RSSI",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = RSSI,
        },
    },
  },
  [0x0006] = {
    .name = "HCI_Read_AFH_Channel_Map",
    .opcode = 0x1406,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 4,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "AFH_Mode",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "AFH_Channel_Map",
            .length = 10,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0007] = {
    .name = "HCI_Read_Clock",
    .opcode = 0x1407,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Which_Clock",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Clock",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Accuracy",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0008] = {
    .name = "HCI_Read_Encryption_Key_Size",
    .opcode = 0x1408,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Key_Size",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
  },
  [0x0009] = {
    .name = "HCI_Read_Local_AMP_Info",
    .opcode = 0x1409,
    .parameter_count = 0,
    .return_parameter_count = 11,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "AMP_Status",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Total_Bandwidth",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Max_Guaranteed_Bandwidth",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Min_Latency",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Max_PDU_Size",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "Controller_Type",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "PAL_Capablities",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Max_AMP_ASSOC_Length",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "Max_Flush_Timeout",
            .length = 4,
            .display_type = INT_HEX,
        },
        {.name = "Best_Effort_Flush_Timeout",
            .length = 4,
            .display_type = INT_HEX,
        },
    },
  },
  [0x000A] = {
    .name = "HCI_Read_Local_AMP_ASSOC",
    .opcode = 0x140A,
    .parameter_count = 3,
    .parameter = {
        {.name = "Physical_Link_Handle",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Length_So_Far",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "AMP_ASSOC_Length",
            .length = 2,
            .display_type = INT_DEC,
        },
    },
    .return_parameter_count = 4,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Physical_Link_Handle",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "AMP_ASSOC_Remaining_Length",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "AMP_ASSOC_fragment", // variable
            .length = INT_MAX,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x000B] = {
    .name = "HCI_Write_Remote_AMP_ASSOC",
    .opcode = 0x140B,
    .parameter_count = 4,
    .parameter = {
        {.name = "Physical_Link_Handle",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Length_So_Far",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "AMP_ASSOC_Remaining_Length",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "AMP_ASSOC_fragment", // variable
            .length = -1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Physical_Link_Handle",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x000C] = {
    .name = "HCI_Get_MWS_Transport_Layer_Configuration", // repeat parameter!!!
    .opcode = 0x140C,
    .parameter_count = 0,
    .return_parameter_count = 6,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Num_Transports",
            .length = 1,
            .repeat_param_num = 2,
            .display_type = INT_DEC,
        },
        {.name = "Transport_Layer",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Num_Baud_Rates",
            .length = 1,
            .repeat_param_num = 2,
            .display_type = INT_DEC,
        },
        {.name = "To_MWS_Baud_Rate",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "From_MWS_Baud_Rate",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x000D] = {
    .name = "HCI_Set_Triggered_Clock_Capture",
    .opcode = 0x140D,
    .parameter_count = 5,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Enable",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Which_Clock",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "LPO_Allowed",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Num_Clock_Captures_To_Filter",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  };

#define TESTING_NUM 10
const HCI_COMMAND_REPR HCI_TESTING_COMMANDS[TESTING_NUM + 1] = {
  [0x0001] = {
    .name = "HCI_Read_Loopback_Mode",
    .opcode = 0x1801,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Loopback_Mode",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0002] = {
    .name = "HCI_Write_Loopback_Mode",
    .opcode = 0x1802,
    .parameter_count = 1,
    .parameter = {
        {.name = "Loopback_Mode",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0003] = {
    .name = "HCI_Enable_Device_Under_Test_Mode",
    .opcode = 0x1803,
    .parameter_count = 0,
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0004] = {
    .name = "HCI_Write_Simple_Pairing_Debug_Mode",
    .opcode = 0x1804,
    .parameter_count = 1,
    .parameter = {
        {.name = "Simple_Pairing_Debug_Mode",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SIMPLE_PAIRING_DEBUG_MODE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0007] = {
    .name = "HCI_Enable_AMP_Receiver_Reports",
    .opcode = 0x1807,
    .parameter_count = 2,
    .parameter = {
        {.name = "Enable",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Interval",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0008] = {
    .name = "HCI_AMP_Test_End",
    .opcode = 0x1808,
    .parameter_count = 0,
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0009] = {
    .name = "HCI_AMP_Test",
    .opcode = 0x1809,
    .parameter_count = 1,
    .parameter = {
        {.name = "Test_Parameters",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x000A] = {
    .name = "HCI_Write_Secure_Connections_Test_Mode",
    .opcode = 0x180A,
    .parameter_count = 3,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "DM1_ACL-U_Mode",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "eSCO_Loopback_Mode",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
};

#define LE_CONTROLLER_NUM 47
const HCI_COMMAND_REPR HCI_LE_CONTROLLER_COMMANDS[LE_CONTROLLER_NUM + 1] = {
  [0x0001] = {
    .name = "HCI_LE_Set_Event_Mask",
    .opcode = 0x2001,
    .parameter_count = 1,
    .parameter = {
        {.name = "LE_Event_Mask",
            .length = 8,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0002] = {
    .name = "HCI_LE_Read_Buffer_Size",
    .opcode = 0x2002,
    .parameter_count = 0,
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "HC_LE_ACL_Data_Packet_Length",
            .length = 2,
            .display_type = INT_DEC,
        },
        {.name = "HC_Total_Num_LE_ACL_Data_Packets",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
  },
  [0x0003] = {
    .name = "HCI_LE_Read_Local_Supported_Features",
    .opcode = 0x2003,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "LE_Features",
            .length = 8,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0005] = {
    .name = "HCI_LE_Set_Random_Address",
    .opcode = 0x2005,
    .parameter_count = 1,
    .parameter = {
        {.name = "Random_Address",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0006] = {
    .name = "HCI_LE_Set_Advertising_Parameters",
    .opcode = 0x2006,
    .parameter_count = 8,
    .parameter = {
        {.name = "Advertising_Interval_Min",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Advertising_Interval_Max",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Advertising_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = ADVERTISING_TYPE,
        },
        {.name = "Own_Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = OWN_ADDRESS_TYPE,
        },
        {.name = "Peer_Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PEER_ADDRESS_TYPE,
        },
        {.name = "Peer_Address",
            .length = 6,
            .display_type = SEQ_HEX,
        },
        {.name = "Advertising_Channel_Map",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Advertising_Filter_Policy",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0007] = {
    .name = "HCI_LE_Read_Advertising_Channel_Tx_Power",
    .opcode = 0x2007,
    .parameter_count = 0,
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Transmit_Power_Level",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0008] = {
    .name = "HCI_LE_Set_Advertising_Data",
    .opcode = 0x2008,
    .parameter_count = 2,
    .parameter = {
        {.name = "Advertising_Data_Length",
            .length = 1,
            .display_type = INT_DEC,
        },
        {.name = "Advertising_Data",
            .length = 31,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0009] = {
    .name = "HCI_LE_Set_Scan_Response_Data",
    .opcode = 0x2009,
    .parameter_count = 2,
    .parameter = {
        {.name = "Scan_Response_Data_Length",
            .length = 1,
            .display_type = INT_DEC,
        },
        {.name = "Scan_Response_Data",
            .length = 31,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x000A] = {
    .name = "HCI_LE_Set_Advertise_Enable",
    .opcode = 0x200A,
    .parameter_count = 1,
    .parameter = {
        {.name = "Advertising_Enable",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = ADVERTISING_ENABLE,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x000B] = {
    .name = "HCI_LE_Set_Scan_Parameters",
    .opcode = 0x200B,
    .parameter_count = 5,
    .parameter = {
        {.name = "LE_Scan_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LE_SCAN_TYPE,
        },
        {.name = "LE_Scan_Interval",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "LE_Scan_Window",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Own_Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = OWN_ADDRESS_TYPE,
        },
        {.name = "Scanning_Filter_Policy",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x000C] = {
    .name = "HCI_LE_Set_Scan_Enable",
    .opcode = 0x200C,
    .parameter_count = 2,
    .parameter = {
        {.name = "LE_Scan_Enable",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = LE_SCAN_ENABLE,
        },
        {.name = "Filter_Duplicates",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = FILTER_DUPLICATES,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x000D] = {
    .name = "HCI_LE_Create_Connection",
    .opcode = 0x200D,
    .parameter_count = 12,
    .parameter = {
        {.name = "LE_Scan_Interval",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "LE_Scan_Window",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Initiator_Filter_Policy",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Peer_Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PEER_ADDRESS_TYPE,
        },
        {.name = "Peer_address",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
        {.name = "Own_Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = OWN_ADDRESS_TYPE,
        },
        {.name = "Conn_Interval_Min",
            .length = 2,
            .display_type = TIME_CLK2,
        },
        {.name = "Conn_Interval_Max",
            .length = 2,
            .display_type = TIME_CLK2,
        },
        {.name = "Conn_Latency",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Supervision_Timeout",
            .length = 2,
            .display_type = TIME_CLK5,
        },
        {.name = "Minimum_CE_Length",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Maximum_CE_Length",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 0,
  },
  [0x000E] = {
    .name = "HCI_LE_Create_Connection_Cancel",
    .opcode = 0x200E,
    .parameter_count = 0,
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x000F] = {
    .name = "HCI_LE_Read_White_List_Size",
    .opcode = 0x200F,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "White_List_Size",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
  },
  [0x0010] = {
    .name = "HCI_LE_Clear_White_List",
    .opcode = 0x2010,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0011] = {
    .name = "HCI_LE_Add_Device_To_White_List",
    .opcode = 0x2011,
    .parameter_count = 2,
    .parameter = {
        {.name = "Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = ADDRESS_TYPE,
        },
        {.name = "Address",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0012] = {
    .name = "HCI_LE_Remove_Device_From_White_List",
    .opcode = 0x2012,
    .parameter_count = 2,
    .parameter = {
        {.name = "Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = ADDRESS_TYPE,
        },
        {.name = "Address",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0013] = {
    .name = "HCI_LE_Connection_Update",
    .opcode = 0x2013,
    .parameter_count = 7,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Conn_Interval_Min",
            .length = 2,
            .display_type = TIME_CLK2,
        },
        {.name = "Conn_Interval_Max",
            .length = 2,
            .display_type = TIME_CLK2,
        },
        {.name = "Conn_Latency",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Supervision_Timeout",
            .length = 2,
            .display_type = TIME_CLK5,
        },
        {.name = "Minimum_CE_Length",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Maximum_CE_Length",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 0,
    .return_parameter = {},
  },
  [0x0014] = {
    .name = "HCI_LE_Set_Host_Channel_Classification",
    .opcode = 0x2014,
    .parameter_count = 1,
    .parameter = {
        {.name = "Channel_Map",
            .length = 5,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0015] = {
    .name = "HCI_LE_Read_Channel_Map",
    .opcode = 0x2015,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Channel_Map",
            .length = 5,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0016] = {
    .name = "HCI_LE_Read_Remote_Used_Features",
    .opcode = 0x2016,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 0,
    .return_parameter = {},
  },
  [0x0017] = {
    .name = "HCI_LE_Encrypt",
    .opcode = 0x2017,
    .parameter_count = 2,
    .parameter = {
        {.name = "Key",
            .length = 16,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SECURITY_KEY_TYPE,
        },
        {.name = "Plaintext_Data",
            .length = 16,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SECURITY_KEY_TYPE,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Encrypted_Data",
            .length = 16,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0018] = {
    .name = "HCI_LE_Rand",
    .opcode = 0x2018,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Random_Number",
            .length = 8,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x0019] = {
    .name = "HCI_LE_Start_Encryption",
    .opcode = 0x2019,
    .parameter_count = 4,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Random_Number",
            .length = 8,
            .display_type = SEQ_HEX,
        },
        {.name = "Encrypted_Diversifier",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Long_Term_Key",
            .length = 16,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SECURITY_KEY_TYPE,
        },
    },
    .return_parameter_count = 0,
    .return_parameter = {},
  },
  [0x001A] = {
    .name = "HCI_LE_Long_Term_Key_Request_Reply",
    .opcode = 0x201A,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Long_Term_Key",
            .length = 16,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = SECURITY_KEY_TYPE,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x001B] = {
    .name = "HCI_LE_Long_Term_Key_Request_Negative_Reply",
    .opcode = 0x201B,
    .parameter_count = 1,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x001C] = {
    .name = "HCI_LE_Read_Supported_States",
    .opcode = 0x201C,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "LE_States",
            .length = 8,
            .display_type = SEQ_HEX,
        },
    },
  },
  [0x001D] = {
    .name = "HCI_LE_Receiver_Test",
    .opcode = 0x201D,
    .parameter_count = 1,
    .parameter = {
        {.name = "RX_Channel",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x001E] = {
    .name = "HCI_LE_Transmitter_Test",
    .opcode = 0x201E,
    .parameter_count = 3,
    .parameter = {
        {.name = "TX_Channel",
            .length = 1,
            .display_type = INT_HEX,
        },
        {.name = "Length_Of_Test_Data",
            .length = 1,
            .display_type = INT_DEC,
        },
        {.name = "Packet_Payload",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x001F] = {
    .name = "HCI_LE_Test_End",
    .opcode = 0x201F,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Number_Of_Packets",
            .length = 2,
            .display_type = INT_DEC,
        },
    },
  },
  [0x0020] = {
    .name = "LE_Remote_Connection_Parameter_Request_Reply",
    .opcode = 0x2020,
    .parameter_count = 7,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Interval_Min",
            .length = 2,
            .display_type = TIME_CLK2,
        },
        {.name = "Interval_Max",
            .length = 2,
            .display_type = TIME_CLK2,
        },
        {.name = "Latency",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "Timeout",
            .length = 2,
            .display_type = TIME_CLK5,
        },
        {.name = "Minimum_CE_Length",
            .length = 2,
            .display_type = TIME_CLK1,
        },
        {.name = "Maximum_CE_Length",
            .length = 2,
            .display_type = TIME_CLK1,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x0021] = {
    .name = "LE_Remote_Connection_Parameter_Request_Negative_Reply",
    .opcode = 0x2021,
    .parameter_count = 2,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "Reason",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x0022] = {
    .name = "HCI_LE_Set_Data_Length",
    .opcode = 0x2022,
    .parameter_count = 3,
    .parameter = {
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
        {.name = "TxOctets",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "TxTime",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Connection_Handle",
            .length = 2,
            .display_type = INT_HANDLE,
        },
    },
  },
  [0x0023] = {
    .name = "HCI_LE_Read_Suggested_Default_Data_Length",
    .opcode = 0x2023,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 3,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "SuggestedMaxTxOctets",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "SuggestedMaxTxTime",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
  },
  [0x0024] = {
    .name = "HCI_LE_Write_Suggested_Default_Data_Length",
    .opcode = 0x2024,
    .parameter_count = 2,
    .parameter = {
        {.name = "SuggestedMaxTxOctets",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "SuggestedMaxTxTime",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0025] = {
    .name = "HCI_LE_Read_Local_P-256_Public_Key",
    .opcode = 0x2025,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 0,
    .return_parameter = {},
  },
  [0x0026] = {
    .name = "HCI_LE_Generate_DHKey",
    .opcode = 0x2026,
    .parameter_count = 1,
    .parameter = {
        {.name = "Remote_P-256_Public_Key",
            .length = 64,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 0,
    .return_parameter = {},
  },
  [0x0027] = {
    .name = "HCI_LE_Add_Device_To_Resolving_List",
    .opcode = 0x2027,
    .parameter_count = 4,
    .parameter = {
        {.name = "Peer_Identity_Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PEER_IDENTITY_ADDRESS_TYPE,
        },
        {.name = "Peer_Identity_Address",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
        {.name = "Peer_IRK",
            .length = 16,
            .display_type = SEQ_HEX,
        },
        {.name = "Local_IRK",
            .length = 16,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0028] = {
    .name = "HCI_LE_Remove_Device_From_Resolving_List",
    .opcode = 0x2028,
    .parameter_count = 2,
    .parameter = {
        {.name = "Peer_Identity_Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PEER_IDENTITY_ADDRESS_TYPE,
        },
        {.name = "Peer_Identity_Address",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x0029] = {
    .name = "HCI_LE_Clear_Resolving_List",
    .opcode = 0x2029,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x002A] = {
    .name = "HCI_LE_Read_Resolving_List_Size",
    .opcode = 0x202A,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Resolving_List_Size",
            .length = 1,
            .display_type = INT_DEC,
        },
    },
  },
  [0x002B] = {
    .name = "HCI_LE_Read_Peer_Resolvable_Address",
    .opcode = 0x202B,
    .parameter_count = 2,
    .parameter = {
        {.name = "Peer_Identity_Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PEER_IDENTITY_ADDRESS_TYPE,
        },
        {.name = "Peer_Identity_Address",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Peer_Resolvable_Address",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
    },
  },
  [0x002C] = {
    .name = "HCI_LE_Read_Local_Resolvable_Address",
    .opcode = 0x202C,
    .parameter_count = 2,
    .parameter = {
        {.name = "Peer_Identity_Address_Type",
            .length = 1,
            .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
            .index_of_special_display_param = PEER_IDENTITY_ADDRESS_TYPE,
        },
        {.name = "Peer_Identity_Address",
            .length = 6,
            .display_type = SEQ_HEX,
        },
    },
    .return_parameter_count = 2,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "Local_Resolvable_Address",
            .length = 6,
            .display_type = TEXT_BD_ADDR,
        },
    },
  },
  [0x002D] = {
    .name = "HCI_LE_Set_Address_Resolution_Enable",
    .opcode = 0x202D,
    .parameter_count = 1,
    .parameter = {
        {.name = "Address_Resolution_Enable",
            .length = 1,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x002E] = {
    .name = "HCI_LE_Set_Resolvable_Private_Address_Timeout",
    .opcode = 0x202E,
    .parameter_count = 1,
    .parameter = {
        {.name = "RPA_Timeout",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
    .return_parameter_count = 1,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
    },
  },
  [0x002F] = {
    .name = "HCI_LE_Read_Maximum_Data_Length",
    .opcode = 0x202F,
    .parameter_count = 0,
    .parameter = {},
    .return_parameter_count = 5,
    .return_parameter = {
        {.name = "Status",
            .length = 1,
            .display_type = TEXT_REASON_STATUS_CODE,
        },
        {.name = "supportedMaxTxOctets",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "supportedMaxTxTime",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "supportedMaxRxOctets",
            .length = 2,
            .display_type = INT_HEX,
        },
        {.name = "supportedMaxRxTime",
            .length = 2,
            .display_type = INT_HEX,
        },
    },
  },
};

#define VENDOR_SPECIFIC_COMMAND_NUM 0
const HCI_COMMAND_REPR VENDOR_SPECIFIC_COMMAND[VENDOR_SPECIFIC_COMMAND_NUM + 1] = {
    [0x0000] = {
        .name = "Vendor Specific Command",
        .opcode = 0xFC00,
        .parameter_count = 0,
        .parameter = {},
        .return_parameter_count = 0,
        .return_parameter = {},
    },
};

#define HCI_EVENT_NUMBER  87
const HCI_EVENT_REPR HCI_EVENTS[HCI_EVENT_NUMBER + 1] = {
     [0x01] = {.name = "Inquiry Complete",
         .opcode = 0x01,
         .parameter_count = 1,
         .parameter = {
             {.name = "status",
                 .length = 1,
                 .display_type = INT_HEX,
             }
       },
     },
     [0x02] = {.name = "Inquiry Result",
         .opcode = 0x02,
         .parameter_count = 7,
         .parameter = {
             {.name = "Num_Responses",
                 .length = 1,
                 .repeat_param_num = 6,
                 .display_type = INT_DEC,
             },
             {.name = "BD_ADDR",
                 .length = 6,
                 .display_type = TEXT_BD_ADDR,
             },
             {.name = "Page_Scan_Repetition_Mode",
                 .length = 1,
                 .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
                 .index_of_special_display_param = PAGE_SCAN_REPETITION_MODE,
             },
             {.name = "Reserved1",
                 .length = 1,
                 .display_type = INT_HEX,
             },
             {.name = "Reserved2",
                 .length = 1,
                 .display_type = INT_HEX,
             },
             {.name = "Class_of_Device",
                 .length = 3,
                 .display_type = INT_HEX,
             },
             {.name = "Clock_Offset",
                 .length = 2,
                 .display_type = INT_HEX,
             },
       }
     },
     [0x03] = {.name = "Connection Complete",
         .opcode = 0x03,
         .parameter_count = 5,
         .parameter = {
             {.name = "Status",
                 .length = 1,
                 .display_type = TEXT_REASON_STATUS_CODE,
             },
             {.name = "Connection_Handle",
                 .length = 2,
                 .display_type = INT_HANDLE,
             },
             {.name = "BD_ADDR",
                 .length = 6,
                 .display_type = TEXT_BD_ADDR,
             },
             {.name = "Link_Type",
                 .length = 1,
                 .display_type = INT_HEX,
             },
             {.name = "Encryption_Enabled",
                 .length = 1,
                 .display_type = INT_HEX,
             },
       },
     },
     [0x04] = {.name = "Connection Request",
         .opcode = 0x04,
         .parameter_count = 3,
         .parameter = {
             {.name = "BD_ADDR",
                 .length = 6,
                 .display_type = TEXT_BD_ADDR,
             },
             {.name = "Class_of_Device",
                 .length = 3,
                 .display_type = INT_HEX,
             },
             {.name = "Link_Type",
                 .length = 1,
                 .display_type = INT_HEX,
             },
       }
     },
     [0x05] = {.name = "Disconnection Complete",
         .opcode = 0x05,
         .parameter_count = 3,
         .parameter = {
             {.name = "Status",
                 .length = 1,
                 .display_type = TEXT_REASON_STATUS_CODE,
             },
             {.name = "Connection_Handle",
                 .length = 2,
                 .display_type = INT_HANDLE,
             },
             {.name = "Reason",
                 .length = 1,
                 .display_type = TEXT_REASON_STATUS_CODE,
             }
       },
     },
     [0x06] = {
       .name = "Authentication Complete",
       .opcode = 0x06,
       .parameter_count = 2,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
       },
     },
     [0x07] = {
       .name = "Remote Name Request Complete",
       .opcode = 0x07,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "Remote_Name",
               .length = 248,
               .display_type = SEQ_CHAR,
           },
       },
     },
     [0x08] = {
       .name = "Encryption Change",
       .opcode = 0x08,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Encryption_Enabled",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x09] = {
       .name = "Change Connection Link Key Complete",
       .opcode = 0x09,
       .parameter_count = 2,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
       },
     },
     [0x0A] = {
       .name = "Master Link Key Complete",
       .opcode = 0x0A,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Key_Flag",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x0B] = {
       .name = "Read Remote Supported Features Complete",
       .opcode = 0x0B,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Key_Flag",
               .length = 8,
               .display_type = SEQ_HEX,
           },
       },
     },
     [0x0C] = {
       .name = "Read Remote Version Information Complete",
       .opcode = 0x0C,
       .parameter_count = 5,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Version",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Manufacturer_Name",
               .length = 2,
               .display_type = INT_HEX,
           },
           {.name = "Subversion",
               .length = 2,
               .display_type = INT_HEX,
           },
       },
     },
     [0x0D] = {
       .name = "QoS Setup Complete",
       .opcode = 0x0D,
       .parameter_count = 8,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Flags",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Service_Type",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Token_Rate",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Peak_Bandwidth",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Latency",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Delay_Variation",
               .length = 4,
               .display_type = INT_HEX,
           },
       },
     },
     [0x0E] = {
       .name = "Command Complete",
       .opcode = 0x0E,
       .parameter_count = 2,
       .parameter = {
           {.name = "Num_HCI_Command_Packets",
               .length = 1,
               .display_type = INT_DEC,
           },
           {.name = "Command_Opcode",
               .length = 2,
               .display_type = INT_HEX,
           },
       },
     },
     [0x0F] = {
       .name = "Command Status",
       .opcode = 0x0F,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Num_HCI_Command_Packets",
               .length = 1,
               .display_type = INT_DEC,
           },
           {.name = "Command_Opcode",
               .length = 2,
               .display_type = INT_HEX,
           },
       },
     },
     [0x10] = {
       .name = "Hardware Error",
       .opcode = 0x10,
       .parameter_count = 1,
       .parameter = {
           {.name = "Hardware_Code",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x11] = {
       .name = "Flush Occurred",
       .opcode = 0x11,
       .parameter_count = 1,
       .parameter = {
           {.name = "Handle",
               .length = 2,
               .display_type = INT_HEX,
           },
       },
     },
     [0x12] = {
       .name = "Role Change",
       .opcode = 0x12,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "New_Role",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x13] = {
       .name = "Number Of Completed Packets",
       .opcode = 0x13,
       .parameter_count = 3,
       .parameter = {
           {.name = "Number_of_Handles",
               .length = 1,
               .display_type = INT_DEC,
               .repeat_param_num = 2,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "HC_Num_Of_Completed_Packet",
               .length = 2,
               .display_type = INT_DEC,
           },
       },
     },
     [0x14] = {
       .name = "Mode Change",
       .opcode = 0x14,
       .parameter_count = 4,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Current_Mode",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Interval",
               .length = 2,
               .display_type = TIME_CLK1,
           },
       },
     },
     [0x15] = {
       .name = "Return Link Keys",
       .opcode = 0x15,
       .parameter_count = 3,
       .parameter = {
           {.name = "Num_Keys",
               .length = 1,
               .display_type = INT_DEC,
               .repeat_param_num = 2,
           },
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "Link_Key",
               .length = 16,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = SECURITY_KEY_TYPE,
           },
       },
     },
     [0x16] = {
       .name = "PIN Code Request",
       .opcode = 0x16,
       .parameter_count = 1,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
       },
     },
     [0x17] = {
       .name = "Link Key Request",
       .opcode = 0x17,
       .parameter_count = 1,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
       },
     },
     [0x18] = {
       .name = "Link Key Notification",
       .opcode = 0x18,
       .parameter_count = 3,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "Link_Key",
               .length = 16,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = SECURITY_KEY_TYPE,
           },
           {.name = "Key_Type",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x19] = {
       .name = "Loopback Command",
       .opcode = 0x19,
       .parameter_count = 0,
       .parameter = {},
     },
     [0x1A] = {
       .name = "Data Buffer Overflow",
       .opcode = 0x1A,
       .parameter_count = 1,
       .parameter = {
           {.name = "Link_Type",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x1B] = {
       .name = "Max Slots Change",
       .opcode = 0x1B,
       .parameter_count = 2,
       .parameter = {
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "LMP_Max_Slots",
               .length = 1,
               .display_type = INT_DEC,
           },
       },
     },
     [0x1C] = {
       .name = "Read Clock Offset Complete",
       .opcode = 0x1C,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Clock_Offset",
               .length = 2,
               .display_type = INT_HEX,
           },
       },
     },
     [0x1D] = {
       .name = "Connection Packet Type Changed",
       .opcode = 0x1D,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Packet_Type",
               .length = 2,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = PACKET_TYPE_ACL,
           },
       },
     },
     [0x1E] = {
       .name = "QoS Violation",
       .opcode = 0x1E,
       .parameter_count = 1,
       .parameter = {
           {.name = "Handle",
               .length = 2,
               .display_type = INT_HEX,
           },
       },
     },
     [0x20] = {
      .name = "Page Scan Repetition Mode Change",
      .opcode = 0x20,
      .parameter_count = 2,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Page_Scan_Repetition_Mode",
               .length = 1,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = PAGE_SCAN_REPETITION_MODE,
           },
      },
    },
     [0x21] = {
       .name = "Flow Specification Complete",
       .opcode = 0x21,
       .parameter_count = 9,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Flags",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Flow_direction",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Service_Type",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Token_Rate",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Token_Bucket_Size",
               .length = 4,
               .display_type = INT_DEC,
           },
           {.name = "Peak_Bandwidth",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Access_Lantency",
               .length = 4,
               .display_type = INT_HEX,
           },
       },
     },
     [0x22] = {
       .name = "Inquiry Result with RSSI",
       .opcode = 0x22,
       .parameter_count = 7,
       .parameter = {
           {.name = "Num_responses",
               .length = 1,
               .display_type = INT_DEC,
               .repeat_param_num = 6,
           },
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "Page_Scan_Repetition_Mode",
               .length = 1,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = PAGE_SCAN_REPETITION_MODE,
           },
           {.name = "Reserved",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Class_Of_Device",
               .length = 3,
               .display_type = INT_HEX,
           },
           {.name = "Clock_Offset",
               .length = 2,
               .display_type = INT_HEX,
           },
           {.name = "RSSI",
               .length = 1,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = RSSI,
           },
       },
     },
     [0x23] = {
       .name = "Read Remote Extended Features Complete",
       .opcode = 0x23,
       .parameter_count = 5,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Page_Number",
               .length = 1,
               .display_type = INT_DEC,
           },
           {.name = "Maximum_Page_Number",
               .length = 1,
               .display_type = INT_DEC,
           },
           {.name = "Extended_LMP_Features",
               .length = 8,
               .display_type = SEQ_HEX,
           },
       },
     },
     [0x2C] = {
      .name = "Synchronous Connection Complete",
      .opcode = 0x2C,
      .parameter_count = 9,
      .parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Link_Type",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Transmission_Interval",
              .length = 1,
              .display_type = INT_DEC,
          },
          {.name = "Retransmission_Window",
              .length = 1,
              .display_type = INT_DEC,
          },
          {.name = "Rx_Packet_Length",
              .length = 2,
              .display_type = INT_DEC,
          },
          {.name = "Tx_Packet_Length",
              .length = 2,
              .display_type = INT_DEC,
          },
          {.name = "Air_Mode",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
    },
     [0x2D] = {
       .name = "Synchronous Connection Changed",
       .opcode = 0x2D,
       .parameter_count = 6,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Transmission_Interval",
               .length = 1,
               .display_type = INT_DEC,
           },
           {.name = "Retransmission_Window",
               .length = 1,
               .display_type = INT_DEC,
           },
           {.name = "Rx_Packet_Length",
               .length = 2,
               .display_type = INT_DEC,
           },
           {.name = "Tx_Packet_Length",
               .length = 2,
               .display_type = INT_DEC,
           },
       },
     },
     [0x2E] = {
       .name = "Sniff Subrating",
       .opcode = 0x2E,
       .parameter_count = 6,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Maximum_Transmit_Latency",
               .length = 2,
               .display_type = TIME_CLK1,
           },
           {.name = "Maximum_Receive_Latency",
               .length = 2,
               .display_type = TIME_CLK1,
           },
           {.name = "Minimum_Remote_Timeout",
               .length = 2,
               .display_type = TIME_CLK1,
           },
           {.name = "Minimum_Local_Timeout",
               .length = 2,
               .display_type = TIME_CLK1,
           },
       },
     },
     [0x2F] = {
       .name = "Extended Inquiry Result",
       .opcode = 0x2F,
       .parameter_count = 8,
       .parameter = {
           {.name = "Num_Responses",
               .length = 1,
               .display_type = INT_DEC,
           },
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "Page_Scan_Repetition_Mode",
               .length = 1,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = PAGE_SCAN_REPETITION_MODE,
           },
           {.name = "Reserved",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Class_Of_Device",
               .length = 3,
               .display_type = INT_HEX,
           },
           {.name = "Clock_Offset",
               .length = 2,
               .display_type = INT_HEX,
           },
           {.name = "RSSI",
               .length = 1,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = RSSI,
           },
           {.name = "Extended_Inquiry_Response",
               .length = 240,
               .display_type = SEQ_HEX,
           },
       },
     },
     [0x30] = {
       .name = "Encryption Key Refresh Complete",
       .opcode = 0x30,
       .parameter_count = 2,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
       },
     },
     [0x31] = {
       .name = "IO Capability Request",
       .opcode = 0x31,
       .parameter_count = 1,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
       },
     },
     [0x32] = {
       .name = "IO Capability Response",
       .opcode = 0x32,
       .parameter_count = 4,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "IO_Capability",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "OOB_Data_Present",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Authenticatioin_requirements",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x33] = {
       .name = "User Confirmation Request",
       .opcode = 0x33,
       .parameter_count = 2,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "Numeric_Value",
               .length = 4,
               .display_type = INT_HEX,
           },
       },
     },
     [0x34] = {
       .name = "User Passkey Request",
       .opcode = 0x34,
       .parameter_count = 1,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
       },
     },
     [0x35] = {
       .name = "Remote OOB Data Request",
       .opcode = 0x35,
       .parameter_count = 1,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
       },
     },
     [0x36] = {
       .name = "Simple Pairing Complete",
       .opcode = 0x36,
       .parameter_count = 2,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
       },
     },
     [0x38] = {
      .name = "Link Supervision Timeout Changed",
      .opcode = 0x38,
      .parameter_count = 2,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Link_Supervision_Timeout",
              .length = 2,
              .display_type = INT_HEX,
          },
      },
    },
     [0x39] = {
       .name = "Enhanced Flush Complete",
       .opcode = 0x39,
       .parameter_count = 1,
       .parameter = {
           {.name = "Handle",
               .length = 2,
               .display_type = INT_HEX,
           },
       },
     },
     [0x3B] = {
      .name = "User Passkey Notification",
      .opcode = 0x3B,
      .parameter_count = 2,
      .parameter = {
          {.name = "BD_ADDR",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Passkey",
              .length = 4,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = SECURITY_PASSKEY_TYPE,
          },
      },
    },
     [0x3C] = {
       .name = "Keypress Notification",
       .opcode = 0x3C,
       .parameter_count = 2,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "Notification_Type",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x3D] = {
       .name = "Remote Host Supported Features Notification",
       .opcode = 0x3D,
       .parameter_count = 2,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "Host_Supported_Features",
               .length = 8,
               .display_type = SEQ_HEX,
           },
       },
     },
     [0x3E] = {
       .name = "LE Meta Event",
       .opcode = 0x3E,
       .parameter_count = 0,
       .parameter = {},
     },
     [0x40] = {
      .name = "Physical Link Complete",
      .opcode = 0x40,
      .parameter_count = 2,
      .parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "Physical_Link_Handle",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
    },
     [0x41] = {
       .name = "Channel Selected",
       .opcode = 0x41,
       .parameter_count = 1,
       .parameter = {
           {.name = "Physical_Link_Handle",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x42] = {
       .name = "Disconnection Physical Link Complete",
       .opcode = 0x42,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Physical_Link_Handle",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Reason",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
       },
     },
     [0x43] = {
       .name = "Physical Link Loss Early Warning",
       .opcode = 0x43,
       .parameter_count = 2,
       .parameter = {
           {.name = "Physical_Link_Handle",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Link_Loss_Reason",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x44] = {
       .name = "Physical Link Recovery",
       .opcode = 0x44,
       .parameter_count = 1,
       .parameter = {
           {.name = "Physical_Link_Handle",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x45] = {
       .name = "Logical Link Complete",
       .opcode = 0x45,
       .parameter_count = 4,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Logical_Link_Handle",
               .length = 2,
               .display_type = INT_HEX,
           },
           {.name = "Physical_Link_Handle",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Tx_Flow_Spec_ID",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x46] = {
       .name = "Disconnection Logical Link Complete",
       .opcode = 0x46,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Logical_Link_Handle",
               .length = 2,
               .display_type = INT_HEX,
           },
           {.name = "Reason",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           }
       },
     },
     [0x47] = {
       .name = "Flow Spec Modify Complete",
       .opcode = 0x47,
       .parameter_count = 2,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Handle",
               .length = 2,
               .display_type = INT_HEX,
           },
       },
     },
     [0x48] = {
       .name = "Number Of Completed Data Blocks",
       .opcode = 0x48,
       .parameter_count = 5,
       .parameter = {
           {.name = "Total_Num_Data_Blocks",
               .length = 2,
               .display_type = INT_DEC,
           },
           {.name = "Number_Of_Handles",
               .length = 1,
               .display_type = INT_DEC,
               .repeat_param_num = 3,
           },
           {.name = "Handle",
               .length = 2,
               .display_type = INT_HEX,
           },
           {.name = "Num_Of_Completed_Pakcets",
               .length = 2,
               .display_type = INT_DEC,
           },
           {.name = "Num_Of_Completed_Blocks",
               .length = 2,
               .display_type = INT_DEC,
           },
       },
     },
     [0x49] = {
       .name = "AMP Start Test",
       .opcode = 0x49,
       .parameter_count = 2,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Test Scenario",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x4A] = {
       .name = "AMP Test End",
       .opcode = 0x4A,
       .parameter_count = 2,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Test Scenario",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x4B] = {
       .name = "AMP Receiver Report",
       .opcode = 0x4B,
       .parameter_count = 7,
       .parameter = {
           {.name = "Controller_Type",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Reason",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Event_type",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Number_Of_Frames",
               .length = 2,
               .display_type = INT_DEC,
           },
           {.name = "Number_Of_Error_Frames",
               .length = 2,
               .display_type = INT_DEC,
           },
           {.name = "Number_Of_Bits",
               .length = 4,
               .display_type = INT_DEC,
           },
           {.name = "Number_Of_Error_Bits",
               .length = 4,
               .display_type = INT_DEC,
           },
       },
     },
     [0x4C] = {
       .name = "Short_Range_Mode_Change_Complete",
       .opcode = 0x4C,
       .parameter_count = 3,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "Physical_Link_Handle",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Short_Range_Mode_State",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x4D] = {
       .name = "AMP_Status_Change",
       .opcode = 0x4D,
       .parameter_count = 2,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "AMP_Status",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x4E] = {
       .name = "Triggered Clock Capture",
       .opcode = 0x4E,
       .parameter_count = 4,
       .parameter = {
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
           {.name = "Which_Clock",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Clock",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Slot_Offset",
               .length = 2,
               .display_type = INT_HEX,
           },
       },
     },
     [0x4F] = {
       .name = "Synchronization Train Complete",
       .opcode = 0x4F,
       .parameter_count = 1,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
       },
     },
     [0x50] = {
       .name = "Synchronization Train Received",
       .opcode = 0x50,
       .parameter_count = 8,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "Clock_Offset",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "AFH_Channel_Map",
               .length = 10,
               .display_type = SEQ_HEX,
           },
           {.name = "LT_ADDR",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Next_Broadcast_Instant",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Connectionless_Slave_Broadcast_Interval",
               .length = 2,
               .display_type = INT_HEX,
           },
           {.name = "Service_Data",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x51] = {
       .name = "Connectionless Slave Broadcast Receive",
       .opcode = 0x51,
       .parameter_count = 8,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "LT_ADDR",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "CLK",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Offset",
               .length = 4,
               .display_type = INT_HEX,
           },
           {.name = "Receive_Status",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Fragment",
               .length = 1,
               .display_type = INT_HEX,
           },
           {.name = "Data_Length",
               .length = 1,
               .display_type = INT_DEC,
           },
           {.name = "Data",
               .length = -1,
               .display_type = SEQ_HEX,
           },
       },
     },
     [0x52] = {
       .name = "Connectionless Slave Broadcast Timeout",
       .opcode = 0x52,
       .parameter_count = 2,
       .parameter = {
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
           {.name = "LT_ADDR",
               .length = 1,
               .display_type = INT_HEX,
           },
       },
     },
     [0x53] = {
       .name = "Truncated Page Complete",
       .opcode = 0x53,
       .parameter_count = 2,
       .parameter = {
           {.name = "Status",
               .length = 1,
               .display_type = TEXT_REASON_STATUS_CODE,
           },
           {.name = "BD_ADDR",
               .length = 6,
               .display_type = TEXT_BD_ADDR,
           },
       },
     },
     [0x54] = {
       .name = "Slave Page Response Timeout",
       .opcode = 0x54,
       .parameter_count = 0,
       .parameter = {},
     },
     [0x55] = {
       .name = "Connectionless Slave Broadcast Channel Map Change",
       .opcode = 0x55,
       .parameter_count = 1,
       .parameter = {
           {.name = "Channel_Map",
               .length = 10,
               .display_type = SEQ_HEX,
           },

       },
     },
     [0x56] = {
       .name = "Inquiry Response Notification",
       .opcode = 0x56,
       .parameter_count = 2,
       .parameter = {
           {.name = "LAP",
               .length = 3,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = LAP_IAC,
           },
           {.name = "RSSI",
               .length = 1,
               .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
               .index_of_special_display_param = RSSI,
           },
       },
     },
     [0x57] = {
       .name = "Authenticated Payload Timeout Expired",
       .opcode = 0x57,
       .parameter_count = 1,
       .parameter = {
           {.name = "Connection_Handle",
               .length = 2,
               .display_type = INT_HANDLE,
           },
       },
     },
};

#define HCI_LE_META_EVENT_SUBEVENT_NUMBER  11
const HCI_EVENT_REPR LE_META_EVENTS[HCI_LE_META_EVENT_SUBEVENT_NUMBER + 1] = {
    [0x01] = {
      .name = "LE Connection Complete",
      .opcode = 0x01,
      .parameter_count = 9,
      .parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Role",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Peer_Address_Type",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PEER_ADDRESS_TYPE,
          },
          {.name = "Peer_Address",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Conn_Interval",
              .length = 2,
              .display_type = TIME_CLK2,
          },
          {.name = "Conn_Latency",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Supervision_Timeout",
              .length = 2,
              .display_type = TIME_CLK5,
          },
          {.name = "Master_Clock_Accuracy",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
    },
    [0x02] = {
      .name = "LE Advertising Report",
      .opcode = 0x02,
      .parameter_count = 7,
      .parameter = {
          {.name = "Num_Reports",
              .length = 1,
              .display_type = INT_DEC,
              .repeat_param_num = 6,
          },
          {.name = "Event_Type",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = LE_META_EVENT_ADVERTISING_REPORT_EVENT_TYPE,
          },
          {.name = "Address_Type",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = LE_META_EVENT_ADVERTISING_REPORT_ADDRESS_TYPE,
          },
          {.name = "Address",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Length_Data",
              .length = 1,
              .display_type = INT_DEC,
          },
          {.name = "Data",
              .length = -1,
              .display_type = SEQ_HEX,
          },
          {.name = "RSSI",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = RSSI,
          },
      },
    },
    [0x03] = {
      .name = "LE Connection Update Complete",
      .opcode = 0x03,
      .parameter_count = 5,
      .parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Conn_Interval",
              .length = 2,
              .display_type = TIME_CLK2,
          },
          {.name = "Conn_Latency",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Supervision_Timeout",
              .length = 2,
              .display_type = TIME_CLK5,
          },
      },
    },
    [0x04] = {
      .name = "LE Read Remote Used Features Complete",
      .opcode = 0x04,
      .parameter_count = 3,
      .parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "LE_Features",
              .length = 8,
              .display_type = SEQ_HEX,
          },
      },
    },
    [0x05] = {
      .name = "LE Long Term Key Request",
      .opcode = 0x05,
      .parameter_count = 3,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Random_Number",
              .length = 8,
              .display_type = SEQ_HEX,
          },
          {.name = "Encrypted_Diversifier",
              .length = 2,
              .display_type = INT_HEX,
          },
      },
    },
    [0x06] = {
      .name = "LE Remote Connection Parameter Request",
      .opcode = 0x06,
      .parameter_count = 5,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Interval_Min",
              .length = 2,
              .display_type = TIME_CLK2,
          },
          {.name = "Interval_Max",
              .length = 2,
              .display_type = TIME_CLK2,
          },
          {.name = "Latency",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Timeout",
              .length = 2,
              .display_type = TIME_CLK5,
          },
      },
    },
    [0x07] = {
      .name = "LE Data Length Changes",
      .opcode = 0x07,
      .parameter_count = 5,
      .parameter = {
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "MaxTxOctets",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "MaxTxTime",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "MaxRxOctets",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "MaxRxTime",
              .length = 2,
              .display_type = INT_HEX,
          },
      },
    },
    [0x08] = {
      .name = "LE Read Local P-256 Public Key Complete",
      .opcode = 0x08,
      .parameter_count = 2,
      .parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "Local_P-256_Public_Key",
              .length = 64,
              .display_type = SEQ_HEX,
          },
      },
    },
    [0x09] = {
      .name = "LE Generate DHKey Complete",
      .opcode = 0x09,
      .parameter_count = 2,
      .parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "DHKey",
              .length = 32,
              .display_type = SEQ_HEX,
          },
      },
    },
    [0x0A] = {
      .name = "LE Enhanced Connection Complete",
      .opcode = 0x0A,
      .parameter_count = 11,
      .parameter = {
          {.name = "Status",
              .length = 1,
              .display_type = TEXT_REASON_STATUS_CODE,
          },
          {.name = "Connection_Handle",
              .length = 2,
              .display_type = INT_HANDLE,
          },
          {.name = "Role",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Peer_Address_Type",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = PEER_ADDRESS_TYPE,
          },
          {.name = "Peer_Address",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Local_Resolvable_Private_Address",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Peer_Resolvable_Private_Address",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Conn_Interval",
              .length = 2,
              .display_type = TIME_CLK2,
          },
          {.name = "Conn_Latency",
              .length = 2,
              .display_type = INT_HEX,
          },
          {.name = "Supervision_Timeout",
              .length = 2,
              .display_type = TIME_CLK5,
          },
          {.name = "Master_Clock_Accuracy",
              .length = 1,
              .display_type = INT_HEX,
          },
      },
    },
    [0x0B] = {
      .name = "LE Direct Advertising Report",
      .opcode = 0x0B,
      .parameter_count = 7,
      .parameter = {
          {.name = "Num_Reports",
              .length = 1,
              .display_type = INT_DEC,
              .repeat_param_num = 6,
          },
          {.name = "Event_Type",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = LE_META_EVENT_ADVERTISING_REPORT_EVENT_TYPE,
          },
          {.name = "Address_Type",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = LE_META_EVENT_ADVERTISING_REPORT_ADDRESS_TYPE,
          },
          {.name = "Address",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "Direct_Address_Type",
              .length = 1,
              .display_type = INT_HEX,
          },
          {.name = "Direct_Address",
              .length = 6,
              .display_type = TEXT_BD_ADDR,
          },
          {.name = "RSSI",
              .length = 1,
              .display_type = TEXT_SPECIAL_DISPLAY_PARAM,
              .index_of_special_display_param = RSSI,
          },
      },
    },
};

const char * EVENT_STATUS_TEXT[] = {
    [0x00] = "Success",
    [0x01] = "Unknown HCI Command",
    [0x02] = "Unknown Connection Identifier",
    [0x03] = "Hardware Failure",
    [0x04] = "Page Timeout",
    [0x05] = "Authentication Failure",
    [0x06] = "PIN or Key Missing",
    [0x07] = "Memory Capacity Exceeded",
    [0x08] = "Connection Timeout",
    [0x09] = "Connection Limit Exceeded",
    [0x0A] = "Synchronous Connection Limit To A Device Exceeded",
    [0x0B] = "ACL Connection Already Exists",
    [0x0C] = "Command Disallowed",
    [0x0D] = "Connection Rejected due to Limited Resources",
    [0x0E] = "Connection Rejected Due To Security Reasons",
    [0x0F] = "Connection Rejected due to Unacceptable BD_ADDR",
    [0x10] = "Connection Accept Timeout Exceeded",
    [0x11] = "Unsupported Feature or Parameter Value",
    [0x12] = "Invalid HCI Command Parameters",
    [0x13] = "Remote User Terminated Connection",
    [0x14] = "Remote Device Terminated Connection due to Low Resources",
    [0x15] = "Remote Device Terminated Connection due to Power Off",
    [0x16] = "Connection Terminated By Local Host",
    [0x17] = "Repeated Attempts",
    [0x18] = "Pairing Not Allowed",
    [0x19] = "Unknown LMP PDU",
    [0x1A] = "Unsupported Remote Feature / Unsupported LMP Feature",
    [0x1B] = "SCO Offset Rejected",
    [0x1C] = "SCO Interval Rejected",
    [0x1D] = "SCO Air Mode Rejected",
    [0x1E] = "Invalid LMP Parameters / Invalid LL Parameters",
    [0x1F] = "Unspecified Error",
    [0x20] = "Unsupported LMP Parameter Value / Unsupported LL Parameter Value",
    [0x21] = "Role Change Not Allowed",
    [0x22] = "LMP Response Timeout / LL Response Timeout",
    [0x23] = "LMP Error Transaction Collision",
    [0x24] = "LMP PDU Not Allowed",
    [0x25] = "Encryption Mode Not Acceptable",
    [0x26] = "Link Key cannot be Changed",
    [0x27] = "Requested QoS Not Supported",
    [0x28] = "Instant Passed",
    [0x29] = "Pairing With Unit Key Not Supported",
    [0x2A] = "Different Transaction Collision",
    [0x2B] = "Reserved",
    [0x2C] = "QoS Unacceptable Parameter",
    [0x2D] = "QoS Rejected",
    [0x2E] = "Channel Classification Not Supported",
    [0x2F] = "Insufficient Security",
    [0x30] = "Parameter Out Of Mandatory Range",
    [0x31] = "Reserved",
    [0x32] = "Role Switch Pending",
    [0x33] = "Reserved",
    [0x34] = "Reserved Slot Violation",
    [0x35] = "Role Switch Failed",
    [0x36] = "Extended Inquiry Response Too Large",
    [0x37] = "Secure Simple Pairing Not Supported By Host",
    [0x38] = "Host Busy - Pairing",
    [0x39] = "Connection Rejected due to No Suitable Channel Found",
    [0x3A] = "Controller Busy",
    [0x3B] = "Unacceptable Connection Parameters",
    [0x3C] = "Directed Advertising Timeout",
    [0x3D] = "Connection Terminated due to MIC Failure",
    [0x3E] = "Connection Failed to be Established",
    [0x3F] = "MAC Connection Failed",
    [0x40] = "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging",
};

#if DBG_LOG_ENABLE == TRUE
static bool const_data_is_checked = false;
void check_hci_unit_group(const HCI_UNIT_REPR * hci_unit_group, const int group_len) {
  const HCI_UNIT_REPR * hci_unit;
  const HCI_PARAMETER_REPR * param;
  for (int i = 0; i <= group_len; i++) {
    hci_unit = &hci_unit_group[i];
    for(size_t ii = 0; ii < hci_unit->parameter_count; ii++) {
      param = &hci_unit->parameter[ii];
      if (param->repeat_param_num > 0) {
        if (param->display_type != INT_DEC) {
          DBG_LOG(LOG_TAG,
              "%s FAIL: %s(0x%04x)->%s: repeat_param_num param display type should be INT_DEC ",
              __func__, hci_unit->name, hci_unit->opcode, param->name);
        }
      }
      if (param->display_type == INT_DEC || param->display_type == INT_HEX) {
        if (param->length > (int)sizeof(uint32_t)) {
          DBG_LOG(LOG_TAG,
              "%s FAIL: %s(0x%04x)->%s: length of INT_DEC/INT_HEX param should be less then %d",
              __func__, hci_unit->name, hci_unit->opcode, param->name, sizeof(uint32_t));
        }
      }
      if (param->display_type >= TIME_CLK1 && param->display_type <= TIME_CLK12) {
        if (param->length > (int)sizeof(uint16_t)) {
          DBG_LOG(LOG_TAG,
              "%s FAIL: %s(0x%04x)->%s: length of TIME_* param should be less then %d",
              __func__, hci_unit->name, hci_unit->opcode, param->name, sizeof(uint16_t));
        }
      }
    }
    for(size_t ii = 0; ii < hci_unit->return_parameter_count; ii++) {
      param = &hci_unit->return_parameter[ii];
      if (param->repeat_param_num > 0) {
        if (param->display_type != INT_DEC) {
          DBG_LOG(LOG_TAG,
              "%s FAIL: %s(0x%04x)->%s: repeat_param_num param display type should be INT_DEC ",
              __func__, hci_unit->name, hci_unit->opcode, param->name);
        }
      }
      if (param->display_type == INT_DEC || param->display_type == INT_HEX) {
        if (param->length > (int)sizeof(uint32_t)) {
          DBG_LOG(LOG_TAG,
              "%s FAIL: %s(0x%04x)->%s: length of INT_DEC/INT_HEX param should be less then %d",
              __func__, hci_unit->name, hci_unit->opcode, param->name, sizeof(uint32_t));
        }
      }
      if (param->display_type >= TIME_CLK1 && param->display_type <= TIME_CLK12) {
        if (param->length > (int)sizeof(uint16_t)) {
          DBG_LOG(LOG_TAG,
              "%s FAIL: %s(0x%04x)->%s: length of TIME_* param should be less then %d",
              __func__, hci_unit->name, hci_unit->opcode, param->name, sizeof(uint16_t));
        }
      }
    }
  }
}

void validate_const_data_format() {
  if (!const_data_is_checked) {
    check_hci_unit_group(HCI_LINK_CONTROL_COMMANDS, LING_CONTROL_NUM);
    check_hci_unit_group(HCI_LINK_POLICY_COMMANDS, LINK_POLICY_NUM);
    check_hci_unit_group(HCI_CONTROLLER_BASEBAND_COMMANDS,
        CONTROLLER_BASEBAND_NUM);
    check_hci_unit_group(HCI_INFORMATIONAL_PARAMETERS,
        INFORMATIONAL_PARAMETERS_NUM);
    check_hci_unit_group(HCI_STATUS_PARAMETERS, STATUS_PARAMETERS_NUM);
    check_hci_unit_group(HCI_TESTING_COMMANDS, TESTING_NUM);
    check_hci_unit_group(HCI_LE_CONTROLLER_COMMANDS, LE_CONTROLLER_NUM);

    check_hci_unit_group(HCI_EVENTS, HCI_EVENT_NUMBER);
    check_hci_unit_group(LE_META_EVENTS, HCI_LE_META_EVENT_SUBEVENT_NUMBER);
    const_data_is_checked = true;
  }
}
#endif

#define GET_CMD_AT(cmd_group, group_len, index) \
      (((index) > group_len) ? NULL : &(cmd_group[index]))

const HCI_COMMAND_REPR * get_matched_hci_cmd_repr(uint16_t opcode) {
  uint8_t ogf = HCI_OGF(opcode);
  uint16_t ocf = HCI_OCF(opcode);
  switch (ogf) {
  case HCI_CMD_GRP_LINK_CONTROL:
    return GET_CMD_AT(HCI_LINK_CONTROL_COMMANDS, LING_CONTROL_NUM, ocf);
  case HCI_CMD_GRP_LINK_POLICY:
    return GET_CMD_AT(HCI_LINK_POLICY_COMMANDS, LINK_POLICY_NUM, ocf);
  case HCI_CMD_GRP_CONTROLLER_BASEBAND:
    return GET_CMD_AT(HCI_CONTROLLER_BASEBAND_COMMANDS, CONTROLLER_BASEBAND_NUM,
        ocf);
  case HCI_CMD_GRP_INFORMATIONAL_PARAMETERS:
    return GET_CMD_AT(HCI_INFORMATIONAL_PARAMETERS,
        INFORMATIONAL_PARAMETERS_NUM, ocf);
  case HCI_CMD_GRP_STATUS_PARAMETERS:
    return GET_CMD_AT(HCI_STATUS_PARAMETERS, STATUS_PARAMETERS_NUM, ocf);
  case HCI_CMD_GRP_TESTING:
    return GET_CMD_AT(HCI_TESTING_COMMANDS, TESTING_NUM, ocf);
  case HCI_CMD_GRP_LE_CONTROLLER:
    return GET_CMD_AT(HCI_LE_CONTROLLER_COMMANDS, LE_CONTROLLER_NUM, ocf);
  case HCI_CMD_GRP_VENDOR_SPECIFIC: {
    const HCI_COMMAND_REPR *vendor_cmd = GET_CMD_AT(VENDOR_SPECIFIC_COMMAND,
        VENDOR_SPECIFIC_COMMAND_NUM, ocf);
    if (vendor_cmd == NULL) {
      vendor_cmd = &VENDOR_SPECIFIC_COMMAND[0];
    }
    return vendor_cmd;
  }
  default:
    break;
  }
  return NULL;
}

typedef struct {
  const char * name;
  int seq_num;
  char value[255 * 3];
  int indent_level;
} HCI_PARAM_VALUE;

typedef struct _HCI_INSTANCE {
  const char * name;
  uint16_t opcode;
  size_t parameter_length;
  size_t parameter_count;
  size_t value_index;
  HCI_PARAM_VALUE value[MAX_HCI_PARAM_NUM];
  size_t extra_count;
  HCI_PARAM_VALUE *extra_value;
} HCI_INSTANCE;

bool parse_special_displayed_parameters(int specific_index, void *val_in,
    __attribute__((__unused__)) int val_len, char * display_buf) {
  switch (specific_index) {
  case SCAN_ENABLE: { //scan enable
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) No Scans enabled.", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Inquiry Scan enabled. Page Scan always disabled.", value);
    } else if (value == 0x02) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Inquiry Scan disabled. Page Scan enabled.", value);
    } else if (value == 0x03) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Inquiry Scan enabled. Page Scan enabled.", value);
    } else {
      break;
    }
    return true;
  }
  case 2: // inquiry scan interval
  case 3: // inquiry scan window
    break;
  case INQUIRY_SCAN_TYPE: { // inquiry scan type
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Mandatory: Standard Scan(default)", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Optional: Interlaced Scan",
          value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case INQUIRY_MODE: { // inquiry mode
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Standard Inquiry Result event format", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Inquiry Result format with RSSI", value);
    } else if (value == 0x02) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Inquiry Result with RSSI format or Extended Inquiry Result format",
              value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case 6: // page timeout
  case 7: // connection accept timeout
  case 8: // page scan interval
  case 9: // page scan window
    break;
  case 10: { // page scan period mode(deprecated)
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) P0", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) P1", value);
    } else if (value == 0x02) {
      display_buf += sprintf(display_buf, "(0x%02x) P2", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case PAGE_SCAN_TYPE: { // page scan type
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Mandatory: Standard Scan(default)", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Optional: Interlaced Scan",
          value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case VOICE_SETTING: { // void setting
    uint16_t value = *((uint16_t*) val_in);
    display_buf += sprintf(display_buf, "(0x%04x)\n", value);
    uint8_t tmp;
    // input coding
    tmp = (value & 0x0300) >> 8;
    if (tmp == 0x00) {
      display_buf += sprintf(display_buf, "%sInput Coding: Linear\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x01) {
      display_buf += sprintf(display_buf,
          "%sInput Coding: u-law Input Coding\n", LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x02) {
      display_buf += sprintf(display_buf,
          "%sInput Coding: A-law Input Coding\n", LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x03) {
      display_buf += sprintf(display_buf, "%sReserved for future use\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    // input data format
    tmp = (value & 0x00A0) >> 6;
    if (tmp == 0x00) {
      display_buf += sprintf(display_buf,
          "%sInput Data Format: 1's complement\n", LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x01) {
      display_buf += sprintf(display_buf,
          "%sInput Data Format: 2's complement\n", LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x02) {
      display_buf += sprintf(display_buf,
          "%sInput Data Format: Sign-Magnitude\n", LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x03) {
      display_buf += sprintf(display_buf, "%sInput Data Format: Unsigned\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    // input sample size
    tmp = (value & 0x0020) >> 5;
    if (tmp == 0x00) {
      display_buf += sprintf(display_buf,
          "%sInput Sample Size: 8-bit(only for linear PCM)\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x01) {
      display_buf += sprintf(display_buf,
          "%sInput Sample Size: 16-bit(only for linear PCM)\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    // Linear_PCM_Bit_Pos
    tmp = (value & 0x001A) >> 2;
    display_buf +=
        sprintf(display_buf,
            "%sLinear_PCM_Bit_Pos: %u bit positions that MSB of sample is away from starting at MSB(only for Linear PCM)\n",
            LINE_INDENT[INDENT_LEVEL_4], tmp);
    // input coding
    tmp = value & 0x0003;
    if (tmp == 0x00) {
      display_buf += sprintf(display_buf, "%sAir Coding Format: CVSD\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x01) {
      display_buf += sprintf(display_buf, "%sAir Coding Format: u-law\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x02) {
      display_buf += sprintf(display_buf, "%sAir Coding Format: A-law\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else if (tmp == 0x03) {
      display_buf += sprintf(display_buf,
          "%sAir Coding Format: Transparent Data\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    return true;
  }
  case PIN_TYPE: { // PIN type
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) Variable PIN", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Fixed PIN", value);
    } else {
      break;
    }
    return true;
  }
  case 14: //Link key
  case 15: //failed contact counter
  case AUTHENTICATION_ENABLE: { // authentication enable
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Authentication not required", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Authentication required for all connections", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case HOLD_MODE_ACTIVITY: { // hold mode activity
    uint8_t value = *((uint8_t*) val_in);
    display_buf += sprintf(display_buf, "(0x%02x) ", value);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, " Maintain current Power State");
    } else if ((value & 0x01) || (value & 0x02) || (value & 0x04)) {
      if (value & 0x01) {
        display_buf += sprintf(display_buf, "| Suspend Page Scan ");
      }
      if (value & 0x02) {
        display_buf += sprintf(display_buf, "| Suspend Inquiry Scan");
      }
      if (value & 0x04) {
        display_buf += sprintf(display_buf, "| Suspend Periodic Inquiries");
      }
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case LINK_POLICY_SETTING: { // Link Policy Setting
    uint16_t value = *((uint16_t*) val_in);
    display_buf += sprintf(display_buf, "(0x%04x) ", value);
    if (value == 0x0000) {
      display_buf += sprintf(display_buf, " Disable All LM Modes Default");
    } else if ((value & 0x01) || (value & 0x02) || (value & 0x04)
        || (value & 0x08)) {
      if (value & 0x0001) {
        display_buf += sprintf(display_buf, " Role switch: Enable ");
      } else {
        display_buf += sprintf(display_buf, " Role switch: Disable");
      }
      if (value & 0x0002) {
        display_buf += sprintf(display_buf, "| Hold Mode: Enable");
      } else {
        display_buf += sprintf(display_buf, "| Hold Mode: Disable");
      }
      if (value & 0x0004) {
        display_buf += sprintf(display_buf, "| Sniff Mode: Enable");
      } else {
        display_buf += sprintf(display_buf, "| Sniff Mode: Disable");
      }
      if (value & 0x0008) {
        display_buf += sprintf(display_buf, "| Park State: Enable");
      } else {
        display_buf += sprintf(display_buf, "| Park State: Disable");
      }
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case 19: // Flush timeout
  case 20: // Num Broadcast Retransmissions
  case 21: // Link Supervision Timeout
    break;
  case SYNCHRONOUS_FLOW_CONTROL_ENABLE: { // Synchronous Flow Control Enable
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Synchronous Flow Control is disabled", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Synchronous Flow Control is enabled", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case 23: // local Name
    break;
  case 24: { // extended inquiry response
    break;
  }
  case ERRONEOUS_DATA_REPORTING: { // erroneous data reporting
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Erroneous data reporting disabled", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Erroneous data reporting enabled", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case 26: // class of device
    break;
  case 27: { //support commands
    break;
  }
  case 28: // logical link accept timeout
    break;
  case LOCATION_DOMAIN_AWARE: { // location domain aware
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) Regulatory domain unknown",
          value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Regulatory domain known",
          value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case 30: // location domain
  case LOCATION_DOMAIN_OPTIONS: { // location domain options
    uint8_t value = *((uint8_t*) val_in);
    if (value & 0x20) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) 'space' indicates that the code applies to the entire country",
              value);
    } else if (value & 0x4F) {
      display_buf += sprintf(display_buf,
          "(0x%02x) 'O' indicates for use outdoors only", value);
    } else if (value & 0x49) {
      display_buf += sprintf(display_buf,
          "(0x%02x) 'I' indicates for use indoors only", value);
    } else if (value & 0x58) {
      display_buf += sprintf(display_buf,
          "(0x%02x) 'X' indicates a non-country entity", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case LOCATION_OPTIONS: { // location options
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) Not mains-powered", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Mains powered", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case FLOW_CONTROL_MODE: { // Flow control mode
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Packet based data flow control mode", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Data block based data flow control mode", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case LE_SUPPORTED_HOST: { // LE Supported Host
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) LE Supported(Host) disabled(default)", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) LE Supported(Host) enabled",
          value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case 35: { // simultaneous LE host
    break;
  }
  case 36: // Synchronization Train Interval
  case 37: // Synchronization Train Timeout
  case 38: // Service Data
    break;
  case SECURE_CONNECTIONS_HOST_SUPPORT: { // Secure Connections Host Support
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Secure_Connections_Host_Support is 'disabled'. Host does not support secure connection(default)",
              value);
    } else if (value == 0x01) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Secure_Connection_Host_Support is 'enabled'. Host supports secure connections",
              value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case 40: // Authenticated Payload Timeout
  case 41: // Extended Page Timeout
  case 42: // Extended Inquiry Length
    break;
  case PAGE_SCAN_REPETITION_MODE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) R0", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) R1", value);
    } else if (value == 0x02) {
      display_buf += sprintf(display_buf, "(0x%02x) R2", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case LAP_IAC: {
    uint32_t value = *((uint32_t*) val_in);
    DBG_LOG(LOG_TAG, "%s handle LAP_IAC value: 0x%08X", __func__, value);
    if (value == 0x009E8B33) {
      display_buf += sprintf(display_buf,
          "(0x%08x) General/Unlimited Inquiry Access Code(GIAC)", value);
    } else {
      display_buf += sprintf(display_buf, "0x%08x", value);
    }
    return true;
  }
  case PACKET_TYPE_ACL: {
    uint16_t value = *((uint16_t*) val_in);
    display_buf += sprintf(display_buf, "0x%04x\n", value);
    if (value & 0x0002) {
      display_buf += sprintf(display_buf, "%s2-DH1 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s2-DH1 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0004) {
      display_buf += sprintf(display_buf, "%s3-DH1 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s3-DH1 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0008) {
      display_buf += sprintf(display_buf, "%s  DM1 may be used \n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  DM1 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0010) {
      display_buf += sprintf(display_buf, "%s  DH1 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  DH1 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0100) {
      display_buf += sprintf(display_buf, "%s2-DH3 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s2-DH3 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0200) {
      display_buf += sprintf(display_buf, "%s3-DH3 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s3-DH3 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0400) {
      display_buf += sprintf(display_buf, "%s  DM3 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  DM3 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0800) {
      display_buf += sprintf(display_buf, "%s  DH3 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  DH3 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x1000) {
      display_buf += sprintf(display_buf, "%s2-DH5 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s2-DH5 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x2000) {
      display_buf += sprintf(display_buf, "%s3-DH5 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s3-DH5 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x4000) {
      display_buf += sprintf(display_buf, "%s  DM5 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  DM5 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x8000) {
      display_buf += sprintf(display_buf, "%s  DH5 may be used",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  DH5 may not be used",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    return true;
  }
  case PACKET_TYPE_SCO: {
    uint16_t value = *((uint16_t*) val_in);
    display_buf += sprintf(display_buf, "0x%04x\n", value);
    if (value & 0x0001) {
      display_buf += sprintf(display_buf, "%s  HV1 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  HV1 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0002) {
      display_buf += sprintf(display_buf, "%s  HV2 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  HV2 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0004) {
      display_buf += sprintf(display_buf, "%s  HV3 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  HV3 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0008) {
      display_buf += sprintf(display_buf, "%s  EV3 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  EV3 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0010) {
      display_buf += sprintf(display_buf, "%s  EV4 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  EV4 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0020) {
      display_buf += sprintf(display_buf, "%s  EV5 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s  EV5 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0040) {
      display_buf += sprintf(display_buf, "%s2-EV3 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s2-EV3 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0080) {
      display_buf += sprintf(display_buf, "%s3-EV3 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s3-EV3 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0100) {
      display_buf += sprintf(display_buf, "%s2-EV5 may not be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s2-EV5 may be used\n",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    if (value & 0x0200) {
      display_buf += sprintf(display_buf, "%s3-EV5 may not be used",
          LINE_INDENT[INDENT_LEVEL_4]);
    } else {
      display_buf += sprintf(display_buf, "%s3-EV5 may be used",
          LINE_INDENT[INDENT_LEVEL_4]);
    }
    return true;
  }
  case SIMPLE_PAIRING_MODE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Simple Pairing mode disabled(default)", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Simple Pairing mode enabled", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case SIMPLE_PAIRING_DEBUG_MODE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Simple Pairing debug mode disabled(default)", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Simple Pairing debug mode enabled", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case FEC_REQUIRED: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) FEC is not required",
          value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) FEC is required", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved", value);
    }
    return true;
  }
  case RSSI: {
    int8_t value = *((int8_t*) val_in);
    if (value == 127) {
      display_buf += sprintf(display_buf, "(0x%02x) RSSI is not available",
          value & 0xFF);
    } else if (value > 21 && value < 126) {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value & 0xFF);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) %d dBm", value & 0xFF,
          value);
    }
    return true;
  }
  case DELETE_ALL_FLAG: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Delete only the Link Key for specified BD_ADDR", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Delete all stored Link Keys.", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case LE_META_EVENT_ADVERTISING_REPORT_EVENT_TYPE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Connectable undirected advertising(ADV_IND)", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Connectable directed advertising(ADV_DIRECT_IND)", value);
    } else if (value == 0x02) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Scannable undirected advertising(ADV_SCAN_IND)", value);
    } else if (value == 0x03) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Non connectable undirected advertising(ADV_NONCONN_IND)",
          value);
    } else if (value == 0x04) {
      display_buf += sprintf(display_buf, "(0x%02x) Scan Response(SCAN_RSP)",
          value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case LE_META_EVENT_ADVERTISING_REPORT_ADDRESS_TYPE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) Public Device Address",
          value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Random Device Address",
          value);
    } else if (value == 0x02) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Public Identity Address(Corresponds to Resolved Private Address)",
              value);
    } else if (value == 0x03) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Random(static) Identity Address(Corresponds to Resolved Private Address)",
              value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case ADVERTISING_TYPE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Connectable undirected advertising(ADV_IND)(default)",
          value);
    } else if (value == 0x01) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Connectable high duty cycle directed advertising(ADV_DIRECT_IND, high duty cycle)",
              value);
    } else if (value == 0x02) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Scannable undirected advertising(ADV_SCAN_IND)", value);
    } else if (value == 0x03) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Non connectable undirected advertising(ADV_NONCONN_IND)",
          value);
    } else if (value == 0x04) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Connectable low duty cycle directed advertising(ADV_DIRECT_IND, low duty cycle)",
              value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case ADVERTISING_ENABLE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Advertising is disabled(default)", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Advertising is enabled",
          value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case LE_SCAN_TYPE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Passive Scanning. No SCAN_REQ packets shall be sent.(default)",
              value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Active scanning. SCAN_REQ packets may be sent.", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case LE_SCAN_ENABLE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) Scanning disabled", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Scanning enabled", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case FILTER_DUPLICATES: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Duplicate filtering disabled", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Duplicate filtering  enabled", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case ADDRESS_TYPE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) Public Device Address",
          value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Random Device Address",
          value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case OWN_ADDRESS_TYPE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Public Device Address(default)", value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf, "(0x%02x) Random Device Address",
          value);
    } else if (value == 0x02) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Controller generates Resolvable Private Address based on the local IRK from resolving list. If resolving list contains no matching entry, use public address",
              value);
    } else if (value == 0x03) {
      display_buf +=
          sprintf(display_buf,
              "(0x%02x) Controller generates Resolvable Private Address based on the local IRK from resolving list. If resolving list contains no matching entry, use random address from LE_Set_Random_Address",
              value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case PEER_IDENTITY_ADDRESS_TYPE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf, "(0x%02x) Public Identity Address",
          value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Random(static) Identity Address", value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
  case PEER_ADDRESS_TYPE: {
    uint8_t value = *((uint8_t*) val_in);
    if (value == 0x00) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Public Device Address(default) or Public Identity Address",
          value);
    } else if (value == 0x01) {
      display_buf += sprintf(display_buf,
          "(0x%02x) Random Device Address or Random(static) Identity Address",
          value);
    } else {
      display_buf += sprintf(display_buf, "(0x%02x) Reserved for future use",
          value);
    }
    return true;
  }
#if HCI_HIDE_SECURITY_DATA == TRUE
  case SECURITY_KEY_TYPE:
  case SECURITY_PASSKEY_TYPE: {
    display_buf += sprintf(display_buf, "(Security Data is Hidden)");
  }
  return true;
#endif
  default:
    break;
  }
  return false;
}

void parse_parameter(HCI_INSTANCE *instance,
    const HCI_PARAMETER_REPR *param_repr, const int param_seq_num,
    const uint8_t **parse_data, int *data_left, int indent_level) {
  DBG_LOG(LOG_TAG,
      "[%s]Name:%s, Opcode:0x%04x, Len:%d, p-name:%s, p-len:%d, p-display_type:%d, p-index: %d, left_len: %d",
      __func__, instance->name, instance->opcode, instance->parameter_length,
      param_repr->name, param_repr->length, param_repr->display_type,
      instance->value_index, *data_left);
  int data_left_length = *data_left;
  HCI_PARAM_VALUE *param_ptr = &(instance->value[instance->value_index]);

  param_ptr->name = param_repr->name;
  param_ptr->seq_num = param_seq_num;
  param_ptr->indent_level = indent_level;
  char * buf_ptr = param_ptr->value;

  const uint8_t *data = *parse_data;

  int param_length = param_repr->length;
  if (param_length < 0) {
    const char * length_refer_str = instance->value[instance->value_index
        + param_length].value;
    param_length = (int) strtol(length_refer_str, NULL, 0);
  }
  HCI_PARAM_DISPLAY_TYPE param_type = param_repr->display_type;

  // If data left is less than parameter length, there are 2 case:
  // 1. data left is truncated.
  // 2. parameter length is INT_MAX, which means it should print all data left
  //    as sequence.
  bool data_truncated = false;
  if (param_length > data_left_length) {
    DBG_LOG(LOG_TAG,
        "[%s]param_name: %s, param_length: %d, data_left_length: %d",
        param_ptr->name, __func__, param_length, data_left_length);
    if (param_length != INT_MAX) {
      data_truncated = true;
    }
    param_length = data_left_length;
    param_type = SEQ_HEX;
  }

  switch (param_type) {
  case INT_HEX: {
    if (param_length == sizeof(uint8_t)) {
      uint8_t param_value;
      STREAM_TO_UINT8(param_value, data);
      buf_ptr += sprintf(buf_ptr, "0x%02x", param_value);
    } else if (param_length == sizeof(uint16_t)) {
      uint16_t param_value;
      STREAM_TO_UINT16(param_value, data);
      buf_ptr += sprintf(buf_ptr, "0x%04x", param_value);
    } else if (param_length == sizeof(uint32_t) - 1) {
      uint32_t param_value;
      STREAM_TO_UINT24(param_value, data);
      buf_ptr += sprintf(buf_ptr, "0x%08x", param_value);
    } else if (param_length == sizeof(uint32_t)) {
      uint32_t param_value;
      STREAM_TO_UINT32(param_value, data);
      buf_ptr += sprintf(buf_ptr, "0x%08x", param_value);
    } else {
      assert(0);
    }
    break;
  }
  case INT_DEC: {
    uint32_t param_value;
    if (param_length == sizeof(uint8_t)) {
      STREAM_TO_UINT8(param_value, data);
    } else if (param_length == sizeof(uint16_t)) {
      STREAM_TO_UINT16(param_value, data);
    } else if (param_length == sizeof(uint32_t) - 1) {
      STREAM_TO_UINT24(param_value, data);
    } else if (param_length == sizeof(uint32_t)) {
      STREAM_TO_UINT32(param_value, data);
    } else {
      assert(0);
    }
    buf_ptr += sprintf(buf_ptr, "%u", param_value);
    break;
  }
  case INT_HANDLE: {
    assert(param_length == sizeof(uint16_t));
    uint16_t param_value;
    STREAM_TO_UINT16(param_value, data);
    param_value = param_value & 0x0fff;
    buf_ptr += sprintf(buf_ptr, "(0x%04x) %u", param_value, param_value);
    break;
  }
  case SEQ_HEX: {
    uint8_t param_value;
    for (int n = 0; n < param_length; n++) {
      STREAM_TO_UINT8(param_value, data);
      buf_ptr += sprintf(buf_ptr, "%02x ", param_value);
    }
    if (data_truncated) {
      buf_ptr += sprintf(buf_ptr, "(truncated)");
    }
    break;
  }
  case SEQ_CHAR: {
    uint8_t param_value;
    for (int n = 0; n < param_length; n++) {
      STREAM_TO_UINT8(param_value, data);
      buf_ptr += sprintf(buf_ptr, "%c", param_value);
    }
    if (data_truncated) {
      buf_ptr += sprintf(buf_ptr, "(truncated)");
    }
    break;
  }
  case TIME_CLK1:
  case TIME_CLK2:
  case TIME_CLK5:
  case TIME_CLK12: {
    uint16_t param_value;
    if (param_length == sizeof(uint8_t)) {
      STREAM_TO_UINT8(param_value, data);
    } else if (param_length == sizeof(uint16_t)) {
      STREAM_TO_UINT16(param_value, data);
    } else {
      assert(0);
    }
    double time_value_ms;
    if (param_type == TIME_CLK1) {
      time_value_ms = ((double) param_value) * 0.625;
      buf_ptr += sprintf(buf_ptr, "(0x%04x) %lf msec.", param_value,
          time_value_ms);
    } else if (param_type == TIME_CLK2) {
      time_value_ms = ((double) param_value) * 0.625 * 2;
      buf_ptr += sprintf(buf_ptr, "(0x%04x) %lf msec.", param_value,
          time_value_ms);
    } else if (param_type == TIME_CLK5) {
      time_value_ms = ((double) param_value) * 10;
      buf_ptr += sprintf(buf_ptr, "(0x%04x) %lf msec.", param_value,
          time_value_ms);
    } else if (param_type == TIME_CLK12) {
      time_value_ms = ((double) param_value) * 1.28;
      buf_ptr += sprintf(buf_ptr, "(0x%04x) %lf sec.", param_value,
          time_value_ms);
    } else {
      assert(0);
    }
    break;
  }
  case TEXT_REASON_STATUS_CODE: {
    uint8_t param_value;
    STREAM_TO_UINT8(param_value, data);
    buf_ptr += sprintf(buf_ptr, "(0x%02x) %s", param_value,
        EVENT_STATUS_TEXT[param_value]);
    break;
  }
  case TEXT_BD_ADDR: {
    assert(param_length = 6); //BD ADDR's parameter should be 6
    uint8_t addr[6];
    int i = 0;
    for (; i < 6; i++) {
      STREAM_TO_UINT8(addr[i], data);
    }
    i--;
    buf_ptr += sprintf(buf_ptr, "0x%02x", addr[i]);
    while (--i >= 0) {
      buf_ptr += sprintf(buf_ptr, "-%02x", addr[i]);
    }
    break;
  }
  case TEXT_SPECIAL_DISPLAY_PARAM: {
    uint32_t param_value;
    void * param_ptr = (void *)&param_value;
    if (param_length == sizeof(uint8_t)) {
      STREAM_TO_UINT8(param_value, data);
    } else if (param_length == sizeof(uint16_t)) {
      STREAM_TO_UINT16(param_value, data);
    } else if (param_length == sizeof(uint32_t) - 1) {
      STREAM_TO_UINT24(param_value, data);
    } else if (param_length == sizeof(uint32_t)) {
      STREAM_TO_UINT32(param_value, data);
    } else {
      param_ptr = (void*) data;
      data += param_length;
    }
    if (parse_special_displayed_parameters(
        param_repr->index_of_special_display_param, param_ptr, param_length,
        buf_ptr)) {
      break;
    }
    // if can not parse_special_displayed_parameters, reset the data pointer
    data -= param_length;
  }
  default: {
    uint8_t param_value;
    for (int n = 0; n < param_length; n++) {
      STREAM_TO_UINT8(param_value, data);
      buf_ptr += sprintf(buf_ptr, "%02x ", param_value);
    }
    if (data_truncated) {
      buf_ptr += sprintf(buf_ptr, "(truncated)");
    }
    break;
  }
  }

  instance->value_index++;
  *data_left = data_left_length - param_length;
  *parse_data = data;
}

// A HCI instance refers to a HCI command or a HCI event
void parse_hci_instance(HCI_INSTANCE * const hci_object,
    const HCI_PARAMETER_REPR * const hci_param_repr, const size_t param_count,
    const uint8_t ** parse_data, const size_t length, int *length_left,
    int indent_level) {
  const uint8_t * data = *parse_data;
  int left_len = *length_left;
  int repeat_param_num = 0;
  for (size_t i = 0; i < param_count && left_len >= 0; i++) {
    // At present, all repeat count is defined before the repeated parameter
    // in Bluetooth Spec(Vol2: PartE Section 7)
    // so we here parse repeated_count parameter firstly, and then parse repeated parameter.
    parse_parameter(hci_object, &(hci_param_repr[i]), 0, &data, &left_len, indent_level);
    repeat_param_num = hci_param_repr[i].repeat_param_num;
    if (repeat_param_num <= 0)
      continue;
    // The last value index in hci_object is (value_index - 1), and here we
    // want to refer this value to get the parameters' repeat count.
    int repeat_count = (int) strtol(
        hci_object->value[hci_object->value_index - 1].value, NULL, 0);
    DBG_LOG(LOG_TAG, "------------>repeat_param_num: %d, repeat_count: %d",
        repeat_param_num, repeat_count);

    for (int repeat = 0; repeat < repeat_count && left_len >= 0; repeat++) {
      for (int repeat_param_index = 1;
          repeat_param_index <= repeat_param_num && left_len >= 0;
          repeat_param_index++) {
        parse_parameter(hci_object,
            &(hci_param_repr[i + repeat_param_index]), (repeat + 1),
            &data, &left_len, indent_level);
      }
    }
    i += repeat_param_num;
  }
  *parse_data = data;
  *length_left = left_len;
}

void parse_hci_command(const uint8_t * parse_command, const char * time_str) {
  uint16_t opcode;
  size_t length;
  const uint8_t * data = parse_command;

  STREAM_TO_UINT16(opcode, data);
  STREAM_TO_UINT8(length, data);

  const HCI_COMMAND_REPR *hci_cmd_matched = get_matched_hci_cmd_repr(opcode);

  if (hci_cmd_matched == NULL || hci_cmd_matched->name == NULL) {
    DBG_LOG(LOG_TAG,
        "%s --- can not find hci_cmd_matched. opCode: 0x%04x, length: %d",
        __func__, opcode, length);
    return;
  }

  HCI_INSTANCE hci_command;
  memset(&hci_command, 0, sizeof(hci_command));

  // Parse HCI command
  hci_command.name = hci_cmd_matched->name;
  hci_command.opcode = opcode;
  hci_command.parameter_length = length;
  hci_command.parameter_count = hci_cmd_matched->parameter_count;
  hci_command.value_index = 0;

  int left_len = length;

  // Parse common HCI command parameters that are pre-defined.
  if (hci_cmd_matched->parameter_count > 0) {
    parse_hci_instance(&hci_command, hci_cmd_matched->parameter,
        hci_cmd_matched->parameter_count, &data, length, &left_len,
        INDENT_LEVEL_1);
  }

  // Handle HCI command that need special parsing.
  if (hci_cmd_matched->opcode == 0x0C05) { // HCI_Set_Event_Filter
    char * curr_value_buf = hci_command.value[hci_command.value_index - 1].value;
    uint8_t filter_type = (uint8_t) strtol(curr_value_buf, NULL, 0);
    if (filter_type == 0x00) {
      sprintf(curr_value_buf, "(0x%02x) Clear All Filters.", filter_type);
    } else if (filter_type == 0x01) {
      sprintf(curr_value_buf, "(0x%02x) Inquiry Result", filter_type);
      uint8_t inquiry_result_filter_condition_type;
      STREAM_TO_UINT8(inquiry_result_filter_condition_type, data);
      left_len--;
      hci_command.value[hci_command.value_index].name =
          "Inquiry_Result_Filter_Condition_Type";
      hci_command.value[hci_command.value_index].indent_level = INDENT_LEVEL_1;
      char * inquiry_result_value_buf =
          hci_command.value[hci_command.value_index].value;
      hci_command.value_index++;
      if (inquiry_result_filter_condition_type == 0x00) {
        sprintf(inquiry_result_value_buf,
            "(0x%02x) Return responses from all devices during the Inquiry process",
            inquiry_result_filter_condition_type);
      } else if (inquiry_result_filter_condition_type == 0x01) {
        sprintf(inquiry_result_value_buf,
            "(0x%02x) A device with a specific Class of Device responded to the Inquiry process",
            inquiry_result_filter_condition_type);
        uint32_t class_of_device;
        STREAM_TO_UINT24(class_of_device, data);
        left_len -= 3;
        hci_command.value[hci_command.value_index].name = "Class_of_Device";
        hci_command.value[hci_command.value_index].indent_level =
            INDENT_LEVEL_1;
        sprintf(hci_command.value[hci_command.value_index].value, "0x%08x",
            class_of_device);
        hci_command.value_index++;
        uint32_t class_of_device_mask;
        STREAM_TO_UINT24(class_of_device_mask, data);
        left_len -= 3;
        hci_command.value[hci_command.value_index].name =
            "Class_of_Device_Mask";
        hci_command.value[hci_command.value_index].indent_level =
            INDENT_LEVEL_1;
        sprintf(hci_command.value[hci_command.value_index].value, "0x%08x",
            class_of_device_mask);
        hci_command.value_index++;
      } else if (inquiry_result_filter_condition_type == 0x02) {
        sprintf(inquiry_result_value_buf,
            "(0x%02x) A device with a specific BD_ADDR responded to the Inquiry process",
            inquiry_result_filter_condition_type);
        hci_command.value[hci_command.value_index].name = "BD_ADDR";
        hci_command.value[hci_command.value_index].indent_level =
            INDENT_LEVEL_1;
        char * tmp_value_buf_ptr =
            hci_command.value[hci_command.value_index].value;
        hci_command.value_index++;
        uint8_t addr[6];
        int i = 0;
        for (; i < 6; i++) {
          STREAM_TO_UINT8(addr[i], data);
        }
        left_len -= 6;
        i--;
        tmp_value_buf_ptr += sprintf(tmp_value_buf_ptr, "0x%02x", addr[i]);
        while (--i >= 0) {
          tmp_value_buf_ptr += sprintf(tmp_value_buf_ptr, "-%02x", addr[i]);
        }
      } else {
        sprintf(inquiry_result_value_buf, "(0x%02x) Reserved for future use",
            inquiry_result_filter_condition_type);
      }
    } else if (filter_type == 0x02) {
      sprintf(curr_value_buf, "(0x%02x) Connection Setup.", filter_type);
      uint8_t connection_setup_filter_condition_type;
      STREAM_TO_UINT8(connection_setup_filter_condition_type, data);
      left_len--;
      hci_command.value[hci_command.value_index].name =
          "Connection_Setup_Filter_Condition_Type";
      char * connection_setup_value_buf =
          hci_command.value[hci_command.value_index].value;
      hci_command.value[hci_command.value_index].indent_level = INDENT_LEVEL_1;
      hci_command.value_index++;
      if (connection_setup_filter_condition_type == 0x00) {
        sprintf(connection_setup_value_buf,
            "(0x%02x) Allow Connections from all devices",
            connection_setup_filter_condition_type);
        hci_command.value[hci_command.value_index].name = "Auto_Accept_Flag";
        hci_command.value[hci_command.value_index].indent_level =
        INDENT_LEVEL_1;
        uint8_t auto_accept_flag;
        STREAM_TO_UINT8(auto_accept_flag, data);
        left_len--;
        if (auto_accept_flag == 0x01) {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Do NOT Auto accept the connection (Auto accept is off).",
              auto_accept_flag);
        } else if (auto_accept_flag == 0x02) {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Do Auto accept the connection with role switch disabled (Auto accept is on).",
              auto_accept_flag);
        } else if (auto_accept_flag == 0x03) {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Do Auto accept the connection with role switch enabled (Auto accept is on).",
              auto_accept_flag);
        } else {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Reserved for future use.", auto_accept_flag);
        }
        hci_command.value_index++;
      } else if (connection_setup_filter_condition_type == 0x01) {
        sprintf(connection_setup_value_buf,
            "(0x%02x) Allow Connections from a device with a specific Class of Device",
            connection_setup_filter_condition_type);
        uint32_t class_of_device;
        STREAM_TO_UINT24(class_of_device, data);
        left_len -= 3;
        hci_command.value[hci_command.value_index].name = "Class_of_Device";
        hci_command.value[hci_command.value_index].indent_level =
            INDENT_LEVEL_1;
        sprintf(hci_command.value[hci_command.value_index].value, "0x%08x",
            class_of_device);
        hci_command.value_index++;
        uint32_t class_of_device_mask;
        STREAM_TO_UINT24(class_of_device_mask, data);
        left_len -= 3;
        hci_command.value[hci_command.value_index].name =
            "Class_of_Device_Mask";
        hci_command.value[hci_command.value_index].indent_level =
            INDENT_LEVEL_1;
        sprintf(hci_command.value[hci_command.value_index].value, "0x%08x",
            class_of_device_mask);
        hci_command.value_index++;
        hci_command.value[hci_command.value_index].name = "Auto_Accept_Flag";
        hci_command.value[hci_command.value_index].indent_level =
            INDENT_LEVEL_1;
        uint8_t auto_accept_flag;
        STREAM_TO_UINT8(auto_accept_flag, data);
        left_len--;
        if (auto_accept_flag == 0x01) {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Do NOT Auto accept the connection (Auto accept is off).",
              auto_accept_flag);
        } else if (auto_accept_flag == 0x02) {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Do Auto accept the connection with role switch disabled (Auto accept is on).",
              auto_accept_flag);
        } else if (auto_accept_flag == 0x03) {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Do Auto accept the connection with role switch enabled (Auto accept is on).",
              auto_accept_flag);
        } else {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Reserved for future use.", auto_accept_flag);
        }
        hci_command.value_index++;
      } else if (connection_setup_filter_condition_type == 0x02) {
        sprintf(connection_setup_value_buf,
            "(0x%02x) Allow Connections from a device with a specific BD_ADDR",
            connection_setup_filter_condition_type);
        hci_command.value[hci_command.value_index].name = "BD_ADDR";
        hci_command.value[hci_command.value_index].indent_level =
            INDENT_LEVEL_1;
        char * tmp_value_buf_ptr =
            hci_command.value[hci_command.value_index].value;
        hci_command.value_index++;
        uint8_t addr[6];
        int i = 0;
        for (; i < 6; i++) {
          STREAM_TO_UINT8(addr[i], data);
        }
        left_len -= 6;
        i--;
        tmp_value_buf_ptr += sprintf(tmp_value_buf_ptr, "0x%02x", addr[i]);
        while (--i >= 0) {
          tmp_value_buf_ptr += sprintf(tmp_value_buf_ptr, "-%02x", addr[i]);
        }
        uint8_t auto_accept_flag;
        STREAM_TO_UINT8(auto_accept_flag, data);
        left_len--;
        if (auto_accept_flag == 0x01) {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Do NOT Auto accept the connection (Auto accept is off).",
              auto_accept_flag);
        } else if (auto_accept_flag == 0x02) {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Do Auto accept the connection with role switch disabled (Auto accept is on).",
              auto_accept_flag);
        } else if (auto_accept_flag == 0x03) {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Do Auto accept the connection with role switch enabled (Auto accept is on).",
              auto_accept_flag);
        } else {
          sprintf(hci_command.value[hci_command.value_index].value,
              "(0x%02x) Reserved for future use.", auto_accept_flag);
        }
        hci_command.value_index++;
      } else {
        sprintf(connection_setup_value_buf, "(0x%02x) Reserved for future use",
            connection_setup_filter_condition_type);
      }
    } else {
      sprintf(curr_value_buf, "(0x%02x) Reserved for future use.", filter_type);
    }
  }

  // Print HCI command
  // if command has no parameter and data, print the command in one line
  if (hci_command.value_index == 0 && left_len == 0) {
    LOG_DEBUG(LOG_TAG_CMD, "%s HCI Command: %s(0x%04x), Parameter Length: %zu",
        time_str, hci_command.name, hci_command.opcode,
        hci_command.parameter_length);
    return;
  }
  // if command has parameters, print the command in multiple line as format
  LOG_DEBUG(LOG_TAG_CMD, "%s HCI Command: %s(0x%04x), Parameter Length: %zu",
      time_str, hci_command.name, hci_command.opcode,
      hci_command.parameter_length);
  for (size_t i = 0; i < hci_command.value_index; i++) {
    const HCI_PARAM_VALUE * val = &hci_command.value[i];
    if (val->seq_num > 0) {
      LOG_DEBUG(LOG_TAG_CMD, "%s[%d] %s: %s", LINE_INDENT[val->indent_level],
          val->seq_num, val->name, val->value);
    } else {
      LOG_DEBUG(LOG_TAG_CMD, "%s%s: %s", LINE_INDENT[val->indent_level], val->name,
          val->value);
    }
  }
  if (left_len > 0) {
    char * buf_ptr = log_buf;
    memset(log_buf, '\0', sizeof(log_buf));
    for (int i = 0; i < left_len; i++) {
      buf_ptr += sprintf(buf_ptr, "%02x ", data[i]);
    }
    LOG_DEBUG(LOG_TAG_CMD, "%sRaw Data: %s", LINE_INDENT[INDENT_LEVEL_1], log_buf);
  }
}

void parse_hci_event(const uint8_t *parse_event, const char * time_str) {
  size_t length = 0;
  uint16_t eventcode;
  const uint8_t * data = parse_event;

  STREAM_TO_UINT8(eventcode, data);
  STREAM_TO_UINT8(length, data);

  if (eventcode > HCI_EVENT_NUMBER) {
    return;
  }
  const HCI_EVENT_REPR *hci_event_repr = &HCI_EVENTS[eventcode];

  HCI_INSTANCE hci_event;
  memset(&hci_event, 0, sizeof(hci_event));

  hci_event.name = hci_event_repr->name;
  hci_event.opcode = eventcode;
  hci_event.parameter_length = length;

  hci_event.parameter_count = hci_event_repr->parameter_count;
  hci_event.value_index = 0;

  int left_len = length;

  // Parse common HCI event parameters that are defined in HCI_EVENTS
  parse_hci_instance(&hci_event, hci_event_repr->parameter,
      hci_event_repr->parameter_count, &data, length, &left_len,
      INDENT_LEVEL_1);

  // Handle special event that needs extra processing.
  do {
    if (eventcode == 0x0E) {  // Handle command complete event
      uint16_t opcode = (uint16_t) strtol(hci_event.value[1].value, NULL, 0);
      const HCI_COMMAND_REPR *hci_cmd_matched = get_matched_hci_cmd_repr(
          opcode);

      if (hci_cmd_matched == NULL || hci_cmd_matched->name == NULL) {
        DBG_LOG(LOG_TAG,
            "%s --- can not command complete event matching command(opcode:%04x)",
            __func__, opcode);
        break;
      }
      sprintf(hci_event.value[1].value, "%s(0x%04x)", hci_cmd_matched->name,
          opcode);
      if (hci_cmd_matched->return_parameter_count) {
        hci_event.value[hci_event.value_index].name = "Return Parameter";
        hci_event.value[hci_event.value_index].indent_level = INDENT_LEVEL_1;
        hci_event.value_index++;
        parse_hci_instance(&hci_event, hci_cmd_matched->return_parameter,
            hci_cmd_matched->return_parameter_count, &data, left_len, &left_len,
            INDENT_LEVEL_2);
      }
    } else if (eventcode == 0x0F) {  // Handle command status event
      uint16_t opcode = (uint16_t) strtol(hci_event.value[2].value, NULL, 0);
      const HCI_COMMAND_REPR *hci_cmd_matched = get_matched_hci_cmd_repr(
          opcode);

      if (hci_cmd_matched == NULL || hci_cmd_matched->name == NULL) {
        DBG_LOG(LOG_TAG,
            "%s --- can not command complete event matching command(opcode:%04x)",
            __func__, opcode);
        break;
      }
      sprintf(hci_event.value[2].value, "%s(0x%04x)", hci_cmd_matched->name,
          opcode);
    } else if (eventcode == 0x19) {  // Loopback Command

    } else if (eventcode == 0x3E) {  //LE Meta Event
      uint8_t subeventcode;
      STREAM_TO_UINT8(subeventcode, data);
      HCI_EVENT_REPR subevent = LE_META_EVENTS[subeventcode];
      hci_event.value[hci_event.value_index].name = "Subevent_Code";
      sprintf(hci_event.value[hci_event.value_index].value, "%s(0x%02x)",
          subevent.name, subeventcode);
      hci_event.value[hci_event.value_index].indent_level = INDENT_LEVEL_1;
      hci_event.value_index++;
      left_len--;
      parse_hci_instance(&hci_event, subevent.parameter,
          subevent.parameter_count, &data, left_len, &left_len, INDENT_LEVEL_1);
    }
  } while (0);

  // Print HCI Event
  // if HCI event has no data, print it in one line.
  if (hci_event.value_index == 0 && left_len == 0) {
    LOG_DEBUG(LOG_TAG_EVT, "%s HCI Event: %s(0x%02x), Parameter Length: %zu",
        time_str, hci_event.name, hci_event.opcode, hci_event.parameter_length);
    return;
  }
  // if HCI event has data, print it in multiple lines.
  LOG_DEBUG(LOG_TAG_EVT, "%s HCI Event: %s(0x%02x), Parameter Length: %zu",
      time_str, hci_event.name, hci_event.opcode, hci_event.parameter_length);
  for (size_t i = 0; i < hci_event.value_index; i++) {
    const HCI_PARAM_VALUE * val = &hci_event.value[i];
    if (val->seq_num > 0) {
      LOG_DEBUG(LOG_TAG_EVT, "%s[%d] %s: %s", LINE_INDENT[val->indent_level],
          val->seq_num, val->name, val->value);
    } else {
      LOG_DEBUG(LOG_TAG_EVT, "%s%s: %s", LINE_INDENT[val->indent_level], val->name,
          val->value);
    }
  }
  if (left_len > 0) {
    char * buf_ptr = log_buf;
    memset(log_buf, '\0', sizeof(log_buf));
    for (int i = 0; i < left_len; i++) {
      buf_ptr += sprintf(buf_ptr, "%02x ", data[i]);
    }
    LOG_DEBUG(LOG_TAG_EVT, "%sRaw Data: %s", LINE_INDENT[INDENT_LEVEL_1], log_buf);
  }
}

// Time string format "%02d:%02d:%02d.%06ld", total string length is 15.
#define TIME_STR_LEN 15

typedef enum {
  COMMAND_PACKET = 0x01,
  ACL_PACKET = 0x02,
  SCO_PACKET = 0x03,
  EVENT_PACKET = 0x04,
} packet_type_t;

static thread_t *m_hci_dump_thread = NULL;
static fixed_queue_t *m_hci_dump_data_queue = NULL;
static bool b_is_hci_dump_running = false;

static void hci_raw_data_ready(fixed_queue_t *queue, UNUSED_ATTR void *context) {
#if DBG_LOG_ENABLE == TRUE && DBG_NEED_VALIDATE_CONST_DATA_FORMAT== TRUE
  validate_const_data_format();
#endif
  uint8_t *packet = (uint8_t *) fixed_queue_dequeue(queue);
  switch (packet[0] & 0xFF) {
  case COMMAND_PACKET: {
    // declare 1 more byte for string end '\0'
    char time_str[TIME_STR_LEN + 1] = { 0 };
    memcpy(time_str, packet + 1, TIME_STR_LEN);
    parse_hci_command(packet + 1 + TIME_STR_LEN, time_str);
    break;
  }
  case ACL_PACKET:
  case SCO_PACKET:
    break;
  case EVENT_PACKET: {
    // declare 1 more byte for string end '\0'
    char time_str[TIME_STR_LEN + 1] = { 0 };
    memcpy(time_str, packet + 1, TIME_STR_LEN);
    parse_hci_event(packet + 1 + TIME_STR_LEN, time_str);
    break;
  }
  default:
    break;
  }
  osi_free(packet);
}

static future_t *start_up(void) {
  static const char * CONFIG_MTK_HCI_DUMP_SECTION = "MtkBtHciDump";
  static const char * FIRMWARE_LOG_OPEN_KEY = "MtkBtHciDump_enable";
  config_t * config = stack_config_get_interface()->get_all();
  if (!config_get_bool(config, CONFIG_MTK_HCI_DUMP_SECTION, FIRMWARE_LOG_OPEN_KEY, false)) {
    LOG_DEBUG(LOG_TAG, "bt_stack.config set not start %s module", HCI_DATA_DUMP_MODULE);
    goto error;
  }

  DBG_LOG(LOG_TAG, "%s", __func__);
  m_hci_dump_data_queue = fixed_queue_new(SIZE_MAX);
  if (!m_hci_dump_data_queue) {
    LOG_ERROR(LOG_TAG, "%s unable to create hci dump data queue.", __func__);
    goto error;
  }

  m_hci_dump_thread = thread_new("hci_dump_thread");
  if (!m_hci_dump_thread) {
    LOG_ERROR(LOG_TAG, "%s unable to create thread.", __func__);
    goto error;
  }

  fixed_queue_register_dequeue(m_hci_dump_data_queue,
      thread_get_reactor(m_hci_dump_thread), hci_raw_data_ready, NULL);

  b_is_hci_dump_running = true;
  DBG_LOG(LOG_TAG, "%s %s", __func__, HCI_DATA_DUMP_MODULE);
  return NULL;
error:
  if (m_hci_dump_data_queue) {
    fixed_queue_free(m_hci_dump_data_queue, osi_free);
    m_hci_dump_data_queue = NULL;
  }
  return future_new_immediate(FUTURE_FAIL);
}

static future_t *shut_down() {
  DBG_LOG(LOG_TAG, "%s hci dump running %d", __func__, b_is_hci_dump_running);
  b_is_hci_dump_running = false;
  if (m_hci_dump_thread) {
    thread_stop(m_hci_dump_thread);
    thread_join(m_hci_dump_thread);
    m_hci_dump_thread = NULL;
  }
  if (m_hci_dump_data_queue) {
    fixed_queue_free(m_hci_dump_data_queue, osi_free);
    m_hci_dump_data_queue = NULL;
  }
  DBG_LOG(LOG_TAG, "%s %s", __func__, HCI_DATA_DUMP_MODULE);
  return NULL;
}

EXPORT_SYMBOL const module_t hci_data_dump_module = {
  .name = HCI_DATA_DUMP_MODULE,
  .init = NULL,
  .start_up = start_up,
  .shut_down = shut_down,
  .clean_up = NULL,
  .dependencies = {
    NULL
  }
};

void display_hci_data(const BT_HDR *packet) {
  if (packet == NULL)
    return;
  if (!b_is_hci_dump_running)
    return;

  uint8_t type;
  switch (packet->event & BT_EVT_MASK) {
  case BT_EVT_TO_LM_HCI_CMD: {
    type = COMMAND_PACKET;
    break;
  }
  case BT_EVT_TO_BTU_HCI_EVT: {
    type = EVENT_PACKET;
#if FILTER_FW_PICUS_LOG_EVENT == TRUE
    // filter firmware picus log event
    if (*(packet->data + packet->offset) == 0xFF
        && *(packet->data + packet->offset + 1) > 0
        && *(packet->data + packet->offset + 2) == 0x50) {
      return;
    }
#endif
    break;
  }
  default:
    return;
  }
  // 1 more type for packet type, and 15 more types for time string
  uint8_t * hci_raw_data = (uint8_t *) osi_malloc(
      packet->len + 1 + TIME_STR_LEN);
  const uint8_t *src = &packet->data[packet->offset];
  hci_raw_data[0] = type;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  snprintf((char *) (hci_raw_data + 1), TIME_STR_LEN, "%02d:%02d:%02d.%06ld",
      (int) tv.tv_sec / 3600 % 24, (int) (tv.tv_sec % 3600) / 60,
      (int) tv.tv_sec % 60, tv.tv_usec);
  memcpy(hci_raw_data + 1 + TIME_STR_LEN, src, packet->len);
  fixed_queue_enqueue(m_hci_dump_data_queue, hci_raw_data);
}
