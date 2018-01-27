#define LOG_TAG "fw_logger"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "btcore/include/module.h"
#include "bt_types.h"
#include "hcidefs.h"
#include "osi/include/allocator.h"
#include "osi/include/future.h"
#include "osi/include/log.h"
#include "osi/include/future.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/osi.h"
#include "osi/include/thread.h"
#include "stack_config.h"

#include "fw_logger.h"
#include "mdroid_stack_config.h"

/*****************************************************************************
 * firmware logger module
 *****************************************************************************/
static const char FIRMWARE_LOG_MODULE[] = "fw_log_module";

// default firmware log file's max size is 20M
#define DEFAULT_FIRMWARE_LOG_MAX_SZIE 20

// default firmware log  file's max count
#define DEFAULT_FIRMWARE_LOG_MAX_COUNT 5

// firmware log block 8 bytes
#define FIRMWARE_LOG_BLOCK_SIZE 8

// firmware log header size 24 bytes
#define FIRMWARE_LOG_HEADER_SIZE (FIRMWARE_LOG_BLOCK_SIZE * 3)

#define FIRMWARE_LOG_FOLDER "firmware_log/"
#define FIRMWARE_LOG_SUFFIX ".picus"
#define FIRMWARE_LOG_PREFIX "bt_fw_log"
#define FIRMWARE_LOG_FULL_NAME "%s"FIRMWARE_LOG_PREFIX"_%d%s"FIRMWARE_LOG_SUFFIX
#define FIRMWARE_LOG_LOGGING_FILE_FLAG "_curr"

#define FIRMWARE_LOG_FILE_INVALID_INDEX -1
#define FIRMWARE_LOG_FILE_INIT_INDEX 1

typedef struct {
  uint64_t timestamp;
  BT_HDR * packet;
} fwlog_packet_t;

static uint32_t s_log_max_size;
static int s_log_max_count = DEFAULT_FIRMWARE_LOG_MAX_COUNT;

static fixed_queue_t * m_fw_log_data_queue = NULL;
static thread_t *m_thread = NULL;
static bool m_fw_logger_running = false;

static int fw_log_fd = INVALID_FD;
static size_t fw_log_curr_size = 0;
static int fw_log_file_index = FIRMWARE_LOG_FILE_INVALID_INDEX;
static char fw_log_curr_file_full_path[PATH_MAX] = {0};

static uint32_t fw_log_chip_id = 0x00000000;
static uint16_t fw_log_sequence_num = 0x0000;

// Epoch in microseconds since 01/01/0000.
static const uint64_t BTSNOOP_EPOCH_DELTA = 0x00dcddb30f2f8000ULL;

static uint64_t get_timestamp(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  // Timestamp is in microseconds.
  uint64_t timestamp = tv.tv_sec * 1000000ULL;
  timestamp += tv.tv_usec;
  timestamp += BTSNOOP_EPOCH_DELTA;
  return timestamp;
}

static int create_fw_log_file(uint8_t first_packet_len,
    uint64_t first_packet_timestamp) {
  // validate fw log folder.
  const char * snoop_log_path =
      stack_config_get_interface()->get_btsnoop_log_path();
  char fw_log_folder[PATH_MAX] = { 0 };
  memcpy(fw_log_folder, snoop_log_path,
      strrchr(snoop_log_path, '/') - snoop_log_path + 1);
  strcat(fw_log_folder, FIRMWARE_LOG_FOLDER);
  LOG_INFO(LOG_TAG, "fw log folder is: %s", fw_log_folder);
  if (access(fw_log_folder, F_OK) != 0) {
    for (int i = 0; fw_log_folder[i] != '\0'; i++) {
      if (fw_log_folder[i] == '/' && i) {
        fw_log_folder[i] = '\0';
        if (access(fw_log_folder, F_OK) != 0) {
          if (mkdir(fw_log_folder, 0770) == 0) {
            LOG_INFO(LOG_TAG, "%s create fw log folder: %s", __func__,
                fw_log_folder);
          } else {
            LOG_ERROR(LOG_TAG, "%s mkdir error! %s", __func__,
                (char* )strerror(errno));
            return INVALID_FD;
          }
        }
        fw_log_folder[i] = '/';
      }
    }
  }
  // iterate fw log folder in order to find "_curr" log.
  if (fw_log_file_index == FIRMWARE_LOG_FILE_INVALID_INDEX) {
    DIR *p_dir = opendir(fw_log_folder);
    if (p_dir != NULL) {
      struct dirent *p_file;
      while ((p_file = readdir(p_dir)) != NULL) {
        if (strcmp(p_file->d_name, "..") == 0
            || strcmp(p_file->d_name, ".") == 0) {
          continue;
        }
        char * temp;
        if ((temp = strstr(p_file->d_name, FIRMWARE_LOG_LOGGING_FILE_FLAG))
            != NULL) {
          fw_log_file_index = (int) (*(temp - 1) - '0');
          strcpy(fw_log_curr_file_full_path, fw_log_folder);
          strcat(fw_log_curr_file_full_path, p_file->d_name);
          LOG_INFO(LOG_TAG, "%s find last logging fw log: %s", __func__,
              fw_log_curr_file_full_path);
          break;
        }
      }
      closedir(p_dir);
    }
  }

  // rename bt_fw_log_XXX_N_curr.picus to bt_fw_log_XXX_N.picus
  if (strlen(fw_log_curr_file_full_path) > 0) {
    char *temp = strstr(fw_log_curr_file_full_path,
    FIRMWARE_LOG_LOGGING_FILE_FLAG);
    if (temp != NULL) {
      char renamed_fw_log_name[PATH_MAX] = { 0 };
      memcpy(renamed_fw_log_name, fw_log_curr_file_full_path,
          temp - fw_log_curr_file_full_path);
      strcat(renamed_fw_log_name, FIRMWARE_LOG_SUFFIX);
      if (rename(fw_log_curr_file_full_path, renamed_fw_log_name) == 0) {
        LOG_INFO(LOG_TAG, "%s rename last fw log file to %s", __func__,
            renamed_fw_log_name);
      } else {
        LOG_WARN(LOG_TAG, "%s rename fw log file failed. file:%s. errno: %d",
            __func__, fw_log_curr_file_full_path, errno);
      }
    }
  }
  // compute next file index
  if (fw_log_file_index < FIRMWARE_LOG_FILE_INIT_INDEX) {
    fw_log_file_index = FIRMWARE_LOG_FILE_INIT_INDEX;
  } else {
    fw_log_file_index++;
    if (fw_log_file_index > s_log_max_count) {
      fw_log_file_index = FIRMWARE_LOG_FILE_INIT_INDEX;
    }
  }
  // remove old file if needed
  memset(fw_log_curr_file_full_path, '\0', sizeof(fw_log_curr_file_full_path));
  snprintf(fw_log_curr_file_full_path, PATH_MAX, FIRMWARE_LOG_FULL_NAME,
      fw_log_folder, fw_log_file_index, "");
  if (access(fw_log_curr_file_full_path, F_OK) == 0) {
    if (remove(fw_log_curr_file_full_path) == 0) {
      LOG_INFO(LOG_TAG, "%s remove fw log file: %s", __func__,
          fw_log_curr_file_full_path);
    } else {
      LOG_WARN(LOG_TAG, "%s remove fw log file failed. file:%s. errno: %d",
          __func__, fw_log_curr_file_full_path, errno);
    }
  }
  // Generate the name of new firmware log file
  memset(fw_log_curr_file_full_path, '\0', sizeof(fw_log_curr_file_full_path));
  snprintf(fw_log_curr_file_full_path, PATH_MAX, FIRMWARE_LOG_FULL_NAME,
      fw_log_folder, fw_log_file_index, FIRMWARE_LOG_LOGGING_FILE_FLAG);

  fw_log_fd = open(fw_log_curr_file_full_path, O_WRONLY | O_CREAT | O_TRUNC,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
  if (fw_log_fd == INVALID_FD) {
    LOG_ERROR(LOG_TAG, "%s unable to open '%s': %s(%d)", __func__,
        fw_log_curr_file_full_path, strerror(errno), errno);
    return INVALID_FD;
  } else {
    LOG_INFO(LOG_TAG, "%s open fw log file: %s", __func__,
        fw_log_curr_file_full_path);
  }

  // write firmware log file header part
  // |                 Log Version(4bytes)                 | Chip ID(4bytes)  |
  // | Sequence Number(2bytes) | 1st Packet Length(2bytes) | Reserved(4bytes) |
  // |                 1st Packet System time stamp(8bytes)                   |
  uint8_t fw_log_header[FIRMWARE_LOG_HEADER_SIZE] = { 0 };
  uint8_t *fw_log_header_stream = fw_log_header;
  uint32_t log_version = 0x00010000;
  UINT32_TO_STREAM(fw_log_header_stream, log_version);
  // fw_log_chip_id
  UINT32_TO_STREAM(fw_log_header_stream, fw_log_chip_id);
  // fw_log_sequence_num
  UINT16_TO_STREAM(fw_log_header_stream, fw_log_sequence_num);
  // uint8_t first_packet_len, uint64_t first_packet_timestamp
  UINT16_TO_STREAM(fw_log_header_stream, first_packet_len);
  fw_log_header_stream += 4;
  UINT64_TO_BE_STREAM(fw_log_header_stream, first_packet_timestamp);

  write(fw_log_fd, fw_log_header, FIRMWARE_LOG_HEADER_SIZE);

  return fw_log_fd;
}

static void event_fw_log_data_ready(fixed_queue_t *queue,
    UNUSED_ATTR void *context) {
  fwlog_packet_t *log_data = (fwlog_packet_t *) fixed_queue_dequeue(queue);
  uint8_t *data = log_data->packet->data;
  // Mimus the length of subevent code from event data length
  size_t data_len = (UINT8) (*(data + 1)) - 1;
  // skip event code 0xff, event length and subevent code 0x50
  data += 3;

  size_t log_record_len = data_len;
  // Adjust record length because log block size should be 8*N based.
  size_t temp = log_record_len % FIRMWARE_LOG_BLOCK_SIZE;
  if (temp > 0) {
    log_record_len += FIRMWARE_LOG_BLOCK_SIZE - temp;
  }

  if (fw_log_fd == INVALID_FD) {
    fw_log_sequence_num = 0x0000;
    fw_log_fd = create_fw_log_file(log_record_len, log_data->timestamp);
    fw_log_curr_size = 0;
  }
  if (fw_log_curr_size + log_record_len > s_log_max_size) {
    // close previous firmware log fd firstly.
    if (fw_log_fd != INVALID_FD) {
      close(fw_log_fd);
    }
    fw_log_sequence_num++;
    fw_log_fd = create_fw_log_file(log_record_len, log_data->timestamp);
    fw_log_curr_size = 0;
  }
  if (fw_log_fd != INVALID_FD) {
    write(fw_log_fd, data, data_len);
    if (log_record_len > data_len) {
      uint8_t append_data[FIRMWARE_LOG_BLOCK_SIZE] = { 0x00 };
      write(fw_log_fd, append_data, log_record_len - data_len);
    }
    fw_log_curr_size += log_record_len;
  }
  osi_free(log_data->packet);
  osi_free(log_data);
}

static void capture_fw_log(BT_HDR *packet) {
  if (m_fw_log_data_queue) {
    // We record timestamp here for every FW log event, so that we can get
    // the accurate timestamp in accordance with btsnoop log
    fwlog_packet_t * log_data = osi_malloc(sizeof(fwlog_packet_t));
    log_data->timestamp = get_timestamp();
    log_data->packet = packet;
    fixed_queue_enqueue(m_fw_log_data_queue, log_data);
  }
}

static future_t *start_up(void) {
  m_fw_log_data_queue = fixed_queue_new(SIZE_MAX);
  if (!m_fw_log_data_queue) {
    LOG_ERROR(LOG_TAG, "%s unable to create fw log data queue.", __func__);
    goto error;
  }

  m_thread = thread_new("bt_fw_log_thread");
  if (!m_thread) {
    LOG_ERROR(LOG_TAG, "%s unable to create fw log thread.", __func__);
    goto error;
  }
  // this thread is born from btu thread whose priority is -19,
  // however fw logger thread doesn't need high priority, so here adjust thread
  // priority to the default value.
  thread_set_priority(m_thread, 0);

  fixed_queue_register_dequeue(m_fw_log_data_queue,
      thread_get_reactor(m_thread), event_fw_log_data_ready, NULL);

  m_fw_logger_running = true;
  LOG_INFO(LOG_TAG, "%s start Bluetooth firmware logger module.", __func__);
  return future_new_immediate(FUTURE_SUCCESS);

error:
  if (m_fw_log_data_queue) {
    fixed_queue_free(m_fw_log_data_queue, osi_free);
    m_fw_log_data_queue = NULL;
  }

  return future_new_immediate(FUTURE_FAIL);
}

static future_t * shut_down(void) {
  m_fw_logger_running = false;
  if (m_thread) {
    thread_stop(m_thread);
    thread_join(m_thread);
  }
  if (m_fw_log_data_queue) {
    fixed_queue_free(m_fw_log_data_queue, osi_free);
    m_fw_log_data_queue = NULL;
  }
  // Make sure picus log file is closed after module is shut down.
  if (fw_log_fd != INVALID_FD) {
    close(fw_log_fd);
    fw_log_fd = INVALID_FD;
  }
  LOG_INFO(LOG_TAG, "%s stop Bluetooth firmware logger module.", __func__);
  return NULL;
}

EXPORT_SYMBOL const module_t fw_log_module = {
    .name = FIRMWARE_LOG_MODULE,
    .init = NULL,
    .start_up = start_up,
    .shut_down = shut_down,
    .clean_up = NULL,
    .dependencies = {
        NULL
    }
};

/*****************************************************************************
 * Capture firmware log in memory
 *****************************************************************************/

/* capture Bluetooth firmware log in memory*/
static void mem_capture_fw_log(const uint8_t * data, const size_t length) {

}

/*****************************************************************************
 * firmware log configure Module
 *****************************************************************************/
#define CONFIG_MTK_FWLOG_SECTION "MtkBtFWLog"

#define MTK_STACK_CONFIG_NUM_OF_HEXROWITEMS 16

#define HCI_COMMAND_MAX_LEN  (0xFF + 1 + 2 + 1)

#define HCI_CMD_C0_READ_FW_LOG_CONF 0xFC5D
#define HCI_CMD_C1_SET_FW_LOG_ENABLE 0xFCBE
#define HCI_CMD_C2_SET_FW_LOG_FILTER 0xFC5F

static future_t *cmd_response_future = NULL;

static bool parse_fwlog_pairs(config_t *pick_fwlog_conf, uint8_t * C1,
    uint8_t * C2) {
#define READ_STR_TO_ARRAY(t_arr, index, s_str)    \
  do { \
    const char *end_pos = s_str + strlen(s_str); \
    unsigned int temp; \
    while (s_str < end_pos) { \
      if (sscanf(s_str, "%02x ", &temp) == EOF) break; \
      *(t_arr+index) = (uint8_t)temp; \
      index++; \
      s_str += 3; \
    } \
  } while(0)

  const char *BTLOG_FWLOG_HCI_CMD1 = "C1";
  const char *BTLOG_FWLOG_HCI_CMD2 = "C2";
  int index = 0;
  const char * c1_str = config_get_string(pick_fwlog_conf,
      CONFIG_MTK_FWLOG_SECTION, BTLOG_FWLOG_HCI_CMD1, NULL);
  if (!c1_str) {
    LOG_WARN(LOG_TAG, "%s can not find firmware config: %s", __func__,
          BTLOG_FWLOG_HCI_CMD1);
    return false;
  }
  LOG_INFO(LOG_TAG, "%s Firmware Config %s: %s", __func__,
      BTLOG_FWLOG_HCI_CMD1, c1_str);
  READ_STR_TO_ARRAY(C1, index, c1_str);
  // 4 is the position of data.
  // Here we want to change data length, so we have to minus 4 to get pure
  // data length.
  C1[3] = index - 4;

  const char * c2_str = config_get_string(pick_fwlog_conf,
      CONFIG_MTK_FWLOG_SECTION, BTLOG_FWLOG_HCI_CMD2, NULL);
  if (!c2_str) {
    LOG_WARN(LOG_TAG, "%s can not find firmware config: %s", __func__,
        BTLOG_FWLOG_HCI_CMD2);
    return false;
  }
  LOG_INFO(LOG_TAG, "%s Firmware Config %s: %s", __func__,
      BTLOG_FWLOG_HCI_CMD2, c2_str);
  index = 0;
  READ_STR_TO_ARRAY(C2, index, c2_str);
  char filter_name_key[32] = { 0 };
  for (int i = 1; i < MTK_STACK_CONFIG_NUM_OF_HEXROWITEMS; i++) {
    sprintf(filter_name_key, "%s%02d", BTLOG_FWLOG_HCI_CMD2, i);
    const char * c2_param_str = config_get_string(pick_fwlog_conf,
        CONFIG_MTK_FWLOG_SECTION, filter_name_key, NULL);
    if (!c2_param_str) {
      break;
    }
    LOG_INFO(LOG_TAG, "%s Firmware Config %s: %s", __func__,
        filter_name_key, c2_param_str);
    READ_STR_TO_ARRAY(C2, index, c2_param_str);
  }
  C2[3] = index - 4;
  return true;
}

static BT_HDR* fw_logger_make_hci_command(uint16_t opcode, int data_len,
    uint8_t * data) {
  BT_HDR * cmd = osi_malloc(sizeof(BT_HDR) + 3 + data_len);
  cmd->event = 0;
  cmd->offset = 0;
  cmd->layer_specific = 0;
  cmd->len = 3 + data_len;
  uint8_t * stream = cmd->data;
  UINT16_TO_STREAM(stream, opcode);
  UINT8_TO_STREAM(stream, data_len);
  if (stream != NULL && data != NULL && data_len > 0) {
    ARRAY_TO_STREAM(stream, data, data_len);
  }
  return cmd;
}

void fw_logger_hci_command_complete_cb(BT_HDR *response, void *context) {
  // Make sure cmd_response_future is new firstly.
  assert(cmd_response_future != NULL);
  future_ready(cmd_response_future, response);
}

void fw_logger_hci_command_status_cb(uint8_t status, BT_HDR *command,
    void *context) {
  // Make sure cmd_response_future is new firstly.
  assert(cmd_response_future != NULL);
  if (status != HCI_SUCCESS) {
    uint16_t opcode;
    uint8_t * stream = command->data + command->offset;
    STREAM_TO_UINT16(opcode, stream);
    LOG_ERROR(LOG_TAG, "%s: 0x%04x return status - 0x%x", __func__, opcode,
        status);
    future_ready(cmd_response_future, NULL);
  } else {
    // else pass through success status event
  }
}

static uint8_t *process_command_complete_event_header(
    BT_HDR *response,
    command_opcode_t expected_opcode) {
  uint8_t *stream = response->data + response->offset;

  uint8_t event_code;
  STREAM_TO_UINT8(event_code, stream);
  assert(event_code == HCI_COMMAND_COMPLETE_EVT);

  STREAM_SKIP_UINT8(stream);// Skip the parameter total length field
  STREAM_SKIP_UINT8(stream);// skip the number of hci command packets field

  command_opcode_t opcode;
  STREAM_TO_UINT16(opcode, stream);
  assert(opcode == expected_opcode);

  uint8_t status;
  STREAM_TO_UINT8(status, stream);

  if (status != HCI_SUCCESS){
    LOG_ERROR(LOG_TAG, "%s: return status - 0x%x", __func__, status);
    return NULL;
  }

  return stream;
}

bool check_fw_log_config(const hci_t *hci) {
  static const char * FIRMWARE_LOG_OPEN_KEY = "MtkBtFWLogOpen";
  static const char * FIRMWARE_LOG_MAX_SIZE_KEY = "MtkBtFwLogFileMaxSize";
  static const char * FIRMWARE_LOG_MAX_COUNT_KEY = "MtkBtFwLogFileMaxCount";
  // check bt_stack.conf* firstly
  const char *fw_log_config;
  bool is_force_open_fw_log = false;

  config_t * config = stack_config_get_interface()->get_all();
  if ((fw_log_config = config_get_string(config, CONFIG_MTK_FWLOG_SECTION,
      FIRMWARE_LOG_OPEN_KEY, NULL)) == NULL) {
    LOG_INFO(LOG_TAG,
        "No Firmware log config. Use default setting(Not open Firmware logger).");
    return false;
  }

  if (!strcmp(fw_log_config, "force_disable")) {
    LOG_INFO(LOG_TAG,
        "bt_stack.conf FW log config: 'force_disable' firmware logger.");
    return false;
  } else if (!strcmp(fw_log_config, "fw_control")) {
    LOG_INFO(LOG_TAG,
        "bt_stack.conf FW log config: 'fw_control' firmware logger, Enable FW logger according to Controller configure.");
  } else if (!strcmp(fw_log_config, "force_enable")) {
    LOG_INFO(LOG_TAG,
        "bt_stack.conf FW log config: 'force_enable' firmware logger.");
    is_force_open_fw_log = true;
  } else {
    LOG_INFO(LOG_TAG,
        "bt_stack.conf FW log config: invalid value. Use default setting(Not open Firmware logger).");
    return false;
  }

  BT_HDR * vendor_cmd_fwlog_config;
  BT_HDR *response;
  uint8_t * response_stream;
  uint8_t is_fw_enable_picus_log = 0x00;
  uint8_t picus_log_feature_mask = 0x00;

  vendor_cmd_fwlog_config = fw_logger_make_hci_command(
  HCI_CMD_C0_READ_FW_LOG_CONF, 0, NULL);
  cmd_response_future = future_new();
  hci->transmit_command(vendor_cmd_fwlog_config,
      fw_logger_hci_command_complete_cb, fw_logger_hci_command_status_cb, NULL);
  response = future_await(cmd_response_future);
  do {
    if (response == NULL) {
      LOG_INFO(LOG_TAG, "%s: Controller does not support 0xfc5d.", __func__);
      break;
    }
    response_stream = process_command_complete_event_header(response,
        HCI_CMD_C0_READ_FW_LOG_CONF);
    if (!response_stream) {
      osi_free(response);
      response = NULL;
      break;
    }
    STREAM_TO_UINT32(fw_log_chip_id, response_stream);
    STREAM_TO_UINT8(is_fw_enable_picus_log, response_stream);
    if (is_fw_enable_picus_log) {
      STREAM_TO_UINT8(picus_log_feature_mask, response_stream);
    }
    osi_free(response);
    response = NULL;
  } while (0);

  LOG_INFO(LOG_TAG,
      "%s: Controller enable fw picus log: %d, Host force enabling fw log: %d",
      __func__, is_fw_enable_picus_log, is_force_open_fw_log);

  if (!is_fw_enable_picus_log && !is_force_open_fw_log)
    return false;

  uint8_t C1_data[HCI_COMMAND_MAX_LEN];
  uint8_t C2_data[HCI_COMMAND_MAX_LEN];
  if (!parse_fwlog_pairs(config, C1_data, C2_data)) {
    LOG_ERROR(LOG_TAG,
        "FW log config C1/C2 in bt_stack.conf is invalid. Use default setting(Not open Firmware logger).");
    return false;
  }
  if (C1_data[4] == 0x00) {
    LOG_ERROR(LOG_TAG,
        "FW log config C1[4]=0x%02x in bt_stack.conf means to close Firmware logger",
        C1_data[4]);
    return false;
  }

  int size_megabytes = config_get_int(config, CONFIG_MTK_FWLOG_SECTION,
      FIRMWARE_LOG_MAX_SIZE_KEY, DEFAULT_FIRMWARE_LOG_MAX_SZIE);
  s_log_max_size = (uint32_t) size_megabytes * 1024 * 1024;
  s_log_max_count = config_get_int(config, CONFIG_MTK_FWLOG_SECTION,
      FIRMWARE_LOG_MAX_COUNT_KEY, DEFAULT_FIRMWARE_LOG_MAX_COUNT);
  LOG_DEBUG(LOG_TAG, "%s FW Picus Log Max size: %dMB, Max count: %d", __func__,
      size_megabytes, s_log_max_count);

  response = future_await(
      hci->transmit_command_futured(
          fw_logger_make_hci_command(HCI_CMD_C1_SET_FW_LOG_ENABLE, C1_data[3],
              C1_data + 4)));
  process_command_complete_event_header(response, HCI_CMD_C1_SET_FW_LOG_ENABLE);
  osi_free(response);

  uint8_t is_send_c2_enable = picus_log_feature_mask & 0x01;

  if (is_send_c2_enable || is_force_open_fw_log) {
    response = future_await(
        hci->transmit_command_futured(
            fw_logger_make_hci_command(HCI_CMD_C2_SET_FW_LOG_FILTER, C2_data[3],
                C2_data + 4)));
    process_command_complete_event_header(response,
        HCI_CMD_C2_SET_FW_LOG_FILTER);
    osi_free(response);
  }

  return true;
}

/*****************************************************************************
 * firmware logger public API
 *****************************************************************************/
// subevent code indicates the debug event is firmware log,
// and it is the 1st byte of the data of vendor debugging event(0xff)
#define SUBEVENT_CODE_FW_LOG 0x50

void init_fw_logger(const hci_t *hci) {
  bool enable_fw_logger = check_fw_log_config(hci);
  if (enable_fw_logger) {
    module_start_up(get_module(FIRMWARE_LOG_MODULE));
    LOG_INFO(LOG_TAG, "%s Start FW logger.", __func__);
  } else {
    LOG_INFO(LOG_TAG,
        "%s Don't start FW logger because FW logger is not enabled.", __func__);
  }
}

void deinit_fw_logger() {
  if (m_fw_logger_running) {
    module_shut_down(get_module(FIRMWARE_LOG_MODULE));
    LOG_INFO(LOG_TAG, "%s Stop FW logger.", __func__);
  }
}

bool filter_fw_log(BT_HDR *packet) {
  if (!m_fw_logger_running) {
    return false;
  }

  uint8_t *data = packet->data;
  uint8_t event_code;
  size_t data_length;
  uint8_t subevent_code;
  STREAM_TO_UINT8(event_code, data);
  if (event_code != 0xFF) {
    return false;
  }
  STREAM_TO_UINT8(data_length, data);
  if (data_length == 0) {
    return false;
  }
  STREAM_TO_UINT8(subevent_code, data);
  if (subevent_code != SUBEVENT_CODE_FW_LOG) {
    return false;
  }

  mem_capture_fw_log(data, data_length - 1);
  capture_fw_log(packet);

  return true;
}
