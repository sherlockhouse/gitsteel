#define LOG_TAG "hci_fw_core_dump_ctrl"

#include "osi/include/log.h"
#include "hci_fw_core_dump_ctrl.h"

#if (MTK_SUPPORT_FW_CORE_DUMP == TRUE)
static volatile bool b_trig_coredump = false;
static const vendor_t *m_vendor = NULL;

bool is_chip_doing_reset(void) {
  LOG_INFO(LOG_TAG, "%s %d", __func__, b_trig_coredump);
  return b_trig_coredump;
}

/* When fw coredump is triggered, stack doesn't need to kill bt process because that
 * "fw coredump" of vendor library includes coredump and whole-chip-reset,
 * the feature of "MTK_HCITRANS_DETECT_CHIP_RESET" would take care of detecting
 * the end of whole-chip-reset and then kill bt process
 */
bool triggerFirmwareAssert(uint16_t assert_type, uint16_t reason) {
  LOG_INFO(LOG_TAG,
      "%s Stack triggers firmware coredump. Type: %d, reason: 0x%04x", __func__,
      assert_type, reason);
  uint32_t stack_trigger_reason = (reason << 16) | (assert_type & 0xFFFF);
  if (m_vendor == NULL) {
    LOG_INFO(LOG_TAG, "%s Act FW Coredump Fails! Vender not set.", __func__);
    return false;
  }
  if (!m_vendor->send_command(VENDOR_SET_FW_ASSERT, &stack_trigger_reason)) {
    LOG_INFO(LOG_TAG, "%s Act FW Coredump Success!", __func__);
    b_trig_coredump = true;
    return true;
  }
  LOG_WARN(LOG_TAG, "%s Act FW Coredump Fails!", __func__);
  return false;
}

void setFimrwareCoreDumpVendor(const vendor_t * vendor) {
  m_vendor = vendor;
}
#endif
