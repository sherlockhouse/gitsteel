#pragma once
#include "hci/include/vendor.h"
#include "mdroid_buildcfg.h"

#if (MTK_SUPPORT_FW_CORE_DUMP == TRUE)

#define BT_PANIC_HOST_ASSERT   31

bool triggerFirmwareAssert(uint16_t assert_type, uint16_t reason);

bool is_chip_doing_reset();

void setFimrwareCoreDumpVendor(const vendor_t * vendor);

#endif
