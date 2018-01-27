#pragma once
#include "bt_types.h"
#include "hci/include/hci_layer.h"

void init_fw_logger(const hci_t *hci);
void deinit_fw_logger();

bool filter_fw_log(BT_HDR *packet);

