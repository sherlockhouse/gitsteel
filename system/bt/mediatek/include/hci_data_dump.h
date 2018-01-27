#pragma once
#include "bt_types.h"

static const char HCI_DATA_DUMP_MODULE[] = "hci_data_dump_module";

void display_hci_data(const BT_HDR *packet);
