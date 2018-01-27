#pragma once

#include "osi/include/config.h"

#if MTK_STACK_CONFIG == TRUE

#define CONFIG_MTK_CONF_SECTION "MtkBtConf"

bool parse_override_cfg(config_t * config);

#endif
