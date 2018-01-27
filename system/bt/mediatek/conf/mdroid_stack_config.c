#define LOG_TAG "mdroid_stack_config"
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "osi/include/config.h"
#include "osi/include/log.h"
#include "osi/include/list.h"
#include "stack_config.h"
#include "mdroid_buildcfg.h"
#include "mdroid_stack_config.h"


#if MTK_STACK_CONFIG == TRUE
static const char *STACK_CONF_OVERRIDE_KEY = "MtkStackConfigOverride";
static const char *EXTFILE_OVERRIDE_TMPKEY = "OverrideConf"; /* easy to parse /sdcard/btsc, it's not a key in config */

#if MTK_STACK_CONFIG_DEFAULT_OVERRIDE == TRUE
const char *BTDefaultConfOverrideFile = "bt_stack.conf.sqc";
#endif

/**
 * Override default configure file /etc/bluetooth/bt_stack.conf
 *
 * Current Design:
 *  1. Upper Layer or User control the config file path written in sdcard/btrc
 *  2. Here override the stack configure according to the preset configure
 *
 * TODO:
 * 1. Move config relevant definition to local. e.g. MTK_STACK_CONFIG_FPATH_LEN
 * 2. Use system property to control the log mode
 */
bool parse_override_cfg(config_t * config) {
  FILE * target_file = NULL;
  char str_ovconf_fpath[MTK_STACK_CONFIG_FPATH_LEN] = { '\0' };
  const char *p_redir_ovconf_fpath = NULL;
  char * p_fpath = NULL;
  char prefix_fpath1[MTK_STACK_CONFIG_FPATH_LEN] = "/etc/bluetooth/";
  char str_redir_ov_fpath[MTK_STACK_CONFIG_FPATH_LEN] = { '\0' };
  bool b_override = false;

  if (config == NULL) {
    LOG_ERROR(LOG_TAG, "%s Override fail. The default config content is NULL.", __func__);
    return b_override;
  }

  /* MtkStackConfigOverride = /scard/btsc in bt_stack.conf */
  strlcpy(str_redir_ov_fpath, config_get_string(config, CONFIG_MTK_CONF_SECTION, STACK_CONF_OVERRIDE_KEY, ""), sizeof(str_redir_ov_fpath));

  LOG_INFO(LOG_TAG, "%s M_BTCONF redir file is \"%s\"", __func__, str_redir_ov_fpath);

  p_redir_ovconf_fpath = str_redir_ov_fpath;

  target_file = fopen(p_redir_ovconf_fpath, "rt");
  if (!target_file) {
    LOG_INFO(LOG_TAG, "%s M_BTCONF open redir-file %s fails!", __func__, p_redir_ovconf_fpath);

#if MTK_STACK_CONFIG_DEFAULT_OVERRIDE == TRUE
    LOG_INFO(LOG_TAG, "%s M_BTCONF set the override default config: %s!", __func__, BTDefaultConfOverrideFile);
    strlcpy(str_ovconf_fpath, BTDefaultConfOverrideFile, sizeof(str_ovconf_fpath));
#else
    /* MTK_STACK_CONFIG_DEFAULT_OVERRIDE is not defined or MTK_STACK_CONFIG_DEFAULT_OVERRIDE == 0 */
    return false; /* Don't override config - keep it as default config of bluedroid */
#endif

  } else {
      fclose(target_file);

      config_t *redir_config = config_new(p_redir_ovconf_fpath);
      if (redir_config) {
          /* copy ov filepath from /scard/btsc */
          strlcpy(str_ovconf_fpath, config_get_string(redir_config, CONFIG_DEFAULT_SECTION, EXTFILE_OVERRIDE_TMPKEY, ""), sizeof(str_ovconf_fpath));

          config_free(redir_config);
      }
  }

  LOG_INFO(LOG_TAG, "%s M_BTCONF OverrideConf= %s", __func__, str_ovconf_fpath);

  if (str_ovconf_fpath[0] != '\0') {
    FILE *test_file = NULL;

    if (!strcmp(str_ovconf_fpath, "bt_stack.conf.sqc") ||
        !strcmp(str_ovconf_fpath, "bt_stack.conf.debug") ||
        !strcmp(str_ovconf_fpath, "bt_stack.conf.usertrial") ) {

      if ((strlen(str_ovconf_fpath) + strlen(prefix_fpath1)) <= (MTK_STACK_CONFIG_FPATH_LEN - 1))
        strcat(prefix_fpath1, str_ovconf_fpath);
      else {
        LOG_ERROR(LOG_TAG, "%s M_BTCONF file/path \"prefix+overrideconf_fpath\" exceeds the size of array: %d", __func__, MTK_STACK_CONFIG_FPATH_LEN);
        return false;
      }

      test_file = fopen(prefix_fpath1, "rt");
      if (!test_file) {
        LOG_INFO(LOG_TAG, "%s M_BTCONF open %s fails!", __func__, prefix_fpath1);
        return false;
      } else {

        fclose(test_file);
        p_fpath = prefix_fpath1;
      }
    } else {

      test_file = fopen(str_ovconf_fpath, "rt");
      if (!test_file) {
        LOG_INFO(LOG_TAG, "%s M_BTCONF open %s fails!", __func__, str_ovconf_fpath);
        return false;
      } else {

        fclose(test_file);
        p_fpath = str_ovconf_fpath;
      }
    }
  }

  if (p_fpath) {
    LOG_INFO(LOG_TAG, "%s M_BTCONF config_override file/path \"%s\"", __func__, p_fpath);
    b_override = config_override(config, p_fpath);
  } else
      LOG_INFO(LOG_TAG, "%s M_BTCONF config_override file/path is NULL", __func__);

  return b_override;
}

#endif
