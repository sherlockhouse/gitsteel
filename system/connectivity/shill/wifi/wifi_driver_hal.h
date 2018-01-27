//
// Copyright (C) 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef SHILL_WIFI_WIFI_DRIVER_HAL_H_
#define SHILL_WIFI_WIFI_DRIVER_HAL_H_

#include <string>

#include <base/lazy_instance.h>
#include <base/macros.h>

namespace shill {

// This is a singleton class for invoking calls to WiFi driver HAL,
// mainly for configuring device operation mode (station vs AP mode).
class WiFiDriverHal {
 public:
  virtual ~WiFiDriverHal();

  // Since this is a singleton, use WiFiDriverHal::GetInstance()->Foo().
  static WiFiDriverHal* GetInstance();

  // Setup WiFi interface in station mode. Return an |interface_name| if
  // success. Otherwise, return an empty string.
  // This will attempt to initialize the WiFi driver before configuring
  // the interface mode. It will be a noop in the driver if it is already
  // initialized. So there won't be any performance penalty for doing it.
  virtual std::string SetupStationModeInterface();

  // Setup WiFi interface in AP mode. Return an |interface_name| if
  // success. Otherwise, return an empty string.
  // This will attempt to initialize the WiFi driver before configuring
  // the interface mode. It will be a noop in the driver if it is already
  // initialized. So there won't be any performance penalty for doing it.
  virtual std::string SetupApModeInterface();

 protected:
  WiFiDriverHal();

 private:
  friend struct base::DefaultLazyInstanceTraits<WiFiDriverHal>;

  DISALLOW_COPY_AND_ASSIGN(WiFiDriverHal);
};

}  // namespace shill

#endif  // SHILL_WIFI_WIFI_DRIVER_HAL_H_
