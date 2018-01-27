#!/bin/bash

#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

OUT=$1
shift
PC_IN=$1
shift
INCLUDE_DIR=$1
shift

sed \
  -e "s|@INCLUDE_DIR@|${INCLUDE_DIR}|g" \
  "${PC_IN}.pc.in" > "${OUT}/${PC_IN}.pc"
