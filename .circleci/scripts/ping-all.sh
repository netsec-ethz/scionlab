#!/bin/bash
# Copyright 2020 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eo pipefail

# Ping _a_ host in all destination ASes.
# Note that pinging the local AS is fine.

ias=(
  '19-ffaa:0:1301'
  '19-ffaa:0:1303'
  '19-ffaa:0:1305'
  '20-ffaa:0:1401'
  '20-ffaa:0:1405'
  '20-ffaa:1:4'
)

set -x
for dstIA in ${ias[@]}; do
  chronic scion ping -c 1 "$dstIA,127.0.0.1"
done
