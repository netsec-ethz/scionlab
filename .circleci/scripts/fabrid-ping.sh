#!/bin/bash
# Copyright 2024 ETH Zurich
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
set -x

chronic scion ping -c 1 "19-ffaa:0:1301,127.0.0.1" --fabridquery "0-0#0,0@0"
chronic scion ping -c 1 "20-ffaa:1:4,127.0.0.1" --fabridquery "0-0#0,0@0"