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

cs_config_file=/etc/scion/cs-1.toml

# Get prometheus metrics address from config toml file :
prom=$(sed -n "/prometheus/s/.*=\s*\"\(.*\)\"/\1/p" "$cs_config_file")
while true; do
  # Fetch & parse metrics, possibly aggregate multiple results with different tags
  received_beacons=$(curl --silent "$prom/metrics" |
                      grep control_beaconing_received_beacons_total |
                      grep 'result="ok' |
                      sed 's/.* //' |
                      awk '{s+=$1}END{print s}')
  if [[ $received_beacons -gt 0 ]]; then
    break
  fi
  sleep 1
done
