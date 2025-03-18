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


file_path="/etc/scion/sciond.toml"
search="[drkey_level2_db]"
new_entry=$'[drkey_level2_db]\nconnection = "/var/lib/scion/sd.drkey.db"'

# Check if the file exists
if [ -f "$file_path" ]; then
  # Check if the file contains the text
  if ! grep -Fxq "$search" "$file_path"; then
    # Add the text if it's not present
    echo "$new_entry" >> "$file_path"
  fi
fi