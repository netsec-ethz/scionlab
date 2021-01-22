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

containers=$(docker-compose ps --services | grep -v coord)

set -x
sleep 5  # Give the services enough time to start (or fail)
for c in $containers; do
  docker-compose exec -T "$c" check-scion-status.sh
done
for c in $containers; do
  docker-compose exec -T --user user "$c" await-beacons.sh
done
for c in $containers; do
  docker-compose exec -T --user user "$c" ping-all.sh
done

