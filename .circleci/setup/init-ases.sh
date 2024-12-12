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

docker-compose exec useras4 /bin/bash -c 'enable-fabrid-sciond.sh'
docker-compose exec as1301 /bin/bash -c 'enable-fabrid-sciond.sh'

for c in $(docker-compose ps --services | egrep -x '(user)?as[0-9]+'); do
  docker-compose exec -T "$c" /bin/bash -c 'scionlab-config --host-id ${SCIONLAB_HOST_ID} --host-secret ${SCIONLAB_HOST_SECRET} --url http://coord:8000'
done
