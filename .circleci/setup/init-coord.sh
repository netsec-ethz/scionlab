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

# wait a bit for the migrations in the django-entrypoint.sh are done:
docker-compose exec -T coord appdeps.py --interval-secs 1 --wait-secs 60 --port-wait coord:8000
docker-compose exec -T coord /bin/bash -c \
  './manage.py loaddata scionlab/fixtures/testdata.yaml; \
   cp scionlab/fixtures/dev_root_ca_*.pem run/'
