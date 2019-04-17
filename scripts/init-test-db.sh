#!/bin/sh
#
# Copyright 2018 ETH Zurich
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

set -e

rm run/dev.sqlite3 || true
rm -r scionlab/migrations/ || true

python manage.py makemigrations scionlab
python manage.py migrate

python manage.py loaddata scionlab/fixtures/testuser-admin.yaml \
    scionlab/fixtures/testuser.yaml \
    scionlab/fixtures/testtopo-ases-links.yaml

cp scionlab/fixtures/testtopo_ca_key.pem run/dev_root_ca_key.pem
cp scionlab/fixtures/testtopo_ca_cert.pem run/dev_root_ca_cert.pem
