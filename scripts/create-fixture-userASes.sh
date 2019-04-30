#!/bin/sh
#
# Copyright 2019 ETH Zurich
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

# run this import script after creating the infrastructure fixture
# this import script needs three CSV files located in the root dir (where "scripts" is):
# - users.csv
# - connection.csv
# - scion_lab_as.csv

# backup db
tempdir=`mktemp -d`
mv run/dev.sqlite3 $tempdir || true

# init new db
python manage.py makemigrations scionlab
python manage.py migrate -v 1

# import user accounts:
python ./scripts/import-scion-coord-users.py users.csv
# import infrastructure:
python manage.py loaddata scionlab/fixtures/scionlab-infrastructure.yaml
# import user ASes:
python manage.py shell -c "from scionlab.fixtures.scionlab_userASes import load_user_ASes; load_user_ASes()"

# dump into fixture and get original db back
python manage.py dumpdata --format=yaml scionlab > scionlab/fixtures/scionlab-withuserASes.yaml
mv run/dev.sqlite3 run/infrastructure.sqlite3
[ -f $tempdir/dev.sqlite3 ] && mv $tempdir/dev.sqlite3 run/
