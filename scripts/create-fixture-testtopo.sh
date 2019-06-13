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

# backup db
tempdir=`mktemp -d`
mv run/dev.sqlite3 $tempdir

# init new db
python manage.py migrate -v 1

# create and dump data for fixture
python manage.py shell -c 'from scionlab.fixtures.testtopo import *; create_testtopo_isds()'
python manage.py dumpdata --format=yaml scionlab > scionlab/fixtures/testtopo-isds.yaml
python manage.py shell -c 'from scionlab.fixtures.testtopo import *; create_testtopo_ases()'
python manage.py dumpdata --format=yaml scionlab > scionlab/fixtures/testtopo-ases.yaml
python manage.py shell -c 'from scionlab.fixtures.testtopo import *; create_testtopo_vpn()'
python manage.py dumpdata --format=yaml scionlab > scionlab/fixtures/testtopo-ases-vpn.yaml
python manage.py shell -c 'from scionlab.fixtures.testtopo import *; create_testtopo_links()'
python manage.py dumpdata --format=yaml scionlab > scionlab/fixtures/testtopo-ases-links.yaml
python manage.py shell -c 'from scionlab.fixtures.testtopo import *; create_testtopo_extraservices()'
python manage.py dumpdata --format=yaml scionlab > scionlab/fixtures/testtopo-ases-links-extraserv.yaml

# get db back
mv $tempdir/dev.sqlite3 run/
