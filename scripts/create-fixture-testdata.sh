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
python manage.py shell -c 'from scionlab.fixtures.testdata import create_testdata; create_testdata()'
python manage.py dumpdata --format=yaml scionlab > scionlab/fixtures/testdata.yaml

# fixup timestamps to reduce noise
# Note: these timestamps are only informative and are not supposed to change the behaviour in any way
sed 's/\(created_date\|modified_date\|date_joined\): .*$/\1: 2019-10-02 03:00:00.00/' -i scionlab/fixtures/testdata.yaml

# get db back
mv $tempdir/dev.sqlite3 run/
