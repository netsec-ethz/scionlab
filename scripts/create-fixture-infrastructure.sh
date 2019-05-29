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

if [ $# -ne 1 ]; then
    echo "Argument: location of gen folder with all infrastructure"
    echo "e.g. $0 ~/go/src/github.com/netsec-ethz/scion-web/gen"
    exit 1
fi
GEN_PATH="$1"

# backup db
tempdir=`mktemp -d`
mv run/dev.sqlite3 $tempdir || true

# init new db
python manage.py migrate -v 1

# create and dump data for fixture
python manage.py shell -c "from scionlab.fixtures.scionlab_infrastructure import build_scionlab_topology; build_scionlab_topology(\"$GEN_PATH\")"
python manage.py dumpdata --format=yaml scionlab > scionlab/fixtures/scionlab-infrastructure.yaml

# get db back
mv run/dev.sqlite3 run/infrastructure.sqlite3
[ -f $tempdir/dev.sqlite3 ] && mv $tempdir/dev.sqlite3 run/
