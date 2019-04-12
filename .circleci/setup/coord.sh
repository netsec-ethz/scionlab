#!/bin/bash

# Get scion dependency
[ -d /tmp/scion ] || git clone https://github.com/netsec-ethz/netsec-scion.git /tmp/scion
cd /tmp/scion
git fetch && git checkout scionlab && git reset --hard origin/scionlab

# Get code under test from executor
cd ~/repo; until [ -d ./scionlab ]; do sleep 10; done
cd scionlab

# Regular coordinator installation procedure
python3 -m venv /tmp/venv
. /tmp/venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -r dev-requirements.txt

# Recreate fixture and initalize test DB
PYTHONPATH=/tmp/scion/python scripts/create-fixture-testtopo.sh
PYTHONPATH=/tmp/scion/python scripts/init-test-db.sh

# Start coordinator
PYTHONPATH=/tmp/scion/python python manage.py runserver 0.0.0.0:8000

