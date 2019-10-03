#!/bin/bash

# Regular coordinator installation procedure
python3 -m venv /tmp/venv
. /tmp/venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -r dev-requirements.txt

# Load fixtures and initalize test DB
PYTHONPATH=/tmp/scion/python scripts/init-test-db.sh

# Start coordinator
PYTHONPATH=/tmp/scion/python python manage.py runserver 0.0.0.0:8000

