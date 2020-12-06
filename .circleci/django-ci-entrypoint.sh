#!/bin/sh

set -e

# Wait for DB
appdeps.py --interval-secs 1 --wait-secs 60 --port-wait $POSTGRES_HOST:$POSTGRES_PORT

# Initialise/migrate DB
/scionlab/manage.py migrate

/scionlab/manage.py runserver 0.0.0.0:8000
