#!/bin/sh

set -e

# Collect/update static files. These will be consumed by caddy, reading from the same volume.
/scionlab/manage.py collectstatic --noinput

# Wait for DB
appdeps.py --interval-secs 1 --wait-secs 60 --port-wait $POSTGRES_HOST:$POSTGRES_PORT

# Initialise/migrate DB
/scionlab/manage.py migrate

gunicorn --log-level info --capture-output -b django:8000 scionlab.wsgi
