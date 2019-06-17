#!/bin/sh

set -e

# Collect/update static files. These will be consumed by caddy, reading from the same volume.
/scionlab/manage.py collectstatic --noinput

# Wait for DB
appdeps.py --wait-secs 60 --port-wait $POSTGRES_HOST:$POSTGRES_PORT

# Initialise/migrate DB
/scionlab/manage.py migrate

gunicorn -b django:8000 scionlab.wsgi
#/scionlab/manage.py runserver 0.0.0.0:8000
