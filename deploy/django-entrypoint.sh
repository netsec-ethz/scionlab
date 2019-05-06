#!/bin/sh

set -e

appdeps.py --wait-secs 60 --port-wait db:5432

/scionlab/manage.py makemigrations scionlab
/scionlab/manage.py migrate
gunicorn -b django:8000 scionlab.wsgi
