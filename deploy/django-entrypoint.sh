#!/bin/sh

set -e

appdeps.py --wait-secs 60 --port-wait db:5432

/scionlab/manage.py makemigrations scionlab
/scionlab/manage.py migrate
#/scionlab/manage.py runserver 0.0.0.0:8000
gunicorn -b 0.0.0.0:8000 scionlab.wsgi
