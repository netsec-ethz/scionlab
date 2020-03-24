#!/bin/sh

set -e

# Initialise/migrate DB
/scionlab/manage.py migrate

/scionlab/manage.py runserver 0.0.0.0:8000
