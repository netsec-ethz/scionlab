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

import os
import re
import huey
from .common import *


def _getenv(key):
    """ Helper for `os.environ[key]` with a specific error message """
    v = os.environ.get(key)
    if v is None:
        raise Exception("Missing '%s' from environment.\n" % key +
                        "This is required for scionlab.settings.production.\n"
                        "NOTE: in the docker-compose setup, this variable needs to be defined in "
                        "the (unversioned) file `run/scionlab.env`.")
    return v


# ##### INSTANCE AND PROXY CONFIGURATION #####################
# Parse host out of "site", so we won't need two settings for this.
# This enviornment variable is shared with the Caddyfile
SCIONLAB_SITE = _getenv('SCIONLAB_SITE')
_scionlab_host = re.sub(r'^\w+://|:\d+$', '', SCIONLAB_SITE)

ALLOWED_HOSTS = [_scionlab_host]
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Test instance indicator (controls ribbon in base template):
# - Empty string for production instance at scionlab.org and www.scionlab.org.
# - 'testing' for testing.scionlab.org etc.
_subdomain = re.sub(r'\.?scionlab\.org$', '', _scionlab_host)
INSTANCE_NAME = '' if _subdomain == 'www' else _subdomain


# ##### DB CONFIGURATION #####################
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'HOST': _getenv('POSTGRES_HOST'),
        'PORT': _getenv('POSTGRES_PORT'),
        'NAME': _getenv('POSTGRES_DB'),
        'USER': _getenv('POSTGRES_USER'),
        'PASSWORD': _getenv('POSTGRES_PASSWORD'),
        'ATOMIC_REQUESTS': True,
    },
}


# ##### HUEY TASK QUEUE CONFIGURATION #####################
HUEY = huey.RedisHuey('scionlab-huey', host='redis')

# ##### MAILER CONFIGURATION ##############################
DEFAULT_FROM_EMAIL = 'no-reply@scionlab.org'
SERVER_EMAIL = 'django@scionlab.org'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'mail.ethz.ch'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = _getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = _getenv('EMAIL_HOST_PASSWORD')


# ##### RECAPTCHA KEYS ##############################
RECAPTCHA_PUBLIC_KEY = _getenv('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = _getenv('RECAPTCHA_PRIVATE_KEY')
