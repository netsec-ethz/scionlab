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


ALLOWED_HOSTS = [
    'django',
]


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': _getenv('POSTGRES_DB'),
        'USER': _getenv('POSTGRES_USER'),
        'PASSWORD': _getenv('POSTGRES_PASSWORD'),
        'HOST': 'db',
        'PORT': '5432',
        'ATOMIC_REQUESTS': True,
    },
}

# ##### HUEY TASK QUEUE CONFIGURATION #####################
HUEY = huey.RedisHuey('scionlab-huey', host='redis')

# ##### MAILER CONFIGURATION ##############################
DEFAULT_FROM_EMAIL = 'no-reply@scionlab.org'
SERVER_EMAIL = 'django@scionlab.org'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = _getenv('EMAIL_HOST')
EMAIL_HOST_USER = _getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = _getenv('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = True


# ##### RECAPTCHA KEYS ##############################
RECAPTCHA_PUBLIC_KEY = _getenv('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = _getenv('RECAPTCHA_PRIVATE_KEY')


# ##### TEST INSTANCE INDICATOR ##############################
# Set this to empty string explicitly for production
INSTANCE_NAME = _getenv('INSTANCE_NAME')
