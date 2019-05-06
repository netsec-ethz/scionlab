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
from .common import *
import huey

ALLOWED_HOSTS = [
    '*'
]

DEBUG=True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ.get('POSTGRES_DB'),
        'USER': os.environ.get('POSTGRES_USER'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD'),
        'HOST': 'db',
        'PORT': '5432',
        'ATOMIC_REQUESTS': True,
    },
}

STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# ##### HUEY TASK QUEUE CONFIGURATION #####################
HUEY = huey.RedisHuey('scionlab-huey', host='redis')

# ##### MAILER CONFIGURATION ##############################
DEFAULT_FROM_EMAIL = 'no-reply@scionlab.org'
SERVER_EMAIL = 'django@scionlab.org'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp0.ethz.ch'

# ##### TEST INSTANCE INDICATOR ##############################
DEVELOPMENT_MODE = 'testing'

# TODO: django-recaptcha2 test keys
RECAPTCHA_PUBLIC_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'
RECAPTCHA_PRIVATE_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'
