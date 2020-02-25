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

SCIONLAB_SITE = 'http://localhost:8000'

# ##### DEBUG CONFIGURATION ###############################
DEBUG = True
TEMPLATES[0]['OPTIONS']['debug'] = True
CRISPY_FAIL_SILENTLY = not DEBUG

# allow all hosts during development
ALLOWED_HOSTS = ['*']

# ##### DATABASE CONFIGURATION ############################
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'run', 'dev.sqlite3'),
        'ATOMIC_REQUESTS': True,
    }
}


# ##### HUEY TASK QUEUE CONFIGURATION #####################
HUEY = huey.SqliteHuey('scionlab-huey',
                       filename=os.path.join(BASE_DIR, 'run', 'dev-huey.sqlite3'))

# ##### APPLICATION CONFIGURATION #########################
INSTALLED_APPS += [
    'django_extensions',  # used for graph_models command during develop
    'django_nose',
]

TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'

# ##### EXTENSIONS CONFIGURATION ##########################

# django-recaptcha2 test keys
RECAPTCHA_PUBLIC_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'
RECAPTCHA_PRIVATE_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'

# ##### MAILER CONFIGURATION ##############################
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'


# ##### VPN CONFIG OVERRIDES ##############################
VPN_CA_KEY_PASSWORD = 'sci0nl4b'
VPN_CA_KEY_PATH = os.path.join(BASE_DIR, 'run', 'dev_root_ca_key.pem')
VPN_CA_CERT_PATH = os.path.join(BASE_DIR, 'run', 'dev_root_ca_cert.pem')


class VPNKeygenConfDev(VPNKeygenConf):
    KEY_SIZE = 1024  # Shortest workable keys for faster tests.
                     # Note: 512-bit can be generated, but cannot initiate openvpn connection.


VPN_KEYGEN_CONFIG = VPNKeygenConfDev
