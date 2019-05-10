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

# Python imports
import os

# ##### PATH CONFIGURATION ################################
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ##### APPLICATION CONFIGURATION #########################

INSTALLED_APPS = [
    'scionlab',
    'django_registration',  # used for two-step user account activation (Email verification)
    'snowpenguin.django.recaptcha2',  # used for human verification (no bot)
    'crispy_forms',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'huey.contrib.djhuey',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'scionlab.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'scionlab.context_processors.grafana_url',
                'scionlab.context_processors.instance_indicator',
            ],
        },
    },
]

# ##### DJANGO RUNNING CONFIGURATION ######################

# the URL for static files
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')


# ##### AUTH CONFIGURATION ################################
AUTH_USER_MODEL = 'scionlab.User'
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'user'

PASSWORD_HASHERS = [
  'django.contrib.auth.hashers.PBKDF2PasswordHasher',
  'scionlab.util.hashers.SCryptPasswordHasher',  # to verify passwords imported from old coordinator
]

# ##### EXTENSIONS CONFIGURATION ##########################

# django_registration
ACCOUNT_ACTIVATION_DAYS = 14  # Allow a two-week time window for account activation after signup
REGISTRATION_OPEN = True  # Accept new registrations

# crispy_forms
CRISPY_TEMPLATE_PACK = 'bootstrap4'

# ##### DEFAULT SETTINGS CONFIGURATION ####################
MAX_ASES_ADMIN = 10
MAX_ASES_USER = 5
GRAFANA_URL = "https://prometheus.scionlab.org"

# Rate limit for host deployments, specified by the minimal time between
# two consecutive deployments (value in seconds).
DEPLOYMENT_PERIOD = 60

# SSH Config file for managed hosts
SSH_CONFIG_PATH = os.path.join(BASE_DIR, 'run', 'ssh_config')

# Openvpn key/cert:
VPN_CA_KEY_PASSWORD = os.environ.get('VPN_CA_KEY_PASSWORD')
VPN_CA_KEY_PATH = os.path.join(BASE_DIR, 'run', 'root_ca_key.pem')
VPN_CA_CERT_PATH = os.path.join(BASE_DIR, 'run', 'root_ca_cert.pem')


class VPNKeygenConf:
    # A large key size will slow down TLS negotiation performance as well as the one-time DH parms
    # generation process.
    KEY_SIZE = 4096

    # In how many days should the root CA key expire?
    CA_EXPIRE = 1000

    # In how many days should certificates expire?
    KEY_EXPIRE = 730

    # Fields which will be placed in the certificate.
    KEY_COUNTRY = "CH"
    KEY_PROVINCE = "ZH"
    KEY_CITY = "Zurich"
    KEY_ORG = "ETH"
    KEY_EMAIL = "scion@lists.inf.ethz.ch"
    KEY_OU = "NetSec"

    # X509 Subject Field
    KEY_NAME = "SCIONVPN"
    KEY_ALTNAMES = "SCIONVPN"


VPN_KEYGEN_CONFIG = VPNKeygenConf()


# ##### DEBUG CONFIGURATION ###############################
ALLOWED_HOSTS = []
DEBUG = False

# ##### SECURITY CONFIGURATION ############################

# We store the secret key here
# The required SECRET_KEY is fetched at the end of this file
SECRET_FILE = os.path.join(BASE_DIR, 'run', 'SECRET.key')

# finally grab the SECRET KEY
try:
    SECRET_KEY = open(SECRET_FILE).read().strip()
except IOError:
    try:
        from django.core.management.utils import get_random_secret_key
        SECRET_KEY = get_random_secret_key()
        with open(SECRET_FILE, 'w') as f:
            f.write(SECRET_KEY)
    except IOError:
        raise Exception('Could not open %s for writing!' % SECRET_FILE)
