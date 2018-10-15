import os
from .common import *

# ##### DEBUG CONFIGURATION ###############################
DEBUG = True

# allow all hosts during development
ALLOWED_HOSTS = ['*']

# ##### DATABASE CONFIGURATION ############################
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'run', 'dev.sqlite3'),
    }
}

# ##### APPLICATION CONFIGURATION #########################
INSTALLED_APPS += ['django_extensions']  # used for graph_models command during develop
INSTALLED_APPS += ['django_registration']  # used for two-step user account activation (Email verification)

# ##### AUTH CONFIGURATION ################################
LOGIN_URL = ''
LOGIN_REDIRECT_URL = '/user/ASes/'

# ##### EXTENSIONS CONFIGURATION ##########################
# django_registration
ACCOUNT_ACTIVATION_DAYS = 14  # Allow a two-week time window for account activation after signup
REGISTRATION_OPEN = True  # Accept new registrations
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
