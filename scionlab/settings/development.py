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
INSTALLED_APPS += ['django_extensions'] # used for graph_models command during develop

# ##### MAILER CONFIGURATION ##############################
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
