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
INSTALLED_APPS += ['snowpenguin.django.recaptcha2']  # used for human verification (no bot)

# ##### AUTH CONFIGURATION ################################
LOGIN_URL = ''
LOGIN_REDIRECT_URL = '/user/ASes/'

# ##### EXTENSIONS CONFIGURATION ##########################
# django_registration
ACCOUNT_ACTIVATION_DAYS = 14  # Allow a two-week time window for account activation after signup
REGISTRATION_OPEN = True  # Accept new registrations
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
# django-recaptcha2
RECAPTCHA_PUBLIC_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'
RECAPTCHA_PRIVATE_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'
