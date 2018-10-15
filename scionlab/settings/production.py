from .common import *

ALLOWED_HOSTS = [
    # TODO
]

DATABASES = {
    # TODO
}

# ##### APPLICATION CONFIGURATION #########################
INSTALLED_APPS += ['django_registration'] # used for two-step user account activation (Email verification)

# ##### EXTENSIONS CONFIGURATION ##########################
# django_registration
ACCOUNT_ACTIVATION_DAYS = 14 # Allow a two-week time window for account activation after signup
REGISTRATION_OPEN = True # Accept new registrations
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
