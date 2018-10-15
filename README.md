# SCIONLab
SCIONLab user interface and administration

## Start development

Steps to start up the django webserver for development (very early testing).

```bash
# (optional) make a virtualenv for scionlab
pip3 install virtualenv
virtualenv /tmp/scionlab
source /tmp/scionlab/bin/activate
# install Django
pip3 install Django django-extensions
# initialise dev db
python manage.py makemigrations scionlab
python manage.py migrate
# create an admin
python manage.py createsuperuser
# start the server
python manage.py runserver
```

