# SCIONLab
SCIONLab user interface and administration

## Start development

Steps to start up the django webserver for development (very early testing).

```bash
# (optional) make a venv for scionlab
# Note: on debian/ubuntu python venv requires: apt install python3-venv
python3 -m venv /tmp/scionlab
source /tmp/scionlab/bin/activate

# install Python requirements (Django, libraries, etc.)
pip3 install --require-hashes -r requirements.txt
# for development, additionally use the dev-requirements file:
# pip3 install --require-hashes -r requirements.txt -r dev-requirements.txt

# initialise dev db
python manage.py makemigrations scionlab
python manage.py migrate

# create an admin
python manage.py createsuperuser

# start the server
python manage.py runserver
```
