FROM python:3
ENV PYTHONUNBUFFERED 1

# Appdeps is used by the entrypoint script to wait for the DB services.
# Not included in requirements because it's a requirement of the
# docker-compose plumbing, not the application.
RUN pip install appdeps

# Clone SCION repo to get it's python modules
RUN git clone https://github.com/netsec-ethz/netsec-scion/ /scion
ENV PYTHONPATH=/scion/python:/scion

RUN mkdir /scionlab
WORKDIR /scionlab
COPY requirements.txt /scionlab/
RUN pip install -r requirements.txt
COPY . /scionlab/


ENV DJANGO_SETTINGS_MODULE=scionlab.settings.production
CMD /scionlab/scripts/docker-entrypoint.sh
#CMD ["/scionlab/manage.py","runserver","0.0.0.0:8000"]
#CMD ["gunicorn","scionlab.wsgi"]
