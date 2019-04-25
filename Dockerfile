FROM python:3
ENV PYTHONUNBUFFERED 1
RUN mkdir /scionlab
WORKDIR /scionlab
COPY requirements.txt /scionlab/
RUN pip install -r requirements.txt
COPY . /scionlab/
