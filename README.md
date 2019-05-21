# :construction: Under Construction :construction:

# SCIONLab
SCIONLab user interface and administration

## Start development

Steps to start up the django webserver for development (very early testing).

```bash
# Make a venv for scionlab
python3 -m venv /tmp/scionlab
source /tmp/scionlab/bin/activate

# Note: on debian/ubuntu python venv requires: apt install python3-venv
#       and because it's apparently botched, update pip etc. in the venv:
# pip install --upgrade pip setuptools wheel

# Install Python requirements (Django, libraries, etc.)
pip install --require-hashes -r requirements.txt
# for development, additionally use the dev-requirements file:
# pip install --require-hashes -r requirements.txt -r dev-requirements.txt

# Make sure the scion libraries are in the PYTHONPATH:
export PYTHONPATH=/path/to/scionproto/scion/python

# Initialise development DB with some an admin, a testuser and some ASes.
scripts/init-test-db.sh
```

To render the topology graph, `graphviz` needs to be installed additionally to the python dependencies. On ubuntu:
```
apt install graphviz
```
If this is missing, the topology graph will fail to render (with a 500 error code).
