# SCIONLab
SCIONLab is a global research network to test the SCION next-generation
internet architecture.  Users can join the SCION network with their own
computation resources and can set up and run their own autonomous systems
(ASes).

This repository contains the central website that orchestrates the
configuration of ASes in the SCIONLab network.
The website creates a configuration tar-ball for all the SCION services,
including keys, certificates and all other options and settings, for each host
in the SCIONLab network.

The website has two parts:
- public:
  - registration, password management etc.
  - simple interface to create/edit "user ASes" with a single link to a
    predefined "attachment point" ASes.
    The important point here is that the configuration of the corresponding
    attachment point AS(es) is automatically updated after any change to a user
    AS.
- admin:
  - general website administration (user management etc.)
  - configuration of SCIONLab _infrastructure_ ASes
  - deployment of configuration to managed infrastructure nodes


## Development

### Installation
Steps to start up the django webserver for development and local testing.

```bash
# Make a venv for scionlab
python3 -m venv venv
source venv/bin/activate

# NOTE: on debian/ubuntu python venv requires:
#         apt install python3-venv
#       and because it's apparently botched, update pip etc. in the venv:
# pip install --upgrade pip setuptools wheel

# Install Python requirements (Django, libraries, etc.)
pip install --require-hashes -r requirements.txt -r dev-requirements.txt

# NOTE: the 'scrypt' package may fail to build if libssl is not installed
#       on your machine; install and try again.
#         apt install libssl1.0
```

To render the topology graph, `graphviz` needs to be installed additionally to the python dependencies. On ubuntu:
```
apt install graphviz
```
If this is missing, the topology graph will fail to render (with a 500 error code).

### Running

The commands below assume an environment as installed above.

Initialise development sqlite-DB with some an admin, a testuser and some ASes.
The usernames and passwords for the test users can be found in [scionlab/fixtures/testuser.py](scionlab/fixtures/testuser.py).
```bash
scripts/init-test-db.sh
```

Start the django development server:
```bash
python manage.py runserver
```

If required, additionally start the huey task queue (used for asynchronous
tasks, currently only push deployment triggers).
```bash
python manage.py run_huey
```

### Managing Dependencies
There are two requirements-files for pip; `requirements.txt` contains the
requirements for the production environment and `dev-requirements.txt` contains
the _additional_ requirements for a development environment (style-checker,
testing infrastructure etc).

We use [pip-tools](https://pypi.org/project/pip-tools/) to manage the requirements.
The `*.txt` files are generated from the corresponding `*.in` file. To generate/update requirements files, run
```bash
pip-compile --generate-hashes --output-file=requirements.txt requirements.in
pip-compile --generate-hashes --output-file=dev-requirements.txt dev-requirements.in
```
These commands are also recorded in the preamble of the `*.txt` files.


### Testing

##### Unit tests:

```bash
./manage.py test
```

##### Style checker:

```bash
flake8
```

##### Integration tests:

A set of more complex integration tests that will actually run the generated
configuration for multiple SCION ASes uses the CircleCI infrastructure.

## Deployment

There exists an internal [GitLab repository](https://gitlab.inf.ethz.ch/PRV-PERRIG/scionlab-deploy) containing the configuration for the pipeline deploying SCIONLab coordinator into running environment. GitHub webhook against this repo will triger deployment every time when there are changes in the `master` branch.

In order to have a fully functional installation [the internal configuration](https://gitlab.inf.ethz.ch/PRV-PERRIG/scionlab-config) is needed. It contains some internal secret keys and configurations for accessing the SCIONLab infrastructure machines. More detailed informations can be found directly in its repository.
