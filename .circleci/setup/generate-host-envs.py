# Parse the testdata.yaml fixture to extract host-uid and secrets for the hosts in the test setup.
# Write the information to /tmp/asXY.env files, so it can easily be consumed in the docker-compose
# setup.

from __future__ import print_function
import yaml
import pathlib

TESTDATA_FILE = 'scionlab/fixtures/testdata.yaml'
TEST_ASES = [
    'ffaa:0:1301',
    'ffaa:0:1303',
    'ffaa:0:1305',
    'ffaa:0:1401',
    'ffaa:0:1405',
]

with open(TESTDATA_FILE) as f:
    data = yaml.load(f, Loader=yaml.SafeLoader)

ases = {}
hosts = {}
for entry in data:
    if entry['model'] == 'scionlab.as':
        ases[entry['pk']] = entry['fields']
    elif entry['model'] == 'scionlab.host':
        hosts[entry['pk']] = entry['fields']

for host in hosts.values():
    as_id = ases[host['AS']]['as_id']
    env_filename = '/tmp/as%s.env' % (as_id.split(':')[-1])
    if as_id in TEST_ASES:
        envs = {
            'SCIONLAB_HOST_ID': host['uid'],
            'SCIONLAB_HOST_SECRET': host['secret'],
        }
        env_str = '\n'.join('%s=%s' % (k, v) for k, v in envs.items())
        pathlib.Path(env_filename).write_text(env_str)
        print(env_filename, ':')
        print(env_str)
