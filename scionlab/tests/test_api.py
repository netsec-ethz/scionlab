# Copyright 2018 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io
import re
import tarfile
import pathlib
from django.test import TestCase
from scionlab.models import Host


class GetHostConfigTests(TestCase):
    fixtures = ['testtopo-ases-links']

    def setUp(self):
        # Avoid duplication, get this info here:
        self.host = Host.objects.last()
        self.host_config_url = '/api/host/%i/config' % self.host.pk

    def test_bad_secret(self):
        ret = self.client.get(self.host_config_url, {'secret': self.host.secret + '_foobar'})
        self.assertEqual(ret.status_code, 403)

    def test_no_secret(self):
        ret = self.client.get(self.host_config_url)
        self.assertEqual(ret.status_code, 403)

    def test_unchanged(self):
        request_data = {'secret': self.host.secret, 'version': self.host.config_version}

        ret = self.client.get(self.host_config_url, request_data)
        self.assertEqual(ret.status_code, 304)

        ret = self.client.head(self.host_config_url, request_data)
        self.assertEqual(ret.status_code, 304)

    def test_changed(self):
        prev_version = self.host.config_version
        self.host.bump_config()
        request_data = {'secret': self.host.secret, 'version': prev_version}

        ret_get = self.client.get(self.host_config_url, request_data)
        self.assertEqual(ret_get.status_code, 200)
        self._check_tarball(ret_get, self.host)

        ret_head = self.client.head(self.host_config_url, request_data)
        self.assertEqual(ret_head.status_code, 200)
        self.assertEqual(ret_head._headers, ret_get._headers)

    def test_empty(self):
        prev_version = self.host.config_version
        self.host.AS.delete()  # Nothing left to do for this host
        request_data = {'secret': self.host.secret, 'version': prev_version}

        ret = self.client.get(self.host_config_url, request_data)
        self.assertEqual(ret.status_code, 204)

        ret = self.client.head(self.host_config_url, request_data)
        self.assertEqual(ret.status_code, 204)

    def _check_tarball(self, response, host):
        self.assertTrue(re.search(r'attachment;\s*filename="[^"]*.tar.gz"',
                                  response['Content-Disposition']))
        self.assertEqual(response['Content-Type'], 'application/gzip')
        self.assertEqual(int(response['Content-Length']), len(response.content))

        # Simple sanity checks:
        # The tarfile can be opened:
        tar = tarfile.open(mode='r:gz', fileobj=io.BytesIO(response.content))
        filenames = tar.getnames()

        # Check first level listing:
        subfolders = [f for f in filenames if '/' not in f]
        self.assertEqual(subfolders, ['gen'])

        # The gen/-folder looks roughly like expected:
        as_gen_dir = 'gen/ISD%i/AS%s' % (host.AS.isd.isd_id, host.AS.as_path_str())
        gen_subfolders = [f for f in filenames if pathlib.PurePath(f).match('gen/*/*')]
        self.assertEqual([as_gen_dir], gen_subfolders)
        topofiles = [f for f in filenames if
                     pathlib.PurePath(f).match(as_gen_dir + "/*/topology.json")]
        self.assertTrue(topofiles)
