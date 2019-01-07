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

from django.test import TestCase
from scionlab.models import Host
from scionlab.tests import utils


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
        utils.check_tarball_host(self, ret_get, self.host)

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


class PostHostConfigVersionTests(TestCase):
    fixtures = ['testtopo-ases-links']

    def setUp(self):
        # Avoid duplication, get this info here:
        self.host = Host.objects.last()
        self.host_config_url = '/api/host/%i' % self.host.pk
