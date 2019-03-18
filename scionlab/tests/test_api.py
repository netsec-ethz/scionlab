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
import base64


def _basic_auth(username, password):
    uname_pwd = '%s:%s' % (username, password)
    uname_pwd_encoded = base64.b64encode(uname_pwd.encode('utf-8')).decode('ascii')
    return {"HTTP_AUTHORIZATION": "Basic %s" % uname_pwd_encoded}


class GetHostConfigTests(TestCase):
    fixtures = ['testtopo-ases-links']

    def setUp(self):
        # Avoid duplication, get this info here:
        self.host = Host.objects.last()
        self.url = '/api/host/%i/config' % self.host.pk
        self.auth_headers = _basic_auth(self.host.id, self.host.secret)

    def test_aaa(self):
        ret = self.client.get(self.url, **self.auth_headers)
        self.assertEqual(ret.status_code, 200)

    def test_bad_auth(self):
        auth_headers = _basic_auth(self.host.id, self.host.secret + "_foobar")
        ret = self.client.get(self.url, **auth_headers)
        self.assertEqual(ret.status_code, 401)

    def test_no_auth(self):
        ret = self.client.get(self.url)
        self.assertEqual(ret.status_code, 401)

    def test_bad_request(self):
        ret = self.client.get(self.url, {'version': 'nan'}, **self.auth_headers)
        self.assertEqual(ret.status_code, 400)

    def test_post_not_allowed(self):
        ret = self.client.post(self.url, {'version': 1}, **self.auth_headers)
        self.assertEqual(ret.status_code, 405)

    def test_unchanged(self):
        request_data = {'version': self.host.config_version}

        ret = self.client.get(self.url, request_data, **self.auth_headers)
        self.assertEqual(ret.status_code, 304)

        ret = self.client.head(self.url, request_data, **self.auth_headers)
        self.assertEqual(ret.status_code, 304)

    def test_changed(self):
        prev_version = self.host.config_version
        self.host.bump_config()
        request_data = {'version': prev_version}

        ret_get = self.client.get(self.url, request_data, **self.auth_headers)
        self.assertEqual(ret_get.status_code, 200)
        utils.check_tarball_host(self, ret_get, self.host)

        ret_head = self.client.head(self.url, request_data, **self.auth_headers)
        self.assertEqual(ret_head.status_code, 200)
        self.assertEqual(ret_head._headers, ret_get._headers)

    def test_empty(self):
        prev_version = self.host.config_version
        self.host.AS.delete()  # Nothing left to do for this host
        request_data = {'version': prev_version}

        ret = self.client.get(self.url, request_data, **self.auth_headers)
        self.assertEqual(ret.status_code, 204)

        ret = self.client.head(self.url, request_data, **self.auth_headers)
        self.assertEqual(ret.status_code, 204)


class PostHostConfigVersionTests(TestCase):
    fixtures = ['testtopo-ases-links']

    def setUp(self):
        # Avoid duplication, get this info here:
        self.host = Host.objects.last()
        self.url = '/api/host/%i/deployed_config_version' % self.host.pk
        self.auth_headers = _basic_auth(self.host.id, self.host.secret)

    def test_bad_auth(self):
        auth_headers = _basic_auth(self.host.id, self.host.secret + "_foobar")
        ret = self.client.post(self.url, **auth_headers)
        self.assertEqual(ret.status_code, 401)

    def test_no_auth(self):
        ret = self.client.post(self.url)
        self.assertEqual(ret.status_code, 401)

    def test_bad_request(self):
        ret = self.client.post(self.url, {'version': 'nan'}, **self.auth_headers)
        self.assertEqual(ret.status_code, 400)

    def test_get_not_allowed(self):
        ret = self.client.get(self.url, {'version': 1}, **self.auth_headers)
        self.assertEqual(ret.status_code, 405)

    def test_older_than_prev_deployed(self):
        # Make sure there is a previously deployed version number...
        self.host.config_version_deployed = self.host.config_version
        self.host.config_version += 1
        self.host.save()

        ret = self.client.post(self.url,
                               {'version': self.host.config_version_deployed - 1},
                               **self.auth_headers)
        self.assertEqual(ret.status_code, 304)

    def test_newer_than_config(self):
        ret = self.client.post(self.url,
                               {'version': self.host.config_version + 1},
                               **self.auth_headers)
        self.assertEqual(ret.status_code, 304)

    def test_success(self):
        ret = self.client.post(self.url,
                               {'version': self.host.config_version},
                               **self.auth_headers)
        self.assertEqual(ret.status_code, 200)

        self.host.refresh_from_db()
        self.assertEqual(self.host.config_version_deployed, self.host.config_version)
