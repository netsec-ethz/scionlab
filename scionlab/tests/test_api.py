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

import json

from django.test import TestCase
from parameterized import parameterized
from scionlab.models.core import Host
from scionlab.tests import utils
from scionlab.tests.utils import basic_auth


class GetHostConfigTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        # Avoid duplication, get this info here:
        self.host = Host.objects.last()
        self.url = '/api/v3/host/%s/config' % self.host.uid
        self.auth_headers = basic_auth(self.host.uid, self.host.secret)

    def test_aaa(self):
        ret = self.client.get(self.url, **self.auth_headers)
        self.assertEqual(ret.status_code, 200)

    def test_bad_auth(self):
        auth_headers = basic_auth(self.host.uid, self.host.secret + "_foobar")
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
        # Fails, because file-timestamps in tar-file which causes content-length difference
        # self.assertEqual(ret_head._headers, ret_get._headers)

    def test_empty(self):
        prev_version = self.host.config_version
        self.host.AS.delete()  # Nothing left to do for this host
        request_data = {'version': prev_version}

        ret = self.client.get(self.url, request_data, **self.auth_headers)
        self.assertEqual(ret.status_code, 204)

        ret = self.client.head(self.url, request_data, **self.auth_headers)
        self.assertEqual(ret.status_code, 204)


class GetHostConfigExtraServicesTests(TestCase):
    fixtures = ['testdata']

    @staticmethod
    def _get_url(host):
        return '/api/v3/host/%s/config' % host.uid

    @staticmethod
    def _get_auth_headers(host):
        return basic_auth(host.uid, host.secret)

    def test_get(self):
        # in the fixture, the host for 17-ffaa:0:1107 has extra services
        hosts = Host.objects.filter(AS__as_id='ffaa:0:1107')
        host = hosts[0]
        resp = self.client.get(self._get_url(host), {}, **self._get_auth_headers(host))
        self.assertEqual(resp.status_code, 200)
        tar = utils.check_tarball_host(self, resp, host)
        services = json.loads(utils.tar_cat(tar, 'scionlab-config.json'))['systemd_units']
        self.assertIn('scion-bwtestserver.service', services)


class PostHostConfigVersionTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        # Avoid duplication, get this info here:
        self.host = Host.objects.last()
        self.url = '/api/v3/host/%s/deployed_config_version' % self.host.uid
        self.auth_headers = basic_auth(self.host.uid, self.host.secret)

    def test_bad_auth(self):
        auth_headers = basic_auth(self.host.uid, self.host.secret + "_foobar")
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


class OldVersionTests(TestCase):
    fixtures = ['testdata']
    old_versions = [
        ('', 'oldest, unversioned'),
        ('v2/', 'v2')
    ]

    @parameterized.expand(old_versions)
    def test_get_config(self, version_str, _comment):
        # Note: using an existing host and correct auth headers, but this will not matter.
        host = Host.objects.last()
        url = '/api/%shost/%s/config' % (version_str, host.uid)
        auth_headers = basic_auth(host.uid, host.secret)

        ret = self.client.get(url, **auth_headers)
        self.assertEqual(ret.status_code, 410)

    @parameterized.expand(old_versions)
    def test_post_(self, version_str, _comment):
        host = Host.objects.last()
        url = '/api/%shost/%s/deployed_config_version' % (version_str, host.uid)
        auth_headers = basic_auth(host.uid, host.secret)

        ret = self.client.post(url, {'version': 1}, **auth_headers)
        self.assertEqual(ret.status_code, 410)

    def test_topology_json_v2_redirect(self):
        url_pattern = '/api/{version}/topology/topology'
        url_v2 = url_pattern.format(version='v2')
        url_v3 = url_pattern.format(version='v3')

        ret = self.client.get(url_v2, follow=True)
        self.assertEqual(ret.redirect_chain, [(url_v3, 301)])
        self.assertEqual(ret.status_code, 200)
        self.assertEqual(ret['Content-Type'], 'application/json')
