# Copyright 2019 ETH Zurich
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

from django.test import TestCase, override_settings
from django.urls import reverse


@override_settings(MAINTENANCE_MODE=True)
class MaintenanceModeTests(TestCase):
    def test_get(self):
        response = self.client.get('/')
        self.check_response_maintenance(response)

    def test_post(self):
        response = self.client.post(
            reverse('login'),
            {'username': 'foo', 'password': 'bar'},
            follow=True
        )
        self.check_response_maintenance(response)

    def test_get_admin(self):
        response = self.client.get('/admin/login/')
        self.assertEqual(response.status_code, 200)

    def check_response_maintenance(self, response):
        self.assertEqual(response.status_code, 503)
        self.assertTrue(b"<title>SCIONLab - Site Maintenance</title>" in response.content)
