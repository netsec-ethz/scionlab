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

from django.test import TestCase, override_settings
from django.urls import path
from django.http import HttpResponse
from scionlab.models import User
from scionlab.fixtures.testuser import (
    TESTUSER_EMAIL,
    TESTUSER_PWD
)


def extract_request(request):
    """
    View that just stores the request in a class variable
    for analysis.
    """
    ProxyUserBackendTests.request = request
    return HttpResponse()


class ProxyUserBackendTests(TestCase):
    fixtures = ['testuser']
    request = None

    class TestUrls:
        urlpatterns = [path('', extract_request)]

    @override_settings(ROOT_URLCONF=TestUrls)
    def test_user_model(self):
        """
        Make a request using the test client (to a stub-view that only records
        the request and check that the type of `request.user` is
        `scionlab.model.User`.
        """
        self.client.login(username=TESTUSER_EMAIL, password=TESTUSER_PWD)
        self.client.get('')
        self.assertIsNotNone(self.request)
        # Check that the type of the user in
        # the extracted request is scionlab.models.User
        user = self.request.user
        # Check the __class__ (note: type is actually SimpleLazyObject...)
        self.assertEqual(user.__class__, User)
        # Call some functions to see it actually works as it should:
        self.assertEqual(user.num_ases(), 0)
        self.assertGreater(user.max_ases(), 0)
