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
from scionlab.models import ISD, AS, UserAS
from scionlab.tests import utils


class StringRepresentationTests(TestCase):

    def setUp(self):
        isd17 = ISD.objects.create(id=17, label='Switzerland')
        ISD.objects.create(id=18, label='North America')
        ISD.objects.create(id=19, label='EU')
        ISD.objects.create(id=60)

        AS.objects.create(isd=isd17, as_id='ff00:0:1101', label='SCMN')
        AS.objects.create(isd=isd17, as_id='ff00:0:1102', label='ETHZ')
        AS.objects.create(isd=isd17, as_id='ff00:0:1103', label='SWTH')
        AS.objects.create(isd=isd17, as_id='ff00:1:1')

    def test_isd_str(self):
        isd_strs = list(sorted(str(isd) for isd in ISD.objects.all()))
        expected_isd_strs = [
            'ISD 17 (Switzerland)',
            'ISD 18 (North America)',
            'ISD 19 (EU)',
            'ISD 60',
        ]
        self.assertEqual(isd_strs, expected_isd_strs)

    def test_as_str(self):
        as_strs = list(sorted(str(a) for a in AS.objects.all()))
        expected_as_strs = [
            '17-ff00:0:1101 (SCMN)',
            '17-ff00:0:1102 (ETHZ)',
            '17-ff00:0:1103 (SWTH)',
            '17-ff00:1:1',
        ]
        self.assertEqual(as_strs, expected_as_strs)


class InitASTests(TestCase):
    def test_create_as_with_keys(self):
        isd = ISD.objects.create(id=17, label='Switzerland')
        as_ = AS.objects.create(isd=isd, as_id='ff00:1:1')
        utils.check_as_keys(self, as_)

    def test_create_coreas_with_keys(self):
        isd = ISD.objects.create(id=17, label='Switzerland')
        as_ = AS.objects.create(isd=isd, as_id='ff00:1:1', is_core=True)
        utils.check_as_keys(self, as_)
        utils.check_as_core_keys(self, as_)

    def test_create_useras_with_keys(self):
        isd = ISD.objects.create(id=17, label='Switzerland')
        userAS = UserAS.objects.create(isd=isd, as_id='ff00:1:1')
        utils.check_as_keys(self, userAS)

    def test_create_as_with_default_services(self):
        isd = ISD.objects.create(id=17, label='Switzerland')
        as_ = AS.objects.create(isd=isd, as_id='ff00:1:1')
        as_.init_default_services()

        self.assertTrue(hasattr(as_, 'hosts'))
        self.assertEqual(as_.hosts.count(), 1)
        host = as_.hosts.first()
        self.assertEqual(host.config_version, 0)
        self.assertEqual(host.ip, "127.0.0.1")

        self.assertTrue(hasattr(host, 'services'))
        self.assertEqual(sorted(s.type for s in host.services.iterator()),
                         ['BS', 'CS', 'PS', 'ZK'])
