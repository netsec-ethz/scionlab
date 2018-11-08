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
from scionlab.models import ISD, AS, UserAS, Link, Host, Interface
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
        self.assertEqual(host.ip, "127.0.0.1")
        self.assertTrue(host.needs_config_deployment())

        self.assertTrue(hasattr(host, 'services'))
        self.assertEqual(sorted(s.type for s in host.services.iterator()),
                         ['BS', 'CS', 'PS', 'ZK'])


class LinkModificationTests(TestCase):
    fixtures = ['scionlab-isds', 'scionlab-ases-ch']

    AS_SCMN = 'ffaa:0:1101'
    AS_ETHZ = 'ffaa:0:1102'
    AS_SWTH = 'ffaa:0:1103'

    def _as_a(self):
        return AS.objects.get(as_id=self.AS_SCMN)

    def _as_b(self):
        return AS.objects.get(as_id=self.AS_ETHZ)

    def _as_c(self):
        return AS.objects.get(as_id=self.AS_SWTH)

    def test_create_delete_link(self):
        as_a = self._as_a()
        as_b = self._as_b()

        Host.objects.reset_needs_config_deployment()

        link = Link.objects.create(as_a.hosts.first(), as_b.hosts.first(), Link.PROVIDER)
        self._sanity_check_link(link)
        self.assertEqual(link.type, Link.PROVIDER)
        self.assertEqual(Interface.objects.count(), 2)
        self.assertEqual(as_a.interfaces.get().remote_as(), as_b)
        self.assertEqual(as_b.interfaces.get().remote_as(), as_a)

        self.assertEqual(Host.objects.needs_config_deployment().count(), 2)
        Host.objects.reset_needs_config_deployment()

        link.delete()
        self.assertEqual(Link.objects.count(), 0)
        self.assertEqual(Interface.objects.count(), 0)

        self.assertEqual(Host.objects.needs_config_deployment().count(), 2)

    def test_update_link(self):
        as_a = self._as_a()
        as_b = self._as_b()
        link = Link.objects.create(as_a.hosts.first(), as_b.hosts.first(), Link.PROVIDER)
        self._sanity_check_link(link)

        Host.objects.reset_needs_config_deployment()

        # Update bind address: this is a local change
        link.interfaceA.update(bind_ip='192.0.2.1', bind_port=50000)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(as_a.hosts.all())
        )
        Host.objects.reset_needs_config_deployment()

        # Update public address: this affects local and remote interfaces
        link.interfaceA.update(public_ip='192.0.2.1', public_port=50000)
        self._sanity_check_link(link)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(as_a.hosts.all() | as_b.hosts.all())
        )
        Host.objects.reset_needs_config_deployment()

        # change the link from A-B to A-C
        as_c = self._as_c()
        link.interfaceB.update(host=as_c.hosts.first())
        self._sanity_check_link(link)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(as_a.hosts.all() | as_b.hosts.all() | as_c.hosts.all())
        )


    # TODO(matzf): tests that check validation

    def _sanity_check_link(self, link):
        self.assertIsNotNone(link)
        self.assertNotEqual(link.interfaceA, link.interfaceB)
        self._sanity_check_interface(link.interfaceA)
        self._sanity_check_interface(link.interfaceB)
        self.assertTrue(link.active)
        self.assertEquals(link.interfaceA.link(), link)
        self.assertEquals(link.interfaceB.link(), link)
        self.assertEquals(link.interfaceA.remote_interface(), link.interfaceB)
        self.assertEquals(link.interfaceB.remote_interface(), link.interfaceA)
        self.assertEquals(link.interfaceA.remote_as(), link.interfaceB.AS)
        self.assertEquals(link.interfaceB.remote_as(), link.interfaceA.AS)

    def _sanity_check_interface(self, interface):
        self.assertIsNotNone(interface)
        self.assertIsNotNone(interface.AS)
        self.assertIsNotNone(interface.host)
        self.assertEqual(interface.host.AS, interface.AS)
        self.assertTrue(1 <= interface.interface_id < 128)
