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

from unittest.mock import patch
from django.test import TestCase
from scionlab.models import ISD, AS, UserAS, Link, Host, Interface, Service
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


class UpdateASKeysTests(TestCase):
    fixtures = ['scionlab-isds', 'scionlab-ases-ch']

    def test_update_keys(self):
        Host.objects.reset_needs_config_deployment()

        as_ = AS.objects.first()

        as_.update_keys()

        self.assertTrue(as_.certificates_needs_update)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(as_.hosts.all())
        )


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

        link = Link.objects.create(type=Link.PROVIDER,
                                   kwargsA=dict(host=as_a.hosts.first()),
                                   kwargsB=dict(host=as_b.hosts.first()))
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
        link = Link.objects.create_default(Link.PROVIDER, as_a, as_b)
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


class DeleteASTests(TestCase):
    # TODO(matzf) add link fixture
    fixtures = ['scionlab-isds', 'scionlab-ases-ch']

    def setUp(self):
        patcher = patch('scionlab.models.AS._pre_delete', side_effect=AS._pre_delete, autospec=True)
        self.mock_as_pre_delete = patcher.start()
        self.addCleanup(patcher.stop)

    def test_delete_single_as(self):
        as_ = AS.objects.last()

        # Add a link just so there is one
        # TODO(matzf) move to fixture
        Link.objects.create_default(Link.PROVIDER, as_, AS.objects.first())

        host_ids = [h.id for h in as_.hosts.all().iterator()]
        interface_ids = [h.id for h in as_.interfaces.all().iterator()]
        service_ids = [h.id for h in as_.services.all().iterator()]
        # Check that we are testing something useful:
        self.assertGreater(len(host_ids), 0, msg="Uninteresting test data")
        self.assertGreater(len(interface_ids), 0, msg="Uninteresting test data")
        self.assertGreater(len(service_ids), 0, msg="Uninteresting test data")

        Host.objects.reset_needs_config_deployment()

        as_.delete()

        self.assertEqual(self.mock_as_pre_delete.call_count, 1)

        # Check hosts have not been deleted and `needs_config_deployment`:
        for host_id in host_ids:
            self.assertTrue(Host.objects.filter(id=host_id).exists())
            self.assertTrue(Host.objects.get(id=host_id).needs_config_deployment())

        # Check interfaces and service objects have been deleted
        for interface_id in interface_ids:
            self.assertFalse(Interface.objects.filter(id=interface_id).exists())
        for service_id in service_ids:
            self.assertFalse(Service.objects.filter(id=service_id).exists())

    def test_delete_bulk(self):
        ases = AS.objects.filter(is_core=False)
        ases_count = ases.count()
        self.assertGreater(ases_count, 0, msg="Uninteresting test data")

        ases.delete()

        self.assertEqual(self.mock_as_pre_delete.call_count, ases_count)
