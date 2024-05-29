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
import ipaddress

from unittest.mock import patch
from django.db import models
from django.test import TestCase
from scionlab.defines import (
    DISPATCHER_PORT,
    DISPATCHER_METRICS_PORT,
    SD_TCP_PORT,
    SD_METRICS_PORT,
)
from scionlab.models.core import ISD, AS, Link, Host, Interface, BorderRouter, Service
from scionlab.models.pki import Certificate, Key
from scionlab.models.vpn import find_free_subnet
from scionlab.fixtures import testtopo
from scionlab.tests import utils


class StringRepresentationTests(TestCase):

    def setUp(self):
        isd17 = ISD.objects.create(isd_id=17, label='Switzerland')
        ISD.objects.create(isd_id=18, label='North America')
        ISD.objects.create(isd_id=19, label='EU')
        ISD.objects.create(isd_id=60)

        AS.objects.create(isd=isd17, as_id='ff00:0:1101', label='SCMN', init_certificates=False)
        AS.objects.create(isd=isd17, as_id='ff00:0:1102', label='ETHZ', init_certificates=False)
        AS.objects.create(isd=isd17, as_id='ff00:0:1103', label='SWTH', init_certificates=False)
        AS.objects.create(isd=isd17, as_id='ff00:1:1', init_certificates=False)

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
    def test_create_coreas_with_keys(self):
        isd = ISD.objects.create(isd_id=17, label='Switzerland')
        as_ = AS.objects.create(isd=isd, as_id='ff00:0:1', is_core=True)
        utils.check_as_keys(self, as_)
        utils.check_as_core_keys(self, as_)
        utils.check_issuer_certs(self, as_)
        utils.check_as_certs(self, as_)

    def test_create_as_with_keys(self):
        isd = ISD.objects.create(isd_id=17, label='Switzerland')
        AS.objects.create(isd=isd, as_id='ff00:0:1', is_core=True)
        as_ = AS.objects.create(isd=isd, as_id='ff00:1:1')
        utils.check_as_keys(self, as_)
        utils.check_as_certs(self, as_)

    def test_create_as_with_default_services(self):
        isd = ISD.objects.create(isd_id=17, label='Switzerland')
        AS.objects.create(isd=isd, as_id='ff00:1:1', is_core=True)
        as_ = AS.objects.create_with_default_services(
            isd=isd,
            as_id='ff00:1:2',
            public_ip='192.0.2.11'
        )

        self.assertTrue(hasattr(as_, 'hosts'))
        self.assertEqual(as_.hosts.count(), 1)
        host = as_.hosts.first()
        self.assertEqual(host.internal_ip, "127.0.0.1")
        self.assertTrue(host.needs_config_deployment())

        self.assertTrue(hasattr(host, 'services'))
        self.assertEqual(sorted(s.type for s in host.services.iterator()), ['CS'])

        utils.check_as(self, as_)


class UpdateASKeysTests(TestCase):
    fixtures = ['testdata']

    def test_update_keys(self):
        Host.objects.reset_needs_config_deployment()

        as_ = AS.objects.first()

        prev_certificate = Certificate.objects.latest(Key.CP_AS, as_)

        as_.update_keys_certs()

        new_certificate = Certificate.objects.latest(Key.CP_AS, as_)

        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(as_.hosts.all())
        )
        self.assertEqual(new_certificate.version, prev_certificate.version + 1)

    def test_is_core_not_modified(self):
        # if the is_core property is not modified, do not expect new keys or certs.
        as_ = AS.objects.get(as_id='ffaa:0:1304')
        prev_certs = list(as_.certificates())
        prev_keys = list(as_.keys.all())
        as_.mtu = 800  # modify a property but not is_core
        as_.save()

        got_certs = list(as_.certificates().all())
        got_keys = list(as_.keys.all())
        self.assertEqual(got_certs, prev_certs)
        self.assertEqual(got_keys, prev_keys)

    def test_is_core_modification(self):
        as_ = AS.objects.get(as_id='ffaa:0:1304')
        # test sanity check: the fixture should have ffaa:0:1304 as non core.
        self.assertFalse(as_.is_core)

        prev_certs = list(as_.certificates())
        prev_keys = list(as_.keys.all())
        prev_trcs = list(as_.isd.trcs.all())
        prev_ifaces = as_.interfaces.all()
        prev_links = Link.objects.filter(
            models.Q(interfaceA__in=prev_ifaces) |
            models.Q(interfaceB__in=prev_ifaces))
        self.assertGreater(prev_links.count(), 0)
        prev_links = list(prev_links)
        prev_ifaces = list(prev_ifaces)

        # now promote AS 19-ffaa:0:1304 to core AS. We expect the following to happen:
        # - existing links starting or ending at that AS are removed.
        # - new keys and certificates are issued (as core) for that AS.
        # - all certificates in that ISD are reissued.
        # - the ISD issues a new TRC
        as_.mtu = 800
        as_.is_core = True
        as_.save()

        # Verify the previous links do not exist anymore.
        self.assertEqual(Link.objects.filter(pk__in=[
            link.pk for link in prev_links]).count(), 0)

        # Same with interfaces.
        self.assertEqual(Interface.objects.filter(pk__in=[
            iface.pk for iface in prev_ifaces]).count(), 0)

        # This AS doesn't have interfaces or links.
        got_ifaces = as_.interfaces.all()
        self.assertEqual(got_ifaces.count(), 0)
        got_links = Link.objects.filter(
            models.Q(interfaceA__in=got_ifaces) |
            models.Q(interfaceB__in=got_ifaces))
        self.assertEqual(got_links.count(), 0)

        # We have now more certificates and keys.
        got_certs = list(as_.certificates().all())
        self.assertTrue(set(prev_certs).issubset(got_certs))
        got_keys = list(as_.keys.all())
        self.assertTrue(set(prev_keys).issubset(got_keys))

        # We have a new TRC.
        got_trcs = list(as_.isd.trcs.all())
        self.assertTrue(set(prev_trcs).issubset(got_trcs))


class LinkModificationTests(TestCase):
    fixtures = []

    AS_SCMN = 'ffaa:0:1101'
    AS_ETHZ = 'ffaa:0:1102'
    AS_SWTH = 'ffaa:0:1103'

    def setUp(self):
        testtopo.create_isds()
        testtopo.create_ases()

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

        link = Link.objects.create_from_ases(Link.PROVIDER, as_a, as_b)
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
        link = Link.objects.create_from_ases(Link.PROVIDER, as_a, as_b)
        self._sanity_check_link(link)

        Host.objects.reset_needs_config_deployment()

        # Update public address: this affects local and remote interfaces
        link.interfaceA.update(public_ip='192.0.2.1', public_port=50000)
        self._sanity_check_link(link)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(as_a.hosts.all() | as_b.hosts.all())
        )
        Host.objects.reset_needs_config_deployment()

        # Update bind address: this is a local change
        # Note: interface bind_ip only effective because interface.public_ip has been set just above
        link.interfaceA.update(bind_ip='192.0.2.99')
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(as_a.hosts.all())
        )
        Host.objects.reset_needs_config_deployment()

        # change the link from A-B to A-C
        as_c = self._as_c()
        link.interfaceB.update(
            border_router=BorderRouter.objects.first_or_create(as_c.hosts.first())  # XXX
        )
        self._sanity_check_link(link)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(as_a.hosts.all() | as_b.hosts.all() | as_c.hosts.all())
        )

    def test_empty_border_router(self):
        as_a = self._as_a()
        as_b = self._as_b()
        self.assertEqual(as_b.border_routers.count(), 0)
        self.assertEqual(len([0 for _ in as_b.border_routers.iterator_non_empty()]), 0)
        link = Link.objects.create_from_ases(Link.PROVIDER, as_a, as_b)
        self.assertEqual(as_b.border_routers.count(), 1)
        self.assertEqual(len([0 for _ in as_b.border_routers.iterator_non_empty()]), 1)
        link.delete()
        self.assertEqual(as_b.border_routers.count(), 1)
        self.assertEqual(len([0 for _ in as_b.border_routers.iterator_non_empty()]), 0)

    def _sanity_check_link(self, link):
        self.assertIsNotNone(link)
        self.assertNotEqual(link.interfaceA, link.interfaceB)
        self._sanity_check_interface(link.interfaceA)
        self._sanity_check_interface(link.interfaceB)
        self.assertTrue(link.active)
        self.assertEqual(link.interfaceA.link(), link)
        self.assertEqual(link.interfaceB.link(), link)
        self.assertEqual(link.interfaceA.remote_interface(), link.interfaceB)
        self.assertEqual(link.interfaceB.remote_interface(), link.interfaceA)
        self.assertEqual(link.interfaceA.remote_as(), link.interfaceB.AS)
        self.assertEqual(link.interfaceB.remote_as(), link.interfaceA.AS)

    def _sanity_check_interface(self, interface):
        self.assertIsNotNone(interface)
        self.assertIsNotNone(interface.AS)
        self.assertIsNotNone(interface.host)
        self.assertEqual(interface.host.AS, interface.AS)
        self.assertTrue(1 <= interface.interface_id < 128)


class DeleteASTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        patcher = patch('scionlab.models.core.AS._post_delete',
                        side_effect=AS._post_delete,
                        autospec=True)
        self.mock_as_post_delete = patcher.start()
        self.addCleanup(patcher.stop)

    def test_delete_single_as(self):
        as_ = AS.objects.last()

        host_pks = [h.pk for h in as_.hosts.iterator()]
        interface_pks = [h.pk for h in as_.interfaces.iterator()]
        service_pks = [h.pk for h in as_.services.iterator()]
        # Check that we are testing something useful:
        self.assertGreater(len(host_pks), 0, msg="Uninteresting test data")
        self.assertGreater(len(interface_pks), 0, msg="Uninteresting test data")
        self.assertGreater(len(service_pks), 0, msg="Uninteresting test data")

        Host.objects.reset_needs_config_deployment()

        as_.delete()

        self.assertEqual(self.mock_as_post_delete.call_count, 1)

        # Check hosts have not been deleted and `needs_config_deployment`:
        for host_pk in host_pks:
            self.assertTrue(Host.objects.filter(pk=host_pk).exists())
            self.assertTrue(Host.objects.get(pk=host_pk).needs_config_deployment())

        # Check interfaces and service objects have been deleted
        for interface_pk in interface_pks:
            self.assertFalse(Interface.objects.filter(pk=interface_pk).exists())
        for service_pk in service_pks:
            self.assertFalse(Service.objects.filter(pk=service_pk).exists())

        utils.check_no_dangling_interfaces(self)

    def test_delete_bulk(self):
        ases = AS.objects.filter(is_core=False)
        ases_count = ases.count()
        self.assertGreater(ases_count, 0, msg="Uninteresting test data")

        ases.delete()

        self.assertEqual(self.mock_as_post_delete.call_count, ases_count)


class PortSchemeTests(TestCase):
    def setUp(self):
        isd17 = ISD.objects.create(isd_id=17, label='Switzerland')
        as_1101 = AS.objects.create(isd=isd17, as_id='ff00:0:1101', label='SCMN', is_core=True)
        as_1101.init_default_services()
        self.assertEqual(Host.objects.filter(AS=as_1101).count(), 1)
        self.host = Host.objects.first()

    def test_add_border_routers(self):
        # check service ports do not clash
        ports_in_use = {SD_TCP_PORT, SD_METRICS_PORT, DISPATCHER_PORT, DISPATCHER_METRICS_PORT}
        for srv in self.host.services.iterator():
            self.assertNotIn(srv.port, ports_in_use)
            ports_in_use.add(srv.port)
            if srv.metrics_port is not None:
                self.assertNotIn(srv.metrics_port, ports_in_use)
                ports_in_use.add(srv.metrics_port)

        # create a lot border routers. No port clash should occur.
        # Note that with the currently defined port ranges, we _will_ have clashes with more
        # routers.
        for i in range(40):
            br = BorderRouter.objects.create(host=self.host)
            self.assertNotIn(br.internal_port, ports_in_use)
            ports_in_use.add(br.internal_port)
            self.assertNotIn(br.metrics_port, ports_in_use)
            ports_in_use.add(br.metrics_port)


class CreateVPNTests(TestCase):
    def test_first_vpn(self):
        test = find_free_subnet(ipaddress.ip_network('10.10.0.0/16'), 24, {})
        self.assertEqual(str(test), "10.10.1.0/24")

    def test_second_vpn(self):
        test = find_free_subnet(ipaddress.ip_network('10.10.0.0/16'),
                                24,
                                {"10.10.1.0/24"})
        self.assertEqual(str(test), "10.10.2.0/24")

    def test_middle_vpn(self):
        test = find_free_subnet(ipaddress.ip_network('10.10.0.0/16'),
                                24,
                                {"10.10.1.0/24", "10.10.3.0/24"})
        self.assertEqual(str(test), "10.10.2.0/24")
