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

import random
from unittest.mock import patch
from parameterized import parameterized
from django.test import TestCase
from scionlab.models import (
    AttachmentPoint,
    VPN,
    Host,
    UserAS,
    Link,
    USER_AS_ID_BEGIN,
    USER_AS_ID_END,
    DEFAULT_HOST_INTERNAL_IP,
    DEFAULT_PUBLIC_PORT,
)

from scionlab.fixtures import testtopo
from scionlab.fixtures.testuser import get_testuser
from scionlab.tests import utils
from scionlab.util.openvpn_config import write_vpn_ca_config

testtopo_num_attachment_points = sum(1 for as_def in testtopo.ases if as_def.is_ap)

# Some test data:
test_public_ip = '192.0.2.111'
test_public_port = 54321
test_bind_ip = '192.168.1.2'
test_bind_port = 6666


def setup_vpn_attachment_point(ap):
    """ Setup a VPN server config for the given attachment point """
    if VPN.objects.count() == 0:
        write_vpn_ca_config()
    # TODO(matzf): move to a fixture once the VPN stuff is somewhat stable
    ap.vpn = VPN.objects.create(server=ap.AS.hosts.first(),
                                subnet='10.0.8.0/24',
                                server_port=4321)
    ap.save()


def get_provider_link(parent_as, child_as):
    """
    Get the PROVIDER link from `parent_as` to `child_as`.
    :param AS parent_as: the AS on the parent side of the link
    :param AS child_as: the AS on the child side of the link
    :return: Link
    :raises: if none or more than one matching Link exists
    """
    return Link.objects.get(
        type=Link.PROVIDER,
        interfaceA__AS=parent_as,
        interfaceB__AS=child_as
    )


def _get_public_ip_testtopo(as_id):
    """
    Find the main IP for the AS from the testtopo-fixtures' metadata.
    :param str as_id: AS-id
    :return: str, ip
    """
    as_def = next(a for a in testtopo.ases if a.as_id == as_id)
    return as_def.public_ip


def create_and_check_useras(testcase,
                            attachment_point,
                            owner,
                            use_vpn,
                            public_port,
                            public_ip=None,
                            bind_ip=None,
                            bind_port=None,
                            installation_type=UserAS.DEDICATED,
                            label='label foo'):
    """
    Helper function for testing. Create a UserAS and verify that things look right.
    """
    hosts_pending_before = set(Host.objects.needs_config_deployment())

    user_as = UserAS.objects.create(
        owner=owner,
        attachment_point=attachment_point,
        installation_type=installation_type,
        label=label,
        use_vpn=use_vpn,
        public_ip=public_ip,
        public_port=public_port,
        bind_ip=bind_ip,
        bind_port=bind_port,
    )

    # Check AS needs_config_deployment:
    testcase.assertSetEqual(
        hosts_pending_before | set(user_as.hosts.all() | attachment_point.AS.hosts.all()),
        set(Host.objects.needs_config_deployment())
    )

    check_useras(testcase,
                 user_as,
                 attachment_point,
                 owner,
                 use_vpn,
                 public_ip,
                 public_port,
                 bind_ip,
                 bind_port,
                 installation_type,
                 label)

    return user_as


def check_useras(testcase,
                 user_as,
                 attachment_point,
                 owner,
                 use_vpn,
                 public_ip,
                 public_port,
                 bind_ip,
                 bind_port,
                 installation_type,
                 label):
    """
    Check the state of `user_as`. Verify that a link to the attachment point exists and
    that it is configured according to the given parameters.
    """
    testcase.assertEqual(user_as.owner, owner)
    testcase.assertEqual(user_as.label, label)
    testcase.assertEqual(user_as.installation_type, installation_type)
    testcase.assertEqual(user_as.attachment_point, attachment_point)
    testcase.assertEqual(user_as.is_use_vpn(), use_vpn)
    testcase.assertEqual(user_as.public_ip, public_ip)
    testcase.assertEqual(user_as.get_public_port(), public_port)
    testcase.assertEqual(user_as.bind_ip, bind_ip)
    testcase.assertEqual(user_as.bind_port, bind_port)

    utils.check_as(testcase, user_as)
    utils.check_as(testcase, attachment_point.AS)

    link = get_provider_link(attachment_point.AS, user_as)
    if use_vpn:
        utils.check_link(testcase, link, utils.LinkDescription(
            type=Link.PROVIDER,
            from_as_id=attachment_point.AS.as_id,
            from_public_ip=attachment_point.vpn.server_vpn_ip(),
            from_bind_ip=None,
            from_internal_ip=DEFAULT_HOST_INTERNAL_IP,
            to_public_ip=user_as.hosts.get().vpn_clients.get(active=True).ip,
            to_public_port=public_port,
            to_bind_ip=None,
            to_bind_port=None,
            to_internal_ip=DEFAULT_HOST_INTERNAL_IP,
        ))
    else:
        utils.check_link(testcase, link, utils.LinkDescription(
            type=Link.PROVIDER,
            from_as_id=attachment_point.AS.as_id,
            from_public_ip=_get_public_ip_testtopo(attachment_point.AS.as_id),
            from_bind_ip=None,
            from_internal_ip=DEFAULT_HOST_INTERNAL_IP,
            to_public_ip=public_ip,
            to_public_port=public_port,
            to_bind_ip=bind_ip,
            to_bind_port=bind_port,
            to_internal_ip=DEFAULT_HOST_INTERNAL_IP,
        ))


def update_useras(user_as, **kwargs):
    """
    Helper function for tests: update only the given parameters of a UserAS, leaving
    all others unchanged.
    Note: this logic could also be implemented in the actual UserAS.update function,
    but it seems preferable to keep the "production" logic lean, as this functionality
    only seems to be used here.
    """
    user_as.update(
        attachment_point=kwargs.get('attachment_point', user_as.attachment_point),
        label=kwargs.get('label', user_as.label),
        installation_type=kwargs.get('installation_type', user_as.installation_type),
        use_vpn=kwargs.get('use_vpn', user_as.is_use_vpn()),
        public_ip=kwargs.get('public_ip', user_as.public_ip),
        public_port=kwargs.get('public_port', user_as.get_public_port()),
        bind_ip=kwargs.get('bind_ip', user_as.bind_ip),
        bind_port=kwargs.get('bind_port', user_as.bind_port),
    )


def _get_random_useras_params(seed, force_public_ip=False, force_bind_ip=False, **kwargs):
    """
    Generate some "random" parameters for a UserAS based on `seed`.
    Any parameters to UserAS.objects.create can be specified to override the generated values.
    Note: overriding parameters may affect the generated value for other parameters.
    :returns: kwargs dict for UserAS.objects.create
    """
    r = random.Random(seed)

    def _randbool():
        return r.choice([True, False])

    use_vpn = kwargs.setdefault('use_vpn', _randbool())
    if use_vpn:
        candidate_APs = AttachmentPoint.objects.filter(vpn__isnull=False)
    else:
        candidate_APs = AttachmentPoint.objects.all()
    kwargs.setdefault('attachment_point', r.choice(candidate_APs))
    kwargs.setdefault('owner', get_testuser())

    public_ip = '192.0.2.%i' % r.randint(10, 254)
    public_port = r.choice(range(DEFAULT_PUBLIC_PORT, DEFAULT_PUBLIC_PORT + 20))
    if _randbool() or not use_vpn or force_public_ip:
        kwargs.setdefault('public_ip', public_ip)
    else:
        kwargs.setdefault('public_ip', None)
    kwargs.setdefault('public_port', public_port)

    bind_ip = '192.168.1.%i' % r.randint(10, 254)
    bind_port = r.choice(range(DEFAULT_PUBLIC_PORT + 1000, DEFAULT_PUBLIC_PORT + 1020))
    if _randbool() or force_bind_ip:
        kwargs.setdefault('bind_ip', bind_ip)
        kwargs.setdefault('bind_port', bind_port)
    else:
        kwargs.setdefault('bind_ip', None)
        kwargs.setdefault('bind_port', None)

    kwargs.setdefault('installation_type', r.choice((UserAS.DEDICATED, UserAS.VM)))
    randstr = r.getrandbits(1024).to_bytes(1024//8, 'little').decode('utf8', 'ignore')
    kwargs.setdefault('label', randstr)

    return kwargs


def create_random_useras(testcase, seed, **kwargs):
    """
    Create and check UserAS with "random" parameters based on `seed`.
    Any parameters to UserAS.objects.create can be specified to override the generated values.
    """
    return create_and_check_useras(testcase,
                                   **_get_random_useras_params(seed, **kwargs))


def check_random_useras(testcase, user_as, seed, **kwargs):
    """
    Check the state of a `user_as` based on the "random" parameters generated with `seed`.
    Any parameters to UserAS.objects.create can be specified to override the generated values.
    """
    check_useras(testcase, user_as, **_get_random_useras_params(seed, **kwargs))


class GenerateUserASIDTests(TestCase):
    def test_first(self):
        as_id_int = UserAS.objects.get_next_id()
        self.assertEqual(as_id_int, USER_AS_ID_BEGIN)

    @patch('scionlab.models.UserAS.objects._max_id', return_value=USER_AS_ID_BEGIN)
    def test_second(self, mock):
        as_id_int = UserAS.objects.get_next_id()
        self.assertEqual(as_id_int, USER_AS_ID_BEGIN+1)

    @patch('scionlab.models.UserAS.objects._max_id', return_value=USER_AS_ID_END-1)
    def test_last(self, mock):
        as_id_int = UserAS.objects.get_next_id()
        self.assertEqual(as_id_int, USER_AS_ID_END)

    @patch('scionlab.models.UserAS.objects._max_id', return_value=USER_AS_ID_END)
    def test_exhausted(self, mock):
        with self.assertRaises(RuntimeError):
            UserAS.objects.get_next_id()

    @patch('scionlab.models.UserAS.objects._max_id', return_value=1)
    def test_corrupted_max_id(self, mock):
        as_id_int = UserAS.objects.get_next_id()
        self.assertEqual(as_id_int, USER_AS_ID_BEGIN)


class CreateUserASTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()
        setup_vpn_attachment_point(AttachmentPoint.objects.first())

    @parameterized.expand(zip(range(testtopo_num_attachment_points)))
    def test_create_public_ip(self, ap_index):
        attachment_point = AttachmentPoint.objects.all()[ap_index]
        create_and_check_useras(self,
                                owner=get_testuser(),
                                attachment_point=attachment_point,
                                use_vpn=False,
                                public_ip=test_public_ip,
                                public_port=test_public_port)

    @parameterized.expand(zip(range(testtopo_num_attachment_points)))
    def test_create_public_bind_ip(self, ap_index):
        attachment_point = AttachmentPoint.objects.all()[ap_index]
        create_and_check_useras(self,
                                owner=get_testuser(),
                                attachment_point=attachment_point,
                                use_vpn=False,
                                public_ip=test_public_ip,
                                public_port=test_public_port,
                                bind_ip=test_bind_ip,
                                bind_port=test_bind_port)

    def test_create_vpn(self):
        attachment_point = AttachmentPoint.objects.get(vpn__isnull=False)
        create_and_check_useras(self,
                                owner=get_testuser(),
                                attachment_point=attachment_point,
                                use_vpn=True,
                                public_port=test_public_port)

    @patch('scionlab.models.User.max_num_ases', return_value=32)
    def test_create_mixed(self, mock):
        r = random.Random()
        r.seed(5)
        for i in range(0, 32):
            if r.choice([True, False]):     # pretend to deploy sometimes
                Host.objects.reset_needs_config_deployment()
            create_random_useras(self, seed=i)


class UpdateUserASTests(TestCase):
    # TODO(matzf): fixture currently only has two APs, should extend this a bit
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()
        setup_vpn_attachment_point(AttachmentPoint.objects.first())

    def test_enable_vpn(self):
        seed = 1
        attachment_point = AttachmentPoint.objects.get(vpn__isnull=False)
        user_as = create_random_useras(self,
                                       seed=seed,
                                       attachment_point=attachment_point,
                                       use_vpn=False)
        update_useras(user_as, use_vpn=True)
        check_random_useras(self,
                            user_as,
                            seed=seed,
                            attachment_point=attachment_point,
                            use_vpn=True,
                            force_public_ip=True)

    def test_disable_vpn(self):
        seed = 2
        attachment_point = AttachmentPoint.objects.get(vpn__isnull=False)
        user_as = create_random_useras(self,
                                       seed=seed,
                                       attachment_point=attachment_point,
                                       use_vpn=True)
        update_useras(user_as, use_vpn=False)
        check_random_useras(self,
                            user_as,
                            seed=seed,
                            attachment_point=attachment_point,
                            use_vpn=False)

    def test_cycle_vpn(self):
        seed = 3
        attachment_point = AttachmentPoint.objects.get(vpn__isnull=False)
        user_as = create_random_useras(self,
                                       seed=seed,
                                       attachment_point=attachment_point,
                                       use_vpn=True)

        vpn_client = user_as.hosts.get().vpn_clients.get()
        vpn_client_pk = vpn_client.pk
        vpn_client_ip = vpn_client.ip
        del vpn_client

        update_useras(user_as,
                      use_vpn=False,
                      public_ip=test_public_ip)
        check_random_useras(self,
                            user_as,
                            seed=seed,
                            attachment_point=attachment_point,
                            use_vpn=False,
                            public_ip=test_public_ip)

        # Sanity check: VPN client config still there, but inactive
        vpn_client = user_as.hosts.get().vpn_clients.get()
        self.assertEqual(vpn_client.pk, vpn_client_pk)
        self.assertFalse(vpn_client.active)
        del vpn_client

        update_useras(user_as,
                      use_vpn=True,
                      public_ip=None)
        check_random_useras(self,
                            user_as,
                            seed=seed,
                            attachment_point=attachment_point,
                            use_vpn=True)

        # Check VPN client IP has not changed:
        vpn_client = user_as.hosts.get().vpn_clients.get()
        self.assertEqual(vpn_client.pk, vpn_client_pk)
        self.assertTrue(vpn_client.active)
        self.assertEqual(vpn_client.ip, vpn_client_ip)

    @parameterized.expand(zip(range(testtopo_num_attachment_points)))
    def test_change_ap(self, ap_index):
        seed = 4
        attachment_points = list(AttachmentPoint.objects.all())
        user_as = create_random_useras(self,
                                       seed=seed,
                                       attachment_point=attachment_points[ap_index],
                                       use_vpn=False)

        other_ap_index = (ap_index + 1) % testtopo_num_attachment_points
        self._change_ap(user_as, attachment_points[other_ap_index])

        check_random_useras(self,
                            user_as,
                            seed=seed,
                            attachment_point=attachment_points[other_ap_index],
                            use_vpn=False)

    def test_cycle_ap(self):
        seed = 5
        attachment_point_iter = iter(list(AttachmentPoint.objects.all()) * 2)

        user_as = create_random_useras(self,
                                       seed=seed,
                                       attachment_point=next(attachment_point_iter),
                                       use_vpn=False)

        for attachment_point in attachment_point_iter:
            self._change_ap(user_as, attachment_point)
            check_random_useras(self,
                                user_as,
                                seed=seed,
                                attachment_point=attachment_point,
                                use_vpn=False)

    def test_cycle_ap_vpn(self):
        seed = 6
        for ap in AttachmentPoint.objects.filter(vpn__isnull=True).iterator():
            setup_vpn_attachment_point(ap)

        attachment_point_iter = iter(list(AttachmentPoint.objects.all()) * 2)
        attachment_point = next(attachment_point_iter)
        user_as = create_random_useras(self,
                                       seed=seed,
                                       attachment_point=attachment_point,
                                       use_vpn=True)
        # record per attachment point VPN info to verify IP/keys don't change
        vpn_client = user_as.hosts.get().vpn_clients.get(active=True)
        vpn_client_infos = {attachment_point.pk: (vpn_client.pk, vpn_client.ip)}
        del vpn_client, attachment_point

        for attachment_point in attachment_point_iter:
            self._change_ap(user_as, attachment_point)
            check_random_useras(self,
                                user_as,
                                seed=seed,
                                attachment_point=attachment_point,
                                use_vpn=True)
            vpn_client = user_as.hosts.get().vpn_clients.get(active=True)
            vpn_client_info = (vpn_client.pk, vpn_client.ip)
            expected = vpn_client_infos.get(attachment_point.pk)
            if expected:
                self.assertEqual(expected, vpn_client_info)
            else:
                vpn_client_infos[attachment_point.pk] = vpn_client_info

    def _change_ap(self, user_as, attachment_point):
        """ Helper: update UserAS, changing only the attachment point. """

        prev_ap = user_as.attachment_point
        prev_certificate_chain = user_as.certificate_chain
        hosts_pending_before = set(Host.objects.needs_config_deployment())

        update_useras(user_as, attachment_point=attachment_point)

        # Check needs_config_deployment: hosts of UserAS and both APs
        self.assertSetEqual(
            hosts_pending_before | set(
                user_as.hosts.all() |
                prev_ap.AS.hosts.all() |
                attachment_point.AS.hosts.all()
            ),
            set(Host.objects.needs_config_deployment())
        )

        # Check certificates reset if ISD changed
        if prev_ap.AS.isd != attachment_point.AS.isd:
            prev_version = prev_certificate_chain['0']['Version']
            curr_version = user_as.certificate_chain['0']['Version']
            self.assertEqual(
                curr_version,
                prev_version + 1,
                ("Certificate needs to be recreated on ISD change: "
                 "ISD before: %s, ISD after:%s" % (prev_ap.AS.isd, attachment_point.AS.isd))
            )
        else:
            self.assertEqual(prev_certificate_chain, user_as.certificate_chain)

        utils.check_topology(self)


class ActivateUserASTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()

        setup_vpn_attachment_point(AttachmentPoint.objects.first())

    def test_cycle_active(self):
        seed = 123
        user_as = create_random_useras(self, seed=seed)

        user_as.set_active(False)

        uplink = Link.objects.get(interfaceB__AS=user_as)
        self.assertFalse(uplink.active)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(user_as.hosts.all() |
                 user_as.attachment_point.AS.hosts.all())
        )

        user_as.set_active(True)

        uplink = Link.objects.get(interfaceB__AS=user_as)
        self.assertTrue(uplink.active)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(user_as.hosts.all() |
                 user_as.attachment_point.AS.hosts.all())
        )

        check_random_useras(self, user_as, seed=seed)


class DeleteUserASTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()
        setup_vpn_attachment_point(AttachmentPoint.objects.first())

    def test_delete_single(self):
        seed = 456
        user_as = create_random_useras(self, seed=seed)
        user_as_hosts = list(user_as.hosts.all())
        attachment_point = user_as.attachment_point

        user_as.delete()

        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            sorted(user_as_hosts + list(attachment_point.AS.hosts.all()),
                   key=lambda host: host.pk)
        )

        utils.check_topology(self)

    def test_delete_user(self):
        testuser = get_testuser()
        user_as_pks = []
        user_as_hosts = []
        attachment_point_hosts = set()
        for i in range(testuser.max_num_ases()):
            seed = 789 + i
            user_as = create_random_useras(self, seed=seed)
            user_as_pks.append(user_as.pk)
            user_as_hosts += list(user_as.hosts.all())
            attachment_point_hosts |= set(user_as.attachment_point.AS.hosts.all())

        testuser.delete()

        for user_as_pk in user_as_pks:
            self.assertFalse(UserAS.objects.filter(pk=user_as_pk).exists())

        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            sorted(user_as_hosts + list(attachment_point_hosts),
                   key=lambda host: host.pk)
        )

        utils.check_topology(self)
