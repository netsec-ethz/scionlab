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



def _create_and_check_useras(testcase,
                             attachment_point,
                             owner,
                             use_vpn,
                             public_ip=None,
                             public_port=None,
                             bind_ip=None,
                             bind_port=None,
                             installation_type=UserAS.DEDICATED,
                             label='label foo'):
    """
    Helper function for testing. Create a UserAS and verify that things look right.
    Set some defaults to reduce verbosity in tests.
    """
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

    testcase.assertEqual(user_as.owner, owner)
    testcase.assertEqual(user_as.label, label)
    testcase.assertEqual(user_as.installation_type, installation_type)
    testcase.assertEqual(user_as.attachment_point, attachment_point)
    testcase.assertEqual(user_as.is_use_vpn(), use_vpn)
    testcase.assertEqual(user_as.public_ip, public_ip)
    testcase.assertEqual(user_as.bind_ip, bind_ip)
    testcase.assertEqual(user_as.bind_port, bind_port)

    # Check AS needs_config_deployment:
    testcase.assertEqual(
        list(Host.objects.needs_config_deployment()),
        list(user_as.hosts.all() | attachment_point.AS.hosts.all())
    )

    link = _get_provider_link(attachment_point.AS, user_as)
    utils.check_link(testcase, link, utils.LinkDescription(
        type=Link.PROVIDER,
        from_as_id=attachment_point.AS.as_id,
        from_public_ip=_get_public_ip_testtopo(attachment_point.AS.as_id),
        from_bind_ip=None,
        to_public_ip=public_ip,
        to_public_port=public_port,
        to_bind_ip=bind_ip,
        to_bind_port=bind_port
    ))

    return user_as

# Some test data:
test_public_ip = '192.0.2.111'
test_public_port = 54321
test_bind_ip = '192.168.1.2'
test_bind_port = 6666


def _create_test_useras(testcase, seed, **kwargs):
    """

    """
    r = random.Random(seed)

    def _randbool():
        return r.choice((True, False))

    use_vpn = kwargs.setdefault('use_vpn', _randbool())
    candidate_APs = AttachmentPoint.objects.all()
    if use_vpn:
        candidate_APs = candidate_APs.filter(vpn__isnull=False)
    kwargs.setdefault('attachment_point', r.choice(candidate_APs))
    kwargs.setdefault('owner', get_testuser())
    if not use_vpn or _randbool():
        kwargs.setdefault('public_ip', '192.0.2.%i' % r.randint(10, 254))
        public_port_range = range(DEFAULT_PUBLIC_PORT, DEFAULT_PUBLIC_PORT + 20)
        kwargs.setdefault('public_port', r.choice(public_port_range))
    if _randbool():
        kwargs.setdefault('bind_ip', '192.168.1.%i' % r.randing(10, 254))
        bind_port_range = range(DEFAULT_PUBLIC_PORT + 1000, DEFAULT_PUBLIC_PORT + 1020)
        kwargs.setdefault('bind_port', r.choice(bind_port_range))
    kwargs.setdefault('installation_type', r.choice((UserAS.DEDICATED, UserAS.VM)))

    return _create_and_check_useras(testcase, **kwargs)


def _setup_vpn_attachment_point():
    """ Setup VPN for the first AP """
    # TODO(matzf): move to a fixture once the VPN stuff is somewhat stable
    ap = AttachmentPoint.objects.all()[0]
    ap.vpn = VPN.objects.create(server=ap.AS.hosts.first(),
                                subnet='10.0.8.0/8',
                                server_port=4321)
    ap.save()


def _get_provider_link(parent_as, child_as):
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
    asdef = next(a for a in testtopo.ases if a.as_id == as_id)
    return asdef.public_ip


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
        _setup_vpn_attachment_point()

    @parameterized.expand(zip(range(2)))
    def test_create_public_ip(self, ap_index):
        attachment_point = AttachmentPoint.objects.all()[ap_index]
        _create_and_check_useras(self,
                                 owner=get_testuser(),
                                 attachment_point=attachment_point,
                                 use_vpn=False,
                                 public_ip=test_public_ip,
                                 public_port=test_public_port)

    @parameterized.expand(zip(range(2)))
    def test_create_public_bind_ip(self, ap_index):
        attachment_point = AttachmentPoint.objects.all()[ap_index]
        _create_and_check_useras(self,
                                 owner=get_testuser(),
                                 attachment_point=attachment_point,
                                 use_vpn=False,
                                 public_ip=test_public_ip,
                                 public_port=test_public_port,
                                 bind_ip=test_bind_ip,
                                 bind_port=test_bind_port)

    def test_create_vpn(self):
        pass



class UpdateUserASTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()
        _setup_vpn_attachment_point()

    def test_enable_vpn(self):
        pass

    def test_cycle_vpn(self):
        # TODO(matzf): move to view tests?
        pass

    @parameterized.expand(zip(range(2)))
    def test_change_ap(self, ap_index):
        attachment_point_1 = AttachmentPoint.objects.all()[ap_index]
        user_as = _create_test_useras(self,
                                      seed=1,
                                      attachment_point=attachment_point_1,
                                      use_vpn=False)

        attachment_point_2 = AttachmentPoint.objects.all()[(ap_index + 1) %
                                                           AttachmentPoint.objects.count()]

        self._change_ap(user_as, attachment_point_2)

    def test_cycle_ap(self):
        pass

    def test_cycle_ap_vpn(self):
        pass

    def _change_ap(self, user_as, attachment_point):
        """ Helper: update UserAS, changing only the attachment point. """
        ap_old = user_as.attachment_point
        user_as.update(
            attachment_point=attachment_point,
            label=user_as.label,
            installation_type=user_as.installation_type,
            use_vpn=user_as.is_use_vpn(),
            public_ip=user_as.public_ip,
            public_port=user_as.get_public_port(),
            bind_ip=user_as.bind_ip,
            bind_port=user_as.bind_port,
        )
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(user_as.hosts.all() |
                 ap_old.AS.hosts.all() |
                 attachment_point.AS.hosts.all())
        )
        utils.check_topology(self)
        # TODO check links


class ActivateUserASTests(TestCase):
    def test_cycle_active(self):
        pass


class DeleteUserASTests(TestCase):
    def test_delete_single(self):
        pass

    def test_delete_user(self):
        pass
