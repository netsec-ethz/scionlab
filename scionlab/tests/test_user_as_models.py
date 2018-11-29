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
)
from scionlab.fixtures import testtopo
from scionlab.fixtures.testuser import get_testuser
from scionlab.tests import utils


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

    public_port = 54321
    public_ip = '192.0.2.111'
    bind_port = 666
    bind_ip = '192.168.1.2'

    def setUp(self):
        Host.objects.reset_needs_config_deployment()
        _setup_vpn_attachment_point()

    @parameterized.expand(zip(range(AttachmentPoint.objects.count())))
    def test_create_public_ip(self, ap_index):
        label = 'foo_%s' % __name__
        installation_type = 'DEDICATED'
        attachment_point = AttachmentPoint.objects.all()[ap_index]
        user_as = UserAS.objects.create(
            owner=get_testuser(),
            attachment_point=attachment_point,
            installation_type=installation_type,
            label=label,
            use_vpn=False,
            public_ip=self.public_ip,
            public_port=self.public_port
        )

        # Check AS needs_config_deployment
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(user_as.hosts.all() | attachment_point.AS.hosts.all())
        )

        link = _get_provider_link(attachment_point.AS, user_as)
        self.assertEqual(link.interfaceA.get_public_ip(),
                         _get_public_ip_testtopo(attachment_point.AS.as_id))
        self.assertEqual(link.interfaceA.get_bind_ip(), None)
        # TODO(matzf): check port assignment (once this is implemented...)
        self.assertEqual(link.interfaceB.get_public_ip(), self.public_ip)
        self.assertEqual(link.interfaceB.public_port, self.public_port)
        self.assertEqual(link.interfaceB.get_bind_ip(), None)
        self.assertEqual(link.interfaceB.bind_port, None)

        self.assertEqual(user_as.label, label)
        self.assertEqual(user_as.installation_type, installation_type)
        self.assertEqual(user_as.attachment_point, attachment_point)

    def test_create_public_bind_ip(self):
        pass

    def test_create_vpn(self):
        pass


class UpdateUserASTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()
        _setup_vpn_attachment_point()

    # TODO(matzf): avoid duplication, add some helpers
    public_port = 54321
    public_ip = '192.0.2.111'
    bind_port = 666
    bind_ip = '192.168.1.2'

    def _create_user_as(self, attachment_point):
        installation_type = 'DEDICATED'
        return UserAS.objects.create(
            owner=get_testuser(),
            attachment_point=attachment_point,
            installation_type=installation_type,
            use_vpn=False,
            public_ip=self.public_ip,
            public_port=self.public_port
        )

    def test_enable_vpn(self):
        pass

    def test_cycle_vpn(self):
        # TODO(matzf): move to view tests?
        pass

    @parameterized.expand(zip(range(AttachmentPoint.objects.count())))
    def test_change_ap(self, ap_index):
        attachment_point_1 = AttachmentPoint.objects.all()[ap_index]
        user_as = self._create_user_as(attachment_point_1)

        attachment_point_2 = AttachmentPoint.objects.all()[(ap_index + 1) %
                                                           AttachmentPoint.objects.count()]
        user_as.update(
            attachment_point=attachment_point_2,
            label=user_as.label,
            installation_type=user_as.installation_type,
            use_vpn=False,
            public_ip=self.public_ip,
            public_port=self.public_port,
            bind_ip=None,
            bind_port=None,
        )

        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(user_as.hosts.all() |
                 attachment_point_1.AS.hosts.all() |
                 attachment_point_2.AS.hosts.all())
        )

        utils.check_topology(self)
        # TODO check links

    def test_cycle_ap(self):
        pass

    def test_cycle_ap_vpn(self):
        pass


class ActivateUserASTests(TestCase):
    def test_cycle_active(self):
        pass


class DeleteUserASTests(TestCase):
    def test_delete_single(self):
        pass

    def test_delete_user(self):
        pass
