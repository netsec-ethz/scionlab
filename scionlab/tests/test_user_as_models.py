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
from enum import Enum
from collections import namedtuple
from typing import List, Dict
from itertools import combinations, chain
from ipaddress import ip_address, ip_network
from unittest.mock import patch
from parameterized import parameterized
from django.test import TestCase
from scionlab.models.core import Host, Link, ISD, AS
from scionlab.models.user_as import AttachmentPoint, AttachmentPointConf, UserAS, \
    _VAGRANT_VM_LOCAL_IP
from scionlab.models.vpn import VPN, VPNClient
from scionlab.defines import (
    USER_AS_ID_BEGIN,
    USER_AS_ID_END,
    DEFAULT_HOST_INTERNAL_IP,
    DEFAULT_PUBLIC_PORT,
)

from scionlab.fixtures import testtopo
from scionlab.fixtures.testuser import get_testuser
from scionlab.tests import utils
from scionlab.util import as_ids
from scionlab.openvpn_config import write_vpn_ca_config

testtopo_num_attachment_points = sum(1 for as_def in testtopo.ases if as_def.is_ap)


class VPNChoice(Enum):
    """
    Enum to instruct the params generator to create attachments with only VPNs (ALL),
    some VPNs chosen at random (SOME), or no VPNs at all (NONE)
    """
    ALL = 0
    SOME = 1
    NONE = 2


# Some test data:
test_public_ip = '172.31.0.111'
test_public_port = 54321
test_bind_ip = '192.168.1.2'
test_bind_port = 6666


def _randbool(r: random.Random):
    return r.choice([True, False])


def setup_vpn_attachment_point(ap):
    """ Setup a VPN server config for the given attachment point """
    if VPN.objects.count() == 0:
        write_vpn_ca_config()
    # TODO(matzf): move to a fixture once the VPN stuff is somewhat stable
    ap.vpn = VPN.objects.create(server=ap.AS.hosts.first(),
                                subnet='10.0.8.0/24',
                                server_vpn_ip='10.0.8.1',
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
                            seed,
                            aps_conf: List[AttachmentPointConf],
                            vpn_choice: VPNChoice,
                            owner, public_ip=None,
                            bind_ip=None,
                            installation_type=UserAS.DEDICATED,
                            label='label foo'):
    """
    Helper function for testing. Create a UserAS, attach it to the attachment_points as
    specified in aps_conf, and verify that things look right.
    """
    hosts_pending_before = set(Host.objects.needs_config_deployment())
    with patch.object(AttachmentPoint, 'trigger_deployment', autospec=True) as mock_deploy:
        isd = aps_conf[0].attachment_point.AS.isd
        user_as = UserAS.objects.create(
            owner,
            installation_type,
            isd,
            label=label,
            public_ip=public_ip,
            bind_ip=bind_ip
        )
        for ap_conf in aps_conf:
            link = user_as.create_attachment(ap_conf.attachment_point,
                                             ap_conf.public_port,
                                             public_ip=ap_conf.public_ip,
                                             use_vpn=ap_conf.use_vpn,
                                             bind_ip=ap_conf.bind_ip,
                                             bind_port=ap_conf.bind_port)
            ap_conf.link = link

    # Check AS needs_config_deployment:
    aps_hosts = []
    attachment_points = [c.attachment_point for c in aps_conf]
    for ap in attachment_points:
        aps_hosts += ap.AS.hosts.all()
    testcase.assertSetEqual(
        hosts_pending_before | set(user_as.hosts.all()) | set(aps_hosts),
        set(Host.objects.needs_config_deployment())
    )

    # Check that deployment was triggered for the attachment point.
    testcase.assertEqual(
        [args[0] for args, kwargs in mock_deploy.call_args_list],
        attachment_points
    )

    check_useras(testcase,
                 user_as,
                 aps_conf,
                 owner,
                 vpn_choice,
                 public_ip,
                 #  public_port,
                 bind_ip,
                 #  bind_port,
                 installation_type,
                 label)

    return user_as


def check_useras(testcase,
                 user_as,
                 aps_conf,
                 owner,
                 vpn_choice,
                 public_ip,
                 bind_ip,
                 installation_type,
                 label):
    """
    Check the state of `user_as` and `aps_conf`.
    Verify that a link to the attachment point exists and that it is configured according to the
    given parameters.
    """
    testcase.assertEqual(user_as.owner, owner)
    testcase.assertEqual(user_as.label, label)
    testcase.assertEqual(user_as.installation_type, installation_type)
    testcase.assertEqual(user_as.host.public_ip, public_ip)
    # NOTE: @same_in_master `bind_ip' depends on the `installation_type'
    bind_ip = _VAGRANT_VM_LOCAL_IP if user_as.installation_type == UserAS.VM else bind_ip
    testcase.assertEqual(user_as.host.bind_ip, bind_ip)
    utils.check_as(testcase, user_as)

    # TODO:(andrea_tulimiero) Clean this section
    aps_as_pk = list(map(lambda c: c.attachment_point.AS.pk, aps_conf))
    aps_conf_dict = {c.attachment_point: c for c in aps_conf}
    # Check all AttachmentPoints are actually AttachmentPoints of the userAS
    user_as_aps_as_pk = list(
        Link.objects.filter(interfaceB__AS=user_as).values_list('interfaceA__AS', flat=True))
    testcase.assertEqual(user_as_aps_as_pk, aps_as_pk)
    for pk in user_as_aps_as_pk:
        attachment_point = AS.objects.get(pk=pk).attachment_point_info
        ap_conf = aps_conf_dict[attachment_point]
        _check_attachment_point(testcase, attachment_point)
        utils.check_as(testcase, attachment_point.AS)
        link = Link.objects.get(interfaceA__AS=attachment_point.AS, interfaceB__AS=user_as)
        testcase.assertEqual(ap_conf.public_port, link.interfaceB.public_port)

        if ap_conf.use_vpn:
            testcase.assertTrue(VPNClient.objects.filter(host=user_as.host,
                                                         vpn=ap_conf.attachment_point.vpn
                                                         ).exists())
            utils.check_link(testcase, link, utils.LinkDescription(
                type=Link.PROVIDER,
                from_as_id=attachment_point.AS.as_id,
                from_public_ip=attachment_point.vpn.server_vpn_ip,
                from_bind_ip=None,
                from_internal_ip=DEFAULT_HOST_INTERNAL_IP,
                to_public_ip=user_as.hosts.get().vpn_clients.get(active=True).ip,
                to_public_port=ap_conf.public_port,
                to_bind_ip=None,
                to_bind_port=None,
                to_internal_ip=DEFAULT_HOST_INTERNAL_IP,
            ))
        else:
            testcase.assertFalse(VPNClient.objects.filter(host=user_as.host,
                                                          vpn=ap_conf.attachment_point.vpn
                                                          ).exists())
            overridden_bind_ip = ap_conf.bind_ip
            if installation_type == UserAS.VM:
                overridden_bind_ip = '10.0.2.15'
            overridden_bind_port = ap_conf.bind_port
            if overridden_bind_ip:
                overridden_bind_port = ap_conf.bind_port or ap_conf.public_port

            utils.check_link(testcase, link, utils.LinkDescription(
                type=Link.PROVIDER,
                from_as_id=attachment_point.AS.as_id,
                from_public_ip=_get_public_ip_testtopo(attachment_point.AS.as_id),
                from_bind_ip=None,
                from_internal_ip=DEFAULT_HOST_INTERNAL_IP,
                to_public_ip=ap_conf.public_ip,
                to_public_port=ap_conf.public_port,
                to_bind_ip=overridden_bind_ip,
                to_bind_port=overridden_bind_port,
                to_internal_ip=DEFAULT_HOST_INTERNAL_IP,
            ))


def _check_attachment_point(testcase, attachment_point):
    """
    Check the assignment of interfaces to border routers in the attachment point.
    """

    host = attachment_point._get_host_for_useras_attachment()
    border_routers = list(host.border_routers.all())

    # The first BR is for the infrastructure links and also contains the inactive interfaces.
    infra_br = border_routers.pop(0)
    for iface in infra_br.interfaces.iterator():
        testcase.assertTrue(iface.remote_as().owner is None or not iface.link().active)

    # The other BRs contain up to 10 interfaces each.
    MAX_IFACES = 10
    for br in border_routers:
        # Expecting only active interfaces in these BRs
        testcase.assertTrue(all(interface.link().active for interface in br.interfaces.iterator()))
        c = br.interfaces.count()
        if br == border_routers[-1]:  # only last one can have less than max
            testcase.assertLessEqual(c, MAX_IFACES)
        else:
            testcase.assertEqual(c, MAX_IFACES)


def update_useras(testcase, user_as, aps_conf, **kwargs):
    """
    Helper function for tests: update only the given parameters of a UserAS, leaving
    all others unchanged.
    Note: this logic could also be implemented in the actual UserAS.update function,
    but it seems preferable to keep the "production" logic lean, as this functionality
    only seems to be used here.
    """
    with patch.object(AttachmentPoint, 'trigger_deployment', autospec=True) as mock_deploy:
        user_as.update(
            #  attachment_point=kwargs.get('attachment_point', user_as.attachment_point),
            label=kwargs.get('label', user_as.label),
            installation_type=kwargs.get('installation_type', user_as.installation_type),
            #  use_vpn=kwargs.get('use_vpn', user_as.is_use_vpn()),
            public_ip=kwargs.get('public_ip', user_as.host.public_ip),
            #  public_port=kwargs.get('public_port', user_as.get_public_port()),
            bind_ip=kwargs.get('bind_ip', user_as.host.bind_ip),
            #  bind_port=kwargs.get('bind_port', user_as.bind_port),
        )
        for ap_conf in aps_conf:
            if ap_conf.link:
                user_as.update_attachment(ap_conf.link,
                                          ap_conf.active,
                                          ap_conf.public_port,
                                          ap_conf.public_ip,
                                          ap_conf.use_vpn,
                                          ap_conf.bind_ip,
                                          ap_conf.bind_port)
            else:
                user_as.create_attachment(ap_conf.attachment_point,
                                          ap_conf.public_port,
                                          public_ip=ap_conf.public_ip,
                                          use_vpn=ap_conf.use_vpn,
                                          bind_ip=ap_conf.bind_ip,
                                          bind_port=ap_conf.bind_port)

    # Check that deployment was triggered once for each of the attachment points.
    testcase.assertEqual(
        sorted((args[0] for args, kwargs in mock_deploy.call_args_list), key=id),
        sorted(set(AttachmentPointConf.attachment_points(aps_conf)), key=id)
    )


def _get_random_aps_params(seed,
                           attachment_points: List[AttachmentPoint],
                           vpn_choice: VPNChoice,
                           force_public_ip=False,
                           force_bind_ip=False) -> List[AttachmentPointConf]:
    """
    Generate random compatible parameters for the given AttachmentPoints based on `seed`.
    """
    r = random.Random(seed)
    aps_confs = []
    used_public_ip_port_pairs = set()
    used_bind_ip_port_pairs = set()
    for ap in attachment_points:
        ap_conf_dict = {}
        ap_conf_dict['attachment_point'] = ap
        if vpn_choice in (VPNChoice.NONE, VPNChoice.ALL):
            ap_conf_dict['use_vpn'] = False if vpn_choice is VPNChoice.NONE else True
        else:
            if not ap.vpn:
                ap_conf_dict['use_vpn'] = False
            else:
                ap_conf_dict['use_vpn'] = _randbool(r)
        while True:
            public_ip = '172.31.0.%i' % r.randint(10, 254)
            public_port = r.choice(range(DEFAULT_PUBLIC_PORT, DEFAULT_PUBLIC_PORT + 20))
            if (public_ip, public_port) not in used_public_ip_port_pairs:
                break
        if _randbool(r) or vpn_choice is not VPNChoice.ALL or force_public_ip:
            ap_conf_dict['public_ip'] = public_ip
        else:
            ap_conf_dict['public_ip'] = None
        ap_conf_dict['public_port'] = public_port

        while True:
            bind_ip = '192.168.1.%i' % r.randint(10, 254)
            bind_port = r.choice(range(DEFAULT_PUBLIC_PORT + 1000, DEFAULT_PUBLIC_PORT + 1020))
            if (bind_ip, bind_port) not in used_bind_ip_port_pairs:
                break
        if _randbool(r) or force_bind_ip:
            ap_conf_dict['bind_ip'] = bind_ip
            ap_conf_dict['bind_port'] = bind_port
        else:
            ap_conf_dict['bind_ip'] = None
            ap_conf_dict['bind_port'] = None
        aps_confs.append(AttachmentPointConf(**ap_conf_dict))

    return aps_confs


def _get_random_useras_params(seed, vpn_choice, force_public_ip=False, force_bind_ip=False,
                              **kwargs):
    """
    Generate some "random" parameters for a UserAS based on `seed`.
    Any parameters to UserAS.objects.create can be specified to override the generated values.
    Note: overriding parameters may affect the generated value for other parameters.
    :returns: kwargs dict for UserAS.objects.create
    """
    r = random.Random(seed)

    #  use_vpn = kwargs.setdefault('use_vpn', _randbool(r))
    #  if use_vpn:
    #  candidate_APs = AttachmentPoint.objects.filter(vpn__isnull=False)
    #  else:
    #  candidate_APs = AttachmentPoint.objects.all()
    #  kwargs.setdefault('attachment_point', r.choice(candidate_APs))
    kwargs.setdefault('owner', get_testuser())

    public_ip = '172.31.0.%i' % r.randint(10, 254)
    #  public_port = r.choice(range(DEFAULT_PUBLIC_PORT, DEFAULT_PUBLIC_PORT + 20))
    if _randbool(r) or vpn_choice is not VPNChoice.ALL or force_public_ip:
        kwargs.setdefault('public_ip', public_ip)
    else:
        kwargs.setdefault('public_ip', None)
    #  kwargs.setdefault('public_port', public_port)

    bind_ip = '192.168.1.%i' % r.randint(10, 254)
    #  bind_port = r.choice(range(DEFAULT_PUBLIC_PORT + 1000, DEFAULT_PUBLIC_PORT + 1020))
    if _randbool(r) or force_bind_ip:
        kwargs.setdefault('bind_ip', bind_ip)
        #  kwargs.setdefault('bind_port', bind_port)
    else:
        kwargs.setdefault('bind_ip', None)
        #  kwargs.setdefault('bind_port', None)

    kwargs.setdefault('installation_type', r.choice((UserAS.DEDICATED, UserAS.VM)))
    randstr = r.getrandbits(1024).to_bytes(1024 // 8, 'little').decode('utf8', 'ignore')
    kwargs.setdefault('label', randstr)

    return kwargs


def create_random_useras(testcase, seed, attachment_points, vpn_choice, **kwargs):
    """
    Create and check UserAS with "random" parameters based on `seed`.
    Any parameters to UserAS.objects.create can be specified to override the generated values.
    """
    aps_conf = _get_random_aps_params(seed, attachment_points, vpn_choice)
    return create_and_check_useras(testcase,
                                   seed,
                                   aps_conf,
                                   vpn_choice,
                                   **_get_random_useras_params(seed, vpn_choice, **kwargs))


def check_random_useras(testcase, seed, user_as, aps_conf, vpn_choice, **kwargs):
    """
    Check the state of a `user_as` based on the "random" parameters generated with `seed`.
    Any parameters to UserAS.objects.create can be specified to override the generated values.
    :param TestCase testcase:
    :param int seed:
    :param UserAS user_as:
    :param List[AttachmentPointConf] aps_conf:
    :param User owner:
    :param VPNChoice vpn_choice:
    """
    check_useras(testcase=testcase, user_as=user_as, aps_conf=aps_conf,
                 vpn_choice=vpn_choice,
                 **_get_random_useras_params(seed, vpn_choice, **kwargs))


class GenerateUserASIDTests(TestCase):
    def test_first(self):
        as_id_int = UserAS.objects.get_next_id()
        self.assertEqual(as_id_int, USER_AS_ID_BEGIN)
        self.assertEqual(as_ids.format(as_id_int), 'ffaa:1:1')

    @patch('scionlab.models.user_as.UserAS.objects._max_id', return_value=USER_AS_ID_BEGIN)
    def test_second(self, mock):
        as_id_int = UserAS.objects.get_next_id()
        self.assertEqual(as_id_int, USER_AS_ID_BEGIN + 1)

    @patch('scionlab.models.user_as.UserAS.objects._max_id', return_value=USER_AS_ID_END - 1)
    def test_last(self, mock):
        as_id_int = UserAS.objects.get_next_id()
        self.assertEqual(as_id_int, USER_AS_ID_END)

    @patch('scionlab.models.user_as.UserAS.objects._max_id', return_value=USER_AS_ID_END)
    def test_exhausted(self, mock):
        with self.assertRaises(RuntimeError):
            UserAS.objects.get_next_id()

    @patch('scionlab.models.user_as.UserAS.objects._max_id', return_value=1)
    def test_corrupted_max_id(self, mock):
        as_id_int = UserAS.objects.get_next_id()
        self.assertEqual(as_id_int, USER_AS_ID_BEGIN)


class VPNServerTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def test_create_new(self):
        ap = AttachmentPoint.objects.first()
        prev_version = ap.AS.hosts.first().config_version
        setup_vpn_attachment_point(ap)
        self.assertGreater(ap.AS.hosts.first().config_version, prev_version)
        self.assertEqual(ap.vpn.server, ap.AS.hosts.first())

    def test_update_vpn(self):
        ap = AttachmentPoint.objects.first()
        setup_vpn_attachment_point(ap)
        server = ap.vpn.server
        prev_version = server.config_version
        ap.vpn.update(subnet='10.0.8.0/22')
        self.assertGreater(server.config_version, prev_version)

    def test_change_vpn_server(self):
        ap = AttachmentPoint.objects.first()
        setup_vpn_attachment_point(ap)
        old_server = ap.vpn.server
        old_server_prev_version = old_server.config_version
        new_server = Host.objects.create()
        self.assertNotEqual(new_server, old_server)
        new_server_prev_version = new_server.config_version
        ap.vpn.update(server=new_server)
        self.assertGreater(old_server.config_version, old_server_prev_version)
        self.assertGreater(new_server.config_version, new_server_prev_version)


def get_all_random_as_defs(has_vpn=False, seed=1) -> List[List[AttachmentPoint]]:
    """
    Generates a list of lists of AttachmentPoints.
    For each ISD sample an AttachmentPoint as a list composed of a single element, 
    and if there are more than one AttachmentPoint in the said ISD, sample a list
    of at least 2 elements
    :param bool has_vpn: use only VPN capable AttachmentPoints
    :param int seed:
    :return List[List[AttachmentPoint]]:
    """
    r = random.Random(seed)
    as_per_isd = {}
    as_choice = []
    for as_def in filter(lambda as_def: as_def.is_ap, testtopo.ases):
        as_per_isd.setdefault(as_def.isd_id, [])
        as_per_isd[as_def.isd_id].append(as_def)
    for isd, as_def in as_per_isd.items():
        if has_vpn:
            raise NotImplementedError()
        if not as_def:
            continue
        as_len = len(as_def)
        # Get a random ap
        random_ap = as_def[r.randrange(0, as_len)]
        as_choice.append([random_ap])
        # If there are more than a single ap for the current ISD, get at least
        # two aps for this ISD
        if as_len >= 2:
            random_aps = r.sample(as_def, r.randint(2, as_len))
            as_choice.append(random_aps)
    return as_choice


def as_defs2aps(ASes_def):
    """
    Returns a list of attachment points from a list of AS definitions
    :param List[Asdef] ASes_def:
    :return List[AttachmentPoint]:
    """
    return [AttachmentPoint.objects.get(AS__as_id=AS.as_id) for AS in ASes_def]


class CreateUserASTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        setup_vpn_attachment_point(AttachmentPoint.objects.first())
        Host.objects.reset_needs_config_deployment()

    @parameterized.expand(zip(get_all_random_as_defs()))
    def test_create_public_ip(self, ASes_def):
        seed = 1
        attachment_points = as_defs2aps(ASes_def)
        vpn_choice = VPNChoice.NONE
        aps_conf = _get_random_aps_params(seed, attachment_points, vpn_choice)
        create_and_check_useras(self,
                                seed,
                                aps_conf=aps_conf,
                                vpn_choice=vpn_choice,
                                owner=get_testuser(),
                                public_ip=test_public_ip)

    @parameterized.expand(zip(get_all_random_as_defs()))
    def test_create_public_bind_ip(self, ASes_def):
        seed = 1
        attachment_points = as_defs2aps(ASes_def)
        vpn_choice = VPNChoice.NONE
        aps_conf = _get_random_aps_params(seed, attachment_points, vpn_choice)
        create_and_check_useras(self,
                                seed,
                                aps_conf=aps_conf,
                                vpn_choice=vpn_choice,
                                owner=get_testuser(),
                                public_ip=test_public_ip,
                                bind_ip=test_bind_ip)

    def test_create_vpn(self):
        attachment_points = [AttachmentPoint.objects.filter(vpn__isnull=False).first()]
        seed = 1
        vpn_choice = VPNChoice.NONE
        aps_conf = _get_random_aps_params(seed, attachment_points, vpn_choice)
        create_and_check_useras(self,
                                seed,
                                aps_conf=aps_conf,
                                vpn_choice=vpn_choice,
                                owner=get_testuser())

    @patch('scionlab.models.user.User.max_num_ases', return_value=32)
    def test_create_mixed(self, mock):
        r = random.Random()
        r.seed(5)
        all_attachment_points = [as_defs2aps(ASes_def_list)
                                 for ASes_def_list in get_all_random_as_defs()]
        for i in range(0, 32):
            if r.choice([True, False]):  # pretend to deploy sometimes
                Host.objects.reset_needs_config_deployment()
            attachment_points = r.choice(all_attachment_points)
            create_random_useras(self, i, attachment_points, VPNChoice.SOME)

    def test_server_vpn_ip(self):
        """ Its IP is not at the beginning of the subnet """
        seed = 1
        attachment_point = AttachmentPoint.objects.filter(vpn__isnull=False).first()
        vpn_choice = VPNChoice.ALL
        aps_conf = _get_random_aps_params(seed, [attachment_point], vpn_choice)
        vpn = attachment_point.vpn
        server_orig_ip = ip_address(vpn.server_vpn_ip)
        vpn.server_vpn_ip = str(server_orig_ip + 1)
        vpn.save()
        # create two clients and check their IP addresses
        c1 = create_and_check_useras(self,
                                     seed,
                                     aps_conf=aps_conf,
                                     vpn_choice=vpn_choice,
                                     owner=get_testuser()).hosts.get().vpn_clients.get()
        c2 = create_and_check_useras(self,
                                     seed,
                                     aps_conf=aps_conf,
                                     vpn_choice=vpn_choice,
                                     owner=get_testuser()).hosts.get().vpn_clients.get()
        ip1 = ip_address(c1.ip)
        ip2 = ip_address(c2.ip)
        self.assertEqual(ip1, server_orig_ip)
        self.assertEqual(ip2, ip_address(vpn.server_vpn_ip) + 1)

    @patch('scionlab.models.user.User.max_num_ases', return_value=2 ** 16)
    def test_exhaust_vpn_clients(self, _):
        seed = 1
        attachment_point = AttachmentPoint.objects.filter(vpn__isnull=False).first()
        vpn = attachment_point.vpn
        vpn.subnet = '10.0.8.0/28'
        vpn.server_vpn_ip = '10.0.8.10'
        vpn.save()
        vpn_choice = VPNChoice.ALL
        subnet = ip_network(vpn.subnet)
        used_ips = list()
        it = subnet.hosts()
        next(it)  # skip one for the server
        aps_conf = _get_random_aps_params(seed, [attachment_point], vpn_choice)
        for i in it:
            a = create_and_check_useras(self,
                                        seed,
                                        aps_conf=aps_conf,
                                        vpn_choice=vpn_choice,
                                        owner=get_testuser())
            used_ips.append(ip_address(a.hosts.get().vpn_clients.get().ip))
        self.assertEqual(len(used_ips), 13)  # 16 - network, broadcast and server addrs
        used_ips_set = set(used_ips)
        self.assertEqual(len(used_ips), len(used_ips_set))
        self.assertNotIn(ip_address(vpn.server_vpn_ip), used_ips_set)
        for ip in used_ips:
            self.assertIn(ip, subnet)
        # one too many:
        with self.assertRaises(RuntimeError):
            a = create_and_check_useras(self,
                                        seed,
                                        aps_conf=aps_conf,
                                        vpn_choice=vpn_choice,
                                        owner=get_testuser())


class UpdateUserASTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        setup_vpn_attachment_point(AttachmentPoint.objects.first())
        Host.objects.reset_needs_config_deployment()

    def test_enable_vpn(self):
        seed = 1
        attachment_point = AttachmentPoint.objects.filter(vpn__isnull=False).first()
        user_as = create_random_useras(self,
                                       seed=seed,
                                       attachment_point=attachment_point,
                                       use_vpn=False)
        update_useras(self, user_as, use_vpn=True)
        check_random_useras(self,
                            user_as,
                            seed=seed,
                            attachment_point=attachment_point,
                            use_vpn=True,
                            force_public_ip=True)

    def test_disable_vpn(self):
        seed = 2
        attachment_point = AttachmentPoint.objects.filter(vpn__isnull=False).first()
        user_as = create_random_useras(self,
                                       seed=seed,
                                       attachment_point=attachment_point,
                                       use_vpn=True,
                                       force_public_ip=True)
        update_useras(self, user_as, use_vpn=False)
        check_random_useras(self,
                            user_as,
                            seed=seed,
                            attachment_point=attachment_point,
                            use_vpn=False)

    def test_cycle_vpn(self):
        seed = 3
        attachment_point = AttachmentPoint.objects.filter(vpn__isnull=False).first()
        user_as = create_random_useras(self,
                                       seed=seed,
                                       attachment_point=attachment_point,
                                       use_vpn=True)

        vpn_client = user_as.hosts.get().vpn_clients.get()
        vpn_client_pk = vpn_client.pk
        vpn_client_ip = vpn_client.ip
        del vpn_client

        update_useras(self,
                      user_as,
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

        update_useras(self,
                      user_as,
                      use_vpn=True,
                      public_ip=None)
        check_random_useras(self,
                            user_as,
                            seed=seed,
                            attachment_point=attachment_point,
                            public_ip=None,
                            use_vpn=True)

        # Check VPN client IP has not changed:
        vpn_client = user_as.hosts.get().vpn_clients.get()
        self.assertEqual(vpn_client.pk, vpn_client_pk)
        self.assertTrue(vpn_client.active)
        self.assertEqual(vpn_client.ip, vpn_client_ip)

    def test_vpn_client_next_ip(self):
        attachment_point = AttachmentPoint.objects.filter(vpn__isnull=False).first()
        vpn_server = VPN.objects.first()
        user_as = create_and_check_useras(self,
                                          attachment_point=attachment_point,
                                          owner=get_testuser(),
                                          use_vpn=True,
                                          public_port=50000)
        vpn_client = user_as.hosts.get().vpn_clients.get()
        # consecutive:
        self.assertEqual(ip_address(vpn_server.server_vpn_ip) + 1,
                         ip_address(vpn_client.ip))
        # leave a gap at the beginning
        former_vpn_ip = ip_address(vpn_client.ip)
        vpn_client.ip = str(former_vpn_ip + 1)
        vpn_client.save()
        user_as = create_and_check_useras(self,
                                          attachment_point=attachment_point,
                                          owner=get_testuser(),
                                          use_vpn=True,
                                          public_port=50000)
        vpn_client_new = user_as.hosts.get().vpn_clients.get()
        self.assertEqual(ip_address(vpn_client_new.ip), former_vpn_ip)

    @parameterized.expand(zip(combinations(get_all_random_as_defs(), 2)))
    def test_change_ap(self, AS_defs_pair):
        seed = 4
        vpn_choice = VPNChoice.NONE
        aps_pair = [as_defs2aps(AS_defs_pair[0]), as_defs2aps(AS_defs_pair[1])]
        aps_conf = _get_random_aps_params(seed, aps_pair[0], vpn_choice)
        user_as = create_and_check_useras(self,
                                          seed,
                                          aps_conf=aps_conf,
                                          vpn_choice=vpn_choice,
                                          owner=get_testuser())

        # Disable the previously set attachment points
        for ap_conf in aps_conf:
            ap_conf.active = False
        aps_conf += _get_random_aps_params(seed, aps_pair[1], vpn_choice)
        self._change_aps(user_as, aps_conf)

        check_random_useras(self,
                            seed,
                            user_as,
                            aps_conf,
                            vpn_choice)

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

    def _change_aps(self, user_as, aps_conf):
        """ Helper: update UserAS, changing only the attachment points. """
        prev_aps_isd = user_as.isd
        aps = [ap_conf.attachment_point for ap_conf in aps_conf]
        prev_certificate_chain = user_as.certificate_chain
        hosts_pending_before = set(Host.objects.needs_config_deployment())

        update_useras(self, user_as, aps_conf)

        # Check needs_config_deployment: hosts of UserAS and both APs
        flatten = lambda l: [z for x in l for z in x]
        aps_hosts = flatten(
            ap.AS.hosts.all() for ap in AttachmentPointConf.attachment_points(aps_conf))
        self.assertSetEqual(
            hosts_pending_before | set(user_as.hosts.all()) | set(aps_hosts),
            set(Host.objects.needs_config_deployment())
        )

        # Check certificates reset if ISD changed
        curr_aps_isd = user_as.isd
        if prev_aps_isd != curr_aps_isd:
            prev_version = prev_certificate_chain['0']['Version']
            curr_version = user_as.certificate_chain['0']['Version']
            self.assertEqual(
                curr_version,
                prev_version + 1,
                ("Certificate needs to be recreated on ISD change: "
                 "ISD before: %s, ISD after:%s" % (prev_aps_isd, curr_aps_isd))
            )
        else:
            self.assertEqual(prev_certificate_chain, user_as.certificate_chain)

        utils.check_topology(self)


class ActivateUserASTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        setup_vpn_attachment_point(AttachmentPoint.objects.first())
        Host.objects.reset_needs_config_deployment()

    def test_cycle_active(self):
        seed = 123
        user_as = create_random_useras(self, seed=seed)

        with patch.object(AttachmentPoint, 'trigger_deployment', autospec=True) as mock_deploy:
            user_as.update_active(False)

        uplink = Link.objects.get(interfaceB__AS=user_as)
        self.assertFalse(uplink.active)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(user_as.hosts.all() |
                 user_as.attachment_point.AS.hosts.all())
        )
        self.assertEqual(
            [args[0] for args, kwargs in mock_deploy.call_args_list],
            [user_as.attachment_point]
        )

        with patch.object(AttachmentPoint, 'trigger_deployment', autospec=True) as mock_deploy:
            user_as.update_active(True)

        uplink = Link.objects.get(interfaceB__AS=user_as)
        self.assertTrue(uplink.active)
        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            list(user_as.hosts.all() |
                 user_as.attachment_point.AS.hosts.all())
        )
        self.assertEqual(
            [args[0] for args, kwargs in mock_deploy.call_args_list],
            [user_as.attachment_point]
        )

        check_random_useras(self, user_as, seed=seed)


class DeleteUserASTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    def setUp(self):
        setup_vpn_attachment_point(AttachmentPoint.objects.first())
        Host.objects.reset_needs_config_deployment()

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
