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
from typing import List
from itertools import combinations
from ipaddress import ip_address, ip_network
from unittest.mock import patch
from parameterized import parameterized
from django.test import TestCase
from scionlab.models.core import AS, Host, Link
from scionlab.models.pki import Certificate, Key
from scionlab.models.user_as import (
    AttachmentPoint,
    AttachmentConf,
    UserAS,
)
from scionlab.models.vpn import VPN, VPNClient
from scionlab.defines import (
    USER_AS_ID_BEGIN,
    USER_AS_ID_END,
    DEFAULT_HOST_INTERNAL_IP,
    DEFAULT_PUBLIC_PORT,
)
from scionlab.scion import as_ids as as_ids_utils
from scionlab.fixtures import testtopo
from scionlab.fixtures.testtopo import ASdef
from scionlab.fixtures.testuser import get_testuser
from scionlab.tests import utils
from scionlab.util import flatten
from scionlab.util.django import value_set

testtopo_num_attachment_points = sum(1 for as_def in testtopo.ases if as_def.is_ap)
testtopo_vpns_as_ids = [vpn.as_id for vpn in testtopo.vpns]


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
test_different_public_ip = '172.31.0.112'
test_public_port = 54321
test_bind_ip = '192.168.1.2'


def _randbool(r: random.Random):
    return r.choice([True, False])


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
                            att_confs: List[AttachmentConf],
                            vpn_choice: VPNChoice,
                            owner,
                            wants_user_ap=False,
                            ap_public_ip="",
                            wants_vpn=False,
                            installation_type=UserAS.PKG,
                            label='label foo',
                            **kwargs) -> UserAS:
    """
    Helper function for testing. Create a UserAS, attach it to the attachment_points as
    specified in att_confs, and verify that things look right.
    """
    hosts_pending_before = set(Host.objects.needs_config_deployment())
    isd = att_confs[0].attachment_point.AS.isd
    user_as = UserAS.objects.create(
        owner,
        installation_type,
        isd,
        label=label,
        ap_public_ip=ap_public_ip,
        wants_vpn=wants_vpn,
        wants_user_ap=wants_user_ap
    )
    user_as.update_attachments(att_confs)

    # Check AS needs_config_deployment:
    aps_hosts = []
    attachment_points = [c.attachment_point for c in att_confs]
    for ap in attachment_points:
        aps_hosts += ap.AS.hosts.all()
    testcase.assertSetEqual(
        hosts_pending_before | set(user_as.hosts.all()) | set(aps_hosts),
        set(Host.objects.needs_config_deployment())
    )

    check_useras(testcase,
                 user_as,
                 att_confs,
                 owner,
                 vpn_choice,
                 installation_type,
                 label,
                 wants_user_ap,
                 ap_public_ip,
                 wants_vpn,
                 **kwargs)

    return user_as


def check_useras(testcase,
                 user_as: UserAS,
                 att_confs: List[AttachmentConf],
                 owner,
                 vpn_choice: VPNChoice,
                 installation_type,
                 label,
                 is_ap,
                 ap_public_ip,
                 wants_vpn,
                 **kwargs):
    """
    Check the state of `user_as` and `att_confs`.

    Verify that the links to the attachment points exists and that they are configured according to
    the given parameters.
    """
    testcase.assertEqual(user_as.owner, owner)
    testcase.assertEqual(user_as.label, label)
    testcase.assertEqual(user_as.installation_type, installation_type)
    testcase.assertEqual(user_as.is_attachment_point(), is_ap)
    if is_ap:
        ap = user_as.attachment_point_info
        host = user_as.hosts.first()
        testcase.assertEqual(host.public_ip, ap_public_ip)
        testcase.assertEqual(ap.vpn is not None, wants_vpn)
    utils.check_as(testcase, user_as)

    # Check that the AttachmentPoints in `att_confs` are now AttachmentPoints of the user_as
    aps_ases = [c.attachment_point.AS for c in att_confs]
    user_as_aps_ases = [link.interfaceA.AS for link in
                        Link.objects.filter(interfaceB__AS=user_as).all()]
    testcase.assertEqual(sorted(user_as_aps_ases, key=lambda _as: _as.id),
                         sorted(aps_ases, key=lambda _as: _as.id))
    # Check attachment points configuration
    for att_conf in filter(lambda att_conf: att_conf.active, att_confs):
        ap = att_conf.attachment_point
        utils.check_as(testcase, ap.AS)
        _check_attachment_point(testcase, ap)
        link = att_conf.link
        testcase.assertEqual(att_conf.active, link.active)
        testcase.assertEqual(att_conf.public_port, link.interfaceB.public_port)

        if att_conf.use_vpn:
            testcase.assertNotEqual(vpn_choice, VPNChoice.NONE)
            testcase.assertTrue(VPNClient.objects.filter(host=user_as.host,
                                                         vpn=ap.vpn
                                                         ).exists())
            utils.check_link(testcase, link, utils.LinkDescription(
                type=Link.PROVIDER,
                from_as_id=ap.AS.as_id,
                from_public_ip=ap.vpn.server_vpn_ip,
                from_bind_ip=None,
                from_internal_ip=DEFAULT_HOST_INTERNAL_IP,
                to_public_ip=user_as.hosts.get().vpn_clients.get(active=True, vpn=ap.vpn).ip,
                to_public_port=att_conf.public_port,
                to_bind_ip=None,
                to_internal_ip=DEFAULT_HOST_INTERNAL_IP,
            ))
        else:
            testcase.assertNotEqual(vpn_choice, VPNChoice.ALL)
            vpn_client = VPNClient.objects.filter(host=user_as.host,
                                                  vpn=att_conf.attachment_point.vpn
                                                  ).first()
            testcase.assertTrue(not vpn_client or not vpn_client.active)
            bind_ip = att_conf.bind_ip
            if installation_type == UserAS.VM:
                bind_ip = '10.0.2.15'

            utils.check_link(testcase, link, utils.LinkDescription(
                type=Link.PROVIDER,
                from_as_id=ap.AS.as_id,
                from_public_ip=_get_public_ip_testtopo(ap.AS.as_id),
                from_bind_ip=None,
                from_internal_ip=DEFAULT_HOST_INTERNAL_IP,
                to_public_ip=att_conf.public_ip,
                to_public_port=att_conf.public_port,
                to_bind_ip=bind_ip,
                to_internal_ip=DEFAULT_HOST_INTERNAL_IP,
            ))


def _check_attachment_point(testcase, attachment_point: AttachmentPoint):
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


def update_useras(testcase,
                  user_as,
                  att_confs: List[AttachmentConf],
                  deleted_links: List[Link] = [],
                  wants_user_ap=False, ap_public_ip="", wants_vpn=False,
                  **kwargs):
    """
    Update a `UserAS` and the configuration of its attachments
    """
    prev_aps_isd = user_as.isd
    prev_cert_chain = Certificate.objects.latest(Key.CP_AS, user_as)
    hosts_pending_before = set(Host.objects.needs_config_deployment())

    user_as.update(
        label=kwargs.get('label', user_as.label),
        installation_type=kwargs.get('installation_type', user_as.installation_type),
        public_ip=ap_public_ip,
        wants_user_ap=wants_user_ap,
        wants_vpn=wants_vpn,
    )
    user_as.update_attachments(att_confs, deleted_links)

    # Check needs_config_deployment: hosts of UserAS and both APs
    aps_hosts = flatten(
        ap.AS.hosts.all() for ap in AttachmentConf.attachment_points(att_confs))
    testcase.assertSetEqual(
        hosts_pending_before | set(user_as.hosts.all()) | set(aps_hosts),
        set(Host.objects.needs_config_deployment())
    )

    # Check certificates reset if ISD changed
    curr_aps_isd = user_as.isd
    cert_chain = Certificate.objects.latest(Key.CP_AS, user_as)
    if prev_aps_isd != curr_aps_isd:
        testcase.assertEqual(
            cert_chain.version,
            prev_cert_chain.version + 1,
            ("Certificate needs to be recreated on ISD change: "
             "ISD before: %s, ISD after:%s" % (prev_aps_isd, curr_aps_isd))
        )
        testcase.assertEqual(user_as.certificates().filter(key__usage=Key.CP_AS).count(), 1)
    else:
        testcase.assertEqual(prev_cert_chain, cert_chain)

    utils.check_topology(testcase)


def _get_random_att_confs(seed,
                          as_ids: List[ASdef],
                          vpn_choice: VPNChoice,
                          force_public_ip=False,
                          force_bind_ip=False,
                          **kwargs) -> List[AttachmentConf]:
    """
    Generate random compatible `AttachmentConf`s for the given `ASdef`s based on `seed`.
    """
    r = random.Random(seed)
    att_confs = []
    used_public_ip_port_pairs = set()
    used_bind_ip_port_pairs = set()
    attachment_points = aps_from_ids(as_ids)
    for ap in attachment_points:
        att_conf_dict = {}
        att_conf_dict['attachment_point'] = ap
        if vpn_choice in (VPNChoice.NONE, VPNChoice.ALL):
            att_conf_dict['use_vpn'] = False if vpn_choice is VPNChoice.NONE else True
        else:
            if not ap.vpn:
                att_conf_dict['use_vpn'] = False
            else:
                att_conf_dict['use_vpn'] = _randbool(r)
        while True:
            public_ip = '172.31.0.%i' % r.randint(10, 254)
            public_port = r.choice(range(DEFAULT_PUBLIC_PORT, DEFAULT_PUBLIC_PORT + 20))
            if (public_ip, public_port) not in used_public_ip_port_pairs:
                used_public_ip_port_pairs.add((public_ip, public_port))
                break
        if _randbool(r) or att_conf_dict['use_vpn'] is False or force_public_ip:
            att_conf_dict['public_ip'] = public_ip
        else:
            att_conf_dict['public_ip'] = None
        att_conf_dict['public_port'] = public_port

        while True:
            bind_ip = '192.168.1.%i' % r.randint(10, 254)
            if (bind_ip, public_port) not in used_bind_ip_port_pairs:
                used_bind_ip_port_pairs.add((bind_ip, public_port))
                break
        if _randbool(r) or force_bind_ip:
            att_conf_dict['bind_ip'] = bind_ip
        else:
            att_conf_dict['bind_ip'] = None
        att_confs.append(AttachmentConf(**att_conf_dict))

    return att_confs


def _get_random_useras_params(seed, vpn_choice, **kwargs):
    """
    Generate some "random" parameters for a UserAS based on `seed`.
    Any parameters to UserAS.objects.create can be specified to override the generated values.
    :returns: kwargs dict for UserAS.objects.create
    """
    r = random.Random(seed)

    kwargs.setdefault('owner', get_testuser())
    kwargs.setdefault('installation_type', r.choice((UserAS.VM, UserAS.PKG, UserAS.SRC)))
    randstr = r.getrandbits(1024).to_bytes(1024 // 8, 'little').decode('utf8', 'ignore')
    kwargs.setdefault('label', randstr)

    return kwargs


def create_and_check_random_useras(testcase, seed, as_ids, vpn_choice, wants_user_ap=False,
                                   ap_public_ip="", wants_vpn=False, **kwargs):
    """
    Create and check UserAS with "random" parameters based on `seed`.
    Any parameters to UserAS.objects.create can be specified to override the generated values.
    """
    att_confs = kwargs.get('att_confs',
                           _get_random_att_confs(seed, as_ids, vpn_choice, **kwargs))
    user_as = create_and_check_useras(testcase,
                                      seed,
                                      att_confs,
                                      vpn_choice,
                                      wants_user_ap=wants_user_ap,
                                      ap_public_ip=ap_public_ip,
                                      wants_vpn=wants_vpn,
                                      **_get_random_useras_params(seed, vpn_choice, **kwargs))
    return user_as, att_confs


def check_random_useras(testcase,
                        seed,
                        user_as,
                        att_confs,
                        vpn_choice,
                        wants_user_ap=False,
                        ap_public_ip="",
                        wants_vpn=False,
                        **kwargs):
    """
    Check the state of a `user_as` based on the "random" parameters generated with `seed`.
    Any parameters to UserAS.objects.create can be specified to override the generated values.
    :param TestCase testcase:
    :param int seed:
    :param UserAS user_as:
    :param List[AttachmentConf] att_confs:
    :param User owner:
    :param VPNChoice vpn_choice:
    :param optional bool wants_user_ap:
    :param optional string ap_public_ip:
    :param optional bool wants_vpn:
    """
    check_useras(testcase=testcase, user_as=user_as, att_confs=att_confs, vpn_choice=vpn_choice,
                 is_ap=wants_user_ap, ap_public_ip=ap_public_ip, wants_vpn=wants_vpn,
                 **_get_random_useras_params(seed, vpn_choice, **kwargs))


class GenerateUserASIDTests(TestCase):
    def test_first(self):
        as_id_int = UserAS.objects.get_next_id()
        self.assertEqual(as_id_int, USER_AS_ID_BEGIN)
        self.assertEqual(as_ids_utils.format(as_id_int), 'ffaa:1:1')

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
    fixtures = ['testdata']

    def test_create_new(self):
        ap = AttachmentPoint.objects.first()
        prev_version = ap.AS.hosts.first().config_version
        self._setup_vpn_attachment_point(ap)
        self.assertGreater(ap.AS.hosts.first().config_version, prev_version)
        self.assertEqual(ap.vpn.server, ap.AS.hosts.first())

    def test_update_vpn(self):
        ap = AttachmentPoint.objects.first()
        self._setup_vpn_attachment_point(ap)
        server = ap.vpn.server
        prev_version = server.config_version
        ap.vpn.update(subnet='10.0.8.0/22')
        self.assertGreater(server.config_version, prev_version)

    def test_change_vpn_server(self):
        ap = AttachmentPoint.objects.first()
        self._setup_vpn_attachment_point(ap)
        old_server = ap.vpn.server
        old_server_prev_version = old_server.config_version
        new_server = Host.objects.create()
        self.assertNotEqual(new_server, old_server)
        new_server_prev_version = new_server.config_version
        ap.vpn.update(server=new_server)
        self.assertGreater(old_server.config_version, old_server_prev_version)
        self.assertGreater(new_server.config_version, new_server_prev_version)

    def _setup_vpn_attachment_point(self, ap):
        """ Setup a VPN server config for the given attachment point """
        ap.vpn = VPN.objects.create(server=ap.AS.hosts.first(),
                                    subnet='10.0.8.0/24',
                                    server_vpn_ip='10.0.8.1',
                                    server_port=4321)
        ap.save()


def get_random_as_ids_combinations(has_vpn: bool = False, seed=1) -> List[List[str]]:
    """
    Generates a list of combinations of AttachmentPoints.
    For each ISD the we sample:
        - a combination composed of a single `AttachmentPoint`, and
        - a combination of at least two `AttachmentPoint`s (if any)
    """
    r = random.Random(seed)
    as_per_isd = {}
    as_ids_combs = []

    def _is_ap(asdef: ASdef) -> bool:
        return asdef.is_ap

    for as_def in filter(_is_ap, testtopo.ases):
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
        as_ids_combs.append([random_ap.as_id])
        # If there are more than a single ap for the current ISD, get at least
        # two aps for this ISD
        if as_len >= 2:
            random_aps = [asdef.as_id for asdef in r.sample(as_def, r.randint(2, as_len))]
            as_ids_combs.append(random_aps)
    return as_ids_combs


def aps_from_ids(as_ids: List[str]) -> List[AttachmentPoint]:
    """
    Returns a list of attachment points from a list of AS definitions
    """
    return [ap_from_id(as_id) for as_id in as_ids]


def ap_from_id(as_id: List[str]) -> List[AttachmentPoint]:
    """
    Returns a list of attachment points from a list of AS definitions
    """
    return AttachmentPoint.objects.get(AS__as_id=as_id)


class CreateUserASTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()

    @parameterized.expand(zip(get_random_as_ids_combinations()))
    def test_create_public_ip(self, as_ids):
        seed = 1
        create_and_check_random_useras(self,
                                       seed,
                                       as_ids,
                                       VPNChoice.NONE,
                                       public_ip=test_public_ip)

    @parameterized.expand(zip(get_random_as_ids_combinations()))
    def test_create_public_bind_ip(self, as_ids):
        seed = 1
        create_and_check_random_useras(self,
                                       seed,
                                       as_ids,
                                       VPNChoice.NONE,
                                       public_ip=test_public_ip,
                                       bind_ip=test_bind_ip)

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def test_create_vpn(self, as_id):
        seed = 1
        create_and_check_random_useras(self, seed, [as_id], VPNChoice.ALL)

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def test_create_user_ap(self, as_id):
        seed = 1
        create_and_check_random_useras(self,
                                       seed,
                                       [as_id],
                                       VPNChoice.ALL,
                                       wants_user_ap=True,
                                       ap_public_ip=test_public_ip)

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def test_create_user_ap_vpn(self, as_id):
        seed = 1
        create_and_check_random_useras(self,
                                       seed,
                                       [as_id],
                                       VPNChoice.ALL,
                                       wants_user_ap=True,
                                       ap_public_ip=test_public_ip,
                                       wants_vpn=True)

    @patch('scionlab.models.user.User.max_num_ases', return_value=32)
    def test_create_mixed(self, mock):
        r = random.Random()
        r.seed(5)
        as_ids_combs = get_random_as_ids_combinations()
        for i in range(0, 32):
            if r.choice([True, False]):  # pretend to deploy sometimes
                Host.objects.reset_needs_config_deployment()
            as_ids = r.choice(as_ids_combs)
            create_and_check_random_useras(self, i, as_ids, VPNChoice.SOME)

    def test_server_vpn_ip(self):
        """ Its IP is not at the beginning of the subnet """
        seed = 1
        ap = AttachmentPoint.objects.filter(AS__as_id='ffaa:0:1404').get()
        as_ids = [ap.AS.as_id]
        vpn = ap.vpn
        server_orig_ip = ip_address(vpn.server_vpn_ip)
        vpn.server_vpn_ip = str(server_orig_ip + 1)
        vpn.save()
        # create two clients and check their IP addresses
        c1, _ = create_and_check_random_useras(self, seed, as_ids, VPNChoice.ALL)
        c1 = c1.hosts.get().vpn_clients.get()
        c2, _ = create_and_check_random_useras(self, seed, as_ids, VPNChoice.ALL)
        c2 = c2.hosts.get().vpn_clients.get()
        ip1 = ip_address(c1.ip)
        ip2 = ip_address(c2.ip)
        self.assertEqual(ip1, server_orig_ip)
        self.assertEqual(ip2, ip_address(vpn.server_vpn_ip) + 1)

    @patch('scionlab.models.user.User.max_num_ases', return_value=2 ** 16)
    def test_exhaust_vpn_clients(self, _):
        seed = 1
        ap = AttachmentPoint.objects.filter(vpn__isnull=False).first()
        vpn = ap.vpn
        vpn.subnet = '10.0.8.0/28'
        vpn.server_vpn_ip = '10.0.8.10'
        vpn.save()
        vpn_choice = VPNChoice.ALL
        subnet = ip_network(vpn.subnet)
        used_ips = list()
        it = subnet.hosts()
        next(it)  # skip one for the server
        as_ids = [as_def.as_id for as_def in testtopo.ases if as_def.as_id == ap.AS.as_id]
        for i in it:
            user_as, _ = create_and_check_random_useras(self, seed, as_ids, vpn_choice)
            used_ips.append(ip_address(user_as.hosts.get().vpn_clients.get().ip))
        self.assertEqual(len(used_ips), 13)  # 16 - network, broadcast and server addrs
        used_ips_set = set(used_ips)
        self.assertEqual(len(used_ips), len(used_ips_set))
        self.assertNotIn(ip_address(vpn.server_vpn_ip), used_ips_set)
        for ip in used_ips:
            self.assertIn(ip, subnet)
        # one too many:
        with self.assertRaises(RuntimeError):
            create_and_check_random_useras(self, seed, as_ids, vpn_choice)


class UpdateUserASTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def test_enable_vpn(self, as_def):
        seed = 1
        user_as, att_confs = create_and_check_random_useras(self, seed, [as_def], VPNChoice.NONE)
        att_confs[0].use_vpn = True
        update_useras(self, user_as, att_confs)
        check_random_useras(self, seed, user_as, att_confs, VPNChoice.ALL)

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def test_disable_vpn(self, as_def):
        seed = 2
        user_as, att_confs = create_and_check_random_useras(self, seed, [as_def], VPNChoice.ALL)
        att_confs[0].use_vpn = False
        update_useras(self, user_as, att_confs)
        check_random_useras(self, seed, user_as, att_confs, VPNChoice.NONE)

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def test_become_user_ap(self, as_def):
        seed = 2
        user_as, att_confs = create_and_check_random_useras(self, seed, [as_def], VPNChoice.ALL)
        update_useras(self, user_as, att_confs, wants_user_ap=True, ap_public_ip=test_public_ip)
        check_random_useras(self,
                            seed,
                            user_as,
                            att_confs,
                            VPNChoice.ALL,
                            wants_user_ap=True,
                            ap_public_ip=test_public_ip)

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def user_ap_change_public_ip(self, as_def):
        seed = 2
        user_as, att_confs = create_and_check_random_useras(self,
                                                            seed,
                                                            [as_def],
                                                            VPNChoice.ALL,
                                                            wants_user_ap=True,
                                                            ap_public_ip=test_public_ip)
        update_useras(self,
                      user_as,
                      att_confs,
                      wants_user_ap=True,
                      ap_public_ip=test_different_public_ip)
        check_random_useras(self,
                            seed,
                            user_as,
                            att_confs,
                            VPNChoice.ALL,
                            wants_user_ap=True,
                            ap_public_ip=test_different_public_ip)

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def user_ap_change_vpn(self, as_def):
        seed = 2
        user_as, att_confs = create_and_check_random_useras(self,
                                                            seed,
                                                            [as_def],
                                                            VPNChoice.ALL,
                                                            wants_user_ap=True,
                                                            ap_public_ip=test_public_ip)
        update_useras(self,
                      user_as,
                      att_confs,
                      wants_user_ap=True,
                      ap_public_ip=test_public_ip,
                      wants_vpn=True)
        check_random_useras(self,
                            seed,
                            user_as,
                            att_confs,
                            VPNChoice.ALL,
                            wants_user_ap=True,
                            ap_public_ip=test_public_ip,
                            wants_vpn=True)

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def user_as_delete_ap(self, as_def):
        seed = 2
        user_as, att_confs = create_and_check_random_useras(self,
                                                            seed,
                                                            [as_def],
                                                            VPNChoice.ALL,
                                                            wants_user_ap=True,
                                                            ap_public_ip=test_public_ip)
        update_useras(self, user_as, att_confs, wants_user_ap=False, ap_public_ip="")
        check_random_useras(self,
                            seed,
                            user_as,
                            att_confs,
                            VPNChoice.ALL,
                            wants_user_ap=False,
                            ap_public_ip="")

    @parameterized.expand(zip(testtopo_vpns_as_ids))
    def test_cycle_vpn(self, as_def):
        seed = 3
        user_as, att_confs = create_and_check_random_useras(self, seed, [as_def], VPNChoice.ALL)

        vpn_client = user_as.hosts.get().vpn_clients.get()
        vpn_client_pk = vpn_client.pk
        vpn_client_ip = vpn_client.ip
        del vpn_client

        att_confs[0].use_vpn = False
        update_useras(self, user_as, att_confs)
        check_random_useras(self, seed, user_as, att_confs, VPNChoice.NONE)

        # Sanity check: VPN client config still there, but inactive
        vpn_client = user_as.hosts.get().vpn_clients.get()
        self.assertEqual(vpn_client.pk, vpn_client_pk)
        self.assertFalse(vpn_client.active)
        del vpn_client

        att_confs[0].use_vpn = True
        update_useras(self, user_as, att_confs)
        check_random_useras(self, seed, user_as, att_confs, VPNChoice.ALL)

        # Check VPN client IP has not changed:
        vpn_client = user_as.hosts.get().vpn_clients.get()
        self.assertEqual(vpn_client.pk, vpn_client_pk)
        self.assertTrue(vpn_client.active)
        self.assertEqual(vpn_client.ip, vpn_client_ip)

    def test_vpn_client_next_ip(self):
        seed = 5
        attachment_point = AttachmentPoint.objects.filter(AS__as_id='ffaa:0:1404').get()
        as_defs = [attachment_point.AS.as_id]
        vpn = attachment_point.vpn
        vpn.clients.all().delete()  # check creation of first client

        user_as, _ = create_and_check_random_useras(self, seed, as_defs, VPNChoice.ALL)
        vpn_client = user_as.hosts.get().vpn_clients.get()
        # consecutive: (assumes server at begin of IP range, not the case for all APs in testdata)
        self.assertEqual(ip_address(vpn.server_vpn_ip) + 1,
                         ip_address(vpn_client.ip))
        # leave a gap at the beginning
        former_vpn_ip = ip_address(vpn_client.ip)
        vpn_client.ip = str(former_vpn_ip + 1)
        vpn_client.save()
        user_as, _ = create_and_check_random_useras(self, seed, as_defs, VPNChoice.ALL)
        vpn_client_new = user_as.hosts.get().vpn_clients.get()
        self.assertEqual(ip_address(vpn_client_new.ip), former_vpn_ip)

    @parameterized.expand(zip(combinations(get_random_as_ids_combinations(), 2)))
    def test_change_ap(self, AS_defs_pair):
        seed = 4
        vpn_choice = VPNChoice.NONE
        user_as, att_confs = create_and_check_random_useras(self, seed, AS_defs_pair[0], vpn_choice)

        # Swap attachment point
        att_confs[0].attachment_point = ap_from_id(AS_defs_pair[1][0])
        update_useras(self, user_as, att_confs)

        check_random_useras(self, seed, user_as, att_confs, vpn_choice)

    @parameterized.expand(zip(combinations(get_random_as_ids_combinations(), 2)))
    def test_change_ap_disable(self, AS_defs_pair):
        seed = 4
        vpn_choice = VPNChoice.NONE
        user_as, att_confs = create_and_check_random_useras(self, seed, AS_defs_pair[0], vpn_choice)

        # Disable old ap
        att_confs[0].active = False
        att_confs += _get_random_att_confs(seed, AS_defs_pair[1], vpn_choice)
        update_useras(self, user_as, att_confs)

        check_random_useras(self, seed, user_as, att_confs, vpn_choice)

    @parameterized.expand(zip(combinations(get_random_as_ids_combinations(), 2)))
    def test_change_ap_delete(self, AS_defs_pair):
        seed = 4
        vpn_choice = VPNChoice.NONE
        user_as, att_confs = create_and_check_random_useras(self, seed, AS_defs_pair[0], vpn_choice)

        # Save links to delete them
        deleted_links = [c.link for c in att_confs]
        att_confs = _get_random_att_confs(seed, AS_defs_pair[1], vpn_choice)
        update_useras(self, user_as, att_confs, deleted_links)

        check_random_useras(self, seed, user_as, att_confs, vpn_choice)

    def test_cycle_ap(self):
        seed = 5
        vpn_choice = VPNChoice.SOME
        as_ids_combs = get_random_as_ids_combinations()
        _iter = iter(as_ids_combs * 2)
        user_as, att_confs = create_and_check_random_useras(self, seed, next(_iter), vpn_choice)
        for as_ids in _iter:
            att_confs[0].attachment_point = ap_from_id(as_ids[0])
            update_useras(self, user_as, att_confs)
            check_random_useras(self, seed, user_as, att_confs, vpn_choice)

    def test_cycle_ap_delete(self):
        seed = 5
        vpn_choice = VPNChoice.SOME
        as_ids_combs = get_random_as_ids_combinations()
        _iter = iter(as_ids_combs * 2)
        user_as, att_confs = create_and_check_random_useras(self, seed, next(_iter), vpn_choice)
        deleted_links = [c.link for c in att_confs]
        for as_ids in _iter:
            att_confs = _get_random_att_confs(seed, as_ids, vpn_choice)
            update_useras(self, user_as, att_confs, deleted_links)
            check_random_useras(self, seed, user_as, att_confs, vpn_choice)
            deleted_links = [c.link for c in att_confs]

    def test_cycle_ap_vpn(self):
        seed = 6
        vpn_choice = VPNChoice.ALL
        # List[ASdef] -> List[List[ASdef]]
        as_ids_list = [[as_def] for as_def in testtopo_vpns_as_ids]
        _iter = iter(as_ids_list * 2)
        user_as, att_confs = create_and_check_random_useras(self, seed, next(_iter), vpn_choice)

        # record per attachment point VPN info to verify IPs don't change
        vpn_client = user_as.hosts.get().vpn_clients.get(active=True)
        vpn_client_ips_per_ap = {att_confs[0].attachment_point.pk: vpn_client.ip}
        del vpn_client

        for as_ids in _iter:
            att_confs[0].attachment_point = ap_from_id(as_ids[0])
            update_useras(self, user_as, att_confs)
            check_random_useras(self, seed, user_as, att_confs, vpn_choice)
            vpn_client = user_as.hosts.get().vpn_clients.get(active=True)
            vpn_ip = vpn_client_ips_per_ap.get(att_confs[0].attachment_point.pk)
            if vpn_ip:
                self.assertEqual(vpn_ip, vpn_client.ip)
            else:
                vpn_client_ips_per_ap[att_confs[0].attachment_point.pk] = vpn_client.ip

    def test_change_ap_vpn_no_clash(self):
        """ attaches a user AS with VPN from one AP to another AP, checks port clashes """
        seed = 6
        ap1 = AS.objects.get(as_id=testtopo_vpns_as_ids[0])
        ap2 = AS.objects.get(as_id=testtopo_vpns_as_ids[1])

        # create two user ases:
        user_as1, att_confs1 = create_and_check_random_useras(self, seed+1, [ap1.as_id],
                                                              VPNChoice.ALL)
        user_as2,          _ = create_and_check_random_useras(self, seed+2, [ap2.as_id],
                                                              VPNChoice.ALL)

        # ensure that we use the same public port on the server side:
        ap_public_port = 55555
        # unlikely to already be in use, check anyway (testing the test):
        assert ap_public_port not in value_set(ap1.hosts.get().interfaces, 'public_port')
        assert ap_public_port not in value_set(ap2.hosts.get().interfaces, 'public_port')
        # now set the public port on AP side for both user-AS - AP links.
        user_as1.interfaces.get().remote_interface().update(public_port=ap_public_port)
        user_as2.interfaces.get().remote_interface().update(public_port=ap_public_port)

        # switch user_as1 from AP1 to AP2 and check the correctness of the topology,
        # in particular, the ports must not clash.
        att_confs1[0].attachment_point = ap2.attachment_point_info
        att_confs1[0].link.refresh_from_db()
        update_useras(self, user_as1, att_confs1)

    def test_cycle_ap_vpn_delete(self):
        seed = 6
        vpn_choice = VPNChoice.ALL
        # List[ASdef] -> List[List[ASdef]]
        as_ids_list = [[as_def] for as_def in testtopo_vpns_as_ids]
        _iter = iter(as_ids_list * 2)
        user_as, att_confs = create_and_check_random_useras(self, seed, next(_iter), vpn_choice)

        # record per attachment point VPN info to verify IPs don't change
        vpn_client = user_as.hosts.get().vpn_clients.get(active=True)
        vpn_client_ips_per_ap = {att_confs[0].attachment_point.pk: vpn_client.ip}
        del vpn_client

        deleted_links = [c.link for c in att_confs]
        for as_ids in _iter:
            att_confs = _get_random_att_confs(seed, as_ids, vpn_choice)
            update_useras(self, user_as, att_confs, deleted_links)
            check_random_useras(self, seed, user_as, att_confs, vpn_choice)
            vpn_client = user_as.hosts.get().vpn_clients.get(active=True)
            vpn_ip = vpn_client_ips_per_ap.get(att_confs[0].attachment_point.pk)
            if vpn_ip:
                self.assertEqual(vpn_ip, vpn_client.ip)
            else:
                vpn_client_ips_per_ap[att_confs[0].attachment_point.pk] = vpn_client.ip
            deleted_links = [c.link for c in att_confs]

    def test_cycle_ap_vpn_disable(self):
        """
        Activate/deactivates attachment points and verify that IP/keys don't change
        """
        seed = 6
        ASdefs = testtopo_vpns_as_ids
        vpn_choice = VPNChoice.ALL
        # Attach the UserAS to the first attachment point
        all_att_confs = []
        user_as, att_confs = create_and_check_random_useras(self, seed, [ASdefs[0]], vpn_choice)

        # Disable the attachment
        att_confs[0].active = False
        all_att_confs = att_confs
        # Save the IPs assigned to vpn_clients
        vpn = att_confs[0].attachment_point.vpn
        vpn_client = user_as.hosts.get().vpn_clients.get(vpn=vpn)
        vpn_clients_infos = {vpn: (vpn_client.pk, vpn_client.ip)}
        del vpn, vpn_client
        # Attach the UserAS to the other attachments, disabling the old ones
        for as_def in ASdefs[1:]:
            att_confs = _get_random_att_confs(seed, [as_def], vpn_choice)
            all_att_confs += att_confs
            update_useras(self, user_as, all_att_confs)
            check_random_useras(self, seed, user_as, all_att_confs, vpn_choice)
            # Disable the attachment not to conflict with the next one
            att_confs[0].active = False
            vpn = att_confs[0].attachment_point.vpn
            vpn_client = user_as.hosts.get().vpn_clients.get(vpn=vpn)
            vpn_clients_infos[vpn] = (vpn_client.pk, vpn_client.ip)
        # Disable also the last one
        update_useras(self, user_as, all_att_confs)
        check_random_useras(self, seed, user_as, all_att_confs, vpn_choice)

        # Activate/Deactivate links one by one
        for att_conf in iter(all_att_confs * 2):
            att_conf.active = True
            update_useras(self, user_as, all_att_confs)
            check_random_useras(self, seed, user_as, all_att_confs, vpn_choice)
            vpn = att_conf.attachment_point.vpn
            vpn_client = user_as.hosts.get().vpn_clients.get(vpn=vpn)
            pk, ip = vpn_clients_infos[vpn]
            self.assertEqual(pk, vpn_client.pk)
            self.assertEqual(ip, vpn_client.ip)
            att_conf.active = False


class ActivateUserASTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()

    def test_cycle_active(self):
        seed = 123
        r = random.Random(seed)
        as_ids = r.choice(get_random_as_ids_combinations())
        vpn_choice = VPNChoice.SOME
        user_as, att_confs = create_and_check_random_useras(self, seed, as_ids, vpn_choice)

        def _check_deployment_needs():
            self.assertEqual(
                set(Host.objects.needs_config_deployment()),
                set(user_as.hosts.all()) |
                set([h for c in att_confs for h in c.attachment_point.AS.hosts.all()])
            )

        user_as.update_active(False)

        uplink = Link.objects.get(interfaceB__AS=user_as)
        self.assertFalse(uplink.active)
        _check_deployment_needs()

        user_as.update_active(True)

        uplink = Link.objects.get(interfaceB__AS=user_as)
        self.assertTrue(uplink.active)
        _check_deployment_needs()

        check_random_useras(self, seed, user_as, att_confs, vpn_choice)


class DeleteUserASTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        Host.objects.reset_needs_config_deployment()

    def test_delete_single(self):
        seed = 456
        r = random.Random(seed)
        vpn_choice = VPNChoice.SOME
        as_ids = r.choice(get_random_as_ids_combinations())
        user_as, att_confs = create_and_check_random_useras(self, seed, as_ids, vpn_choice)
        user_as_hosts = list(user_as.hosts.all())
        user_as.delete()

        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            sorted(user_as_hosts +
                   list(set(h for c in att_confs for h in c.attachment_point.AS.hosts.all())),
                   key=lambda host: host.pk)
        )

        utils.check_topology(self)

    def test_delete_user(self):
        testuser = get_testuser()
        user_as_pks = []
        user_as_hosts = []
        attachment_point_hosts = set()
        as_ids_combs = get_random_as_ids_combinations()
        vpn_choice = VPNChoice.SOME
        for i in range(testuser.max_num_ases()):
            seed = 789 + i
            r = random.Random(seed)
            as_ids = r.choice(as_ids_combs)
            user_as, att_confs = create_and_check_random_useras(self, seed, as_ids, vpn_choice)
            user_as_pks.append(user_as.pk)
            user_as_hosts += list(user_as.hosts.all())
            attachment_point_hosts |= set([h for c in att_confs
                                           for h in c.attachment_point.AS.hosts.all()])

        testuser.delete()

        for user_as_pk in user_as_pks:
            self.assertFalse(UserAS.objects.filter(pk=user_as_pk).exists())

        self.assertEqual(
            list(Host.objects.needs_config_deployment()),
            sorted(user_as_hosts + list(attachment_point_hosts),
                   key=lambda host: host.pk)
        )

        utils.check_topology(self)
