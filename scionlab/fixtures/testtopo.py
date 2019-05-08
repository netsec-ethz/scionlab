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
from collections import namedtuple
from scionlab.models.core import ISD, AS, Link, Host, Service
from scionlab.models.user_as import AttachmentPoint
from scionlab.models.vpn import VPN

# Create records for all the test objects to create, so that they can be
# inspected during tests as ground truth.
ISDdef = namedtuple('ISDdef', ['isd_id', 'label'])
ASdef = namedtuple('ASdef', ['isd_id', 'as_id', 'label', 'public_ip', 'is_core', 'is_ap'])
LinkDef = namedtuple('LinkDef', ['type', 'as_id_a', 'as_id_b'])
VPNDef = namedtuple('VPNDef', ['server', 'vpn_ip', 'vpn_port', 'subnet', 'AP'])


def _expand_as_id(as_id_tail):
    """ Helper to avoid repeating the ffaa:0:-part of the ASes a gazillion times."""
    return 'ffaa:0:%x' % as_id_tail


def makeASdef(isd_id, as_id_tail, label, public_ip, is_core=False, is_ap=False):
    """ Helper for readable ASdef  declaration """
    return ASdef(isd_id, _expand_as_id(as_id_tail), label, public_ip, is_core, is_ap)


def makeLinkDef(type, as_id_tail_a, as_id_tail_b):
    return LinkDef(type, _expand_as_id(as_id_tail_a), _expand_as_id(as_id_tail_b))


# ISDs
isds = [
    ISDdef(16, 'AWS'),
    ISDdef(17, 'Switzerland'),
    ISDdef(18, 'North America'),
    ISDdef(19, 'EU'),
    ISDdef(20, 'Korea'),
    ISDdef(21, 'Japan'),
    ISDdef(22, 'Taiwan'),
    ISDdef(23, 'Singapore'),
    ISDdef(24, 'Australia'),
    ISDdef(25, 'China'),
]

# ASes
ases = [
    # ch
    makeASdef(17, 0x1101, 'SCMN', '192.0.2.11', is_core=True),
    makeASdef(17, 0x1102, 'ETHZ', '192.0.2.12'),
    makeASdef(17, 0x1103, 'SWTH', '192.0.2.13'),
    makeASdef(17, 0x1107, 'ETHZ-AP', '192.0.2.17', is_ap=True),
    # eu
    makeASdef(19, 0x1301, 'PV', '172.31.0.110', is_core=True),
    makeASdef(19, 0x1302, 'GEANT', '192.0.2.32', is_core=True),
    makeASdef(19, 0x1303, 'Magdeburg', '172.31.0.111', is_ap=True),
    makeASdef(19, 0x1304, 'FR@Linode', '192.0.2.34'),
    makeASdef(19, 0x1305, 'Darmstadt', '172.31.0.112'),
    # korea (Kompletely made up)
    makeASdef(20, 0x1401, 'K_core1', '172.31.0.113', is_core=True),
    makeASdef(20, 0x1402, 'K_core2', '192.0.2.42', is_core=True),
    makeASdef(20, 0x1403, 'K_L1', '192.0.2.43'),
    makeASdef(20, 0x1404, 'K_AP1', '192.0.2.44', is_ap=True),
    makeASdef(20, 0x1405, 'K_AP2', '172.31.0.114', is_ap=True),
    makeASdef(20, 0x1406, 'K_L3', '192.0.2.46'),
]

# Links
links = [
    # ch
    makeLinkDef(Link.PROVIDER, 0x1101, 0x1103),
    makeLinkDef(Link.PROVIDER, 0x1103, 0x1102),
    makeLinkDef(Link.PROVIDER, 0x1102, 0x1107),
    # eu
    makeLinkDef(Link.CORE, 0x1301, 0x1302),
    makeLinkDef(Link.PROVIDER, 0x1301, 0x1303),
    makeLinkDef(Link.PROVIDER, 0x1301, 0x1304),
    makeLinkDef(Link.PROVIDER, 0x1303, 0x1305),
    makeLinkDef(Link.PROVIDER, 0x1304, 0x1305),
    # ch-eu
    makeLinkDef(Link.CORE, 0x1101, 0x1301),
    makeLinkDef(Link.CORE, 0x1101, 0x1302),
    # korea
    makeLinkDef(Link.CORE, 0x1401, 0x1402),
    makeLinkDef(Link.PROVIDER, 0x1401, 0x1403),
    makeLinkDef(Link.PROVIDER, 0x1402, 0x1403),
    makeLinkDef(Link.PROVIDER, 0x1403, 0x1404),
    makeLinkDef(Link.PROVIDER, 0x1401, 0x1405),
    makeLinkDef(Link.PROVIDER, 0x1402, 0x1405),
    makeLinkDef(Link.PROVIDER, 0x1404, 0x1406),
]


# other than default services
extra_services = [
    ('ffaa:0:1107', Service.PP),
    ('ffaa:0:1107', Service.BW),
]

# VPNs
vpns = [
   # Asia AP VPN
   VPNDef(14, "10.0.8.1", 1194, "10.0.0.0/16", "14"),
]


def create_testtopo_isds():
    for isd_def in isds:
        ISD.objects.create(**isd_def._asdict())


def create_testtopo_ases():
    r = random.Random(0)

    def seeded_random_bytes(size=32):
        return bytes(r.getrandbits(8) for _ in range(size))

    # Somewhat scary trick; to reduce noise when regenerating the fixture from scratch,
    # make the AS keys somewhat deterministic by replacing os.urandom with seeded "random" bytes.
    with patch('os.urandom', side_effect=seeded_random_bytes):
        for as_def in ases:
            _create_as(**as_def._asdict())

    # Initialise TRCs and certificates. Deferred in AS creation to start with TRC/cert versions 1.
    for isd in ISD.objects.iterator():
        isd.init_trc_and_certificates()


def create_testtopo_links():
    for link_def in links:
        _create_as_link(**link_def._asdict())


def create_testtopo_vpn():
    for vpn_def in vpns:
        _create_vpn(**vpn_def._asdict())


def create_testtopo_extraservices():
    for as_serv in extra_services:
        host = Host.objects.get(AS__as_id=as_serv[0])
        Service.objects.create(host=host, type=as_serv[1])


def _create_as(isd_id, as_id, label, public_ip, is_core=False, is_ap=False):
    isd = ISD.objects.get(isd_id=isd_id)
    as_ = AS.objects.create_with_default_services(
        isd=isd,
        as_id=as_id,
        label=label,
        is_core=is_core,
        public_ip=public_ip,
        init_certificates=False  # Defer certificates generation
    )

    if is_ap:
        for host in as_.hosts.iterator():
            host.managed = True
            host.ssh_host = host.public_ip
            host.save()
        AttachmentPoint.objects.create(AS=as_)


def _create_as_link(type, as_id_a, as_id_b):
    as_a = AS.objects.get(as_id=as_id_a)
    as_b = AS.objects.get(as_id=as_id_b)
    Link.objects.create_from_ases(type, as_a, as_b)


def _create_vpn(server, vpn_ip, vpn_port, subnet, AP):
    vpn = VPN.objects.create(server=Host.objects.get(id=server),
                             server_vpn_ip=vpn_ip, server_port=vpn_port, subnet=subnet)
    # Add vpn to AP
    ap = AttachmentPoint.objects.get(AS_id=AP)
    ap.vpn = vpn
    ap.save()
