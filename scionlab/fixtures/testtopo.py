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

from scionlab.models import ISD, AS, Link, AttachmentPoint
from collections import namedtuple

# Create records for all the test objects to create, so that they can be
# inspected during tests as ground truth.
ISDdef = namedtuple('ISDdef', ['id', 'label'])
ASdef = namedtuple('ASdef', ['isd_id', 'as_id', 'label', 'host_ip', 'is_core', 'is_ap'])
LinkDef = namedtuple('LinkDef', ['type', 'as_id_a', 'as_id_b'])


def _expand_as_id(as_id_tail):
    """ Helper to avoid repeating the ffaa:0:-part of the ASes a gazillion times."""
    return 'ffaa:0:%x' % as_id_tail


def makeASdef(isd_id, as_id_tail, label, host_ip, is_core=False, is_ap=False):
    """ Helper for readable ASdef  declaration """
    return ASdef(isd_id, _expand_as_id(as_id_tail), label, host_ip, is_core, is_ap)


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
    makeASdef(19, 0x1301, 'PV', '192.0.2.31', is_core=True),
    makeASdef(19, 0x1302, 'GEANT', '192.0.2.32', is_core=True),
    makeASdef(19, 0x1303, 'Magdeburg', '192.0.2.33', is_ap=True),
    makeASdef(19, 0x1304, 'FR@Linode', '192.0.2.34'),
    makeASdef(19, 0x1305, 'Darmstadt', '192.0.2.35'),
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
]


def create_testtopo_isds():
    for isddef in isds:
        ISD.objects.create(**isddef._asdict())


def create_testtopo_ases():
    for asdef in ases:
        _create_as(**asdef._asdict())


def create_testtopo_links():
    for linkdef in links:
        _create_as_link(**linkdef._asdict())


def _create_as(isd_id, as_id, label, host_ip, is_core=False, is_ap=False):
    isd = ISD.objects.get(id=isd_id)
    as_ = AS.objects.create_with_default_services(
        isd=isd,
        as_id=as_id,
        label=label,
        is_core=is_core)
    _set_public_ip(as_.hosts.first(), host_ip)

    if is_ap:
        AttachmentPoint.objects.create(AS=as_)


def _create_as_link(type, as_id_a, as_id_b):
    as_a = AS.objects.get(as_id=as_id_a)
    as_b = AS.objects.get(as_id=as_id_b)
    Link.objects.create_default(type, as_a, as_b)


def _set_public_ip(host, public_ip):
    host.public_ip = public_ip
    host.save()
