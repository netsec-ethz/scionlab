# Copyright 2019 ETH Zurich
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


import base64
import json
import os
import re
import uuid
from collections import defaultdict, namedtuple
from django.db.models import Q
from nacl.signing import SigningKey

from lib.crypto.certificate import Certificate

from scionlab.fixtures.testtopo import ISDdef
from scionlab.models.core import (
    ISD, AS, Link, Host, Service, BorderRouter, Interface,
)
from scionlab.models.user_as import AttachmentPoint
from scionlab.models.vpn import VPN
from scionlab.scion_config import SERVICE_TYPES_CONTROL_PLANE
from scionlab.util.local_config_util import TYPES_TO_KEYS

ASDef = namedtuple('ASDef', ['isd_id', 'as_id', 'label'])


# SCIONLab ISDs
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

# SCIONLab ASes
ases = [
    # AWS
    ASDef(16, 0x1001, 'AWS Frankfurt'),
    ASDef(16, 0x1002, 'AWS Ireland'),
    ASDef(16, 0x1003, 'AWS US N. Virginia'),
    ASDef(16, 0x1004, 'AWS US Ohio'),
    ASDef(16, 0x1005, 'AWS US Oregon'),
    ASDef(16, 0x1006, 'AWS Japan'),
    ASDef(16, 0x1007, 'AWS Singapore'),
    ASDef(16, 0x1008, 'AWS Australia'),
    # ch
    ASDef(17, 0x1101, 'SCMN'),
    ASDef(17, 0x1102, 'ETHZ'),
    ASDef(17, 0x1103, 'SWTH'),
    ASDef(17, 0x1104, 'BIT'),
    ASDef(17, 0x1107, 'ETHZ-AP'),
    ASDef(17, 0x110a, 'PCEngines'),
    ASDef(17, 0x110b, 'Odroid XU4'),
    ASDef(17, 0x110c, 'Odroid C1'),
    # US
    ASDef(18, 0x1201, 'CMU'),
    ASDef(18, 0x1202, 'WISC'),
    ASDef(18, 0x1203, 'Columbia'),
    ASDef(18, 0x1204, 'ISG(Toronto)'),
    ASDef(18, 0x1205, 'ISG(Otawa)'),
    # eu
    ASDef(19, 0x1301, 'Magdeburg core'),
    ASDef(19, 0x1302, 'GEANT'),
    ASDef(19, 0x1303, 'Magdeburg AP'),
    ASDef(19, 0x1304, 'FR@Linode'),
    ASDef(19, 0x1305, 'SIDN'),
    ASDef(19, 0x1306, 'Deutsche Telekom'),
    ASDef(19, 0x1307, 'TW Wien'),
    ASDef(19, 0x1308, 'PV'),
    # S. korea
    ASDef(20, 0x1401, 'KISTI Djn'),
    ASDef(20, 0x1402, 'KISTI Seoul'),
    ASDef(20, 0x1403, 'KAIST'),
    ASDef(20, 0x1404, 'KU'),
    ASDef(20, 0x1405, 'ETRI'),
    # Japan
    ASDef(21, 0x1501, 'KDDI'),
    # Taiwan
    ASDef(22, 0x1601, 'NTU'),
    # Singapore
    ASDef(23, 0x1701, 'NUS'),
    # Australia
    ASDef(24, 0x1801, 'OpenSystems'),
    # China
    ASDef(25, 0x1901, 'THU'),
]

attachment_points = [
    0x1107,
    0x1202,
    0x1303,
    0x1404,
]


class Loader:
    isd_re = re.compile(r'^ISD(\d+)$')
    as_re = re.compile(r'^AS(ffaa.+)$')
    trc_re = re.compile(r'^ISD\d+-V\d+.trc$')
    cert_re = re.compile(r'^ISD\d+-AS.+-V\d+.crt$')

    def __init__(self, gen_path):
        # load TRC
        self.core_ases_per_isd = defaultdict(list)
        self.trcs = {}
        self.certs = {}
        self.master0s = {}
        self.master1s = {}
        self.keys_sig = {}
        self.keys_decrypt = {}
        self.core_keys_sig = {}
        self.core_keys_online = {}
        self.core_keys_offline = {}
        self.topologies = {}
        for d in os.listdir(gen_path):
            trc = None
            groups = self.isd_re.match(d)
            if not groups:
                continue
            isd_id = int(groups.group(1))
            dir_isd = os.path.join(gen_path, d)
            for dir_as in os.listdir(dir_isd):
                groups = self.as_re.match(dir_as)
                if not groups:
                    continue
                as_id = groups.group(1).replace('_', ':')
                isd_as_id = '{isd}-{as_}'.format(isd=isd_id, as_=as_id)
                dir_endhost = os.path.join(dir_isd, dir_as, 'endhost')
                dir_certs = os.path.join(dir_endhost, 'certs')
                for cert in os.listdir(dir_certs):
                    if not trc:
                        groups = self.trc_re.match(cert)
                        if groups:
                            with open(os.path.join(dir_certs, cert)) as f:
                                trc = json.load(f)
                    groups = self.cert_re.match(cert)
                    if groups:
                        with open(os.path.join(dir_certs, cert)) as f:
                            self.certs[isd_as_id] = json.load(f)
                dir_keys = os.path.join(dir_endhost, 'keys')
                for key in os.listdir(dir_keys):
                    with open(os.path.join(dir_keys, key)) as f:
                        content = f.read()
                    if key == 'master0.key':
                        self.master0s[isd_as_id] = content
                    elif key == 'master1.key':
                        self.master1s[isd_as_id] = content
                    elif key == 'as-sig.seed':
                        self.keys_sig[isd_as_id] = content
                    elif key == 'as-decrypt.key':
                        self.keys_decrypt[isd_as_id] = content
                    elif key == 'core-sig.seed':
                        self.core_keys_sig[isd_as_id] = content
                        self.core_ases_per_isd[isd_id].append(isd_as_id)
                    elif key == 'online-root.seed':
                        self.core_keys_online[isd_as_id] = content
                    elif key == 'offline-root.seed':
                        self.core_keys_offline[isd_as_id] = content
                with open(os.path.join(dir_endhost, 'topology.json')) as f:
                    topology = json.load(f)
                self.topologies[isd_as_id] = topology
            # insert the trc
            self.trcs[isd_id] = trc


class Generator:
    def __init__(self, scionlab_old_gen_path):
        self.loader = Loader(scionlab_old_gen_path)

    def create_isds(self, isds):
        for isd_def in isds:
            self._create_isd(isd_def)

    def _create_isd(self, isd_def):
        isd_id = isd_def.isd_id
        trc = self.loader.trcs[isd_id]
        trc_priv_keys = {isd_as_id: self.loader.core_keys_online[isd_as_id]
                         for isd_as_id in self.loader.core_ases_per_isd[isd_id]}
        ISD.objects.create(**isd_def._asdict(), trc=trc,
                           trc_priv_keys=trc_priv_keys)

    def create_ases(self, ases):
        for as_def in ases:
            as_id = 'ffaa:0:%x' % as_def.as_id
            isd_as_id = '{isd}-{as_id}'.format(isd=as_def.isd_id, as_id=as_id)
            isd = ISD.objects.get(isd_id=as_def.isd_id)
            topo = self.loader.topologies[isd_as_id]
            assert(topo['Core'] == (
                isd_as_id in self.loader.core_ases_per_isd[as_def.isd_id]))
            as_ = AS.objects.create(isd=isd,
                                    as_id=as_id,
                                    is_core=topo['Core'],
                                    label=as_def.label,
                                    mtu=topo["MTU"],
                                    init_certificates=False)
            self._assign_keys(as_)
            self._assign_services(as_, topo)
        # once we have all ASes, do BRs and links
        for as_def in ases:
            as_id = 'ffaa:0:%x' % as_def.as_id
            as_ = AS.objects.get(isd__isd_id=as_def.isd_id, as_id=as_id)
            topo = self.loader.topologies[as_.isd_as_str()]
            self._assign_routers(as_, topo)
        # and once we have all BRs and interfaces, create links
        for as_def in ases:
            as_id = 'ffaa:0:%x' % as_def.as_id
            as_ = AS.objects.get(isd__isd_id=as_def.isd_id, as_id=as_id)
            topo = self.loader.topologies[as_.isd_as_str()]
            self._assign_links(as_, topo)

    def _assign_keys(self, as_):
        isd_as_id = as_.isd_as_str()
        chain = self.loader.certs[isd_as_id]
        as_.certificate_chain = chain
        assert(chain['0']['Subject'] == isd_as_id)
        as_.sig_pub_key = chain['0']['SubjectSignKey']
        as_.enc_pub_key = chain['0']['SubjectEncKey']
        as_.sig_priv_key = self.loader.keys_sig[isd_as_id]
        as_.enc_priv_key = self.loader.keys_decrypt[isd_as_id]
        as_.master_as_key = self.loader.master0s[isd_as_id]
        if as_.is_core:
            trc = self.loader.trcs[as_.isd.isd_id]
            as_.core_offline_priv_key = self.loader.core_keys_offline[isd_as_id]
            as_.core_offline_pub_key = trc['CoreASes'][isd_as_id]['OfflineKey']
            as_.core_online_priv_key = self.loader.core_keys_online[isd_as_id]
            as_.core_online_pub_key = trc['CoreASes'][isd_as_id]['OnlineKey']
            as_.core_sig_priv_key = self.loader.core_keys_sig[isd_as_id]
            as_.core_sig_pub_key = base64.b64encode(
                SigningKey(base64.b64decode(as_.core_sig_priv_key)).verify_key._key).decode()
            core_cert = Certificate(chain['1'])     # load the one from the json file and adapt it
            core_cert.subject = as_.isd_as_str()
            core_cert.issuer = as_.isd_as_str()     # self signed
            core_cert.subject_enc_key = ''
            core_cert.subject_sig_key = as_.core_sig_pub_key
            core_cert.sign(base64.b64decode(as_.core_online_priv_key))
            as_.core_certificate = core_cert.dict()
            # redo the AS cert in the chain
            cert = Certificate(chain['0'])
            cert.issuer = as_.isd_as_str()
            cert.sign(base64.b64decode(as_.core_sig_priv_key))
            as_.certificate_chain = {
                '0': cert.dict(),
                '1': core_cert.dict()
            }
        as_.save()

    def _assign_services(self, as_, topo):
        for service_type in SERVICE_TYPES_CONTROL_PLANE:
            serv = topo[TYPES_TO_KEYS[service_type]]
            serv = next(iter(serv.values()))
            public = serv['Addrs']['IPv4']['Public']
            public_ip = public['Addr']
            public_port = public['L4Port']
            if 'Bind' in serv['Addrs']['IPv4']:
                internal_ip = serv['Addrs']['IPv4']['Bind']['Addr']
                bind_ip = internal_ip
            else:
                internal_ip = public_ip
                bind_ip = None
            host, _ = _get_or_create_host(AS=as_,
                                          public_ip=public_ip,
                                          internal_ip=internal_ip,
                                          bind_ip=bind_ip)
            Service.objects.create(host=host, type=service_type, port=public_port)
        serv = topo[TYPES_TO_KEYS[Service.ZK]]['1']
        public_ip = serv['Addr']
        public_port = serv['L4Port']
        # ZK is always deployed on an existing machine:
        host = as_.hosts.get(Q(internal_ip=public_ip) | Q(public_ip=public_ip))
        Service.objects.create(host=host, type=Service.ZK, port=public_port)

    def _assign_routers(self, as_, topo):
        """
        Creates the local BRs for each entry. Also works for peer connections
        """
        brs = topo['BorderRouters']
        for brname, br in sorted(brs.items()):
            internal = br['InternalAddrs']['IPv4']
            public_ip = internal['PublicOverlay']['Addr']
            internal_port = internal['PublicOverlay']['OverlayPort']
            if 'BindOverlay' in internal:
                internal_ip = internal['BindOverlay']['Addr']
                assert(internal['BindOverlay']['OverlayPort'] == internal_port)
            else:
                internal_ip = public_ip
            control = br['CtrlAddr']['IPv4']
            assert(control['Public']['Addr'] == public_ip)
            control_port = control['Public']['L4Port']
            ifs = br['Interfaces']
            for ifacenum, iface in ifs.items():
                if iface['Overlay'] != 'UDP/IPv4':
                    print('Warning: assigning BRs, skip BR %s (non IPv4 overlay)' % brname)
                    continue
                bind_ip = iface['BindOverlay']['Addr'] if 'BindOverlay' in iface else None
                host_here, _ = _get_or_create_host(AS=as_,
                                                   public_ip=public_ip,
                                                   internal_ip=internal_ip,
                                                   bind_ip=bind_ip)
                assert(Host.objects.filter(AS=as_,
                                           public_ip=public_ip,
                                           internal_ip=internal_ip).count() == 1)
                br_here, _ = BorderRouter.objects.get_or_create(AS=as_,
                                                                host=host_here,
                                                                internal_port=internal_port,
                                                                control_port=control_port)
                bind_port = iface['BindOverlay']['OverlayPort'] if 'BindOverlay' in iface else None
                iface_public_ip = iface['PublicOverlay']['Addr']
                use_host = (iface_public_ip == public_ip and not bind_ip)
                Interface.objects.create(
                    border_router=br_here,
                    public_ip=iface_public_ip if not use_host else None,
                    public_port=iface['PublicOverlay']['OverlayPort'],
                    bind_ip=bind_ip if not use_host else None,
                    bind_port=bind_port if not use_host else None,
                    interface_id=ifacenum)

    def _assign_links(self, as_, topo):
        """
        Will assign interfaces and links once the BRs for the local side have been created
        """
        brs = topo['BorderRouters']
        for brname, br in sorted(brs.items()):
            internal = br['InternalAddrs']['IPv4']
            internal_ip = (internal.get('BindOverlay') or internal['PublicOverlay'])['Addr']
            internal_port = internal['PublicOverlay']['OverlayPort']
            ifs = br['Interfaces']
            for ifacenum, iface in ifs.items():
                if iface['LinkTo'] == 'CHILD':
                    # CHILD links are the reverse of PARENT; skip them and do only PARENT
                    continue
                if iface['Overlay'] != 'UDP/IPv4':
                    continue
                br_here = BorderRouter.objects.get(AS=as_,
                                                   host__internal_ip=internal_ip,
                                                   internal_port=internal_port)
                iface_here = Interface.objects.get(
                    border_router=br_here,
                    public_port=iface['PublicOverlay']['OverlayPort'])
                assert(iface_here.interface_id == int(ifacenum))
                remote_as = AS.objects.get_by_isd_as(iface['ISD_AS'])
                iface_there = Interface.objects.get_by_address_port(
                    remote_as,
                    iface['RemoteOverlay']['Addr'],
                    iface['RemoteOverlay']['OverlayPort'])
                if iface['LinkTo'] == 'CORE':
                    type = Link.CORE
                elif iface['LinkTo'] == 'PARENT':
                    # there(parent) -> here(child)
                    type = Link.PROVIDER
                elif iface['LinkTo'] == 'PEER':
                    type = Link.PEER
                else:
                    raise Exception('Unknown link type')
                if Link.objects.filter(interfaceB=iface_there, interfaceA=iface_here).exists():
                    # this is a reverse link to an existing one, no need to do anything
                    continue
                Link.objects.create(type=type,
                                    interfaceA=iface_there,
                                    interfaceB=iface_here,
                                    bandwidth=iface['Bandwidth'],
                                    mtu=iface['MTU'])


def _get_or_create_host(AS, public_ip, internal_ip, bind_ip):
    return Host.objects.get_or_create(AS=AS,
                                      public_ip=public_ip,
                                      internal_ip=internal_ip,
                                      bind_ip=bind_ip,
                                      managed=True,
                                      ssh_host=public_ip,
                                      defaults=dict(uid=uuid.uuid4().hex, secret=uuid.uuid4().hex))


def _create_attachmentpoints(ap_list):
    for short_id in ap_list:
        as_id = 'ffaa:0:%x' % short_id
        as_ = AS.objects.get(as_id=as_id)
        host = Host.objects.get(AS=as_)
        vpn = VPN.objects.create(server=host,
                                 server_port=1194,
                                 subnet='10.0.0.0/16',
                                 server_vpn_ip='10.0.8.1')
        AttachmentPoint.objects.create(AS=as_, vpn=vpn)


def build_scionlab_topology(scionlab_old_gen_path):
    gen = Generator(scionlab_old_gen_path)
    gen.create_isds(isds)
    gen.create_ases(ases)
    _create_attachmentpoints(attachment_points)
    print('done')
