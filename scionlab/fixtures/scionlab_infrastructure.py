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


# # TODO: remove this
# import os
# import django
# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scionlab.settings.development')
# django.setup()


import os
import re
import json
from collections import defaultdict, namedtuple
from lib.packet.scion_addr import ISD_AS

from scionlab.fixtures.testtopo import (
    ISDdef, LinkDef,
    makeASdef, makeLinkDef
)
from scionlab.models import (
    ISD, AS, Link, AttachmentPoint, Host, Service,
    User,
    DEFAULT_HOST_INTERNAL_IP,
)
from scionlab.scion_config import SERVICE_TYPES_CONTROL_PLANE
from scionlab.util.local_config_util import (
    # KEY_BR,
    # KEY_BS,
    # KEY_CS,
    # KEY_PS,
    # KEY_ZK,
    TYPES_TO_KEYS
)

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
    # ch
    ASDef(17, 0x1101, 'SCMN'),
    ASDef(17, 0x1102, 'ETHZ'),
    ASDef(17, 0x1103, 'SWTH'),
    ASDef(17, 0x1107, 'ETHZ-AP'),
    # eu
    ASDef(19, 0x1301, 'Magdeburg core'),
    ASDef(19, 0x1302, 'GEANT'),
    ASDef(19, 0x1303, 'Magdeburg AP'),
    ASDef(19, 0x1304, 'FR@Linode'),
    ASDef(19, 0x1305, 'Darmstadt'),
    # korea (Kompletely made up)
    ASDef(20, 0x1401, 'K_core1'),
    ASDef(20, 0x1402, 'K_core2'),
    ASDef(20, 0x1403, 'K_L1'),
    ASDef(20, 0x1404, 'K_AP1'),
    ASDef(20, 0x1405, 'K_AP2'),
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
                as_id = groups.group(1)
                isd_as_id = str(ISD_AS('{isd}-{as_}'.format(isd=isd_id, as_=as_id)))
                dir_endhost = os.path.join(dir_isd, dir_as, 'endhost')
                dir_certs = os.path.join(dir_endhost, 'certs')
                for cert in os.listdir(dir_certs):
                    if not trc:
                        groups = self.trc_re.match(cert)
                        if groups:
                            with open(os.path.join(dir_certs, cert)) as f:
                                trc = f.read()
                    groups = self.cert_re.match(cert)
                    if groups:
                        with open(os.path.join(dir_certs, cert)) as f:
                            self.certs[isd_as_id] = f.read()
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
        # TODO: remove the check user admin exists or create
        if User.objects.filter(username='admin').count() == 0:
            User.objects.create_superuser('admin', 'scionlab@scionlab.org', 'admin')

    def create_isds(self, isds):
        for isd_def in isds:
            self._create_isd(isd_def)
        isd_17 = ISD.objects.get(isd_id=17)
        print(isd_17)

    def _create_isd(self, isd_def):
        isd_id = isd_def.isd_id
        trc = self.loader.trcs[isd_id]
        trc_priv_keys = {isd_as_id: self.loader.core_keys_sig[isd_as_id] 
                         for isd_as_id in self.loader.core_ases_per_isd[isd_id]}
        ISD.objects.create(**isd_def._asdict(), trc=trc, trc_priv_keys=trc_priv_keys)

    def create_ases(self, ases):
        admin_user = User.objects.get(username='admin')
        for as_def in ases:
            as_id = 'ffaa:0:%x' % as_def.as_id
            isd_as_id = '{isd}-{as_id}'.format(isd=as_def.isd_id, as_id=as_id)
            isd = ISD.objects.get(isd_id=as_def.isd_id)
            topo = self.loader.topologies[isd_as_id]
            assert(topo['Core'] == (isd_as_id in self.loader.core_ases_per_isd[as_def.isd_id]))
            as_ = AS.objects.create(isd=isd,
                                    as_id=as_id,
                                    is_core=topo['Core'],
                                    label=as_def.label,
                                    mtu=topo["MTU"],
                                    init_certificates=False,
                                    owner=admin_user)
            self._assign_keys(as_)
            self._assign_services(as_, topo)
            self._assign_routers(as_, topo)
        blah=AS.objects.get(as_id='ffaa:0:1107')
        print(blah.sig_pub_key)

    def _assign_keys(self, as_):
        isd_as_id = as_.isd_as_str()
        json_cert = self.loader.certs[isd_as_id]
        as_.certificate_chain = json_cert
        cert = json.loads(json_cert)
        assert(cert['0']['Subject'] == isd_as_id)
        as_.sig_pub_key = cert['0']['SubjectSignKey']
        as_.enc_pub_key = cert['0']['SubjectEncKey']
        as_.sig_priv_key = self.loader.keys_sig[isd_as_id]
        as_.enc_priv_key = self.loader.keys_decrypt[isd_as_id]
        # TODO: do we have both master0 and master1 here?
        as_.master_as_key = self.loader.master0s[isd_as_id]
        if as_.is_core:
            as_.core_sig_pub_key = cert['1']['SubjectSignKey']
            as_.core_sig_priv_key = self.loader.core_keys_sig[isd_as_id]
            as_.core_certificate = json.dumps(cert['1'])
        as_.save()

    def _assign_services(self, as_, topo):
        for service_type in SERVICE_TYPES_CONTROL_PLANE:
            serv = topo[TYPES_TO_KEYS[service_type]]
            serv = next(iter(serv.values()))
            public = serv['Addrs']['IPv4']['Public']
            public_ip = public['Addr']
            public_port = public['L4Port']
            bind = serv['Addrs']['IPv4'].get('Bind')
            bind_ip = bind['Addr'] if bind else None
            bind_port = bind['L4Port'] if bind else public_port
            assert(bind_port == public_port)
            host, _ = Host.objects.get_or_create(AS=as_,
                                                 public_ip=public_ip,
                                                 bind_ip=bind_ip,
                                                 internal_ip=public_ip)
            Service.objects.create(host=host, type=service_type, port=public_port)
        serv = topo[TYPES_TO_KEYS[Service.ZK]]['1']
        public_ip = serv['Addr']
        public_port = serv['L4Port']
        host, _ = Host.objects.get_or_create(AS=as_,
                                             public_ip=public_ip,
                                             bind_ip=None,
                                             internal_ip=DEFAULT_HOST_INTERNAL_IP)
        Service.objects.create(host=host, type=Service.ZK, port=public_port)

    def _assign_routers(self, as_, topo):
        brs = topo['BorderRouters']
        for brname, br in sorted(brs.items()):
            internal = br['InternalAddrs']['IPv4']
            public_ip = internal['PublicOverlay']['Addr']
            internal_port = internal['PublicOverlay']['OverlayPort']
            bind_ip = internal['BindOverlay']['Addr'] if 'BindOverlay' in internal else None
            
            ifs = br['Interfaces']
            assert(len(ifs) == 1)
            iface = next(iter(ifs.values()))

def build_scionlab_topology(scionlab_old_gen_path):
    gen = Generator(scionlab_old_gen_path)
    gen.create_isds(isds)
    gen.create_ases(ases)
    print('done')


# if __name__ == '__main__':
#     def print_help():
#         print('Arguments:\n\told_gen:\t'
#               'Path to the old gen folder containing the definitions for all infrastructure'
#               ' (it came from scion-web)')
#     if len(sys.argv) != 2:
#         print_help()
#         sys.exit(1)
#     build_scionlab_topology(sys.argv[1])
