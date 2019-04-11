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


import sys
import os
import re
import lib.packet.scion_addr

from scionlab.fixtures.testtopo import (
    ISDdef, ASdef, LinkDef,
    makeASdef, makeLinkDef
)
from scionlab.models import ISD, AS, Link, AttachmentPoint, Host, Service



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
    # korea (Kompletely made up)
    makeASdef(20, 0x1401, 'K_core1', '192.0.2.41', is_core=True),
    makeASdef(20, 0x1402, 'K_core2', '192.0.2.42', is_core=True),
    makeASdef(20, 0x1403, 'K_L1', '192.0.2.43'),
    makeASdef(20, 0x1404, 'K_AP1', '192.0.2.44', is_ap=True),
    makeASdef(20, 0x1405, 'K_AP2', '192.0.2.45', is_ap=True),
    makeASdef(20, 0x1406, 'K_L3', '192.0.2.46'),
]


class Loader:
    isd_re = re.compile(r'^ISD(\d+)$')
    as_re = re.compile(r'^AS(ffaa.+)$')
    trc_re = re.compile(r'^ISD\d+-V\d+.trc$')
    cert_re = re.compile(r'^ISD\d+-AS.+-V\d+.crt$')
    def __init__(self, gen_path):
        # load TRC
        self.trcs = {}
        self.certs = {}
        self.master0s = {}
        self.master1s = {}
        self.keys_sig = {}
        self.keys_decrypt = {}
        self.core_keys_sig = {}
        self.core_keys_online = {}
        self.core_keys_offline = {}
        for d in os.listdir(gen_path):
            trc = None
            groups = self.isd_re.match(d)
            if not groups:
                continue
            isd_id = groups.group(1)
            dir_isd = os.path.join(gen_path, d)
            for dir_as in os.listdir(dir_isd):
                groups = self.as_re.match(dir_as)
                if not groups:
                    continue
                as_id = groups.group(1)
                # TODO: use standard IA here
                # as_id = scion_addr.ISD_AS(as_id)
                # as_id = as_id
                dir_certs = os.path.join(dir_isd, dir_as, 'endhost', 'certs')
                for cert in os.listdir(dir_certs):
                    if not trc:
                        groups = self.trc_re.match(cert)
                        if groups:
                            with open(os.path.join(dir_certs, cert)) as f:
                                trc = f.read()
                    groups = self.cert_re.match(cert)
                    if groups:
                        with open(os.path.join(dir_certs, cert)) as f:
                            self.certs[as_id] = f.read()
                dir_keys = os.path.join(dir_isd, dir_as, 'endhost', 'keys')
                for key in os.listdir(dir_keys):
                    with open(os.path.join(dir_keys, key)) as f:
                        content = f.read()
                    if key == 'master0.key':
                        self.master0s[as_id] = content
                    elif key == 'master1.key':
                        self.master1s[as_id] = content
                    elif key == 'as-sig.seed':
                        self.keys_sig[as_id] = content
                    elif key == 'as-decrypt.key':
                        self.keys_decrypt[as_id] = content
                    elif key == 'core-sig.seed':
                        self.core_keys_sig[as_id] = content
                    elif key == 'online-root.seed':
                        self.core_keys_online[as_id] = content
                    elif key == 'offline-root.seed':
                        self.core_keys_offline[as_id] = content
            # insert the trc
            self.trcs[isd_id] = trc


class Generator:
    def __init__(self, loader):
        self.loader = loader

    def create_isd(self, isd_def):
        trc = self.loader.trcs[isd_def['isd_id']]


def _create_isd(isd_def, trc):
    ISD.objects.create(**isd_def._asdict(), trc=trc)

def _create_scionlab_isds():
    for isd_def in isds:
        # ISD.objects.create(**isd_def._asdict())
        _create_isd(isd_def,{})
    isd_17 = ISD.objects.get(isd_id=17)
    print(isd_17)


def build_scionlab_topology(scionlab_old_gen_path):
    loader = Loader(scionlab_old_gen_path)
    _create_scionlab_isds()
    print('done')





if __name__ == '__main__':
    def print_help():
        print('Arguments:\n\told_gen:\t'
              'Path to the old gen folder containing the definitions for all infrastructure'
              ' (it came from scion-web)')
    if len(sys.argv) != 2:
        print_help()
        sys.exit(1)
    build_scionlab_topology(sys.argv[1])

