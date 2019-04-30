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

import os
import csv

from django.conf import settings
from scionlab.models.user_as import UserAS, AttachmentPoint
from scionlab.models.user import User
from scionlab.util import as_ids


# we have 4 APs. These are their PKs in the CVS:
APs_ROWIDs = [1, 2, 3, 4]
DEFAULT_AP = AttachmentPoint.objects.get(AS__as_id='ffaa:0:1107')


class CSV_Loader:
    class Conn:
        def __init__(self,
                     join_as,
                     respond_ap,
                     join_ip,
                     respond_ip,
                     respond_br_id,
                     is_vpn):
            self.join_as = int(join_as)
            self.respond_ap = int(respond_ap)
            self.join_ip = join_ip
            self.respond_ip = respond_ip
            self.respond_interface_id = int(respond_br_id)
            self.is_vpn = True if is_vpn == '1' else False

        @classmethod
        def from_row(cls, row):
            # join status is 1 or 0
            assert(row[9] == '1' or row[9] == '0')
            return cls(row[1],
                       row[2],
                       row[3],
                       row[4],
                       row[6],
                       row[8])

    class UAS:
        def __init__(self,
                     row_id,
                     email,
                     public_ip,
                     public_port,
                     isd,
                     as_id,
                     label,
                     status,
                     type):
            self.row_id = int(row_id)
            self.email = email
            self.public_ip = public_ip
            self.public_port = int(public_port)
            as_id = int(as_id)
            # TODO: we don't want to migrate old IDs, fix them in the old DB Remove this from here and do not forget
            assert((as_id > 0xffaa00010000 and as_id < 0xffaa00020000) or
                   (as_id > 1000 and as_id < 9000))
            self.as_id = 'ffaa:1:%x' % (as_id - 1000 if as_id < 9000 else (as_id - 0xffaa00010000))
            self.label = label
            self.active = True if status == '1' else False
            if type != '1' and type != '2':
                raise ValueError('Wrong type')
            self.type = UserAS.VM if type == '1' else UserAS.DEDICATED
            # last indicate this UAS is not yet linked with a connection
            self.connection = None

        @classmethod
        def from_row(cls, row):
            return cls(row_id=row[0],
                       email=row[1],
                       public_ip=row[2],
                       public_port=row[3],
                       isd=row[4],
                       as_id=row[5],
                       label=row[7],
                       status=row[8],
                       type=row[9]) if row[9] != '0' else None

    def __init__(self, base_path):
        self.base_path = base_path
        self.conn_rows = []
        self.ases_rows = []

        self._load_connections()
        self._load_user_ases()
        self._match()

    def _load_connections(self):
        """ Loads the connection table from a CSV file """
        path = os.path.join(self.base_path, 'connection.csv')
        with open(path) as f:
            r = csv.reader(f)
            next(iter(r))
            self.conn_rows = [self.Conn.from_row(c) for c in r]

    def _load_user_ases(self):
        """ Loads the scion_lab_as table from a CSV file """
        path = os.path.join(self.base_path, 'scion_lab_as.csv')
        with open(path) as f:
            r = csv.reader(f)
            next(iter(r))
            self.ases_rows = list(filter(None, [self.UAS.from_row(a) for a in r]))

    def _match(self):
        m = {a.row_id: a for a in self.ases_rows}
        for c in self.conn_rows:
            uas = m[c.join_as]
            assert(uas.connection is None)
            uas.connection = c

    def user_ases(self):
        return self.ases_rows


def load_user_ASes():
    # special settings:
    settings.MAX_ASES_USER = 9999
    # load CSV
    loader = CSV_Loader('.')
    APs = {
        APs_ROWIDs[0]: AttachmentPoint.objects.get(AS__as_id='ffaa:0:1107'),
        APs_ROWIDs[1]: AttachmentPoint.objects.get(AS__as_id='ffaa:0:1202'),
        APs_ROWIDs[2]: AttachmentPoint.objects.get(AS__as_id='ffaa:0:1303'),
        APs_ROWIDs[3]: AttachmentPoint.objects.get(AS__as_id='ffaa:0:1404'),
    }
    # create user ASes:
    i = 0
    for uas in loader.user_ases():
        i += 1
        user = User.objects.get(email=uas.email)
        if uas.connection is None:
            active = False
            ap = DEFAULT_AP
            is_vpn = False
            public_ip = '127.0.0.1'  # should be invalid when this gets activated
            public_port = 0
        else:
            active = True
            ap = APs[uas.connection.respond_ap]
            is_vpn = uas.connection.is_vpn
            public_ip = uas.public_ip
            public_port = uas.public_port
        bind_ip = '10.0.2.15' if uas.type == UserAS.VM else None
        bind_port = public_port if bind_ip else None
        try:
            as_ = UserAS.objects.create(owner=user,
                                        attachment_point=ap,
                                        public_port=public_port,
                                        installation_type=uas.type,
                                        label=uas.label,
                                        use_vpn=is_vpn,
                                        public_ip=public_ip,
                                        bind_ip=bind_ip,
                                        bind_port=bind_port,
                                        vpn_client_ip=uas.connection.join_ip if is_vpn else None)
            as_.update_active(active)
            as_.as_id = uas.as_id
            as_.as_id_int = as_ids.parse(uas.as_id)
            as_.save()
        except Exception:
            print('Exception processing row {row} AS ID {asid} from {owner}'.format(
                row=i,
                asid=uas.as_id,
                owner=uas.email
            ))
            raise
        print('done {} / {}'.format(i, len(loader.user_ases())))
