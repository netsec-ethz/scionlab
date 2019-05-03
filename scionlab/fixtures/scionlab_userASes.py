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
from collections import namedtuple

from django.conf import settings
from scionlab.models.user_as import UserAS, AttachmentPoint
from scionlab.models.user import User
from scionlab.util import as_ids


# we have 4 APs. These are their PKs in the CSV:
APs_ROWIDs = [1, 2, 3, 4]
DEFAULT_AP = AttachmentPoint.objects.get(AS__as_id='ffaa:0:1107')


Conn = namedtuple('Conn', (
                'join_as',
                'respond_ap',
                'join_ip',
                'respond_ip',
                'respond_br_id',
                'is_vpn'))


def conn_from_row(row):
    # join status is 1 or 0:
    assert(row[9] == '1' or row[9] == '0')
    return Conn(join_as=int(row[1]),
                respond_ap=int(row[2]),
                join_ip=row[3],
                respond_ip=row[4],
                respond_br_id=int(row[6]),
                is_vpn=row[8] == '1')


UAS = namedtuple('UAS', (
                'connection',
                'row_id',
                'email',
                'public_ip',
                'public_port',
                'isd',
                'as_id',
                'label',
                'active',
                'type'))


def uas_from_row(row):
    if row[9] == '0':
        # ignore infrastructure ASes
        return None
    as_id = int(row[5])
    assert((as_id > 0xffaa00010000 and as_id < 0xffaa00020000) or
           (as_id > 1000 and as_id < 9000))
    if as_id < 9000:
        old_id = True
        as_id -= 1000
    else:
        old_id = False
        as_id -= 0xffaa00010000
    as_id = 'ffaa:1:%x' % as_id
    # only possible AS types left are VM or DEDICATED:
    assert(row[9] == '1' or row[9] == '2')
    return UAS(connection=None,
               row_id=int(row[0]),
               email=row[1],
               public_ip=row[2],
               public_port=int(row[3]),
               isd=int(row[4]),
               as_id=as_id,
               label=row[7],
               active=not old_id and row[8] == '1',
               type=UserAS.VM if row[9] == '1' else UserAS.DEDICATED)


class CSV_Loader:
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
            self.conn_rows = [conn_from_row(c) for c in r]

    def _load_user_ases(self):
        """ Loads the scion_lab_as table from a CSV file """
        path = os.path.join(self.base_path, 'scion_lab_as.csv')
        with open(path) as f:
            r = csv.reader(f)
            next(iter(r))
            self.ases_rows = {a.row_id: a for a in filter(None, [uas_from_row(a) for a in r])}

    def _match(self):
        for c in self.conn_rows:
            assert(self.ases_rows[c.join_as].connection is None)
            self.ases_rows[c.join_as] = self.ases_rows[c.join_as]._replace(connection=c)

    def user_ases(self):
        return self.ases_rows.values()


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
    uases = loader.user_ases()
    for uas in uases:
        i += 1
        user = User.objects.get(email=uas.email)
        active = uas.active
        if uas.connection is None:
            active = False
            ap = DEFAULT_AP
            is_vpn = False
            public_ip = '127.0.0.1'  # should be invalid when this gets activated
            public_port = 0
        else:
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
