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

import csv
import hashlib
from collections import namedtuple

from django.conf import settings
from scionlab.models.user_as import UserAS, AttachmentPoint
from scionlab.models.user import User


# we have 4 APs. These are their PKs in the CSV:
APs_ROWIDs = [1, 2, 3, 4]


Conn = namedtuple('Conn', (
                'respond_ap',
                'join_ip',
                'respond_ip',
                'respond_br_id',
                'is_vpn'))


def conn_from_fields(respond_ap, join_ip, respond_ip, respond_br_id, is_vpn):
    # join status has to be active or inactive (1 or 0). If it is something else, the
    # corresponding AP has to resolve this. Wait 10 minutes and export to CSV again
    # assert(join_status in ['0', '1']) XXX

    if respond_ap == 'NULL':  # No corresponding connection in DB join
        return None

    return Conn(respond_ap=int(respond_ap),
                join_ip=join_ip,
                respond_ip=respond_ip,
                respond_br_id=int(respond_br_id),
                is_vpn=(is_vpn == '1'))


UAS = namedtuple('UAS', (
                'connection',
                'email',
                'public_ip',
                'public_port',
                'isd',
                'as_id',
                'label',
                'active',
                'type',
                'account_id',
                'account_secret'))


def uas_from_fields(conn,
                    user_email, public_ip, start_port, isd, as_id, label, status, type,
                    account_id, secret):

    if type == '0':
        # ignore infrastructure ASes
        return None
    # only possible AS types left are VM or DEDICATED:
    assert(type == '1' or type == '2')

    as_id = int(as_id)
    assert((as_id > 0xffaa00010000 and as_id < 0xffaa00020000) or
           (as_id > 1000 and as_id < 9000))
    if as_id < 9000:
        old_id = True
        as_id -= 1000
    else:
        old_id = False
        as_id -= 0xffaa00010000
    as_id = 'ffaa:1:%x' % as_id

    return UAS(connection=conn,
               email=user_email,
               public_ip=public_ip,
               public_port=int(start_port),
               isd=int(isd),
               as_id=as_id,
               label=label,
               active=not old_id and status == '1',
               type=UserAS.VM if type == '1' else UserAS.DEDICATED,
               account_id=account_id,
               account_secret=secret)


def _read_user_ases(useras_table):
    """
    `useras_table` is the path to a CSV, created with the following query:

SELECT
    uas.user_email,
    uas.public_ip,
    uas.start_port,
    uas.isd,
    uas.as_id,
    uas.label,
    uas.status,
    uas.type,

    account.account_id,
    account.secret,

    connection.respond_ap,
    connection.join_ip,
    connection.respond_ip,
    connection.respond_br_id,
    connection.is_vpn
FROM
    scion_lab_as uas
    INNER JOIN user
        ON uas.user_email = user.email
    INNER JOIN account
        ON account.id = user.account_id
    LEFT JOIN connection
        ON uas.id = connection.join_as
;

    XXX:  The last join could now also be an inner join as we're ignoring all the ASes without conn.
    """
    user_ases = []
    with open(useras_table) as f:
        rows = csv.reader(f)
        next(iter(rows))
        for r in rows:
            conn = conn_from_fields(*r[-5:])
            uas = uas_from_fields(conn, *r[:-5])
            if conn and uas:
                user_ases.append(uas)
            elif uas:
                print('Skipping, no connection. IA = %s , user = %s' % (uas.as_id, uas.email))
    return user_ases


def _host_id(account_id, as_path_str):
    """
    Generate a host id using the account_id and as-id.
    The exact same logic is in `scion_upgrade_script.sh` to allow generating the host id
    when contacting the new API for first time.

    Note: computes a hash; this is not technically necessary (could also use the concated string)
    but this makes the host-ids the same length as the newly generated ones (16 bytes/32-character
    hex string) so it won't *look* different.
    """
    return hashlib.md5((account_id + as_path_str).encode()).hexdigest()


def _port_from_br_id(br_id):
    # see GetPortNumberFromBRID(brID uint16) uint16
    START_PORT = 50000
    return START_PORT + br_id - 1


def load_user_ASes(path):
    # special settings:
    settings.MAX_ASES_USER = 9999
    # load CSV
    APs = {
        APs_ROWIDs[0]: AttachmentPoint.objects.get(AS__as_id='ffaa:0:1107'),
        APs_ROWIDs[1]: AttachmentPoint.objects.get(AS__as_id='ffaa:0:1202'),
        APs_ROWIDs[2]: AttachmentPoint.objects.get(AS__as_id='ffaa:0:1303'),
        APs_ROWIDs[3]: AttachmentPoint.objects.get(AS__as_id='ffaa:0:1404'),
    }
    # create user ASes:
    uases = _read_user_ases(path)
    for i, uas in enumerate(uases):
        print('doing {} / {}'.format(i+1, len(uases)))
        try:
            user = User.objects.get(email=uas.email)
        except User.DoesNotExist as ex:
            print('User %s does not exist in DB' % uas.email)
            raise ex
        ap = APs[uas.connection.respond_ap]
        is_vpn = uas.connection.is_vpn
        public_ip = uas.public_ip
        public_port = uas.public_port
        bind_ip = '10.0.2.15' if uas.type == UserAS.VM else None
        bind_port = public_port if bind_ip else None
        try:
            as_ = UserAS.objects.create(owner=user,
                                        as_id=uas.as_id,
                                        attachment_point=ap,
                                        public_port=public_port,
                                        installation_type=uas.type,
                                        label=uas.label,
                                        use_vpn=is_vpn,
                                        public_ip=public_ip,
                                        bind_ip=bind_ip,
                                        bind_port=bind_port,
                                        vpn_client_ip=uas.connection.join_ip if is_vpn else None)
            if not uas.active:
                as_.update_active(False)
            # update its certificate version: slightly nasty but we don't have a nicer way (and we
            # don't seem to need it otherwise).
            # UserASes in scion-coord are currently at version 2, so we will bump to version 3
            # because we've changed the keys.
            as_.certificate_chain["0"]['Version'] = 2
            as_.generate_certificate_chain()
            as_.save()

            host = as_.hosts.get()
            host.uid = _host_id(uas.account_id, as_.as_path_str())
            host.secret = uas.account_secret
            host.save()

            # Import previously used interface-id/port on AP side:
            ap_interface = as_.interfaces.get().remote_interface()
            ap_interface.interface_id = uas.connection.respond_br_id
            ap_interface.public_port = _port_from_br_id(uas.connection.respond_br_id)
            ap_interface.save()

        except Exception:
            print('Exception processing row {row} AS ID {asid} from {owner}'.format(
                row=i,
                asid=uas.as_id,
                owner=uas.email
            ))
            raise
