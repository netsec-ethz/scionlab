#!/usr/bin/env python3
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
import binascii
import csv
import datetime
import getpass
import sys
import os
from collections import namedtuple

import django

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def format_password(salt, hash):
    """
    Format a password entry for the SCryptPasswordHasher.
    """
    algorithm = "scrypt"
    Nlog2 = 15
    r = 8
    p = 1
    return "%s$%d$%d$%d$%s$%s" % (algorithm, Nlog2, r, p, salt, hash)


def reencode_password(salt, hash):
    """
    Encode salt/hash from scion-coord database to an entry for the SCryptPasswordHasher.
    """
    salt_b64 = base64.b64encode(binascii.unhexlify(salt)).decode()
    hash_b64 = base64.b64encode(binascii.unhexlify(hash)).decode()
    return format_password(salt_b64, hash_b64)


UserDef = namedtuple('UserDef',
                     ('email', 'password', 'first_name', 'last_name', 'organisation',
                      'created', 'updated'))


def load_users(usertable):
    """
    `usertable` is the path to a CSV with the following fields:

        user.*
        account.organisation

    SELECT user.*, account.organisation FROM user LEFT JOIN account ON user.account_id = account.id;
    """

    users = []
    with open(usertable) as f:
        reader = csv.reader(f)
        next(reader)  # skip headers
        for row in reader:
            fields = iter(row)
            _ = next(fields)  # id
            email = next(fields)
            hash = next(fields)
            password_invalid = bool(int(next(fields)))
            salt = next(fields)
            first_name = next(fields)
            last_name = next(fields)
            is_verified = bool(int(next(fields)))
            is_admin = bool(int(next(fields)))
            _ = next(fields)  # verification_uuid
            _ = next(fields)  # account_id
            created = datetime.datetime.strptime(next(fields), DATE_FORMAT)
            updated = datetime.datetime.strptime(next(fields), DATE_FORMAT)

            # from user.account:
            organisation = next(fields)
            # not importing these:
            if password_invalid or not is_verified or (is_admin and email == 'admin@scionlab.org'):
                print('Warning: not importing user %s' % email)
                continue

            encoded = reencode_password(salt, hash)
            users.append(UserDef(email, encoded, first_name, last_name, organisation,
                                 created, updated))

    return users


def create_users(users):
    from scionlab.models.user import User

    for userdef in users:
        user = User.objects.create_user(
            email=userdef.email,
            password=None,
            first_name=userdef.first_name,
            last_name=userdef.last_name,
            organisation=userdef.organisation,
            date_joined=userdef.created,
        )
        user.password = userdef.password
        user.is_active = True
        user.save()


def get_and_check_password(users, email):
    from scionlab.util.hashers import SCryptPasswordHasher

    user = next((u for u in users if u.email == email), None)
    if user is None:
        print("User not found")
        return
    pwd = getpass.getpass()
    h = SCryptPasswordHasher()
    success = h.verify(pwd, user.password)
    print(success and "OK" or "No")


def main(argv):
    users = load_users(argv[1])
    if len(argv) >= 3:
        get_and_check_password(users, email=argv[2])
    else:
        create_users(users)


if __name__ == '__main__':
    # Mess with PYTHONPATH to include scionlab-root-dir:
    scionlab_root = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..'))
    sys.path.append(scionlab_root)
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'scionlab.settings.development')
    django.setup()

    main(sys.argv)
