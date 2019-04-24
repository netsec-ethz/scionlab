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
import getpass
import sys
from collections import namedtuple

from scionlab.util.hashers import SCryptPasswordHasher


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


UserDef = namedtuple('UserDef', ('email', 'first_name', 'last_name', 'password'))


def load_users(filename):
    users = []
    with open(filename) as f:
        reader = csv.reader(f)
        next(reader)  # skip headers
        for row in reader:
            # id,
            email = row[1]
            hash = row[2]
            # password_invalid,
            salt = row[4]
            first_name = row[5]
            last_name = row[6]
            is_verified = bool(int(row[7]))
            is_admin = bool(int(row[8]))
            # verification_uuid
            # account_id # TODO
            # created
            # updated

            if not is_verified or is_admin:  # not importing these...
                continue

            encoded = reencode_password(salt, hash)
            users.append(UserDef(email, first_name, last_name, encoded))
    return users


def get_and_check_password(users, email):
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


if __name__ == '__main__':
    main(sys.argv)
