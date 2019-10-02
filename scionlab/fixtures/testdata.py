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

import os
import random
import datetime
from unittest.mock import patch
from scionlab.fixtures import testtopo, testuser, testuseras
from scionlab.openvpn_config import _generate_private_key


def create_testdata():
    random.seed(0)
    with patch_os_urandom(), patch_django_utils_crypto_random(), \
            patch_time(), patch_datetime(), patch_generate_private_key():
        testuser.create_testusers()
        testtopo.create_testtopo()
        testuseras.create_testuserases()


# Somewhat scary trick; to reduce noise when regenerating the fixture from scratch,
# make the AS keys somewhat deterministic by replacing os.urandom with seeded "random" bytes.
def patch_os_urandom():
    r = random.Random(0)

    def seeded_random_bytes(size=32):
        return bytes(r.getrandbits(8) for _ in range(size))

    return patch('os.urandom', side_effect=seeded_random_bytes)


def patch_django_utils_crypto_random():
    r = random.Random(0)
    return patch('django.utils.crypto.random', new=r)


def patch_time():
    return patch('time.time', return_value=1570002792)


def patch_datetime():

    val = datetime.datetime(2019, 10, 2, 11, 7, 41, 0)

    class mydatetime(datetime.datetime):

        @classmethod
        def utcnow(cls):
            return val

    return patch('scionlab.openvpn_config.datetime', new=mydatetime)  # cannot patch globally


def patch_generate_private_key():
    keys = _load_or_create_vpn_keys()
    key_it = iter(keys)

    def get_precomputed_key():
        return next(key_it)

    return patch('scionlab.openvpn_config._generate_private_key', side_effect=get_precomputed_key)


def _load_or_create_vpn_keys():
    fixture_dir = os.path.dirname(os.path.abspath(__file__))
    keys_file = os.path.join(fixture_dir, 'testdata-vpn-keys.txt')
    if not os.path.exists(keys_file):
        keys = [_generate_private_key() for _ in range(16)]
        _dump_vpn_keys(keys, keys_file)
    return _load_vpn_keys(keys_file)


def _load_vpn_keys(path):
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    with open(path) as f:
        keys_der_b64 = f.read().strip().split('\n')
    keys = []
    for k in keys_der_b64:
        k_der = base64.b64decode(k)
        key = serialization.load_der_private_key(k_der, None, backend=default_backend())
        keys.append(key)
    return keys


def _dump_vpn_keys(keys, path):
    import base64
    from cryptography.hazmat.primitives import serialization
    with open(path, 'w') as f:
        for key in keys:
            k_der = key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            f.write(base64.b64encode(k_der).decode() + '\n')
