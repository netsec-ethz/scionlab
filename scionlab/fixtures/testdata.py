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

import json
import os
import random
import datetime
from contextlib import ExitStack
from unittest.mock import patch
from scionlab.fixtures import testtopo, testuser, testuseras
from scionlab.openvpn_config import _generate_private_key
from scionlab.scion.keys import generate_key
from scionlab.scion.certs import _build_certificate


def create_testdata():
    random.seed(0)
    with patch_os_urandom(), patch_django_utils_crypto_random(), \
            patch_time(), patch_datetime(), patch_generate_vpn_private_key(), \
            patch_generate_as_private_key(), patch_build_certificate():
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
    return patch('secrets.choice', side_effect=r.choice)


def patch_time():
    return patch('time.time', return_value=1570002792)


def patch_datetime():

    val = datetime.datetime(2019, 10, 2, 11, 7, 41, 0)

    class mydatetime(datetime.datetime):

        @classmethod
        def utcnow(cls):
            return val

    # Note: cannot patch globally as datetime is immutable built-in
    # Patch all imports
    patched_imports = [
        'scionlab.openvpn_config.datetime',
        'scionlab.models.core.datetime',
        'scionlab.models.pki.datetime',
    ]
    stack = ExitStack()
    for pi in patched_imports:
        stack.enter_context(patch(pi, new=mydatetime))
    return stack


def patch_generate_vpn_private_key():
    keys = _load_or_create_vpn_keys()
    key_it = iter(keys)

    def get_precomputed_key():
        return next(key_it)

    return patch('scionlab.openvpn_config._generate_private_key', side_effect=get_precomputed_key)


def patch_generate_as_private_key():
    keys = _load_or_create_as_keys()
    key_it = iter(keys)

    def get_precomputed_key():
        return next(key_it)

    return patch('scionlab.scion.keys.generate_key', side_effect=get_precomputed_key)


def patch_build_certificate():
    fixture_dir = os.path.dirname(os.path.abspath(__file__))
    cert_file = os.path.join(fixture_dir, 'testdata-as-certs.json')

    return CertPatcher(cert_file)


def _load_or_create_vpn_keys():
    fixture_dir = os.path.dirname(os.path.abspath(__file__))
    keys_file = os.path.join(fixture_dir, 'testdata-vpn-keys.txt')
    if not os.path.exists(keys_file):
        keys = [_generate_private_key() for _ in range(16)]
        _dump_keys(keys, keys_file)
    return _load_keys(keys_file)


def _load_or_create_as_keys():
    fixture_dir = os.path.dirname(os.path.abspath(__file__))
    keys_file = os.path.join(fixture_dir, 'testdata-as-keys.txt')
    if not os.path.exists(keys_file):
        keys = [generate_key() for _ in range(60)]
        _dump_keys(keys, keys_file)
    return _load_keys(keys_file)


def _load_keys(path):
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


def _dump_keys(keys, path):
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


class CertPatcher:
    def __init__(self, filename):
        self.filename = filename
        self.certs = self._load()
        self.dirty = False
        self.patched = patch('scionlab.scion.certs._build_certificate', side_effect=self.get_cert)

    def __enter__(self):
        self.patched.__enter__()

    def __exit__(self, *exc_info):
        if self.dirty:
            self._save()
            print("Certificates file HAS CHANGED!")
        self.patched.__exit__(*exc_info)

    def get_cert(self, subject, issuer, not_before, not_after, extensions):
        key = ' | '.join([str(subject[1][5][1]),
                          str(issuer[1][5][1]) if issuer else 'None',
                          str(not_before),
                          str(not_after)])

        c = self.certs.setdefault(key, None)
        if c is None:
            self.dirty = True
            c = _build_certificate(subject, issuer, not_before, not_after, extensions)
            self.certs[key] = c

        return c

    def _load(self):
        if os.path.exists(self.filename):
            with open(self.filename) as f:
                return self._decode_certs(json.load(f))
        else:
            return {}

    def _save(self):
        # encode all certs
        with open(self.filename, 'w') as f:
            json.dump(self._encode_certs(self.certs), f, sort_keys=True, indent=2)

    @staticmethod
    def _encode_certs(certs):
        from cryptography.hazmat.primitives import serialization

        serialized = {}
        for k, v in certs.items():
            serialized[k] = v.public_bytes(serialization.Encoding.PEM).decode('ascii')
        return serialized

    @staticmethod
    def _decode_certs(certs):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        raw = {}
        for k, v in certs.items():
            raw[k] = x509.load_pem_x509_certificate(v.encode('ascii'), default_backend())
        return raw
