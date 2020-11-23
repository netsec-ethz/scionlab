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

import datetime
import base64
import json
import os
import random
from contextlib import ExitStack
from unittest.mock import patch
from scionlab.fixtures import testtopo, testuser, testuseras
from scionlab.openvpn_config import _generate_private_key
from scionlab.scion.keys import generate_key
from scionlab.scion.certs import _build_certificate
from scionlab.scion.trcs import generate_trc


def create_testdata():
    random.seed(0)
    with patch_os_urandom(), patch_django_utils_crypto_random(), \
            patch_time(), patch_datetime(), patch_generate_vpn_private_key(), \
            patch_generate_as_private_key(), patch_build_certificate(), patch_generate_trc():
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

    def key_fun(*args, **kwargs):
        # computes the dictionary key, when called mocking _build_certificate
        return ' | '.join([str(kwargs['subject'][1][5][1]),
                           str(kwargs['issuer'][1][5][1]) if kwargs['issuer'] else 'None',
                           str(kwargs['not_before']),
                           str(kwargs['not_after'])])

    def encode_cert(cert):
        from cryptography.hazmat.primitives import serialization
        return cert.public_bytes(serialization.Encoding.PEM).decode('ascii')

    def decode_cert(cert):
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        return x509.load_pem_x509_certificate(cert.encode('ascii'), default_backend())

    return ObjectCacher(cert_file, _build_certificate, key_fun, encode_cert, decode_cert)


def patch_generate_trc():
    fixture_dir = os.path.dirname(os.path.abspath(__file__))
    trc_file = os.path.join(fixture_dir, 'testdata-trcs.json')

    def key_fun(*args, **kwargs):
        # computes the dictionary key, when called mocking generate_trc
        return ' | '.join([str(kwargs['isd_id']),
                           str(kwargs['base']),
                           str(kwargs['serial']),
                           str(kwargs['primary_ases']),
                           str(kwargs['quorum']),
                           str(kwargs['votes']),
                           str(kwargs['grace_period']),
                           str(kwargs['not_before']),
                           str(kwargs['not_after'])])

    def encode_trc(trc: bytes) -> str:
        # these are simply bytes
        return base64.b64encode(trc).decode('ascii')

    def decode_trc(trc: str) -> bytes:
        return base64.b64decode(trc.encode('ascii'))

    return ObjectCacher(trc_file, generate_trc, key_fun, encode_trc, decode_trc)


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
    from cryptography.hazmat.primitives import serialization
    with open(path, 'w') as f:
        for key in keys:
            k_der = key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            f.write(base64.b64encode(k_der).decode() + '\n')


class ObjectCacher:
    def __init__(self, filename, generate_fun, key_fun, encode_fun, decode_fun):
        self.filename = filename
        self.generate_fun = generate_fun
        self.key_fun = key_fun
        self.encode_fun = encode_fun
        self.decode_fun = decode_fun

        self.objs = self._load()
        self.dirty = False
        self.patched = patch(f"{generate_fun.__module__}.{generate_fun.__name__}",
                             side_effect=self.mock_generate_fun)

    def __enter__(self):
        self.patched.__enter__()

    def __exit__(self, *exc_info):
        if self.dirty:
            self._save()
            print(f"{self.filename} file HAS CHANGED!")
        self.patched.__exit__(*exc_info)

    def mock_generate_fun(self, *args, **kwargs):
        key = self.key_fun(*args, **kwargs)
        c = self.objs.get(key, None)
        if c is None:
            self.dirty = True
            c = self.generate_fun(*args, **kwargs)
            self.objs[key] = c

        return c

    def _load(self):
        if os.path.exists(self.filename):
            with open(self.filename) as f:
                encoded = json.load(f)
            raw = {}
            for k, v in encoded.items():
                raw[k] = self.decode_fun(v)
            return raw
        else:
            return {}

    def _save(self):
        # encode all objs
        encoded = {}
        for k, v in self.objs.items():
            encoded[k] = self.encode_fun(v)
        with open(self.filename, 'w') as f:
            json.dump(encoded, f, sort_keys=True, indent=2)
