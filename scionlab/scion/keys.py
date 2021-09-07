# Copyright 2020 ETH Zurich
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


"""
:mod:`scionlab.scion.keys` --- SCION key creation and handling functions
========================================================================
"""

import contextlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from tempfile import NamedTemporaryFile
from typing import cast

from scionlab.scion.util import run_scion_pki


def generate_key() -> ec.EllipticCurvePrivateKeyWithSerialization:
    """ Generate an elliptic curve private key """
    # valid curves are: SECP256R1, SECP384R1, and secp521r1
    key = ec.generate_private_key(curve=ec.SECP256R1())
    key = cast(ec.EllipticCurvePrivateKeyWithSerialization, key)  # only for type hints
    return key


def encode_key(key: ec.EllipticCurvePrivateKeyWithSerialization) -> str:
    """ Returns the key as a PEM formatted string """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("ascii")


def decode_key(pem: str) -> ec.EllipticCurvePrivateKey:
    """ Returns an EllipticCurve key from its PEM encoding """
    return serialization.load_pem_private_key(pem.encode("ascii"), password=None)


def verify_key(key: bytes, cert: bytes):
    """
    Verify that the certificate is valid, using the last TRC as anchor.
    Raises ScionPkiError if the certificate is not valid.
    """
    with contextlib.ExitStack() as stack:
        key_file = stack.enter_context(NamedTemporaryFile(suffix=".key"))
        cert_file = stack.enter_context(NamedTemporaryFile(suffix=".crt"))
        files = [key_file, cert_file]
        for f, value in zip(files, [key, cert]):
            f.write(value)
            f.flush()
        _run_scion_pki('match', 'certificate', key_file.name, cert_file.name)


def _run_scion_pki(*args, cwd=None, check=True):
    return run_scion_pki('key', *args, cwd=cwd, check=check)
