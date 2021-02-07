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

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from typing import cast


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
