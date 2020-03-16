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

import base64

from nacl.exceptions import BadSignatureError
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey


class Base64StringEncoder:
    @staticmethod
    def encode(data):
        return base64.b64encode(data).decode()

    @staticmethod
    def decode(data):
        return base64.b64decode(data)


def generate_sign_key():
    """
    Generate Ed25519 keypair.

    :returns: a private key, usable for signing, encoded in base64
    :rtype: str:
    """
    sk = SigningKey.generate()
    return sk.encode(encoder=Base64StringEncoder)


def public_sign_key(signing_key):
    """
    Return the public key corresponding to this signing private key.

    :returns: a public key corresponding to signing_key, encoded in base64
    :rtype: str:
    """
    sk = SigningKey(signing_key, encoder=Base64StringEncoder)
    return sk.verify_key.encode(encoder=Base64StringEncoder)


def sign(msg, signing_key):
    """
    Sign a message with a given signing key and return the signature.

    :param bytes msg: message to be signed.
    :param str signing_key: signing key from generate_sign_key().
    :returns: ed25519 signature.
    :rtype: bytes
    """
    return SigningKey(signing_key, encoder=Base64StringEncoder).sign(msg).signature


def verify(msg, sig, verifying_key):
    """
    Verify a signature.

    :param bytes msg: message that was signed.
    :param bytes sig: signature to verify.
    :param str verifying_key: verifying key from generate_sign_key().
    :returns: True or False whether the verification succeeds or fails.
    :rtype: boolean
    """
    try:
        return msg == VerifyKey(verifying_key, encoder=Base64StringEncoder).verify(msg, sig)
    except BadSignatureError:
        return False


def generate_enc_key():
    """
    Generate Curve25519 keypair

    :returns: a private key, usable for encryption, encoded in base64
    :rtype: str:
    """
    private_key = PrivateKey.generate()
    return private_key.encode(encoder=Base64StringEncoder)


def public_enc_key(private_key):
    """
    Return the public key corresponding to this private key.

    :returns: a public key corresponding to priv_key, encoded in base64
    :rtype: str:
    """
    pk = PrivateKey(private_key, encoder=Base64StringEncoder)
    return pk.public_key.encode(encoder=Base64StringEncoder)
