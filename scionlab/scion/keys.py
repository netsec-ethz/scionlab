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
=======================================================
"""

import base64

from nacl.exceptions import BadSignatureError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random


class Base64StringEncoder:
    @staticmethod
    def encode(data):
        return base64.b64encode(data).decode()

    @staticmethod
    def decode(data):
        return base64.b64decode(data)


# XXX(matzf): instead of repeating encoder=Base64StringEncoder a dozen times:
# class _B64EncodedMixin(SigningKey):
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, encoder=Base64StringEncoder, **kwargs)

#     def encode(self, *args, **kwargs):
#         return super().encode(*args, encoder=Base64StringEncoder, **kwargs)

# class _SigningKey(PrivateKey, _B64EncodedMixin):
#     pass
# class _VerifyKey(PrivateKey, _B64EncodedMixin):
#     pass


def generate_sign_key():
    """
    Generate Ed25519 keypair.

    :returns: a private key, usable for signing.
    :rtype: bytes:
    """
    sk = SigningKey.generate()
    return sk.encode(encoder=Base64StringEncoder)


def public_sign_key(signing_key):
    """
    Return the public key corresponding to this signing private key.

    :returns: a public key corresponding to priv_key
    :rtype: bytes:
    """
    sk = SigningKey(signing_key, encoder=Base64StringEncoder)
    return sk.verify_key.encode(encoder=Base64StringEncoder)


def sign(msg, signing_key):
    """
    Sign a message with a given signing key and return the signature.

    :param bytes msg: message to be signed.
    :param bytes signing_key: signing key from generate_signature_keypair().
    :returns: ed25519 signature.
    :rtype: bytes
    """
    return SigningKey(signing_key, encoder=Base64StringEncoder).sign(msg)[:64]


def verify(msg, sig, verifying_key):
    """
    Verify a signature.

    :param bytes msg: message that was signed.
    :param bytes sig: signature to verify.
    :param bytes verifying_key: verifying key from generate_signature_keypair().
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

    :returns: a private key, usable for encryption.
    :rtype: bytes:
    """
    private_key = PrivateKey.generate()
    return private_key.encode(encoder=Base64StringEncoder)


def encrypt(msg, private_key, public_key):
    """
    Encrypt message.

    :param bytes msg: message to be encrypted.
    :param bytes private_key: Private Key of encrypter.
    :param bytes public_key: Public Key of decrypter.
    :returns: The encrypted message.
    :rtype: nacl.utils.EncryptedMessage
    """
    box = Box(
        PrivateKey(private_key, encoder=Base64StringEncoder),
        PublicKey(public_key, encoder=Base64StringEncoder)
    )
    return box.encrypt(msg, random(Box.NONCE_SIZE))


def decrypt(msg, private_key, public_key):
    """
    Decrypt ciphertext.

    :param bytes msg: ciphertext to be decrypted.
    :param bytes private_key: Private Key of decrypter.
    :param bytes public_key: Public Key of encrypter.
    :returns: The decrypted message.
    :rtype: bytes
    """
    box = Box(
        PrivateKey(private_key, encoder=Base64StringEncoder),
        PublicKey(public_key, encoder=Base64StringEncoder)
    )
    return box.decrypt(msg)
