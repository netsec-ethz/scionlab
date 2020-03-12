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
:mod:`scionlab.scion.jws` --- Utility/helper module for JSON Web Signatures (JWS)
=================================================================================
"""

import json
import base64
from scionlab.scion import keys


def encode(data: dict) -> str:
    return _b64url(json.dumps(data, sort_keys=True).encode())


def decode(data_enc: str) -> dict:
    return json.loads(_b64urldec(data_enc).decode())


def decode_payload(cert: dict) -> dict:
    """
    Extract the base64-encoded JSON payload.
    Does not verify signatures, nor the payload.
    """
    return decode(cert['payload'])


def signature(payload_enc, protected_enc, signing_key):
    sigmsg = (protected_enc + '.' + payload_enc).encode()
    return _b64url(keys.sign(sigmsg, signing_key))


def verify(payload_enc, protected_enc, signature, verifying_key):
    sigmsg = (protected_enc + '.' + payload_enc).encode()
    return keys.verify(sigmsg, _b64urldec(signature), verifying_key)


def _b64url(input: bytes) -> str:
    return base64.urlsafe_b64encode(input).decode().rstrip('=')


def _b64urldec(input: str) -> bytes:
    # We stripped the (redundant) padding '=', but the decoder checks for them.
    # Appending three = is the easiest way to ensure it won't choke on too little padding.
    return base64.urlsafe_b64decode(input + '===')
