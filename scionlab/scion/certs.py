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

import json
import base64
from scionlab.scion import keys
from scionlab.models.core import AS
from scionlab.models.pki import Key, Certificate


def generate_issuer_certificate(as_, version, trc, not_before, not_after,
                                issuing_grant, issuer_key):
    payload = _build_issuer_cert_payload(as_, version, trc, not_before, not_after, issuer_key)
    return _build_signed_issuer_cert(payload, issuing_grant)


def generate_as_certificate(subject: AS, version, not_before, not_after,
                            encryption_key: Key, signing_key: Key,
                            issuer: AS, issuer_cert: Certificate, issuer_key: Key):

    payload = _build_as_cert_payload(subject, version, not_before, not_after, encryption_key,
                                     signing_key, issuer, issuer_cert)
    return _build_signed_as_cert(payload, issuer_key)


def _build_issuer_cert_payload(as_, version, trc, not_before, not_after, issuer_key):
    return {
        "subject": as_.isd_as_str(),
        "version": version,
        "format_version": 1,
        "description": "Issuer certificate",
        "certificate_type": "issuer",
        "validity": {
            "not_before": int(not_before.timestamp()),
            "not_after": int(not_after.timestamp())
        },
        "keys": {
            "issuing": {
                "algorithm": "Ed25519",
                "key": keys.public_sign_key(issuer_key.key),
                "key_version": issuer_key.version,
            }
        },
        "issuer": {
            "trc_version": trc.version,
        }
    }


def _build_signed_issuer_cert(payload, issuing_grant):
    protected = {
        "alg": "Ed25519",
        "crit": ["type", "trc_version"],
        "type": "trc",
        "trc_version": payload["issuer"]["trc_version"]
    }
    return _build_signed_cert(payload, protected, issuing_grant)


def _build_as_cert_payload(subject: AS, version, not_before, not_after, encryption_key: Key,
                           signing_key: Key, issuer: AS, issuer_cert: Certificate):
    return {
        "subject": subject.isd_as_str(),
        "version": version,
        "format_version": 1,
        "description": "AS certificate",
        "certificate_type": "as",
        "validity": {
            "not_before": int(not_before.timestamp()),
            "not_after": int(not_after.timestamp())
        },
        "keys": {
            "encryption": {
                "algorithm": "curve25519",
                "key": encryption_key.key,
                "key_version": encryption_key.version,
            },
            "signing": {
                "algorithm": "Ed25519",
                "key": signing_key.key,
                "key_version": signing_key.version,
            }
        },
        "issuer": {
            "isd_as": issuer.isd_as_str(),
            "certificate_version": issuer_cert.version,
        }
    }


def _build_signed_as_cert(payload, issuer_key):
    protected = {
        "alg": "Ed25519",
        "crit": ["type", "certificate_version", "isd_as"],
        "type": "certificate",
        "certificate_version": payload["issuer"]["certificate_version"],
        "isd_as": payload["issuer"]["isd_as"],
    }
    return _build_signed_cert(payload, protected, issuer_key)


def _build_signed_cert(payload, protected, signing_key):
    payload_enc = b64url(json.dumps(payload).encode())
    protected_enc = b64url(json.dumps(protected).encode())
    return {
        "payload": payload_enc,
        "protected": protected_enc,
        "signature": _jws_signature(payload_enc, protected_enc, signing_key.key)
    }


def _jws_signature(payload_enc, protected_enc, signing_key):
    sigmsg = (protected_enc + '.' + payload_enc).encode()
    return {
        "protected": protected_enc,
        "signature": b64url(keys.sign(sigmsg, signing_key))
    }


def b64url(input: bytes) -> str:
    return base64.urlsafe_b64encode(input).decode().rstrip('=')


def b64urldec(input: str) -> bytes:
    # We stripped the (redundant) padding '=', but the decoder checks for them.
    # Appending three = is the easiest way to ensure it won't choke on too little padding.
    return base64.urlsafe_b64decode(input + '===')
