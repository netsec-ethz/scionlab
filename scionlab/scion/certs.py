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
:mod:`scionlab.scion.certs` --- SCION Issuer Certificate and AS certificate creation
====================================================================================
"""

from scionlab.scion import keys, jws


def generate_issuer_certificate(as_, version: int, trc, not_before, not_after,
                                issuing_grant, issuer_key):
    payload = _build_issuer_cert_payload(as_, version, trc, not_before, not_after, issuer_key)
    return _build_signed_issuer_cert(payload, issuing_grant)


def generate_as_certificate(subject, version, not_before, not_after,
                            encryption_key, signing_key,
                            issuer, issuer_cert, issuer_key):

    payload = _build_as_cert_payload(subject, version, not_before, not_after, encryption_key,
                                     signing_key, issuer, issuer_cert)
    leaf_cert = _build_signed_as_cert(payload, issuer_key)
    return [issuer_cert.certificate, leaf_cert]


def _build_issuer_cert_payload(as_, version, trc, not_before, not_after, issuer_key):
    return {
        "subject": as_.isd_as_str(),
        "version": version,
        "format_version": 1,
        "description": "Issuer certificate",
        "certificate_type": "issuer",
        "optional_distribution_points": [],
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


def _build_as_cert_payload(subject, version, not_before, not_after, encryption_key,
                           signing_key, issuer, issuer_cert):
    return {
        "subject": subject.isd_as_str(),
        "version": version,
        "format_version": 1,
        "description": "AS certificate",
        "certificate_type": "as",
        "optional_distribution_points": [],
        "validity": {
            "not_before": int(not_before.timestamp()),
            "not_after": int(not_after.timestamp())
        },
        "keys": {
            "encryption": {
                "algorithm": "curve25519",
                "key": keys.public_enc_key(encryption_key.key),
                "key_version": encryption_key.version,
            },
            "signing": {
                "algorithm": "Ed25519",
                "key": keys.public_sign_key(signing_key.key),
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
    payload_enc = jws.encode(payload)
    protected_enc = jws.encode(protected)
    return {
        "payload": payload_enc,
        "protected": protected_enc,
        "signature": jws.signature(payload_enc, protected_enc, signing_key.key)
    }
