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

from datetime import datetime, timedelta
from scionlab.scion import keys, jws
from scionlab.scion.trcs import _utc_timestamp
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec


OID_ISD_AS = ObjectIdentifier("1.3.6.1.4.1.55324.1.2.1")
OID_SENSITIVE_KEY = ObjectIdentifier("1.3.6.1.4.1.55324.1.3.1")
OID_REGULAR_KEY = ObjectIdentifier("1.3.6.1.4.1.55324.1.3.2")
OID_ROOT_KEY = ObjectIdentifier("1.3.6.1.4.1.55324.1.3.3")  # ca root key


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


def test_build_key():
    # valid curves are: SECP256R1, SECP384R1, and secp521r1
    key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
    return key


def test_encode_key(key):
    """
    Returns the bytes as PEM
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())


def test_deleteme_create_a_name(common_name):
    return [(NameOID.COUNTRY_NAME, "CH"),
            (NameOID.STATE_OR_PROVINCE_NAME, "ZH"),
            (NameOID.LOCALITY_NAME, "Zürich"),
            (NameOID.ORGANIZATION_NAME, "Netsec"),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, "Netsec"),
            (NameOID.COMMON_NAME, common_name),
            (OID_ISD_AS, "1-ff00:0:110")]


# def test_build_cert(key, name_list, notvalidbefore, notvalidafter, extensions):
def test_build_cert(subject, issuer, notvalidbefore, notvalidafter, extensions):
    """
    subject is a 2-tuple (key, name_list) for the subject. name_list is a list of 2-tuples (OID, value) for the subject name
    issuer is a 2-tuple (key, name_list) for the issuer name
    extensions is a list of 2-tuples (extension, critical)
    """
    issuer = issuer or subject
    subject_name = x509.Name([x509.NameAttribute(p[0], p[1]) for p in subject[1]])
    issuer_name = x509.Name([x509.NameAttribute(p[0], p[1]) for p in issuer[1]])
    # create certificate
    cert = x509.CertificateBuilder().subject_name(
        subject_name
    ).issuer_name(
        issuer_name
    ).public_key(
        subject[0].public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        notvalidbefore
    ).not_valid_after(
        notvalidafter
    )
    for p in extensions:
        cert = cert.add_extension(p[0], p[1])
    cert = cert.sign(issuer[0], hashes.SHA512(), default_backend())
    return cert


def test_build_extensions_voting(key, issuer_key_type):
    return [(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
            (x509.ExtendedKeyUsage(
                [issuer_key_type, x509.ExtendedKeyUsageOID.TIME_STAMPING]
            ), False)]


def test_build_extensions_root(key):
    """
    Returns a list of 2-tuples (extension,boolean) with the extension and its criticality
    """
    return [(x509.BasicConstraints(True, 1), True),
            (x509.KeyUsage(False,False,False,False,False,True,True, False,False),True),
            (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
            (x509.ExtendedKeyUsage([OID_ROOT_KEY, x509.ExtendedKeyUsageOID.TIME_STAMPING]), False)]


def test_build_extensions_ca(subject_key, issuer_key):
    """
    Returns a list of 2-tuples (extension,boolean) with the extension and its criticality
    """
    return [(x509.BasicConstraints(True, 0), True),
            (x509.KeyUsage(False,False,False,False,False,True,True, False,False),True),
            (x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)]


def test_generate_voting_certs():
    # sensitive:
    key = test_build_key()
    cert = test_build_cert(subject=(key, test_deleteme_create_a_name("sensitive")),
                           issuer=None,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=test_build_extensions_voting(key, OID_SENSITIVE_KEY))
    print(cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    with open("scionlab-test-sensitive.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    # regular:
    key = test_build_key()
    cert = test_build_cert(subject=(key, test_deleteme_create_a_name("regular")),
                           issuer=None,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=test_build_extensions_voting(key, OID_REGULAR_KEY))
    with open("scionlab-test-regular.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    

def test_generate_ca():
    # generate root
    key = test_build_key()
    root_issuer = (key, test_deleteme_create_a_name("root"))
    cert = test_build_cert(subject=root_issuer,
                           issuer=None,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=test_build_extensions_root(key))
    with open("scionlab-test-root.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    # generate ca:
    # TODO the CA is signed with the root key
    key = test_build_key()
    cert = test_build_cert(subject=(key, test_deleteme_create_a_name("ca")),
                           issuer=root_issuer,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=test_build_extensions_ca(key, root_issuer[0]))
    with open("scionlab-test-ca.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    pass


def test_cppki():
    # create voters
    test_generate_voting_certs()
    # create CAs
    test_generate_ca()
    # create ASes
    # create TRCs
    # flatten?


def _build_issuer_cert_payload(as_, version, trc, not_before, not_after, issuer_key):
    return {
        "subject": as_.isd_as_str(),
        "version": version,
        "format_version": 1,
        "description": "Issuer certificate",
        "certificate_type": "issuer",
        "optional_distribution_points": [],
        "validity": {
            "not_before": _utc_timestamp(not_before),
            "not_after": _utc_timestamp(not_after),
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
            "not_before": _utc_timestamp(not_before),
            "not_after": _utc_timestamp(not_after),
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
