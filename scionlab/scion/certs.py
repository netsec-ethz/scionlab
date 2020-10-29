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

import hashlib
import subprocess
import toml

from collections import namedtuple
from datetime import datetime, timedelta
from scionlab.scion import keys, jws
from scionlab.scion.as_ids import parse
from scionlab.scion.keys import encode_key, generate_key
from scionlab.scion.trcs import _utc_timestamp, deleteme_generate_trc
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs7 import PKCS7Encoder
from typing import cast, List, Tuple, NamedTuple, Optional


OID_ISD_AS = ObjectIdentifier("1.3.6.1.4.1.55324.1.2.1")
OID_SENSITIVE_KEY = ObjectIdentifier("1.3.6.1.4.1.55324.1.3.1")
OID_REGULAR_KEY = ObjectIdentifier("1.3.6.1.4.1.55324.1.3.2")
OID_ROOT_KEY = ObjectIdentifier("1.3.6.1.4.1.55324.1.3.3")  # ca root key

CN_VOTING_SENSITIVE = "Sensitive Voting Certificate"
CN_VOTING_REGULAR = "Regular Voting Certificate"
CN_ISSUER_ROOT = "High Security Root Certificate"
CN_ISSUER_CA = "Secure CA Certificate"
CN_AS = "AS Certificate"


# some type aliases:
Name = List[Tuple[ObjectIdentifier, str]]
Extensions = List[Tuple[ObjectIdentifier, bool]]


def encode_certificate(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _create_name(as_id: str, common_name: str) -> Name:
    return [(NameOID.COUNTRY_NAME, "CH"),
            (NameOID.STATE_OR_PROVINCE_NAME, "ZH"),
            (NameOID.LOCALITY_NAME, "Zürich"),
            (NameOID.ORGANIZATION_NAME, "Netsec"),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, "Netsec"),
            (NameOID.COMMON_NAME, common_name),
            (OID_ISD_AS, as_id)]


def _build_certificate(subject: Tuple[ec.EllipticCurvePrivateKey, Name],
                       issuer: Optional[Tuple[ec.EllipticCurvePrivateKey, Name]],
                       notvalidbefore: datetime,
                       notvalidafter: datetime,
                       extensions: Extensions) -> x509.Certificate:
    """ Builds a certificate from the parameters. The certificate is signed by the issuer. """
    issuer = issuer or subject
    subject_name = x509.Name([x509.NameAttribute(p[0], p[1]) for p in subject[1]])
    issuer_name = x509.Name([x509.NameAttribute(p[0], p[1]) for p in issuer[1]])
    # create certificate builder
    cert_builder = x509.CertificateBuilder().subject_name(
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
        cert_builder = cert_builder.add_extension(p[0], p[1])
    # use the issuer to sign a certificate
    return cert_builder.sign(issuer[0], hashes.SHA512(), default_backend())


def _build_extensions_voting(key: ec.EllipticCurvePrivateKey,
                             issuer_key_type: ObjectIdentifier) -> Extensions:
    return [(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
            (x509.ExtendedKeyUsage(
                [issuer_key_type, x509.ExtendedKeyUsageOID.TIME_STAMPING]
            ), False)]


def _build_extensions_root(key: ec.EllipticCurvePrivateKey) -> Extensions:
    """
    Returns a list of 2-tuples (extension,boolean) with the extension and its criticality
    """
    return [(x509.BasicConstraints(True, 1), True),
            (x509.KeyUsage(False, False, False, False, False, True, True, False, False), True),
            (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
            (x509.ExtendedKeyUsage([OID_ROOT_KEY, x509.ExtendedKeyUsageOID.TIME_STAMPING]), False)]


def _build_extensions_ca(subject_key: ec.EllipticCurvePrivateKey,
                         issuer_key: ec.EllipticCurvePrivateKey) -> Extensions:
    """
    Returns a list of 2-tuples (extension,boolean) with the extension and its criticality
    """
    return [(x509.BasicConstraints(True, 0), True),
            (x509.KeyUsage(False, False, False, False, False, True, True, False, False), True),
            (x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)]


def _build_extensions_as(subject_key: ec.EllipticCurvePrivateKey,
                         issuer_key: ec.EllipticCurvePrivateKey) -> Extensions:
    """
    Returns a list of 2-tuples (extension,boolean) with the extension and its criticality
    """
    return [(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True),
            (x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False),
            (x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH,
                                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                                    x509.ExtendedKeyUsageOID.TIME_STAMPING]), False)]


def deleteme_generate_voting_certs() -> None:
    # sensitive:
    key = generate_key()
    cert = _build_certificate(subject=(key, _create_name("1-ff00:0:110", "Sensitive Voting Certificate")),
                           issuer=None,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=_build_extensions_voting(key, OID_SENSITIVE_KEY))
    with open("scionlab-test-sensitive.key", "wb") as f:
        f.write(encode_key(key))
    with open("scionlab-test-sensitive.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    # regular:
    key = generate_key()
    cert = _build_certificate(subject=(key, _create_name("1-ff00:0:110", "regular")),
                           issuer=None,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=_build_extensions_voting(key, OID_REGULAR_KEY))
    with open("scionlab-test-regular.key", "wb") as f:
        f.write(encode_key(key))
    with open("scionlab-test-regular.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def deleteme_generate_ca():
    # generate root:
    key = generate_key()
    root_issuer = (key, _create_name("1-ff00:0:110", "root"))
    cert = _build_certificate(subject=root_issuer,
                               issuer=None,
                               notvalidbefore=datetime.utcnow(),
                               notvalidafter=datetime.utcnow() + timedelta(days=1),
                               extensions=_build_extensions_root(key))
    with open("scionlab-test-root.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    # generate ca:
    key = generate_key()
    ca_issuer = (key, _create_name("1-ff00:0:110", "ca"))
    cert = _build_certificate(subject=ca_issuer,
                               issuer=root_issuer,
                               notvalidbefore=datetime.utcnow(),
                               notvalidafter=datetime.utcnow() + timedelta(days=1),
                               extensions=_build_extensions_ca(key, root_issuer[0]))
    with open("scionlab-test-ca.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return ca_issuer, cert


def deleteme_generate_as(issuer, asid):
    """
    issuer is a 2-tuple (key, name)
    """
    key = generate_key()
    cert = _build_certificate(subject=(key, _create_name("1-ff00:0:110", f"Regular AS {asid}")),
                               issuer=issuer,
                               notvalidbefore=datetime.utcnow(),
                               notvalidafter=datetime.utcnow() + timedelta(days=1),
                               extensions=_build_extensions_as(key, issuer[0]))
    with open(f"scionlab-test-as{asid}.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def deleteme_generate_ases(ca_issuer, asids):
    for asid in asids:
        deleteme_generate_as(ca_issuer, asid)


def deleteme() -> str:
    return "deleteme called"


# TODO(juagargi) remove this function
def test_cppki():
    # create voters
    deleteme_generate_voting_certs()
    # create CAs
    ca_issuer, _ = deleteme_generate_ca()
    # create ASes
    deleteme_generate_ases(ca_issuer, ["1-ff00:0:111", "1-ff00:0:112"])
    # create TRCs
    deleteme_generate_trc(1)
    # flatten?
    print(f"{deleteme()}-V1")


def generate_voting_sensitive_certificate(subject_id: str,
                                          subject_key: ec.EllipticCurvePrivateKey,
                                          not_before: datetime,
                                          not_after: datetime) -> x509.Certificate:
    subject = (subject_key, _create_name(subject_id, CN_VOTING_SENSITIVE))
    return _build_certificate(subject=subject,
                              issuer=None,
                              notvalidbefore=not_before,
                              notvalidafter=not_after,
                              extensions=_build_extensions_voting(subject_key, OID_SENSITIVE_KEY))


def generate_voting_regular_certificate(subject_id: str,
                                        subject_key: ec.EllipticCurvePrivateKey,
                                        not_before: datetime,
                                        not_after: datetime) -> x509.Certificate:
    subject = (subject_key, _create_name(subject_id, CN_VOTING_REGULAR))
    return _build_certificate(subject=subject,
                              issuer=None,
                              notvalidbefore=not_before,
                              notvalidafter=not_after,
                              extensions=_build_extensions_voting(subject_key, OID_REGULAR_KEY))


def generate_issuer_root_certificate(subject_id: str,
                                     subject_key: ec.EllipticCurvePrivateKey,
                                     not_before: datetime,
                                     not_after: datetime) -> x509.Certificate:
    """
    Generates an issuer root certificate. Issuer Root Certificates are used to sign CA certificates.
    """
    subject = (subject_key, _create_name(subject_id, CN_ISSUER_ROOT))
    return _build_certificate(subject=subject,
                              issuer=None,
                              notvalidbefore=not_before,
                              notvalidafter=not_after,
                              extensions=_build_extensions_root(subject_key))


def generate_issuer_ca_certificate(subject_id: str,
                                   subject_key: ec.EllipticCurvePrivateKey,
                                   issuer_id: str,
                                   issuer_key: ec.EllipticCurvePrivateKey,
                                   not_before: datetime,
                                   not_after: datetime) -> x509.Certificate:
    """
    Generates an issuer CA certificate.
    CA certificates are used to sign AS certificates.
    CA certificates are signed by Root certificates.
    """
    subject = (subject_key, _create_name(subject_id, CN_ISSUER_CA))
    issuer = (issuer_key, _create_name(issuer_id, CN_ISSUER_ROOT))
    return _build_certificate(subject=subject,
                              issuer=issuer,
                              notvalidbefore=not_before,
                              notvalidafter=not_after,
                              extensions=_build_extensions_ca(subject_key, issuer_key))


def generate_as_certificate(subject_id: str,
                            subject_key: ec.EllipticCurvePrivateKey,
                            issuer_id: str,
                            issuer_key: ec.EllipticCurvePrivateKey,
                            not_before: datetime,
                            not_after: datetime) -> x509.Certificate:
    subject = (subject_key, _create_name(subject_id, CN_AS))
    issuer = (issuer_key, _create_name(issuer_id, CN_ISSUER_CA))
    return _build_certificate(subject=subject,
                              issuer=issuer,
                              notvalidbefore=not_before,
                              notvalidafter=not_after,
                              extensions=_build_extensions_as(subject_key, issuer_key))
