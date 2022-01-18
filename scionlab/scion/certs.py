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

See https://scion.docs.anapaya.net/en/latest/cryptography/certificates.html
Permalink: https://github.com/scionproto/scion/blob/835b3683c6e6bdf2a98750ec3a04137053f7f142/doc/cryptography/certificates.rst
""" # noqa

from cryptography import x509
from cryptography.x509 import ExtensionType
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime
from tempfile import NamedTemporaryFile
from typing import List, Tuple, Optional, NamedTuple

from scionlab.scion.pkicommand import run_scion_pki


OID_ISD_AS = ObjectIdentifier('1.3.6.1.4.1.55324.1.2.1')
OID_SENSITIVE_KEY = ObjectIdentifier('1.3.6.1.4.1.55324.1.3.1')
OID_REGULAR_KEY = ObjectIdentifier('1.3.6.1.4.1.55324.1.3.2')
OID_ROOT_KEY = ObjectIdentifier('1.3.6.1.4.1.55324.1.3.3')  # ca root key

CN_VOTING_SENSITIVE = 'Sensitive Voting Certificate'
CN_VOTING_REGULAR = 'Regular Voting Certificate'
CN_ISSUER_ROOT = 'High Security Root Certificate'
CN_ISSUER_CA = 'Secure CA Certificate'
CN_AS = 'AS Certificate'


class Extension(NamedTuple):
    extension: ExtensionType
    critical: bool


# some type aliases:
Name = List[Tuple[ObjectIdentifier, str]]
Extensions = List[Extension]


def encode_certificate(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def decode_certificate(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def verify_certificate_valid(cert: str, cert_usage: str):
    """
    Verifies that the certificate's fields are valid for that type.
    The certificate is passed as a PEM string.
    This function does not verify the trust chain
    (see also verify_cp_as_chain).
    """
    with NamedTemporaryFile('w', suffix=".crt") as f:
        f.write(cert)
        f.flush()
        _run_scion_pki_certificate('validate', '--type', cert_usage, '--check-time', f.name)


def verify_cp_as_chain(cert: str, trc: str):
    """
    Verify that the certificate is valid, using the last TRC as anchor.
    The certificate is passed as a PEM string.
    The TRC is passed as bytes, basee 64 format.
    Raises ScionPkiError if the certificate is not valid.
    """
    with NamedTemporaryFile(mode='wt', suffix=".trc") as trc_file,\
         NamedTemporaryFile(mode='wt', suffix=".pem") as cert_file:
        files = [trc_file, cert_file]
        for f, value in zip(files, [trc, cert]):
            f.write(value)
            f.flush()
        _run_scion_pki_certificate('verify', '--trc', trc_file.name, cert_file.name)


def generate_voting_sensitive_certificate(subject_id: str,
                                          subject_key: ec.EllipticCurvePrivateKey,
                                          not_before: datetime,
                                          not_after: datetime) -> x509.Certificate:
    subject = (subject_key, _create_name(subject_id, CN_VOTING_SENSITIVE))
    return _build_certificate(subject=subject,
                              issuer=None,
                              not_before=not_before,
                              not_after=not_after,
                              extensions=_build_extensions_voting(subject_key, OID_SENSITIVE_KEY))


def generate_voting_regular_certificate(subject_id: str,
                                        subject_key: ec.EllipticCurvePrivateKey,
                                        not_before: datetime,
                                        not_after: datetime) -> x509.Certificate:
    subject = (subject_key, _create_name(subject_id, CN_VOTING_REGULAR))
    return _build_certificate(subject=subject,
                              issuer=None,
                              not_before=not_before,
                              not_after=not_after,
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
                              not_before=not_before,
                              not_after=not_after,
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
                              not_before=not_before,
                              not_after=not_after,
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
                              not_before=not_before,
                              not_after=not_after,
                              extensions=_build_extensions_as(subject_key, issuer_key))


def _create_name(as_id: str, common_name: str) -> Name:
    return [(NameOID.COUNTRY_NAME, 'CH'),
            (NameOID.STATE_OR_PROVINCE_NAME, 'ZH'),
            (NameOID.LOCALITY_NAME, 'Zürich'),
            (NameOID.ORGANIZATION_NAME, 'Netsec'),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, 'Netsec'),
            (NameOID.COMMON_NAME, f'{as_id} {common_name}'),
            (OID_ISD_AS, as_id)]


def _build_certificate(subject: Tuple[ec.EllipticCurvePrivateKey, Name],
                       issuer: Optional[Tuple[ec.EllipticCurvePrivateKey, Name]],
                       not_before: datetime,
                       not_after: datetime,
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
        not_before
    ).not_valid_after(
        not_after
    )
    for ext in extensions:
        cert_builder = cert_builder.add_extension(ext.extension, ext.critical)
    # use the issuer to sign a certificate
    return cert_builder.sign(issuer[0], hashes.SHA512())


def _build_extensions_voting(key: ec.EllipticCurvePrivateKey,
                             issuer_key_type: ObjectIdentifier) -> Extensions:
    return [Extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                      critical=False),
            Extension(x509.ExtendedKeyUsage([issuer_key_type,
                                             x509.ExtendedKeyUsageOID.TIME_STAMPING]),
                      critical=False)]


def _build_extensions_root(key: ec.EllipticCurvePrivateKey) -> Extensions:
    """
    Returns a list of Extension with the extension and its criticality
    """
    return [Extension(x509.BasicConstraints(ca=True, path_length=1),
                      critical=True),
            Extension(x509.KeyUsage(digital_signature=False,
                                    content_commitment=False,
                                    key_encipherment=False,
                                    data_encipherment=False,
                                    key_agreement=False,
                                    key_cert_sign=True,
                                    crl_sign=True,
                                    encipher_only=False,
                                    decipher_only=False),
                      critical=True),
            Extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                      critical=False),
            Extension(x509.ExtendedKeyUsage([OID_ROOT_KEY,
                                             x509.ExtendedKeyUsageOID.TIME_STAMPING]),
                      critical=False)]


def _build_extensions_ca(subject_key: ec.EllipticCurvePrivateKey,
                         issuer_key: ec.EllipticCurvePrivateKey) -> Extensions:
    """
    Returns a list of Extension with the extension and its criticality
    """
    return [Extension(x509.BasicConstraints(ca=True, path_length=0),
                      critical=True),
            Extension(x509.KeyUsage(digital_signature=False,
                                    content_commitment=False,
                                    key_encipherment=False,
                                    data_encipherment=False,
                                    key_agreement=False,
                                    key_cert_sign=True,
                                    crl_sign=True,
                                    encipher_only=False,
                                    decipher_only=False),
                      critical=True),
            Extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
                      critical=False),
            Extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                      critical=False)]


def _build_extensions_as(subject_key: ec.EllipticCurvePrivateKey,
                         issuer_key: ec.EllipticCurvePrivateKey) -> Extensions:
    """
    Returns a list of Extension with the extension and its criticality
    """
    return [Extension(x509.KeyUsage(digital_signature=True,
                                    content_commitment=False,
                                    key_encipherment=False,
                                    data_encipherment=False,
                                    key_agreement=False,
                                    key_cert_sign=False,
                                    crl_sign=False,
                                    encipher_only=False,
                                    decipher_only=False),
                      critical=True),
            Extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
                      critical=False),
            Extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                      critical=False),
            Extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH,
                                             x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                                             x509.ExtendedKeyUsageOID.TIME_STAMPING]),
                      critical=False)]


def _run_scion_pki_certificate(*args, cwd=None, check=True):
    return run_scion_pki('certificate', *args, cwd=cwd, check=check)
