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

from datetime import datetime, timedelta
from scionlab.scion import keys, jws
from scionlab.scion.as_ids import parse
from scionlab.scion.trcs import _utc_timestamp
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs7 import PKCS7Encoder


OID_ISD_AS = ObjectIdentifier("1.3.6.1.4.1.55324.1.2.1")
OID_SENSITIVE_KEY = ObjectIdentifier("1.3.6.1.4.1.55324.1.3.1")
OID_REGULAR_KEY = ObjectIdentifier("1.3.6.1.4.1.55324.1.3.2")
OID_ROOT_KEY = ObjectIdentifier("1.3.6.1.4.1.55324.1.3.3")  # ca root key


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


def test_load_key(filename):
    with open(filename, "rb") as f:
        k = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    return k


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


def test_build_extensions_as(subject_key, issuer_key):
    """
    Returns a list of 2-tuples (extension,boolean) with the extension and its criticality
    """
    return [(x509.KeyUsage(True, False, False, False, False, False, False, False, False),True),
            (x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False),
            (x509.ExtendedKeyUsage(
                [x509.ExtendedKeyUsageOID.SERVER_AUTH, x509.ExtendedKeyUsageOID.CLIENT_AUTH, x509.ExtendedKeyUsageOID.TIME_STAMPING]
            ), False)]


def test_generate_voting_certs():
    # sensitive:
    key = test_build_key()
    cert = test_build_cert(subject=(key, test_deleteme_create_a_name("sensitive")),
                           issuer=None,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=test_build_extensions_voting(key, OID_SENSITIVE_KEY))
    with open("scionlab-test-sensitive.key", "wb") as f:
        f.write(test_encode_key(key))
    with open("scionlab-test-sensitive.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    # regular:
    key = test_build_key()
    cert = test_build_cert(subject=(key, test_deleteme_create_a_name("regular")),
                           issuer=None,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=test_build_extensions_voting(key, OID_REGULAR_KEY))
    with open("scionlab-test-regular.key", "wb") as f:
        f.write(test_encode_key(key))
    with open("scionlab-test-regular.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def test_generate_ca():
    # generate root:
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
    key = test_build_key()
    ca_issuer = (key, test_deleteme_create_a_name("ca"))
    cert = test_build_cert(subject=ca_issuer,
                           issuer=root_issuer,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=test_build_extensions_ca(key, root_issuer[0]))
    with open("scionlab-test-ca.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return ca_issuer, cert


def test_generate_as(issuer, asid):
    """
    issuer is a 2-tuple (key, name)
    """
    key = test_build_key()
    cert = test_build_cert(subject=(key, test_deleteme_create_a_name("regular AS " + asid)),
                           issuer=issuer,
                           notvalidbefore=datetime.utcnow(),
                           notvalidafter=datetime.utcnow() + timedelta(days=1),
                           extensions=test_build_extensions_as(key, issuer[0]))
    with open(f"scionlab-test-as{asid}.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def test_generate_ases(ca_issuer, asids):
    for asid in asids:
        test_generate_as(ca_issuer, asid)


class TRCConf:
    def __init__(self, isd_id, authoritative, core, certificates):
        """
        authoritative ASes are those that know which TRC version an ISD has
        authoritative is a list ["ffaa:0:1102",...]
        """
        self.isd_id = isd_id
        # self.authoritative = [parse(asid) for asid in authoritative]
        self.authoritative = authoritative
        self.core = core
        # self.voters = ["1-ff00:0:110"]
        # self.cas = ["1-ff00:0:110"]
        self.certificates = certificates

    def get_conf(self):
        d = {
            "isd": self.isd_id,
            "description": "ISD 1",
            "base_version": 1,
            "serial_version": 1,
            "voting_quorum": 1,
            "grace_period": "0s",  # must be non zero for updates to serial_version only
            "authoritative_ases": self.authoritative,
            "core_ases": self.core,
            "cert_files": self.certificates,
            "no_trust_reset": False,
            # "votes": 1  # empty when updating only serial_version
            "validity": {
                "not_before": int(datetime.now().timestamp()),
                "validity": "24h",  # the TRC must be included in the valid window of all certificates
            },
        }
        return d


def test_run_scion_cppki(*args):
    """
    runs scion-pki
    """
    COMMAND = "/home/juagargi/devel/ETH/scion.scionlab/bin/scion-pki"
    ret = subprocess.run([COMMAND, "trcs", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if ret.returncode != 0:
        print(ret.stdout.decode("utf-8"))
        raise Exception(f"Bad return code: {ret.returncode}")


def test_trc_configure():
    '''
	ISD               addr.ISD        `toml:"isd"`
	Description       string          `toml:"description"`
	SerialVersion     scrypto.Version `toml:"serial_version"`
	BaseVersion       scrypto.Version `toml:"base_version"`
	VotingQuorum      uint8           `toml:"voting_quorum"`
	GracePeriod       util.DurWrap    `toml:"grace_period"`
	NoTrustReset      bool            `toml:"no_trust_reset"`
	Validity          Validity        `toml:"validity"`
	CoreASes          []addr.AS       `toml:"core_ases"`
	AuthoritativeASes []addr.AS       `toml:"authoritative_ases"`
	CertificateFiles  []string        `toml:"cert_files"`
	Votes             []int           `toml:"votes"`
    '''
    certificates = [  # only sensitives, regulars, and roots
        "scionlab-test-sensitive.crt",
        "scionlab-test-regular.crt",
        "scionlab-test-root.crt",
    ]
    conf = TRCConf(1, ["ff00:0:110"], ["ff00:0:110"], certificates)
    # s = toml.dumps(conf.get_conf())
    # print(s)
    with open("scionlab-test-trc-config.toml", "w") as f:
        f.write(toml.dumps(conf.get_conf()))
    # TODO load predecessor when updating only serial_version


def test_trc_generate_payload():
    test_file_name = "scionlab-test-trc-payload.der"
    test_run_scion_cppki("payload", "-t", "scionlab-test-trc-config.toml", "-o", test_file_name)
    return test_file_name


def test_trc_sign_payload():
    # openssl cms -sign -in ISD-B1-S1.pld.der -inform der -md sha512 \
    #     -signer $PUBDIR/regular-voting.crt -inkey $KEYDIR/regular-voting.key \
    #     -nodetach -nocerts -nosmimecap -binary -outform der > ISD-B1-S1.regular.trc

    # verify with:
    # openssl cms -verify -in ISD-B1-S1.regular.trc -inform der \
    # -certfile $PUBDIR/regular-voting.crt -CAfile $PUBDIR/regular-voting.crt \
    # -purpose any -no_check_time > /dev/null
    #
    # k = test_load_key("scionlab-test-regular.key")
    # with open("scionlab-test-trc-payload.der", "rb") as f:
    #     hash = hashlib.sha512(f.read()).digest()
    # k.sign(hash, padding.)
    # TODO(juagargi) replace the execution of openssl with a library
    # XXX(juagargi): I don't find a nice way to encode CMS in python.
    # There seems to be some possibilities:
    # pkcs7.PKCS7Encoder()
    # https://github.com/vbwagner/ctypescrypto
    #
    # signers is a list of 3-tuples (cert,key,outfile)
    signers =[
        ("scionlab-test-sensitive.crt", "scionlab-test-sensitive.key", "scionlab-test-trc-signed.sensitive.trc"),
        ("scionlab-test-regular.crt", "scionlab-test-regular.key", "scionlab-test-trc-signed.regular.trc"),
    ]
    for (cert, key, outfile) in signers:
        command = ["openssl", "cms", "-sign", "-in", "scionlab-test-trc-payload.der",
                   "-inform", "der", "-md", "sha512", "-signer", cert,
                   "-inkey", key, "-nodetach", "-nocerts", "-nosmimecap",
                   "-binary", "-outform", "der", "-out", outfile]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
        # TODO(juagargi) unnecessary:
        command = ["openssl", "cms", "-verify", "-in", outfile,
                "-inform", "der", "-certfile", cert,
                "-CAfile", cert, "-purpose", "any", "-no_check_time"]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)


def test_trc_combine_payloads():
    test_file_name_payload = "scionlab-test-trc-payload.der"
    test_file_names = [
        "scionlab-test-trc-signed.sensitive.trc",
        "scionlab-test-trc-signed.regular.trc",
        ]
    test_run_scion_cppki("combine", "-p", test_file_name_payload, *test_file_names, "-o", "scionlab-test-trc.trc")
    # check the final TRC:
    test_run_scion_cppki("verify", "--anchor", "scionlab-test-trc.trc", "scionlab-test-trc.trc")


def test_generate_trc(isd_id):
    """
    Generates (or regenerates) a TRC
    """
    # configure TRC
    test_trc_configure()
    # generate payload scion-pki trcs payload
    test_trc_generate_payload()
    # sign payload (crypto_lib.sh:sign_payload())
    test_trc_sign_payload()
    # combine signed TRCs
    test_trc_combine_payloads()


def test_cppki():
    # create voters
    test_generate_voting_certs()
    # create CAs
    ca_issuer, _ = test_generate_ca()
    # create ASes
    test_generate_ases(ca_issuer, ["1-ff00:0:111", "1-ff00:0:112"])
    # create TRCs
    test_generate_trc(1)
    # flatten?


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
