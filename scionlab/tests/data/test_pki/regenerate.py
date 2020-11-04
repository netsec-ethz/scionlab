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

import subprocess
import toml

from collections import namedtuple
from datetime import datetime, timedelta, timezone
from scionlab.scion import keys, jws
from scionlab.scion.as_ids import parse
from scionlab.scion.keys import encode_key, generate_key
from scionlab.scion.certs import _build_certificate, _build_extensions_voting,\
                                 _build_extensions_root, _build_extensions_ca,\
                                 _create_name, encode_certificate,\
                                 OID_SENSITIVE_KEY, OID_REGULAR_KEY
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec


def regenerate_voting_certs() -> None:
    not_before = datetime(2020, 11, 12, 8, 0, tzinfo=timezone.utc)
    # sensitive:
    key = generate_key()
    cert = _build_certificate(subject=(key, _create_name("1-ff00:0:110",
                                                         "Sensitive Voting Certificate")),
                              issuer=None,
                              notvalidbefore=not_before,
                              notvalidafter=not_before + timedelta(days=1),
                              extensions=_build_extensions_voting(key, OID_SENSITIVE_KEY))
    with open("voting-sensitive-1.key", "wb") as f:
        f.write(encode_key(key).encode("ascii"))
    with open("voting-sensitive-1.crt", "wb") as f:
        f.write(encode_certificate(cert).encode("ascii"))
    # regular:
    key = generate_key()
    cert = _build_certificate(subject=(key, _create_name("1-ff00:0:110",
                                                         "Regular Voting Certificate")),
                              issuer=None,
                              notvalidbefore=not_before,
                              notvalidafter=not_before + timedelta(days=1),
                              extensions=_build_extensions_voting(key, OID_REGULAR_KEY))
    with open("voting-regular-1.key", "wb") as f:
        f.write(encode_key(key).encode("ascii"))
    with open("voting-regular-1.crt", "wb") as f:
        f.write(encode_certificate(cert).encode("ascii"))


def regenerate_ca():
    not_before = datetime(2020, 11, 12, 8, 0, tzinfo=timezone.utc)
    # generate root:
    key = generate_key()
    root_issuer = (key, _create_name("1-ff00:0:110",
                                     "High Security Root Certificate"))
    cert = _build_certificate(subject=root_issuer,
                              issuer=None,
                              notvalidbefore=not_before,
                              notvalidafter=not_before + timedelta(days=1),
                              extensions=_build_extensions_root(key))
    with open("root-1.key", "wb") as f:
        f.write(encode_key(key).encode("ascii"))
    with open("root-1.crt", "wb") as f:
        f.write(encode_certificate(cert).encode("ascii"))
    # generate ca:
    key = generate_key()
    ca_issuer = (key, _create_name("1-ff00:0:110",
                                   "Secure CA Certificate"))
    cert = _build_certificate(subject=ca_issuer,
                              issuer=root_issuer,
                              notvalidbefore=not_before,
                              notvalidafter=not_before + timedelta(days=1),
                              extensions=_build_extensions_ca(key, root_issuer[0]))
    with open("ca-1.key", "wb") as f:
        f.write(encode_key(key).encode("ascii"))
    with open("ca-1.crt", "wb") as f:
        f.write(encode_certificate(cert).encode("ascii"))


def regenerate():
    regenerate_voting_certs()
    regenerate_ca()
