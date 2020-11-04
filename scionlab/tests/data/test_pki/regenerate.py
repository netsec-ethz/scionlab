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

import os
import subprocess

from datetime import datetime, timedelta, timezone
from scionlab.scion.keys import encode_key, generate_key
from scionlab.scion.certs import _build_certificate, _build_extensions_voting,\
                                 _build_extensions_root, _build_extensions_ca,\
                                 _create_name, encode_certificate,\
                                 OID_SENSITIVE_KEY, OID_REGULAR_KEY


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


def regenerate_trc():
    def run_scion_cppki(*args):
        COMMAND = "scion-pki"
        ret = subprocess.run([COMMAND, "trcs", *args],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        if ret.returncode != 0:
            print(ret.stdout.decode("utf-8"))
            raise Exception(f"Bad return code: {ret.returncode}")
    # 1. gen payload. There is already a manually generated payload-1-config.toml
    run_scion_cppki("payload", "-t", "payload-1-config.toml", "-o", "payload-1.der")
    # 2. sign payload with voters
    signers = [ # cert, key, outfile
        ("voting-sensitive-1.crt", "voting-sensitive-1.key", "payload-1-signed-sensitive-1.der"),
        ("voting-regular-1.crt", "voting-regular-1.key", "payload-1-signed-regular-1.der")]
    for (cert, key, outfile) in signers:
        command = ["openssl", "cms", "-sign", "-in", "payload-1.der",
                   "-inform", "der", "-md", "sha512", "-signer", cert,
                   "-inkey", key, "-nodetach", "-nocerts", "-nosmimecap",
                   "-binary", "-outform", "der", "-out", outfile]
        subprocess.run(command, check=True)
    # 3. combine signed payloads
    run_scion_cppki("combine", "-p", "payload-1.der", *(signed for (_, _, signed) in signers),
                    "-o", "trc-1.trc")
    # 4. verify TRC (sanity check)
    run_scion_cppki("verify", "--anchor", "trc-1.trc", "trc-1.trc")


def regenerate():
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)

    regenerate_voting_certs()
    regenerate_ca()
    regenerate_trc()
