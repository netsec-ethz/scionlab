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
from scionlab.scion.keys import encode_key, decode_key, generate_key
from scionlab.scion.certs import _build_certificate, _build_extensions_as,\
                                 _build_extensions_ca, _build_extensions_root,\
                                 _build_extensions_voting, _create_name, encode_certificate,\
                                 OID_SENSITIVE_KEY, OID_REGULAR_KEY


def regenerate_voting_certs(asid) -> None:
    fasid = asid.replace(':', '_')
    not_before = datetime(2020, 11, 12, 8, 0, tzinfo=timezone.utc)
    # sensitive:
    key = generate_key()
    cert = _build_certificate(subject=(
        key, _create_name(f'1-{asid}', f'1-{asid} Sensitive Voting Certificate')),
                              issuer=None,
                              not_before=not_before,
                              not_after=not_before + timedelta(days=1),
                              extensions=_build_extensions_voting(key, OID_SENSITIVE_KEY))
    with open(f'voting-sensitive-{fasid}.key', 'wb') as f:
        f.write(encode_key(key))
    with open(f'voting-sensitive-{fasid}.crt', 'wb') as f:
        f.write(encode_certificate(cert))
    # regular:
    key = generate_key()
    cert = _build_certificate(subject=(
        key, _create_name(f'1-{asid}', f'1-{asid} Regular Voting Certificate')),
                              issuer=None,
                              not_before=not_before,
                              not_after=not_before + timedelta(days=1),
                              extensions=_build_extensions_voting(key, OID_REGULAR_KEY))
    with open(f'voting-regular-{fasid}.key', 'wb') as f:
        f.write(encode_key(key))
    with open(f'voting-regular-{fasid}.crt', 'wb') as f:
        f.write(encode_certificate(cert))


def regenerate_ca(asid):
    fasid = asid.replace(':', '_')
    not_before = datetime(2020, 11, 12, 8, 0, tzinfo=timezone.utc)
    # generate root:
    key = generate_key()
    root_issuer = (key, _create_name(f'1-{asid}', f'1-{asid} High Security Root Certificate'))
    cert = _build_certificate(subject=root_issuer,
                              issuer=None,
                              not_before=not_before,
                              not_after=not_before + timedelta(days=1),
                              extensions=_build_extensions_root(key))
    with open(f'root-{fasid}.key', 'wb') as f:
        f.write(encode_key(key))
    with open(f'root-{fasid}.crt', 'wb') as f:
        f.write(encode_certificate(cert))
    # generate ca:
    key = generate_key()
    ca_issuer = (key, _create_name(f'1-{asid}', f'1-{asid} Secure CA Certificate'))
    cert = _build_certificate(subject=ca_issuer,
                              issuer=root_issuer,
                              not_before=not_before,
                              not_after=not_before + timedelta(days=1),
                              extensions=_build_extensions_ca(key, root_issuer[0]))
    with open(f'ca-{fasid}.key', 'wb') as f:
        f.write(encode_key(key))
    with open(f'ca-{fasid}.crt', 'wb') as f:
        f.write(encode_certificate(cert))


def regenerate_ases():
    # get the CA key
    with open('ca-ff00_0_110.key', 'rb') as f:
        ca_key = decode_key(f.read().decode('ascii'))
        issuer = (ca_key, _create_name('1-ff00:0:110', '1-ff00:0:110 Secure CA Certificate'))
    # and generate
    for asid in ['1-ff00:0:110', '1-ff00:0:111', '1-ff00:0:112']:
        key = generate_key()
        cert = _build_certificate(subject=(key, _create_name(asid, f'Regular AS {asid}')),
                                  issuer=issuer,
                                  not_before=datetime.utcnow(),
                                  not_after=datetime.utcnow() + timedelta(days=1),
                                  extensions=_build_extensions_as(key, issuer[0]))
        fasid = asid.replace(':', '_')
        with open(f'as{fasid}.key', 'wb') as f:
            f.write(encode_key(key))
        with open(f'as{fasid}.crt', 'wb') as f:
            f.write(encode_certificate(cert))


def regenerate_trc():
    # 1. gen payload. There is already a manually generated payload-1-config.toml
    _run_scion_cppki('payload', '-t', 'payload-1-config.toml', '-o', 'payload-1.der')
    # 2. sign payload with voters
    signers = [  # cert, key, outfile
        ('voting-sensitive-ff00_0_110.crt', 'voting-sensitive-ff00_0_110.key',
         'payload-1-signed-sensitive-ff00_0_110.der'),
        ('voting-regular-ff00_0_110.crt', 'voting-regular-ff00_0_110.key',
         'payload-1-signed-regular-ff00_0_110.der')]
    for (cert, key, outfile) in signers:
        command = ['openssl', 'cms', '-sign', '-in', 'payload-1.der',
                   '-inform', 'der', '-md', 'sha512', '-signer', cert,
                   '-inkey', key, '-nodetach', '-nocerts', '-nosmimecap',
                   '-binary', '-outform', 'der', '-out', outfile]
        subprocess.run(command, check=True)
    # 3. combine signed payloads
    _run_scion_cppki('combine', '-p', 'payload-1.der', *(signed for (_, _, signed) in signers),
                     '-o', 'trc-1.trc')
    # 4. verify TRC (sanity check)
    _run_scion_cppki('verify', '--anchor', 'trc-1.trc', 'trc-1.trc')


def regenerate_regular_updated_trc():
    # 1. gen payload. Use payload-2-config.toml, that declares a regular update
    _run_scion_cppki('payload', '-t', 'payload-2-config.toml', '-p', 'trc-1.trc',
                     '-o', 'payload-2.der')
    # 2. sign again with the regular certificate only
    signers = [  # cert, key, outfile
        ('voting-regular-ff00_0_110.crt', 'voting-regular-ff00_0_110.key',
         'payload-2-signed-regular-ff00_0_110.der')]
    for (cert, key, outfile) in signers:
        command = ['openssl', 'cms', '-sign', '-in', 'payload-2.der',
                   '-inform', 'der', '-md', 'sha512', '-signer', cert,
                   '-inkey', key, '-nodetach', '-nocerts', '-nosmimecap',
                   '-binary', '-outform', 'der', '-out', outfile]
        subprocess.run(command, check=True)
    # 3. combine signed payloads
    _run_scion_cppki('combine', '-p', 'payload-2.der', *(signed for (_, _, signed) in signers),
                     '-o', 'trc-2.trc')
    # 4. verify TRC. This time it is anchored in the previous TRC.
    _run_scion_cppki('verify', '--anchor', 'trc-1.trc', 'trc-2.trc')


def regenerate_sensitive_update_trc():
    """ it adds a new AS 1-ff00:0:210 as core, authoritative, and voter """
    # 1. gen payload. Use payload-3-config.toml, that declares a sensitive update
    _run_scion_cppki('payload', '-t', 'payload-3-config.toml', '-p', 'trc-2.trc',
                     '-o', 'payload-3.der')
    # 2. sign again with the sensitive certificate only
    signers = [  # cert, key, outfile
        ('voting-sensitive-ff00_0_110.crt', 'voting-sensitive-ff00_0_110.key',
         'payload-3-signed-sensitive-ff00_0_110.der'),
        ('voting-sensitive-ff00_0_210.crt', 'voting-sensitive-ff00_0_210.key',
         'payload-3-signed-sensitive-ff00_0_210.der'),
        ('voting-regular-ff00_0_210.crt', 'voting-regular-ff00_0_210.key',
         'payload-3-signed-regular-ff00_0_210.der')]
    for (cert, key, outfile) in signers:
        command = ['openssl', 'cms', '-sign', '-in', 'payload-3.der',
                   '-inform', 'der', '-md', 'sha512', '-signer', cert,
                   '-inkey', key, '-nodetach', '-nocerts', '-nosmimecap',
                   '-binary', '-outform', 'der', '-out', outfile]
        subprocess.run(command, check=True)
    # 3. combine signed payloads
    _run_scion_cppki('combine', '-p', 'payload-3.der', *(signed for (_, _, signed) in signers),
                     '-o', 'trc-3.trc')
    # 4. verify TRC. This time it is anchored in the previous TRC.
    _run_scion_cppki('verify', '--anchor', 'trc-2.trc', 'trc-3.trc')


def regenerate():
    dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir)

    regenerate_voting_certs('ff00:0:110')
    regenerate_ca('ff00:0:110')
    regenerate_trc()
    regenerate_regular_updated_trc()

    regenerate_voting_certs('ff00:0:210')
    regenerate_ca('ff00:0:210')
    regenerate_sensitive_update_trc()


def _run_scion_cppki(*args):
    COMMAND = 'scion-pki'
    ret = subprocess.run([COMMAND, 'trcs', *args],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if ret.returncode != 0:
        print(ret.stdout.decode('utf-8'))
        raise Exception(f'Bad return code: {ret.returncode}')
