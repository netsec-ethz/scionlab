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
:mod:`scionlab.scion.trcs` --- TRC creation
===========================================
"""

import toml
import yaml
import contextlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Dict, List, Optional, Tuple

from scionlab.scion import certs, keys
from scionlab.scion.pkicommand import run_scion_pki


def trc_to_dict(trc: str) -> dict:
    with NamedTemporaryFile('w') as f:
        f.write(trc)
        f.flush()
        ret = _run_scion_pki_trcs('human', '--format', 'yaml', f.name, check=True)
    return yaml.safe_load(ret.stdout)


def verify_trcs(*trcs: str):
    """
    Verify that the sequence of trcs, using the first TRC as anchor.
    TRCs are passed as bytes, base 64 format.
    Raises ScionPkiError if the TRCs are not valid.
    """
    with contextlib.ExitStack() as stack:
        files = [stack.enter_context(NamedTemporaryFile(suffix=".trc", mode="w")) for _ in trcs]
        for f, trc in zip(files, trcs):
            f.write(trc)
            f.flush()
        _run_scion_pki_trcs('verify', '--anchor', *[f.name for f in files])


def generate_trc(prev_trc: bytes,
                 isd_id: int,
                 base: int,
                 serial: int,
                 primary_ases: List[str],
                 quorum: int,
                 votes: List[int],
                 grace_period: timedelta,
                 not_before: datetime,
                 not_after: datetime,
                 certificates: List[str],
                 signers_certs: List[str],
                 signers_keys: List[str]) -> str:
    """
    Generate a new TRC.
    This method is the interface between the DB objects and the scion PKI ones.
    """
    assert (base >= 1 and serial >= 1)
    assert (prev_trc is None) == (base == serial)
    assert len(signers_certs) == len(signers_keys)

    conf = TRCConf(isd_id=isd_id,
                   base_version=base,
                   serial_version=serial,
                   grace_period=grace_period,
                   not_before=not_before,
                   not_after=not_after,
                   core_ases=primary_ases,
                   authoritative_ases=primary_ases,
                   certificates=certificates,
                   signers=list(zip(signers_certs, signers_keys)),
                   quorum=quorum,
                   votes=votes,
                   predecessor_trc=prev_trc)
    return conf.generate()


class TRCConf:
    """
    Configures, creates, signs, and combines all the pieces to finally have a TRC.
    The typical usage is:

    with TRCConf(...).configure() as trc:
        trc.gen_payload()
        trc.sign_payload()
        final_trc = trc.combine()

    The combine step returns the bytes of the final TRC.
    """

    # files created internally (removed after exiting context)
    TRC_FILENAME = 'scionlab-trc.trc'
    PRED_TRC_FILENAME = 'predecessor-trc.trc'
    PAYLOAD_FILENAME = 'scionlab-trc-payload.der'
    CONFIG_FILENAME = 'scionlab-trc-config.toml'

    def __init__(self,
                 isd_id: int,
                 base_version: int,
                 serial_version: int,
                 grace_period: timedelta,
                 not_before: datetime,
                 not_after: datetime,
                 authoritative_ases: List[str],
                 core_ases: List[str],
                 certificates: List[str],
                 signers: List[Tuple[str, str]],
                 quorum: int = None,
                 votes: Optional[List[int]] = None,
                 predecessor_trc: Optional[bytes] = None):
        """
        authoritative_ases ASes are those that know which TRC version an ISD has
        certificates is a map filename: content, of certificates that will be included in the TRC
        """
        assert not_before.tzinfo is None, 'expecting timestamps from DB in naive UTC datetime'
        assert not_after.tzinfo is None, 'expecting timestamps from DB in naive UTC datetime'

        self.isd_id = isd_id
        self.base_version = base_version
        self.serial_version = serial_version
        self.grace_period = grace_period
        self.not_before = not_before.replace(tzinfo=timezone.utc)
        self.not_after = not_after.replace(tzinfo=timezone.utc)
        self.authoritative_ases = authoritative_ases
        self.core_ases = core_ases
        self.certificates = certificates
        self.certificate_files = []  # type: List[str]  # will be populated on configure()
        self.signers = signers
        self.quorum = quorum
        self.votes = votes
        self.predecessor_trc = predecessor_trc

        self._validate()

    def generate(self) -> str:
        with TemporaryDirectory() as temp_dir:
            self._dump_certificates_to_files(temp_dir)
            self._gen_payload(temp_dir)
            signed_payloads = []
            for (cert, key) in self.signers:
                signed_payloads.append(self._sign_payload(temp_dir, cert, key))
            return self._combine(temp_dir, *signed_payloads)

    def _gen_payload(self, temp_dir: str) -> None:
        conf = self._get_conf()
        Path(temp_dir, self.CONFIG_FILENAME).write_text(toml.dumps(conf))
        args = ['payload', '-t', self.CONFIG_FILENAME, '-o', self.PAYLOAD_FILENAME]
        if self.predecessor_trc:
            pred_filename = Path(temp_dir, self.PRED_TRC_FILENAME)
            pred_filename.write_text(self.predecessor_trc)
            args.extend(['-p', str(pred_filename)])
        _run_scion_pki_trcs(*args, cwd=temp_dir)

    def _sign_payload(self, temp_dir: str, cert: str, key: str) -> bytes:
        """ signs the payload with one signer """
        sb = pkcs7.PKCS7SignatureBuilder(Path(temp_dir, self.PAYLOAD_FILENAME).read_bytes())\
            .add_signer(certs.decode_certificate(cert),
                        keys.decode_key(key),
                        hashes.SHA512())
        return sb.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.NoCerts,
                                                    pkcs7.PKCS7Options.NoCapabilities,
                                                    pkcs7.PKCS7Options.Binary])

    def _combine(self, temp_dir: str, *signed) -> str:
        """ returns the final TRC (in PEM format), by combining the signed blocks and payload """
        for i, s in enumerate(signed):
            Path(temp_dir, f'signed-{i}.der').write_bytes(s)
        _run_scion_pki_trcs(
            'combine', '-p', self.PAYLOAD_FILENAME,
            *(f'signed-{i}.der' for i in range(len(signed))),
            '-o', Path(temp_dir, self.TRC_FILENAME),
            '--format', 'pem',
            cwd=temp_dir
        )
        return Path(temp_dir, self.TRC_FILENAME).read_text()

    def is_update(self):
        return self.base_version != self.serial_version

    def _validate(self) -> None:
        if any(x <= 0 for x in [self.isd_id, self.base_version, self.serial_version]):
            raise ValueError('isd_id, base_version and serial_version must be >= 0')
        if self.base_version > self.serial_version:
            raise ValueError('base version should refer to this or older serial version')
        if self.is_update() and self.votes is None:
            raise ValueError('must provide votes when updating')
        if self.is_update() and self.predecessor_trc is None:
            raise ValueError('must provide predecessor TRC when updating')
        if self.not_after <= self.not_before:
            raise ValueError('not_before must precede not_after')
        if not self.certificates:
            raise ValueError('must provide sensitive voting, regular voting, and root certificates')

    def _get_conf(self) -> Dict:
        return {
            'isd': self.isd_id,
            'description': f'SCIONLab TRC for ISD {self.isd_id}',
            'base_version': self.base_version,
            'serial_version': self.serial_version,
            'voting_quorum': self._voting_quorum(),
            'grace_period': self._grace_period(),
            'authoritative_ases': self.authoritative_ases,
            'core_ases': self.core_ases,
            'cert_files': self.certificate_files,
            'no_trust_reset': False,
            'validity': {
                'not_before': int(self.not_before.timestamp()),
                'validity': self._to_seconds(self.not_after - self.not_before),
            },
            'votes': self.votes,
        }

    def _voting_quorum(self) -> int:
        return self.quorum or len(self.core_ases) // 2 + 1

    def _grace_period(self) -> str:
        # must be zero for base TRCs
        if self.base_version == self.serial_version:
            return '0s'
        else:
            return self._to_seconds(self.grace_period)

    def _dump_certificates_to_files(self, temp_dir) -> None:
        self.certificate_files = []
        for c in self.certificates:
            with NamedTemporaryFile('w', dir=temp_dir, delete=False) as f:
                f.write(c)
                self.certificate_files.append(f.name)

    @staticmethod
    def _to_seconds(d: timedelta) -> str:
        return f'{int(d.total_seconds())}s'


def _run_scion_pki_trcs(*args, cwd=None, check=True):
    return run_scion_pki('trcs', *args, cwd=cwd, check=check)
