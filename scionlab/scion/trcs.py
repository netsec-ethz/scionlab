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

import base64
import os
import subprocess
import toml
import yaml

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from django.conf import settings
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Dict, List, Optional


def encode_trc(trc: bytes) -> str:
    return base64.b64encode(trc).decode('ascii')


def decode_trc(trc: str) -> bytes:
    return base64.b64decode(trc.encode('ascii'))


def trc_to_dict(trc: bytes) -> dict:
    with NamedTemporaryFile('wb') as f:
        f.write(trc)
        f.flush()
        ret = _raw_run_scion_cppki("human", "--format", "yaml", f.name)
    stdout = ret.stdout.decode("utf-8")
    if ret.returncode != 0:
        raise Exception(f"{stdout}\n\nExecuting scion-cppki: bad return code: {ret.returncode}")
    return yaml.safe_load(stdout)


def generate_trc(prev_trc: bytes,
                 isd_id: int, base: int, serial: int,
                 primary_ases: List[str], quorum: int, votes: List[int],
                 grace_period: timedelta, not_before: datetime, not_after: datetime,
                 certificates: List[str],
                 signers_certs: List[str],
                 signers_keys: List[str]) -> bytes:
    """
    Generate a new TRC.
    This method is the interface between the DB objects and the scion PKI ones.
    """
    assert (base >= 1 and serial >= 1)
    assert (prev_trc is None) == (base == serial)
    not_before = _utc_timestamp(not_before)
    not_after = _utc_timestamp(not_after)

    conf = TRCConf(isd_id=isd_id,
                   base_version=base,
                   serial_version=serial,
                   grace_period=grace_period,
                   not_before=not_before,
                   not_after=not_after,
                   core_ases=primary_ases,
                   authoritative_ases=primary_ases,
                   certificates=[c.encode("ascii") for c in certificates],  # from str to bytes
                   quorum=quorum,
                   votes=votes,
                   predecessor_trc=prev_trc)

    with conf.configure() as trc:
        trc.gen_payload()
        signed_payload = []
        for c, k in zip(signers_certs, signers_keys):
            signed_payload.append(trc.sign_payload(c.encode("ascii"), k.encode("ascii")))
        return trc.combine(*signed_payload)


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
                 certificates: List[bytes],
                 quorum: int = None,
                 votes: Optional[List[int]] = None,
                 predecessor_trc: Optional[bytes] = None):
        """
        authoritative_ases ASes are those that know which TRC version an ISD has
        certificates is a map filename: content, of certificates that will be included in the TRC
        """
        self.isd_id = isd_id
        self.base_version = base_version
        self.serial_version = serial_version
        self.grace_period = grace_period
        self.not_before = not_before
        self.not_after = not_after
        self.authoritative_ases = authoritative_ases
        self.core_ases = core_ases
        self.certificates = certificates
        self.certificate_files = []  # will be populated on configure()
        self.quorum = quorum
        self.votes = votes
        self.predecessor_trc = predecessor_trc

        self._validate()

    @contextmanager
    def configure(self):
        # create temp dir and temp files for certificates
        with TemporaryDirectory() as temp_dir:
            self._temp_dir = temp_dir
            saved_cert_filenames = self.certificate_files
            self._dump_certificates_to_files()
            yield self
        # only needed to allow nested call to configure():
        self._temp_dir = temp_dir
        self.certificate_files = saved_cert_filenames

    def gen_payload(self) -> None:
        conf = self._get_conf()
        with open(self._tmp_join(self.CONFIG_FILENAME), "w") as f:
            f.write(toml.dumps(conf))
        args = ["payload", "-t", self.CONFIG_FILENAME, "-o", self.PAYLOAD_FILENAME]
        if self.predecessor_trc:
            predecessor_fn = self._tmp_join(self.PRED_TRC_FILENAME)
            with open(predecessor_fn, "wb") as f:
                f.write(self.predecessor_trc)
            args.extend(["-p", predecessor_fn])
        self._run_scion_cppki(*args)

    def sign_payload(self, cert: bytes, key: bytes) -> bytes:
        # TODO(juagargi) replace the execution of openssl with a library call !!.
        # XXX(juagargi): I don't find a nice way to encode CMS in python.
        # There seems to be some possibilities:
        # pkcs7.PKCS7Encoder()
        # https://github.com/vbwagner/ctypescrypto
        # or maybe the new cryptography >= 3.2 ?
        KEY_FILENAME = "key_file.key"
        CERT_FILENAME = "cert_file.crt"
        prev_cwd = os.getcwd()
        try:
            os.chdir(self._temp_dir)
            with open(KEY_FILENAME, "wb") as f:
                f.write(key)
            with open(CERT_FILENAME, "wb") as f:
                f.write(cert)
            command = ["openssl", "cms", "-sign", "-in", self.PAYLOAD_FILENAME,
                       "-inform", "der", "-md", "sha512", "-signer", CERT_FILENAME,
                       "-inkey", KEY_FILENAME, "-nodetach", "-nocerts", "-nosmimecap",
                       "-binary", "-outform", "der", "-out", "trc-signed.der"]
            ret = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 check=False)
            stdout = ret.stdout.decode("utf-8")
            if ret.returncode != 0:
                raise Exception(
                    f"{stdout}\n\nExecuting {command}: bad return code: {ret.returncode}")

            # remove they key, although it should be deleted when the temporary dir is cleaned up
            os.remove(KEY_FILENAME)
            # read the signed trc and return it
            with open("trc-signed.der", "rb") as f:
                return f.read()
        finally:
            os.chdir(prev_cwd)

    def combine(self, *signed) -> bytes:
        """ returns the final TRC by combining the signed blocks and payload """
        for i, s in enumerate(signed):
            with open(os.path.join(self._temp_dir, f"signed-{i}.der"), "wb") as f:
                f.write(s)
        self._run_scion_cppki(
            "combine", "-p", self.PAYLOAD_FILENAME,
            *(f"signed-{i}.der" for i in range(len(signed))),
            "-o", os.path.join(self._temp_dir, self.TRC_FILENAME),
        )
        with open(os.path.join(self._temp_dir, self.TRC_FILENAME), "rb") as f:
            return f.read()

    def is_update(self):
        return self.base_version != self.serial_version

    def _validate(self) -> None:
        if any(x <= 0 for x in [self.isd_id, self.base_version, self.serial_version]):
            raise ValueError("isd_id, base_version and serial_version must be >= 0")
        if self.base_version > self.serial_version:
            raise ValueError("base version should refer to this or older serial version")
        if self.is_update() and self.votes is None:
            raise ValueError("must provide votes when updating")
        if self.is_update() and self.predecessor_trc is None:
            raise ValueError("must provide predecessor TRC when updating")
        if self.not_after <= self.not_before:
            raise ValueError("not_before must precede not_after")
        if not self.certificates:
            raise ValueError("must provide sensitive voting, regular voting, and root certificates")

    def _get_conf(self) -> Dict:
        return {
            "isd": self.isd_id,
            "description": f"SCIONLab TRC for ISD {self.isd_id}",
            "base_version": self.base_version,
            "serial_version": self.serial_version,
            "voting_quorum": self._voting_quorum(),
            "grace_period": self._grace_period(),
            "authoritative_ases": self.authoritative_ases,
            "core_ases": self.core_ases,
            "cert_files": self.certificate_files,
            "no_trust_reset": False,
            "validity": {
                "not_before": int(self.not_before.timestamp()),
                "validity": self._to_seconds(self.not_after - self.not_before),
            },
            "votes": self.votes,
        }

    def _voting_quorum(self) -> int:
        return self.quorum or len(self.core_ases) // 2 + 1

    def _grace_period(self) -> str:
        # must be zero for base TRCs
        if self.base_version == self.serial_version:
            return "0s"
        else:
            return self._to_seconds(self.grace_period)

    def _tmp_join(self, filename: str) -> str:
        return os.path.join(self._temp_dir, filename)

    def _dump_certificates_to_files(self) -> None:
        self.certificate_files = []
        for c in self.certificates:
            with NamedTemporaryFile("wb", dir=self._temp_dir, delete=False) as f:
                f.write(c)
                self.certificate_files.append(f.name)

    def _run_scion_cppki(self, *args) -> str:
        """ runs the binary scion-pki """
        prev_cwd = os.getcwd()
        try:
            os.chdir(self._temp_dir)
            ret = _raw_run_scion_cppki(*args)
        finally:
            os.chdir(prev_cwd)
        stdout = ret.stdout.decode("utf-8")
        if ret.returncode != 0:
            raise Exception(f"{stdout}\n\nExecuting scion-cppki: bad return code: {ret.returncode}")
        return stdout

    @staticmethod
    def _to_seconds(d: timedelta) -> str:
        return f"{int(d.total_seconds())}s"


def _utc_timestamp(dt: datetime) -> datetime:
    """ Return the utc datetime for a naive datetime """
    assert dt.tzinfo is None, "Timestamps from DB are expected to be naive UTC datetimes"
    return dt.replace(tzinfo=timezone.utc)


def _raw_run_scion_cppki(*args):
    return subprocess.run([settings.SCION_CPPKI_COMMAND, "trcs", *args],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
