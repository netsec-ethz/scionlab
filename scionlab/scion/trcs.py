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

import os
import subprocess
import toml

from collections import namedtuple
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory, mktemp
from typing import cast, Dict, List, Tuple, Optional

from scionlab.scion import jws


# TODO(juagargi) move this to a settings variable?
SCION_CPPKI_COMMAND = "/home/juagargi/devel/ETH/scion.scionlab/bin/scion-pki"

# XXX(matzf): maybe this entire thing would be a bit simpler if we keep usage as member of Key.
# Then we dont need so many dicts and stuff.
Key = namedtuple('Key', ['version', 'priv_key', 'pub_key'])
CoreKeys = namedtuple('CoreKeys', ['issuing_grant', 'voting_online', 'voting_offline'])
CoreKeySet = Dict[str, Key]


def generate_trc(prev_trc, isd_id, base, serial,
                 primary_ases, quorum, votes,
                 grace_period, not_before, not_after,
                 certificates: List[str],
                 signers_certs: List[str],
                 signers_keys: List[str]):
    """
    Generate a new TRC.
    """
    assert (base >= 1 and serial >= 1)
    assert (prev_trc is None) == (base == serial)
    not_before = _utc_timestamp(not_before)
    not_after = _utc_timestamp(not_after)

    # TODO(juagargi) check that the votes member gets populated
    conf = TRCConf(isd_id=isd_id,
                   base_version=base,
                   serial_version=serial,
                   grace_period=grace_period,
                   not_before=not_before,
                   not_after=not_after,
                   core_ases=primary_ases,
                   authoritative_ases=primary_ases,
                   certificates={os.path.basename(mktemp()): c.encode("ascii")
                                 for c in certificates},
                   votes=votes,
                   predecessor_trc=prev_trc)

    with conf.configure() as trc:
        trc.gen_payload()
        signed_payload = []
        for c, k in zip(signers_certs, signers_keys):
            signed_payload.append(trc.sign_payload(c.encode("ascii"), k.encode("ascii")))
        return trc.combine(*signed_payload)


def deleteme_is_regular_update(new: Dict[str, CoreKeys], prev: Dict[str, CoreKeys]) -> bool:
    """

    A sensitive update is any update that is not "regular" (as defined above). The following
    conditions must be met:

    - All votes must be issued with the offline voting key authenticated by the previous TRC.

    Compared to the regular update, the restriction that voting ASes with changed online voting key
    must cast a vote is lifted. This allows replacing the online and offline voting key of a voting
    AS that has lost its offline voting key without revoking the voting status.
    """

    return (new.keys() == prev.keys() and
            all(_equal_key(new[as_id].voting_offline, prev[as_id].voting_offline)
                for as_id in prev.keys()))


def _regular_voting_keys(primary_ases: Dict[str, CoreKeys],
                         changed_keys: Dict[str, CoreKeySet]) -> Dict[str, CoreKeySet]:
    def regular_voting_key(as_id, keys):
        if 'voting_online' in changed_keys[as_id]:
            return {'voting_offline': keys.voting_offline}
        else:
            return {'voting_online': keys.voting_online}

    return {as_id: regular_voting_key(as_id, keys) for as_id, keys in primary_ases.items()}


def _sensitive_voting_keys(prev_voting_offline: Dict[str, Key]) -> Dict[str, CoreKeySet]:
    return {as_id: {'voting_offline': key} for as_id, key in prev_voting_offline.items()}


def _changed_keys(new: Dict[str, CoreKeys], prev: Dict[str, CoreKeys]) -> Dict[str, CoreKeySet]:
    def changed_set(new_as_keys, prev_as_keys):
        if prev_as_keys is None:
            return new_as_keys._asdict()
        else:
            return {usage: new_key
                    for usage, new_key in new_as_keys._asdict().items()
                    if not _equal_key(new_key, getattr(prev_as_keys, usage))}

    return {as_id: changed_set(new[as_id], prev.get(as_id)) for as_id in new.keys()}


def _equal_key(a, b):
    return (a.version, a.pub_key) == (b.version, b.pub_key)


def _build_payload(isd,
                   version,
                   grace_period,
                   not_before,
                   not_after,
                   primary_ases,
                   votes,
                   proof_of_possession):
    """
    Build a TRC payload as a dict. See
    https://github.com/scionproto/scion/blob/master/doc/ControlPlanePKI.md#trc-format
    """
    return {
        "isd": isd.isd_id,
        "trc_version": version,
        "base_version": 1,
        "description": "SCIONLab %s" % isd,
        "voting_quorum": len(primary_ases),
        "format_version": 1,
        "grace_period": int(grace_period.total_seconds()),
        "trust_reset_allowed": False,
        "validity": {
            "not_before": _utc_timestamp(not_before),
            "not_after": _utc_timestamp(not_after),
        },
        "primary_ases": {
            as_id: {
                "attributes": ["authoritative", "core", "issuing", "voting"],
                "keys": {
                    usage: {
                        "key_version": key.version,
                        "algorithm": "Ed25519",
                        "key": key.pub_key
                    }
                    for usage, key in primary_ases[as_id]._asdict().items()
                }
            }
            for as_id in primary_ases.keys()
        },
        "votes": {as_id: next(iter(keys.keys()))
                  for as_id, keys in votes.items()},
        "proof_of_possession": {as_id: list(keys.keys())
                                for as_id, keys in proof_of_possession.items()},
    }


def _build_signed_trc(payload, votes, proof_of_possession):
    # one signature for each vote or proof of possession.
    signatures = [(as_id, "vote", usage, key)
                  for as_id, keys in votes.items()
                  for usage, key in keys.items()]
    signatures += [(as_id, "proof_of_possession", usage, key)
                   for as_id, keys in proof_of_possession.items()
                   for usage, key in keys.items()]

    payload_enc = jws.encode(payload)
    return {
        "payload": payload_enc,
        "signatures": [_signature_entry(payload_enc, as_id, type, usage, key)
                       for as_id, type, usage, key in signatures]
    }


def _signature_entry(payload_enc, as_id, type, key_usage, key):
    protected_enc = jws.encode(_build_protected_hdr(as_id, type, key_usage, key))
    return {
        "protected": protected_enc,
        "signature": jws.signature(payload_enc, protected_enc, key.priv_key)
    }


def _build_protected_hdr(as_id, type, key_usage, key):
    return {
        "alg": "Ed25519",
        "crit": ["type", "key_type", "key_version", "as"],
        "type": type,
        "key_type": key_usage,
        "key_version": key.version,
        "as": as_id,
    }


def _decode_primary_ases(trc):
    payload = jws.decode_payload(trc)

    def _key_info(key_entry):
        return Key(
            version=key_entry['key_version'],
            priv_key=None,
            pub_key=key_entry['key'],
        )

    def _core_keys(as_entry):
        return CoreKeys(**{
            usage: _key_info(key_entry) for usage, key_entry in as_entry['keys'].items()
        })

    return {as_id: _core_keys(as_entry)
            for as_id, as_entry in payload['primary_ases'].items()}


def test_verify(trc,
                expected_votes: List[Tuple[str, str, Key]],
                expected_pops: List[Tuple[str, str, Key]]) -> bool:
    """
    Verify that the TRC was signed with (exactly) the given signing keys.

    WARNING: for testing only!
    """

    payload_enc = trc['payload']
    signatures = trc['signatures']

    expected_signatures = [
        (as_id, 'vote', usage, key) for as_id, usage, key in expected_votes
    ] + [
        (as_id, 'proof_of_possession', usage, key) for as_id, usage, key in expected_pops
    ]

    remaining_signatures = {(as_id, type, usage, key.version): key.pub_key
                            for as_id, type, usage, key in expected_signatures}

    for signature in signatures:
        protected_enc = signature['protected']

        protected = jws.decode(protected_enc)
        as_id = protected['as']
        type = protected['type']
        key_usage = protected['key_type']
        key_version = protected['key_version']
        # assume that other fields in protected header are fine.

        pub_key = remaining_signatures.pop((as_id, type, key_usage, key_version))
        if not pub_key:
            return False

        if not jws.verify(payload_enc, protected_enc, signature['signature'], pub_key):
            return False

    if remaining_signatures:
        return False

    return True


# def _utc_timestamp(dt: datetime) -> int:
#     """
#     Return the timestamp for a naive datetime representing UTC time.
#     """
#     assert dt.tzinfo is None, "Timestamps from DB are expected to be naive UTC datetimes"
#     return int(dt.replace(tzinfo=timezone.utc).timestamp())



def _utc_timestamp(dt: datetime) -> datetime:
    """ Return the utc datetime for a naive datetime """
    assert dt.tzinfo is None, "Timestamps from DB are expected to be naive UTC datetimes"
    return dt.replace(tzinfo=timezone.utc)



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
    # TODO(juagargi) certificates should just be a list of certificates;
    # should create random file names on the fly
    def __init__(self,
                 isd_id: int,
                 base_version: int,
                 serial_version: int,
                 grace_period: timedelta,
                 not_before: datetime,
                 not_after: datetime,
                 authoritative_ases: List[str],
                 core_ases: List[str],
                 certificates: Dict[str, bytes],
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
        self.votes = votes
        self.predecessor_trc = predecessor_trc

        self._validate()

    @contextmanager
    def configure(self):
        # create temp dir and temp files for certificates
        try:
            temp_dir = TemporaryDirectory()
            self._temp_dir = temp_dir
            self._dump_certificates_to_files()
            yield self
        finally:
            temp_dir.cleanup()
            self._temp_dir = temp_dir  # only needed if nested call to configure()

    def gen_payload(self) -> None:
        conf = self._get_conf()
        with open(self._tmp_join(self._conf_filename()), "w") as f:
            f.write(toml.dumps(conf))
        args = ["payload", "-t", self._conf_filename(), "-o", self._payload_filename()]
        if self.predecessor_trc:
            predecessor_fn = self._tmp_join(self._predecessor_trc_name())
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
            os.chdir(self._temp_dir.name)
            with open(KEY_FILENAME, "wb") as f:
                f.write(key)
            with open(CERT_FILENAME, "wb") as f:
                f.write(cert)
            command = ["openssl", "cms", "-sign", "-in", self._payload_filename(),
                       "-inform", "der", "-md", "sha512", "-signer", CERT_FILENAME,
                       "-inkey", KEY_FILENAME, "-nodetach", "-nocerts", "-nosmimecap",
                       "-binary", "-outform", "der", "-out", "trc-signed.der"]
            subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
            # remove they key, although it should be deleted when the temporary dir is cleaned up
            os.remove(KEY_FILENAME)
            # read the signed trc and return it
            with open("trc-signed.der", "rb") as f:
                return f.read()
        finally:
            os.chdir(prev_cwd)

    def combine(self, *signed) -> bytes:
        """ returns the final TRC by combining the signed blocks and payload """
        for i in range(len(signed)):
            with open(os.path.join(self._temp_dir.name, f"signed-{i}.der"), "wb") as f:
                f.write(signed[i])
        self._run_scion_cppki(
            "combine", "-p", self._payload_filename(),
            *(f"signed-{i}.der" for i in range(len(signed))),
            "-o", os.path.join(self._temp_dir.name, self._trc_filename()),
        )
        with open(os.path.join(self._temp_dir.name, self._trc_filename()), "rb") as f:
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

        # check the certificate file names only contain file names and not paths.
        # the rest of invalid file names will fail when configure() is called.
        for fn in self.certificates.keys():
            p = os.path.normpath(fn)  # not necessary, as we ask for filenames only and not paths
            if os.path.dirname(p) or not os.path.basename(p) or p in {".", ".."}:
                raise ValueError(f"certificate file name is invalid: {fn}")

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
            "cert_files": list(self.certificates.keys()),
            "no_trust_reset": False,
            # TODO(juagargi) check we will fill the "votes" member later
            # "votes": 1  # empty when updating only serial_version
            "validity": {
                "not_before": int(self.not_before.timestamp()),
                "validity": self._to_seconds(self.not_after - self.not_before),
            },
            "votes": self.votes,
        }

    def _voting_quorum(self) -> int:
        return len(self.core_ases) // 2 + 1

    def _grace_period(self) -> str:
        # must be zero for base TRCs
        if self.base_version == self.serial_version:
            return "0s"
        else:
            return self._to_seconds(self.grace_period)

    def _tmp_join(self, filename: str) -> str:
        return os.path.join(self._temp_dir.name, filename)

    def _dump_certificates_to_files(self) -> None:
        for fn, c in self.certificates.items():
            with open(self._tmp_join(fn), "wb") as f:
                f.write(c)

    def _run_scion_cppki(self, *args) -> str:
        """ runs the binary scion-pki """
        prev_cwd = os.getcwd()
        try:
            os.chdir(self._temp_dir.name)
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

    @staticmethod
    def _conf_filename() -> str:
        return "scionlab-trc-config.toml"

    @staticmethod
    def _payload_filename() -> str:
        return "scionlab-trc-payload.der"

    @staticmethod
    def _trc_filename() -> str:
        return "scionlab-trc.trc"

    @staticmethod
    def _predecessor_trc_name() -> str:
        return "predecessor-trc.trc"


def _raw_run_scion_cppki(*args):
    return subprocess.run([SCION_CPPKI_COMMAND, "trcs", *args],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
