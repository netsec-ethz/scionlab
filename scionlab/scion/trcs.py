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
import subprocess

from collections import namedtuple
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

from scionlab.scion import jws


# XXX(matzf): maybe this entire thing would be a bit simpler if we keep usage as member of Key.
# Then we dont need so many dicts and stuff.
Key = namedtuple('Key', ['version', 'priv_key', 'pub_key'])
CoreKeys = namedtuple('CoreKeys', ['issuing_grant', 'voting_online', 'voting_offline'])
CoreKeySet = Dict[str, Key]


def generate_trc(isd, version, grace_period, not_before, not_after, primary_ases,
                 prev_trc, prev_voting_offline):
    """
    Generate a new TRC.
    """
    # TODO(matzf) doc
    assert (version >= 1)
    assert (version == 1) == (prev_trc is None) == (prev_voting_offline is None)

    if prev_trc:
        prev_primary_ases = _decode_primary_ases(prev_trc)
    else:
        prev_primary_ases = {}

    changed = _changed_keys(primary_ases, prev_primary_ases)
    if version == 1:
        votes = {}
        grace_period = timedelta(0)
    elif _is_regular_update(primary_ases, prev_primary_ases):
        votes = _regular_voting_keys(primary_ases, changed)
    else:
        votes = _sensitive_voting_keys(prev_voting_offline)
    proof_of_possession = changed

    payload = _build_payload(
        isd,
        version,
        grace_period,
        not_before,
        not_after,
        primary_ases,
        votes,
        proof_of_possession,
    )

    return _build_signed_trc(payload, votes, proof_of_possession,)


def _is_regular_update(new: Dict[str, CoreKeys], prev: Dict[str, CoreKeys]) -> bool:
    """
    Check if this is a regular TRC update.


    In a regular update, the voting_quorum parameter must not be changed. In the primary_ases
    section, only the issuing grant and online voting keys can change. No other parts of the
    primary_ases section may change.

    - All votes from ASes with unchanged online voting keys must be cast with the online voting key.
    - All ASes with changed online voting keys must cast a vote with their offline voting key.

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


def _utc_timestamp(dt: datetime) -> int:
    """
    Return the timestamp for a naive datetime representing UTC time.
    """
    assert dt.tzinfo is None, "Timestamps from DB are expected to be naive UTC datetimes"
    return int(dt.replace(tzinfo=timezone.utc).timestamp())






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


def deleteme_run_scion_cppki(*args):
    """
    runs scion-pki
    """
    COMMAND = "/home/juagargi/devel/ETH/scion.scionlab/bin/scion-pki"
    ret = subprocess.run([COMMAND, "trcs", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    if ret.returncode != 0:
        print(ret.stdout.decode("utf-8"))
        raise Exception(f"Bad return code: {ret.returncode}")


def deleteme_trc_configure():
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


def deleteme_trc_generate_payload():
    deleteme_file_name = "scionlab-test-trc-payload.der"
    deleteme_run_scion_cppki("payload", "-t", "scionlab-test-trc-config.toml", "-o", deleteme_file_name)
    return deleteme_file_name


def deleteme_trc_sign_payload():
    # openssl cms -sign -in ISD-B1-S1.pld.der -inform der -md sha512 \
    #     -signer $PUBDIR/regular-voting.crt -inkey $KEYDIR/regular-voting.key \
    #     -nodetach -nocerts -nosmimecap -binary -outform der > ISD-B1-S1.regular.trc

    # verify with:
    # openssl cms -verify -in ISD-B1-S1.regular.trc -inform der \
    # -certfile $PUBDIR/regular-voting.crt -CAfile $PUBDIR/regular-voting.crt \
    # -purpose any -no_check_time > /dev/null
    #
    # k = deleteme_load_key("scionlab-test-regular.key")
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


def deleteme_trc_combine_payloads():
    deleteme_file_name_payload = "scionlab-test-trc-payload.der"
    deleteme_file_names = [
        "scionlab-test-trc-signed.sensitive.trc",
        "scionlab-test-trc-signed.regular.trc",
        ]
    deleteme_run_scion_cppki("combine", "-p", deleteme_file_name_payload, *deleteme_file_names, "-o", "scionlab-test-trc.trc")
    # check the final TRC:
    deleteme_run_scion_cppki("verify", "--anchor", "scionlab-test-trc.trc", "scionlab-test-trc.trc")


def deleteme_generate_trc(isd_id):
    """
    Generates (or regenerates) a TRC
    """
    # configure TRC
    deleteme_trc_configure()
    # generate payload scion-pki trcs payload
    deleteme_trc_generate_payload()
    # sign payload (crypto_lib.sh:sign_payload())
    deleteme_trc_sign_payload()
    # combine signed TRCs
    deleteme_trc_combine_payloads()


