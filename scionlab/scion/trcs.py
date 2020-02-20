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

import json
import base64
from collections import namedtuple
from datetime import timedelta
from typing import Dict

from scionlab.scion import keys

Key = namedtuple('Key', ['version', 'priv_key', 'pub_key'])
CoreKeys = namedtuple('CoreKeys', ['issuing_grant', 'voting_online', 'voting_offline'])
CoreKeySet = Dict[str, Key]


def generate_trc(isd, version, grace_period, not_before, not_after, primary_ases,
                 prev_trc, prev_voting_offline):

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
    pops = changed

    payload = _build_payload(
        isd,
        version,
        grace_period,
        not_before,
        not_after,
        primary_ases,
        votes,
        pops
    )

    return _build_signed_trc(payload, votes, pops)


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
            all(new[as_id].voting_offline == prev[as_id].voting_offline for as_id in prev.keys()))


def _regular_voting_keys(primary_ases: Dict[str, CoreKeys],
                         changed_keys: Dict[str, CoreKeySet]) -> Dict[str, CoreKeySet]:
    def regular_voting_key(as_id, keys):
        if 'voting_online' in changed_keys[as_id]:
            return {'voting_offline', keys.voting_offline}
        else:
            return {'voting_online', keys.voting_online}

    return {as_id: regular_voting_key(as_id, keys) for as_id, keys in primary_ases.items()}


def _sensitive_voting_keys(prev_voting_offline: Dict[str, Key]) -> Dict[str, CoreKeySet]:
    return {as_id: {'voting_offline': key} for as_id, key in prev_voting_offline.items()}


def _changed_keys(new: Dict[str, CoreKeys], prev: Dict[str, CoreKeys]) -> Dict[str, CoreKeySet]:

    def equal_key(a, b):
        return (a.version, a.pub_key) == (b.version, b.pub_key)

    def changed_set(new_as_keys, prev_as_keys):
        if prev_as_keys is None:
            return new_as_keys._asdict()
        else:
            return {usage: new_key
                    for usage, new_key in new_as_keys._asdict().items()
                    if not equal_key(new_key, getattr(prev_as_keys, usage))}

    return {as_id: changed_set(new[as_id], prev.get(as_id)) for as_id in new.keys()}


def _build_payload(isd,
                   version,
                   grace_period,
                   not_before,
                   not_after,
                   primary_ases,
                   votes,
                   proof_of_posession):
    return {
        "isd": isd.isd_id,
        "version": version,
        "base_version": 1,
        "description": "SCIONLab %s" % isd,
        "voting_quorum": len(primary_ases),
        "format_version": 1,
        "grace_period": int(grace_period.total_seconds()),
        "trust_reset_allowed": False,
        "validity": {
            "not_before": int(not_before.timestamp()),
            "not_after": int(not_after.timestamp()),
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
        "proof_of_posession": {as_id: list(keys.keys())
                               for as_id, keys in proof_of_posession.items()},
    }


def _build_signed_trc(payload, votes, proof_of_posession):

    # one signature for each vote or proof of posession.
    signatures = [(as_id, usage, key)
                  for keyset in (votes, proof_of_posession)
                  for as_id, keys in keyset.items()
                  for usage, key in keys.items()]

    payload_enc = b64url(json.dumps(payload).encode())
    return {
        "payload": payload_enc,
        "signatures": [_jws_signature(payload_enc, as_id, usage, key)
                       for as_id, usage, key in signatures]
    }


def _jws_signature(payload_enc, as_id, key_usage, key):
    protected = {
        "alg": "Ed25519",
        "crit": ["type", "key_version", "as"],
        "type": key_usage,
        "key_version": key.version,
        "as": as_id,
    }

    protected_enc = b64url(json.dumps(protected).encode())

    sigmsg = (protected_enc + '.' + payload_enc).encode()
    return {
        "protected": protected_enc,
        "signature": b64url(keys.sign(sigmsg, key.priv_key))
    }


def _decode_primary_ases(trc):
    payload = decode_payload(trc)

    def _key_info(key_entry):
        return Key(
            version=key_entry.version,
            pub_key=key_entry.key
        )

    def _core_keys(as_entry):
        return CoreKeys(**{
            usage: _key_info(key_entry) for usage, key_entry in as_entry['keys'].items()
        })

    return {as_id: _core_keys(as_entry)
            for as_id, as_entry in payload['primary_ases'].items()}


def decode_payload(trc):
    payload_enc = trc['payload']
    payload = json.loads(b64urldec(payload_enc).decode())
    return payload


def verify(trc, signing_keys: Dict[str, CoreKeySet]) -> bool:
    """
    Verify that the TRC was signed with (exactly) the given signing keys.

    WARNING: for testing only!
    """

    payload_enc = trc['payload']
    signatures = trc['signatures']

    remaining_keys = {(as_id, usage, key.version): key
                      for as_id, keyset in signing_keys.items()
                      for usage, key in keyset.items()}

    for signature in signatures:
        protected_enc = signature['protected']
        protected = json.loads(b64urldec(protected_enc).decode())

        as_id = protected['as']
        key_usage = protected['type']
        key_version = protected['key_version']
        # assume that other fields in protected header are fine.

        key = remaining_keys.pop((as_id, key_usage, key_version))
        if not key:
            return False

        sigmsg = (protected_enc + '.' + payload_enc).encode()
        valid = keys.verify(sigmsg, b64urldec(signature['signature']), key.pub_key)
        if not valid:
            return False

    if remaining_keys:
        return False

    return True


def b64url(input: bytes) -> str:
    return base64.urlsafe_b64encode(input).decode().rstrip('=')


def b64urldec(input: str) -> bytes:
    # We stripped the (redundant) padding '=', but the decoder checks for them.
    # Appending three = is the easiest way to ensure it won't choke on too little padding.
    return base64.urlsafe_b64decode(input + '===')
