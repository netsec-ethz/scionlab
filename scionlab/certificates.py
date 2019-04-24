# Copyright 2018 ETH Zurich
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

import time
import base64
from lib.crypto.certificate import Certificate
from lib.crypto.trc import (TRC,
                            ONLINE_KEY_STRING,
                            ONLINE_KEY_ALG_STRING,
                            OFFLINE_KEY_STRING,
                            OFFLINE_KEY_ALG_STRING)


_YEAR_SECONDS = 365 * 24 * 60 * 60
TRC_VALIDITY_PERIOD = _YEAR_SECONDS
CORE_AS_VALIDITY_PERIOD = _YEAR_SECONDS
KEYGEN_ALG = 'ed25519'


def generate_trc(isd):
    """
    Create or update the TRC for the given ISD.
    Returns the TRC as a dict and a dict containing the private keys needed to sign the next
    TRC version.

    :param ISD isd:
    :returns: (dict, dict) TRC, trc_priv_keys
    """
    if isd.trc:
        version = isd.trc['Version'] + 1
    else:
        version = 1

    core_ases = list(isd.ases.filter(is_core=True))

    core_ases_keys = {as_.isd_as_str(): {ONLINE_KEY_STRING: as_.core_online_pub_key,
                                         ONLINE_KEY_ALG_STRING: KEYGEN_ALG,
                                         OFFLINE_KEY_STRING: as_.core_offline_pub_key,
                                         OFFLINE_KEY_ALG_STRING: KEYGEN_ALG}
                      for as_ in core_ases}

    trc = TRC.from_values(isd=isd.isd_id,
                          description=str(isd),
                          version=version,
                          core_ases=core_ases_keys,
                          root_cas={},
                          cert_logs={},
                          threshold_eepki=0,
                          rains={},
                          quorum_trc=len(core_ases),
                          quorum_cas=0,
                          grace_period=0,
                          quarantine=False,
                          signatures={},
                          validity_period=TRC_VALIDITY_PERIOD)

    # Sign with private keys corresponding to public keys (core AS online public keys) in previous
    # TRC version
    # For initial version simply use the private online keys
    core_ases_online_priv_keys = {as_.isd_as_str(): as_.core_online_priv_key for as_ in core_ases}
    signing_keys = isd.trc_priv_keys or core_ases_online_priv_keys

    for isd_as, sig_priv_key in signing_keys.items():
        trc.sign(isd_as, base64.b64decode(sig_priv_key))

    # Return trc and signing keys for next version:
    # The keys and signatures are contained as bytes-objects in the dict returned, encode them
    return _base64encode_dict(trc.dict(with_signatures=True)), core_ases_online_priv_keys


def generate_core_certificate(as_):
    """
    Create or update the Core AS Certificate for `as_`.
    If the AS already has a Core AS Certificate, the version number is incremented for the
    new certificate.

    Requires that TRC for the related ISD exists/is up to date.

    :param AS as_: a core AS
    :returns: the Core AS Certificate as a dict
    """
    isd = as_.isd
    assert isd.trc
    trc = TRC(isd.trc)

    if as_.core_certificate:
        version = as_.core_certificate['Version'] + 1
    else:
        version = 1

    cert = Certificate.from_values(
        subject=as_.isd_as_str(),
        issuer=as_.isd_as_str(),
        trc_version=trc.version,
        version=version,
        comment="Core AS Certificate",
        can_issue=True,
        validity_period=min(trc.exp_time - int(time.time()) - 1, CORE_AS_VALIDITY_PERIOD),
        subject_enc_key=b"",
        subject_sig_key=base64.b64decode(as_.core_sig_pub_key),
        iss_priv_key=base64.b64decode(as_.core_online_priv_key)
    )
    return cert.dict()


def generate_as_certificate_chain(subject_as, issuing_as):
    """
    Create or update the AS Certificate for `subject_as`, issued by `issuing_as`.
    If the AS already has an AS Certificate, the version number is incremented for the
    new certificate.

    Requires that `issuing_as` is a core AS with an existing/up to date Core AS Certificate.
    Requires that the ASes are in the same ISD and that the TRC exists/is up to date.

    :param AS subject_as: Subject AS
    :param AS issuing_AS: Issuing AS
    :returns: the AS Certificate chain as a dict
    """
    assert issuing_as.is_core
    assert issuing_as.core_certificate
    assert issuing_as.isd == subject_as.isd
    isd = issuing_as.isd
    assert isd.trc

    trc_version = isd.trc['Version']

    if subject_as.certificate_chain:
        version = subject_as.certificate_chain["0"]['Version'] + 1
    else:
        version = 1

    core_as_cert = Certificate(issuing_as.core_certificate)

    cert = Certificate.from_values(
        subject=subject_as.isd_as_str(),
        issuer=issuing_as.isd_as_str(),
        trc_version=trc_version,
        version=version,
        comment="AS Certificate",
        can_issue=False,
        validity_period=core_as_cert.expiration_time - int(time.time()) - 1,
        subject_enc_key=base64.b64decode(subject_as.enc_pub_key),  # will be encoded again, but WTH
        subject_sig_key=base64.b64decode(subject_as.sig_pub_key),
        iss_priv_key=base64.b64decode(issuing_as.core_sig_priv_key)
    )
    # CertificateChain does NOT have a dict method (only "to_json"), so we just do this manually:
    cert_chain_dict = {
        "0": cert.dict(),
        "1": core_as_cert.dict()
    }
    return cert_chain_dict


def _base64encode_dict(dict_):
    """
    Base64-encode all `bytes`-items in this `dict_` and recursively in all sub-dicts.
    :param dict dict_: dict, potentially containing bytes objects
    :returns: dict with bytes-objects base64-encoded
    """
    def _encoded(val):
        if isinstance(val, bytes):
            return base64.b64encode(val).decode()
        elif isinstance(val, dict):
            return _base64encode_dict(val)
        else:
            return val
    return {key: _encoded(val) for key, val in dict_.items()}
