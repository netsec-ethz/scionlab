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
import toml
from django.test import TestCase
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Tuple

from scionlab.defines import DEFAULT_TRC_GRACE_PERIOD
from scionlab.scion import certs, keys
from scionlab.scion.trcs import TRCConf, generate_trc, trc_to_dict
from scionlab.tests.utils import check_scion_trc

_TESTDATA_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data/test_scion_trcs")


class TRCCreationTests(TestCase):
    """ tests the correct behavior of the TRCConf class """
    def test_validate(self):
        kwargs = _trcconf_args_dict()
        TRCConf(**kwargs)  # doesn't raise
        kwargs["isd_id"] = -1
        self.assertRaises(ValueError, TRCConf, **kwargs)
        # version and update readyness
        kwargs = _trcconf_args_dict()
        kwargs["base_version"] = 2
        self.assertRaises(ValueError, TRCConf, **kwargs)
        kwargs = _trcconf_args_dict()
        kwargs["serial_version"] = kwargs["serial_version"] + 1
        self.assertRaises(ValueError, TRCConf, **kwargs)  # needs votes and predecessor
        kwargs["votes"] = [1]
        self.assertRaises(ValueError, TRCConf, **kwargs)  # still needs predecessor
        kwargs["predecessor_trc"] = b""
        TRCConf(**kwargs)  # okay now
        # validity
        kwargs = _trcconf_args_dict()
        kwargs["not_after"] = kwargs["not_before"]
        self.assertRaises(ValueError, TRCConf, **kwargs)
        # certificates
        kwargs = _trcconf_args_dict()
        kwargs["certificates"] = []
        self.assertRaises(ValueError, TRCConf, **kwargs)

    def test_gen_payload(self):
        # load conf. toml dictionary
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            toml_conf = toml.load(f)
        kwargs = _transform_toml_conf_to_trcconf_args(toml_conf)
        conf = TRCConf(**kwargs)
        with TemporaryDirectory() as temp_dir:
            conf._dump_certificates_to_files(temp_dir)
            conf._gen_payload(temp_dir)
            gen_conf = toml.loads(_readfile(temp_dir, conf.CONFIG_FILENAME).decode())
            gen_payload = _readfile(temp_dir, conf.PAYLOAD_FILENAME)
        # gen_conf contains random certificate filenames. Replace them before comparing:
        gen_conf["cert_files"] = toml_conf["cert_files"]
        self.assertEqual(gen_conf, toml_conf)
        self.assertEqual(gen_payload, _readfile(_TESTDATA_DIR, "payload-1.der"))

    def test_sign_payload(self):
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            toml_conf = toml.load(f)
        kwargs = _transform_toml_conf_to_trcconf_args(toml_conf)
        conf = TRCConf(**kwargs)
        with TemporaryDirectory() as temp_dir:
            conf._dump_certificates_to_files(temp_dir)
            conf._gen_payload(temp_dir)

            base_filenames = ["voting-sensitive-ff00_0_110",
                              "voting-regular-ff00_0_210"]
            # zip the base filenames with the content to a list of (filename, cert, key):
            signers = zip(base_filenames, *zip(*_get_signers(base_filenames)))
            for (fn, cert, key) in signers:
                signed = conf._sign_payload(temp_dir, cert, key)
                cert_fn = os.path.join(_TESTDATA_DIR, f"{fn}.crt")
                cmd = ["openssl", "cms", "-verify",
                       "-inform", "der", "-certfile", cert_fn,
                       "-CAfile", cert_fn,
                       "-purpose", "any", "-no_check_time"]
                subprocess.run(cmd, input=signed, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    def test_combine(self):
        # list of (cert, key)
        signers = _get_signers(["voting-sensitive-ff00_0_110",
                                "voting-regular-ff00_0_110"])
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            conf = TRCConf(**_transform_toml_conf_to_trcconf_args(toml.load(f)))
        signed_payloads = []
        with TemporaryDirectory() as temp_dir:
            conf._dump_certificates_to_files(temp_dir)
            conf._gen_payload(temp_dir)
            for (cert, key) in signers:
                signed_payloads.append(conf._sign_payload(temp_dir, cert, key))
            trc = conf._combine(temp_dir, *signed_payloads)
        # verify the trc with a call to scion-pki (would raise if error)
        check_scion_trc(self, trc, trc)

    def test_sign_other_certificate(self):
        # list of (cert, key)
        signers = _get_signers(["voting-sensitive-ff00_0_110",
                                "voting-regular-ff00_0_110"])

        # replace the first certificate with a new, valid, one, generated from the key
        key = signers[0][1]  # key at index 1, cert at index 0
        orig_cert = certs.decode_certificate(signers[0][0])
        cert = certs.generate_voting_sensitive_certificate(
            '1-ff00:0:110',
            keys.decode_key(key),
            not_before=orig_cert.not_valid_before,
            not_after=orig_cert.not_valid_after)
        # sanity check for the new certificate:
        self.assertEqual(cert.subject, orig_cert.subject)
        self.assertEqual(cert.issuer, orig_cert.issuer)
        self.assertEqual(cert.not_valid_before, orig_cert.not_valid_before)
        self.assertEqual(cert.not_valid_after, orig_cert.not_valid_after)
        self.assertNotEqual(cert.serial_number, orig_cert.serial_number)
        self.assertNotEqual(cert.signature, orig_cert.signature)
        # actually replace the certificate in the signers list, keep the key
        signers[0] = (certs.encode_certificate(cert),
                      signers[0][1])
        # and go on as usual

        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            conf = TRCConf(**_transform_toml_conf_to_trcconf_args(toml.load(f)))
        signed_payloads = []
        with TemporaryDirectory() as temp_dir:
            conf._dump_certificates_to_files(temp_dir)
            conf._gen_payload(temp_dir)
            for (cert, key) in signers:
                signed_payloads.append(conf._sign_payload(temp_dir, cert, key))
            trc = conf._combine(temp_dir, *signed_payloads)
        # verify the trc with a call to scion-pki (would raise if error)
        check_scion_trc(self, trc, trc, expected_failure=True)

    def test_generate(self):
        signers = _get_signers(["voting-sensitive-ff00_0_110",
                                "voting-regular-ff00_0_110"])
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            conf = TRCConf(**_transform_toml_conf_to_trcconf_args(toml.load(f), signers))
        trc = conf.generate()
        # verify the trc with a call to scion-pki (would raise if error)
        check_scion_trc(self, trc, trc)

    def test_generate_trc(self):
        # generate a new TRC using the generate_trc function
        core_ases = ["ffaa:0:110"]
        certificates = ["voting-sensitive-ff00_0_110.crt",
                        "voting-regular-ff00_0_110.crt",
                        "root-ff00_0_110.crt"]
        certificates = [_readfile(_TESTDATA_DIR, f, text=True) for f in certificates]
        signers = _get_signers(["voting-sensitive-ff00_0_110",
                                "voting-regular-ff00_0_110"])
        scerts, skeys = zip(*signers)
        not_before = datetime.fromtimestamp(1605168000, tz=timezone.utc)
        not_before = not_before.replace(tzinfo=None)  # dates in DB have no timezone (all UTC)
        not_after = not_before + timedelta(seconds=1800)

        trc = generate_trc(prev_trc=None, isd_id=1, base=1, serial=1,
                           primary_ases=core_ases, quorum=1, votes=[],
                           grace_period=DEFAULT_TRC_GRACE_PERIOD,
                           not_before=not_before, not_after=not_after,
                           certificates=certificates,
                           signers_certs=[c.decode("ascii") for c in scerts],
                           signers_keys=[k.decode("ascii") for k in skeys])
        # test final trc
        check_scion_trc(self, trc, trc)


class TRCUpdate(TestCase):
    def test_regular_update(self):
        # initial TRC in TESTDATA/trc-1.trc
        predec_trc = _readfile(_TESTDATA_DIR, "trc-1.trc")
        # update the TRC by just incrementing the serial. That is in payload-2-config.toml
        signers = _get_signers(["voting-regular-ff00_0_110"])
        kwargs = _transform_toml_conf_to_trcconf_args(toml.loads(
            _readfile(_TESTDATA_DIR, "payload-2-config.toml", text=True)), signers)
        conf = TRCConf(**kwargs, predecessor_trc=predec_trc)
        trc = conf.generate()
        # verify trc with the old trc as anchor
        check_scion_trc(self, trc, predec_trc)

    def test_sensitive_update(self):
        # previous TRC in TESTDATA/trc-2.trc
        predec_trc = _readfile(_TESTDATA_DIR, "trc-2.trc")
        # add a core-authoritative AS and its sensitive, regular and root certs
        signers = _get_signers(["voting-sensitive-ff00_0_110",
                                "voting-sensitive-ff00_0_210",
                                "voting-regular-ff00_0_210"])
        with open(os.path.join(_TESTDATA_DIR, "payload-3-config.toml")) as f:
            kwargs = _transform_toml_conf_to_trcconf_args(toml.load(f), signers)
        conf = TRCConf(**kwargs, predecessor_trc=predec_trc)
        trc = conf.generate()
        # verify trc with the old trc as anchor
        check_scion_trc(self, trc, predec_trc)

    def test_generate_trc_regular_update(self):
        # initial TRC in TESTDATA/trc-1.trc
        signers = _get_signers(["voting-regular-ff00_0_110"])
        scerts, skeys = zip(*signers)

        kwargs = _transform_toml_conf_to_trcconf_args(toml.loads(
            _readfile(_TESTDATA_DIR, "payload-2-config.toml", text=True)))
        predec_trc = _readfile(_TESTDATA_DIR, "trc-1.trc")
        _replace_keys(kwargs,
                      [("base", "base_version"),
                       ("serial", "serial_version"),
                       ("primary_ases", "authoritative_ases"),
                       ("primary_ases", "core_ases")])
        # dates in DB have no timezone (all UTC)
        kwargs["not_before"] = kwargs["not_before"].replace(tzinfo=None)
        kwargs["not_after"] = kwargs["not_after"].replace(tzinfo=None)
        kwargs["certificates"] = [c.decode("ascii") for c in kwargs["certificates"]]
        del kwargs["signers"]
        trc = generate_trc(prev_trc=predec_trc, **kwargs,
                           quorum=len(kwargs["primary_ases"]) // 2 + 1,
                           signers_certs=[c.decode("ascii") for c in scerts],
                           signers_keys=[k.decode("ascii") for k in skeys])
        # test final trc
        check_scion_trc(self, trc, predec_trc)

    def test_generate_trc_sensitive_update(self):
        # initial TRC in TESTDATA/trc-1.trc
        signers = _get_signers(["voting-sensitive-ff00_0_110",
                                "voting-sensitive-ff00_0_210",
                                "voting-regular-ff00_0_210"])
        scerts, skeys = zip(*signers)

        kwargs = _transform_toml_conf_to_trcconf_args(toml.loads(
            _readfile(_TESTDATA_DIR, "payload-3-config.toml", text=True)))
        predec_trc = _readfile(_TESTDATA_DIR, "trc-2.trc")
        _replace_keys(kwargs,
                      [("base", "base_version"),
                       ("serial", "serial_version"),
                       ("primary_ases", "authoritative_ases"),
                       ("primary_ases", "core_ases")])
        # dates in DB have no timezone (all UTC)
        kwargs["not_before"] = kwargs["not_before"].replace(tzinfo=None)
        kwargs["not_after"] = kwargs["not_after"].replace(tzinfo=None)
        kwargs["certificates"] = [c.decode("ascii") for c in kwargs["certificates"]]
        del kwargs["signers"]
        trc = generate_trc(prev_trc=predec_trc, **kwargs,
                           quorum=len(kwargs["primary_ases"]) // 2 + 1,
                           signers_certs=[c.decode("ascii") for c in scerts],
                           signers_keys=[k.decode("ascii") for k in skeys])
        # test final trc
        check_scion_trc(self, trc, predec_trc)


class TRCTests(TestCase):
    def test_trc_to_dict(self):
        with open(os.path.join(_TESTDATA_DIR, "trc-3.trc"), 'rb') as f:
            trc = f.read()
        d = trc_to_dict(trc)

        # important keys present:
        for k in ['id', 'validity', 'votes', 'core_ases', 'certificates', 'signatures']:
            self.assertTrue(k in d)
        # check the id fields:
        for k in ['isd', 'base_number', 'serial_number']:
            self.assertTrue(k in d['id'], f'key {k} not present in {d["id"]}')
        # check validity:
        for k in ['not_before', 'not_after']:
            self.assertTrue(k in d['validity'], f'key {k} not present in {d["validity"]}')
        # check votes
        iter(d['votes'])  # it should be iterable (e.g. list). Exception otherwise.
        # check core_ases
        iter(d['core_ases'])  # exception if not iterable
        # check certificates format. Should be a collection of certificates.
        certs = next(iter(d['certificates']))  # exception if not iterable
        for k in ['type', 'common_name', 'validity', 'serial_number']:
            self.assertTrue(k in certs, f'key {k} not present in {certs}')
        # signatures:
        signatures = next(iter(d['signatures']))
        for k in ['common_name', 'isd_as', 'serial_number', 'signing_time']:
            self.assertTrue(k in signatures, f'key {k} not present in {signatures}')


def _trcconf_args_dict():
    return {"isd_id": 1, "base_version": 1, "serial_version": 1, "grace_period": None,
            "not_before": datetime.utcnow(), "not_after": datetime.utcnow() + timedelta(days=1),
            "authoritative_ases": ["1-ff00:0:110"], "core_ases": ["1-ff00:0:110"],
            "certificates": [b"no-content"], "signers": []}


def _readfile(*path_args, text=False):
    mode = "r" if text else "rb"
    with open(os.path.join(*path_args), mode) as f:
        return f.read()


def _transform_toml_conf_to_trcconf_args(toml_dict: Dict,
                                         signers: Optional[List[Tuple[bytes, bytes]]] = []
                                         ) -> Dict[str, Any]:
    """
    transforms a TRC configuration template in toml to the arguments required to
    instantiate a new TRCConf object
    """
    # adapt the dictionary to be used with the TRCConf class
    not_before = datetime.fromtimestamp(toml_dict["validity"]["not_before"], tz=timezone.utc)
    not_before = not_before.replace(tzinfo=None)  # expected in UTC without timezone
    certificates = [_readfile(_TESTDATA_DIR, f) for f in toml_dict["cert_files"]]
    return {
        "isd_id": toml_dict["isd"],
        "base_version": toml_dict["base_version"],
        "serial_version": toml_dict["serial_version"],
        "grace_period": timedelta(seconds=int(toml_dict["grace_period"][:-1])),
        "not_before": not_before,
        "not_after": not_before + timedelta(seconds=int(
            toml_dict["validity"]["validity"][:-1])),
        "authoritative_ases": toml_dict["authoritative_ases"],
        "core_ases": toml_dict["core_ases"],
        "certificates": certificates,
        "signers": signers,
        "votes": toml_dict.get("votes"),
    }


def _replace_keys(d: Dict[str, Any], keys: List[Tuple[str, str]]) -> Dict[str, Any]:
    """ keys is a list of tuples (new_key, old_key) """
    for (nk, ok) in keys:
        d[nk] = d.pop(ok)


def _get_signers(base_filenames):
    return [(_readfile(f"{f}.crt"), _readfile(f"{f}.key")) for f in [
        os.path.join(_TESTDATA_DIR, p) for p in base_filenames]]
