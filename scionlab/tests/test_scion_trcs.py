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
from typing import Any, Dict, List, Tuple

from scionlab.defines import DEFAULT_TRC_GRACE_PERIOD
from scionlab.scion.trcs import TRCConf, generate_trc
from scionlab.tests.utils import check_scion_trc

_TESTDATA_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data/test_scion_trcs")


class TRCCreation(TestCase):
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

    def test_configure(self):
        kwargs = _trcconf_args_dict()
        conf = TRCConf(**kwargs)
        temp_dir_name = ""
        with conf.configure() as c:
            temp_dir_name = c._temp_dir
            # double call (nested in outer, should not happen) must also clean up
            temp_dir_name2 = ""
            with conf.configure() as c2:
                temp_dir_name2 = c2._temp_dir
                self.assertTrue(os.path.isdir(temp_dir_name2))
                self.assertTrue(all(os.path.isfile(f) for f in conf.certificate_files))
            self.assertFalse(os.path.exists(temp_dir_name2))
            # let's do no more shenanigans with nested usage, and check that
            # there is a temporary dir created, with the certificate files
            self.assertTrue(os.path.isdir(temp_dir_name))
            for p, c in zip(conf.certificate_files, conf.certificates):
                self.assertTrue(os.path.isfile(p))
                with open(p, "rb") as f:
                    self.assertEqual(f.read(), c)
        self.assertFalse(os.path.exists(temp_dir_name))

    def test_gen_payload(self):
        # load conf. toml dictionary
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            toml_conf = toml.load(f)
        kwargs = _transform_toml_conf_to_trcconf_args(toml_conf)
        conf = TRCConf(**kwargs)
        with conf.configure() as c:
            c.gen_payload()
            gen_conf = toml.loads(_readfile(c._temp_dir, c._conf_filename()).decode())
            gen_payload = _readfile(c._temp_dir, c._payload_filename())
        # gen_conf contains random certificate filenames. Replace them before comparing:
        gen_conf["cert_files"] = toml_conf["cert_files"]
        self.assertEqual(gen_conf, toml_conf)
        self.assertEqual(gen_payload, _readfile(_TESTDATA_DIR, "payload-1.der"))

    def test_sign_payload(self):
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            toml_conf = toml.load(f)
        kwargs = _transform_toml_conf_to_trcconf_args(toml_conf)
        conf = TRCConf(**kwargs)
        with conf.configure() as c:
            c.gen_payload()
            base_filenames = ["voting-sensitive-ff00_0_110",
                              "voting-regular-ff00_0_210"]
            # zip the base filenames with the content to a list of (filename, cert, key):
            signers = zip(base_filenames, *zip(*_get_signers(base_filenames)))
            for (fn, cert, key) in signers:
                signed = c.sign_payload(cert, key)
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
        with conf.configure() as c:
            c.gen_payload()
            for (cert, key) in signers:
                signed_payloads.append(c.sign_payload(cert, key))
            trc = c.combine(*signed_payloads)
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
            _readfile(_TESTDATA_DIR, "payload-2-config.toml", text=True)))
        conf = TRCConf(**kwargs, predecessor_trc=predec_trc)
        signed_payloads = []
        with conf.configure() as c:
            c.gen_payload()
            for (cert, key) in signers:
                signed_payloads.append(c.sign_payload(cert, key))
            trc = c.combine(*signed_payloads)
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
            kwargs = _transform_toml_conf_to_trcconf_args(toml.load(f))
        conf = TRCConf(**kwargs, predecessor_trc=predec_trc)
        signed_payloads = []
        with conf.configure() as c:
            c.gen_payload()
            for (cert, key) in signers:
                signed_payloads.append(c.sign_payload(cert, key))
            trc = c.combine(*signed_payloads)
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
        trc = generate_trc(prev_trc=predec_trc, **kwargs,
                           quorum=len(kwargs["primary_ases"]) // 2 + 1,
                           signers_certs=[c.decode("ascii") for c in scerts],
                           signers_keys=[k.decode("ascii") for k in skeys])
        # test final trc
        check_scion_trc(self, trc, predec_trc)


def _trcconf_args_dict():
    return {"isd_id": 1, "base_version": 1, "serial_version": 1, "grace_period": None,
            "not_before": datetime.utcnow(), "not_after": datetime.utcnow() + timedelta(days=1),
            "authoritative_ases": ["1-ff00:0:110"], "core_ases": ["1-ff00:0:110"],
            "certificates": [b"no-content"]}


def _readfile(*path_args, text=False):
    mode = "r" if text else "rb"
    with open(os.path.join(*path_args), mode) as f:
        return f.read()


def _transform_toml_conf_to_trcconf_args(toml_dict: Dict) -> Dict[str, Any]:
    """
    transforms a TRC configuration template in toml to the arguments required to
    instantiate a new TRCConf object
    """
    # adapt the dictionary to be used with the TRCConf class
    not_before = datetime.fromtimestamp(toml_dict["validity"]["not_before"], tz=timezone.utc)
    certificates = [_readfile(_TESTDATA_DIR, f) for f in toml_dict["cert_files"]]
    return {
        "isd_id": toml_dict["isd"],
        "base_version": toml_dict["base_version"],
        "serial_version": toml_dict["serial_version"],
        "grace_period": timedelta(seconds=int(toml_dict["grace_period"][:-1])),
        "not_before": not_before,
        "not_after": not_before + timedelta(seconds=int(toml_dict["validity"]
            ["validity"][:-1])),
        "authoritative_ases": toml_dict["authoritative_ases"],
        "core_ases": toml_dict["core_ases"],
        "certificates": certificates,
        "votes": toml_dict.get("votes"),
    }


def _replace_keys(d: Dict[str, Any], keys: List[Tuple[str, str]]) -> Dict[str, Any]:
    """ keys is a list of tuples (new_key, old_key) """
    for (nk, ok) in keys:
        d[nk] = d.pop(ok)


def _get_signers(base_filenames):
    return [(_readfile(f"{f}.crt"), _readfile(f"{f}.key")) for f in [
        os.path.join(_TESTDATA_DIR, p) for p in base_filenames]]
