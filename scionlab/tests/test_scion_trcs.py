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
from tempfile import mktemp
from typing import Any, Dict

from scionlab.defines import DEFAULT_TRC_GRACE_PERIOD
from scionlab.scion.trcs import TRCConf, generate_trc, _raw_run_scion_cppki

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
        kwargs["certificates"] = {}
        self.assertRaises(ValueError, TRCConf, **kwargs)
        kwargs = _trcconf_args_dict()
        # absolute paths not allowed:
        kwargs["certificates"] = {"/tmp/mock-certificate.crt": "no-content"}
        self.assertRaises(ValueError, TRCConf, **kwargs)
        # anything but a filename is not allowed
        kwargs["certificates"] = {"../mock-certificate.crt": "no-content"}
        self.assertRaises(ValueError, TRCConf, **kwargs)
        kwargs["certificates"] = {"": "no-content"}
        self.assertRaises(ValueError, TRCConf, **kwargs)
        kwargs["certificates"] = {"..": "no-content"}
        self.assertRaises(ValueError, TRCConf, **kwargs)
        kwargs["certificates"] = {"/": "no-content"}
        self.assertRaises(ValueError, TRCConf, **kwargs)

    def test_configure(self):
        kwargs = _trcconf_args_dict()
        conf = TRCConf(**kwargs)
        temp_dir_name = ""
        with conf.configure() as trc:
            temp_dir_name = trc._temp_dir.name
            # double call (nested in outer, should not happen) must also clean up
            temp_dir_name2 = ""
            with conf.configure() as trc2:
                temp_dir_name2 = trc2._temp_dir.name
                self.assertTrue(os.path.isdir(temp_dir_name2))
                self.assertTrue(all(os.path.isfile(os.path.join(temp_dir_name2, f))
                                    for f in conf.certificates.keys()))
            self.assertFalse(os.path.exists(temp_dir_name2))
            # let's do no more shenanigans with nested usage, and check that
            # there is a temporary dir created, with the certificate files
            self.assertTrue(os.path.isdir(temp_dir_name))
            for fn, c in conf.certificates.items():
                p = os.path.join(temp_dir_name, fn)
                self.assertTrue(os.path.isfile(p))
                with open(p) as f:
                    self.assertEqual(f.read(), c)
        self.assertFalse(os.path.exists(temp_dir_name))

    def test_gen_payload(self):
        # load conf. toml dictionary
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            toml_conf = toml.load(f)
        kwargs = _transform_toml_conf_to_trcconf_args(toml_conf)
        conf = TRCConf(**kwargs)
        with conf.configure() as trc:
            trc.gen_payload()
            gen_conf = toml.loads(_readfile(trc._temp_dir.name, trc._conf_filename()).decode())
            gen_payload = _readfile(trc._temp_dir.name, trc._payload_filename())
        self.assertEqual(gen_conf, toml_conf)
        self.assertEqual(gen_payload, _readfile(_TESTDATA_DIR, "payload-1.der"))

    def test_sign_payload(self):
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            toml_conf = toml.load(f)
        kwargs = _transform_toml_conf_to_trcconf_args(toml_conf)
        conf = TRCConf(**kwargs)
        with conf.configure() as trc:
            trc.gen_payload()
            base_filenames = ["voting-sensitive-ff00_0_110",
                              "voting-regular-ff00_0_210"]
            # zip the base filenames with the content to a list of (filename, cert, key):
            signers = zip(base_filenames, *zip(*_get_signers(base_filenames)))
            for (fn, cert, key) in signers:
                signed = trc.sign_payload(cert, key)
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
        with conf.configure() as trc:
            trc.gen_payload()
            for (cert, key) in signers:
                signed_payloads.append(trc.sign_payload(cert, key))
            trc.combine(*signed_payloads)
            # verify the trc with a call to scion-pki (would raise if error)
            trc_fn = os.path.join(trc._temp_dir.name, trc._trc_filename())
            trc._run_scion_cppki("verify", "--anchor", trc_fn, trc_fn)

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
        not_after = not_before + timedelta(seconds=1800)

        trc = generate_trc(prev_trc=None, isd_id=1, base=1, serial=1,
                           primary_ases=core_ases, quorum=1, votes=[],
                           grace_period=DEFAULT_TRC_GRACE_PERIOD,
                           not_before=not_before, not_after=not_after,
                           certificates=certificates,
                           signers_certs=scerts, signers_keys=skeys)
        # test final trc
        trc_file = mktemp()
        with open(trc_file, "wb") as f:
            f.write(trc)
        _raw_run_scion_cppki("verify", trc_file)

class TRCUpdate(TestCase):
    def test_regular_update(self):
        # initial TRC in TESTDATA/trc-1.trc
        predec_trc_fn = os.path.join(_TESTDATA_DIR, "trc-1.trc")
        # update the TRC by just incrementing the serial. That is in payload-2-config.toml
        signers = _get_signers(["voting-regular-ff00_0_110"])
        with open(os.path.join(_TESTDATA_DIR, "payload-2-config.toml")) as f:
            kwargs = _transform_toml_conf_to_trcconf_args(toml.load(f))
        with open(predec_trc_fn, "rb") as f:
            conf = TRCConf(**kwargs, predecessor_trc=f.read())
        signed_payloads = []
        with conf.configure() as trc:
            trc.gen_payload()
            for (cert, key) in signers:
                signed_payloads.append(trc.sign_payload(cert, key))
            trc.combine(*signed_payloads)
            # verify trc with the old trc as anchor
            trc._run_scion_cppki("verify", "--anchor", predec_trc_fn,
                                 os.path.join(trc._temp_dir.name, trc._trc_filename()))

    def test_sensitive_update(self):
        # previous TRC in TESTDATA/trc-2.trc
        predec_trc_fn = os.path.join(_TESTDATA_DIR, "trc-2.trc")
        # add a core-authoritative AS and its sensitive, regular and root certs
        signers = _get_signers(["voting-sensitive-ff00_0_110",
                                "voting-sensitive-ff00_0_210",
                                "voting-regular-ff00_0_210"])
        with open(os.path.join(_TESTDATA_DIR, "payload-3-config.toml")) as f:
            kwargs = _transform_toml_conf_to_trcconf_args(toml.load(f))
        with open(predec_trc_fn, "rb") as f:
            conf = TRCConf(**kwargs, predecessor_trc=f.read())
        signed_payloads = []
        with conf.configure() as trc:
            trc.gen_payload()
            for (cert, key) in signers:
                signed_payloads.append(trc.sign_payload(cert, key))
            trc.combine(*signed_payloads)
            # verify trc with the old trc as anchor
            trc._run_scion_cppki("verify", "--anchor", predec_trc_fn,
                                 os.path.join(trc._temp_dir.name, trc._trc_filename()))


def _trcconf_args_dict():
    return {"isd_id": 1, "base_version": 1, "serial_version": 1, "grace_period": None,
            "not_before": datetime.utcnow(), "not_after": datetime.utcnow() + timedelta(days=1),
            "authoritative_ases": ["1-ff00:0:110"], "core_ases": ["1-ff00:0:110"],
            "certificates": {"mock-certificate.crt": "no-content"}}


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
    certificates = {}
    for fn in toml_dict["cert_files"]:
        with open(os.path.join(_TESTDATA_DIR, fn)) as f:
            certificates[fn] = f.read()
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


def _get_signers(base_filenames):
    return [(_readfile(f"{f}.crt"), _readfile(f"{f}.key")) for f in [
        os.path.join(_TESTDATA_DIR, p) for p in base_filenames]]
