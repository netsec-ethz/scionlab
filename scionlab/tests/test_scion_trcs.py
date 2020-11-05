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
from typing import Any, Dict

from scionlab.scion import trcs

_TESTDATA_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data/test_scion_trcs")


class ScionTRCConfTests(TestCase):
    """ tests the correct behavior of the TRCConf class """
    def test_validate(self):
        kwargs = self._args_dict()
        trcs.TRCConf(**kwargs)  # doesn't raise
        kwargs["isd_id"] = -1
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs = self._args_dict()
        kwargs["base_version"] = 2
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs = self._args_dict()
        kwargs["not_after"] = kwargs["not_before"]
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs = self._args_dict()
        kwargs["certificates"] = {}
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs = self._args_dict()
        # absolute paths not allowed:
        kwargs["certificates"] = {"/tmp/mock-certificate.crt": "no-content"}
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        # anything but a filename is not allowed
        kwargs["certificates"] = {"../mock-certificate.crt": "no-content"}
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs["certificates"] = {"": "no-content"}
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs["certificates"] = {"..": "no-content"}
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)
        kwargs["certificates"] = {"/": "no-content"}
        self.assertRaises(ValueError, trcs.TRCConf, **kwargs)

    def test_configure(self):
        kwargs = self._args_dict()
        conf = trcs.TRCConf(**kwargs)
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
        kwargs = self._transform_toml_conf_to_trcconf_args(toml_conf)
        conf = trcs.TRCConf(**kwargs)
        with conf.configure() as trc:
            trc.gen_payload()
            gen_conf = toml.loads(self._readfile(trc._temp_dir.name, trc._conf_filename()).decode())
            gen_payload = self._readfile(trc._temp_dir.name, trc._payload_filename())
        self.assertEqual(gen_conf, toml_conf)
        self.assertEqual(gen_payload, self._readfile(_TESTDATA_DIR, "payload-1.der"))

    def test_sign_payload(self):
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            toml_conf = toml.load(f)
        kwargs = self._transform_toml_conf_to_trcconf_args(toml_conf)
        conf = trcs.TRCConf(**kwargs)
        with conf.configure() as trc:
            trc.gen_payload()
            # sign
            voters = [  # cert_fn, key_fn
                (os.path.join(_TESTDATA_DIR, "voting-sensitive-1.crt"),
                    os.path.join(_TESTDATA_DIR, "voting-sensitive-1.key")),
                (os.path.join(_TESTDATA_DIR, "voting-regular-1.crt"),
                    os.path.join(_TESTDATA_DIR, "voting-regular-1.key"))]
            for (cert_fn, key_fn) in voters:
                cert = self._readfile(cert_fn)
                key = self._readfile(key_fn)
                signed = trc.sign_payload(cert, key)
                cmd = ["openssl", "cms", "-verify",
                       "-inform", "der", "-certfile", cert_fn,
                       "-CAfile", cert_fn,
                       "-purpose", "any", "-no_check_time"]
                subprocess.run(cmd, input=signed, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    def test_combine(self):
        voters = [  # (cert, key)
            (self._readfile(os.path.join(_TESTDATA_DIR, "voting-sensitive-1.crt")),
                self._readfile(os.path.join(_TESTDATA_DIR, "voting-sensitive-1.key"))),
            (self._readfile(os.path.join(_TESTDATA_DIR, "voting-regular-1.crt")),
                self._readfile(os.path.join(_TESTDATA_DIR, "voting-regular-1.key")))]
        with open(os.path.join(_TESTDATA_DIR, "payload-1-config.toml")) as f:
            conf = trcs.TRCConf(**self._transform_toml_conf_to_trcconf_args(toml.load(f)))
        signed_payloads = []
        with conf.configure() as trc:
            trc.gen_payload()
            for (cert, key) in voters:
                signed_payloads.append(trc.sign_payload(cert, key))
            trc.combine(*signed_payloads)
            # verify the trc with a call to scion-pki (would raise if error)
            trc_fn = os.path.join(trc._temp_dir.name, trc._trc_filename())
            trc._run_scion_cppki("verify", "--anchor", trc_fn, trc_fn)

    def test_sensitive_update(self):
        # create initial TRC
        # add a core-authoritative-CA AS
        kwargs = self._args_dict()
        conf = trcs.TRCConf(**kwargs)
        with conf.configure() as c:
            print(c._get_conf())

    def test_regular_update(self):
        # create base TRC
        # change the validity dates
        pass

    def _args_dict(self):
        return {"isd_id": 1, "base_version": 1, "serial_version": 1, "grace_period": None,
                "not_before": datetime.utcnow(), "not_after": datetime.utcnow() + timedelta(days=1),
                "authoritative_ases": ["1-ff00:0:110"], "core_ases": ["1-ff00:0:110"],
                "certificates": {"mock-certificate.crt": "no-content"}}

    def _readfile(self, *path_args, text=False):
        with open(os.path.join(*path_args), "rb") as f:
            return f.read()

    def _transform_toml_conf_to_trcconf_args(self, toml_dict: Dict) -> Dict[str, Any]:
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
        }

