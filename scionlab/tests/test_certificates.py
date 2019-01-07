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

import json
from django.test import TestCase
from scionlab.models import ISD
from scionlab.util.certificates import generate_trc
from scionlab.tests import utils

from lib.crypto.trc import TRC
from lib.crypto.certificate import Certificate
from lib.crypto.certificate_chain import CertificateChain
from lib.errors import SCIONVerificationError


class CreateTRCTests(TestCase):
    fixtures = ['testtopo-ases']

    isd19_core_ases = ['19-ffaa:0:1301', '19-ffaa:0:1302']

    def test_create_empty(self):
        isd = ISD.objects.create(isd_id=1, label='empty')
        trc, trc_priv_keys = generate_trc(isd)
        self.assertEqual(trc['CoreASes'], {})
        self.assertEqual(trc['Signatures'], {})
        self.assertEqual(trc_priv_keys, {})

    def test_create_initial(self):
        isd = ISD.objects.get(isd_id=19)
        self.assertEqual(isd.trc, None)
        self.assertEqual(isd.trc_priv_keys, None)
        self.assertTrue(isd.trc_needs_update)
        isd.update_trc()

        self._check_trc(isd, self.isd19_core_ases, expected_version=1)

    def test_create_update(self):
        isd = ISD.objects.get(isd_id=19)
        isd.update_trc()
        trc_v1 = self._check_trc(isd, self.isd19_core_ases, expected_version=1)

        isd.update_trc()
        trc_v2 = self._check_trc(isd, self.isd19_core_ases, expected_version=2)
        trc_v2.verify(trc_v1)

        # XXX: this might have to be fixed if the grace period is set up properly. Sleep?
        isd.update_trc()
        trc_v3 = self._check_trc(isd, self.isd19_core_ases, expected_version=3)
        trc_v3.verify(trc_v2)

        with self.assertRaises(SCIONVerificationError):
            trc_v3.verify(trc_v1)

    def _check_trc(self, isd, expected_core_ases, expected_version=None):
        """
        Check the ISD's TRC and return it as a TRC object.
        :param ISD isd:
        :param [str] expected_core_ases: ISD-AS strings for all core ases
        :param int expected_version: optional
        :returns: TRC
        :rtype: TRC
        """
        self.assertFalse(isd.trc_needs_update)
        self.assertEqual(set(isd.trc['CoreASes'].keys()), set(expected_core_ases))
        self.assertEqual(set(isd.trc_priv_keys.keys()), set(expected_core_ases))
        for isd_as in expected_core_ases:
            utils.check_sig_keypair(self, isd.trc['CoreASes'][isd_as]['OnlineKey'],
                                    isd.trc_priv_keys[isd_as])

        json_trc = json.dumps(isd.trc)  # round trip through json, just to make sure this works
        trc = TRC.from_raw(json_trc)
        trc.check_active()
        if expected_version is not None:
            self.assertEqual(trc.version, expected_version)
        return trc


class CoreASCertificateTests(TestCase):
    fixtures = ['testtopo-ases']

    def test_create_all_certs(self):
        isd = ISD.objects.get(isd_id=17)
        isd.update_trc()
        isd.save()
        isd.ases.update_certificates()

        trc = TRC(isd.trc)
        self.assertFalse(isd.trc_needs_update)
        for as_ in isd.ases.iterator():
            if as_.is_core:
                self._check_core_cert(as_, trc)
            self._check_cert_chain(as_, trc)

    def test_update_single_cert(self):
        isd = ISD.objects.get(isd_id=17)
        isd.update_trc()
        isd.save()
        isd.ases.update_certificates()

        trc = TRC(isd.trc)

        # Generate fresh cert with same keys
        as_ = isd.ases.first()
        as_.update_certificate_chain()
        self._check_cert_chain(as_, trc)

        # Might as well: update keys and generate cert
        as_.update_keys()
        as_.update_certificate_chain()
        self._check_cert_chain(as_, trc)

    def _check_core_cert(self, as_, trc):
        self.assertFalse(as_.core_certificate_needs_update)
        self.assertIsNotNone(as_.core_certificate)
        cert = Certificate(as_.core_certificate)
        isd_as = as_.isd_as_str()
        cert.verify(isd_as, trc.core_ases[isd_as]['OnlineKey'])

    def _check_cert_chain(self, as_, trc):
        self.assertFalse(as_.certificate_chain_needs_update)
        self.assertIsNotNone(as_.certificate_chain)
        json_cert_chain = json.dumps(as_.certificate_chain)
        cert_chain = CertificateChain.from_raw(json_cert_chain)
        cert_chain.verify(as_.isd_as_str(), trc)
