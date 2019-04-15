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
from scionlab.models.core import ISD
from scionlab.tests import utils

from lib.crypto.trc import TRC
from lib.crypto.certificate import Certificate
from lib.crypto.certificate_chain import CertificateChain
from lib.errors import SCIONVerificationError


class TRCAndCoreASCertificateTests(TestCase):
    fixtures = ['testtopo-ases']

    isd19_core_ases = ['19-ffaa:0:1301', '19-ffaa:0:1302']

    def test_create_empty_isd(self):
        isd = ISD.objects.create(isd_id=1, label='empty')
        isd.init_trc_and_certificates()
        self.assertEqual(isd.trc['CoreASes'], {})
        self.assertEqual(isd.trc['Signatures'], {})
        self.assertEqual(isd.trc_priv_keys, {})

    def test_create_initial(self):
        isd = ISD.objects.get(isd_id=19)

        self._reset_trc_and_certificates(isd)
        self.assertEqual(isd.trc, None)
        self.assertEqual(isd.trc_priv_keys, None)
        isd.init_trc_and_certificates()

        self._check_trc(isd, self.isd19_core_ases, expected_version=1)
        for as_ in isd.ases.iterator():
            if as_.is_core:
                self._check_core_cert(as_, isd.trc)
            self._check_cert_chain(as_, isd.trc)

    def test_create_update(self):
        isd = ISD.objects.get(isd_id=19)

        trc_v1 = self._check_trc(isd, self.isd19_core_ases, expected_version=1)
        self._check_core_certs(isd)

        isd.update_trc_and_core_certificates()
        trc_v2 = self._check_trc(isd, self.isd19_core_ases, expected_version=2)
        trc_v2.verify(trc_v1)
        self._check_core_certs(isd)

        # XXX: this might have to be fixed if the grace period is set up. Sleep?
        isd.update_trc_and_core_certificates()
        trc_v3 = self._check_trc(isd, self.isd19_core_ases, expected_version=3)
        trc_v3.verify(trc_v2)
        self._check_core_certs(isd)

        with self.assertRaises(SCIONVerificationError):
            trc_v3.verify(trc_v1)

    def test_update_single_cert(self):
        isd = ISD.objects.get(isd_id=19)

        as_ = isd.ases.filter(is_core=False).first()

        # Generate fresh cert with same keys
        original_certificate_chain = as_.certificate_chain
        as_.update_certificate_chain()
        self._check_cert_chain(as_, isd.trc)
        self.assertEqual(as_.certificate_chain['0']['Version'],
                         original_certificate_chain['0']['Version'] + 1)

        # Update keys and generate cert
        as_.update_keys()
        self._check_cert_chain(as_, isd.trc)
        self.assertEqual(as_.certificate_chain['0']['Version'],
                         original_certificate_chain['0']['Version'] + 2)

    def test_update_core_cert(self):
        isd = ISD.objects.get(isd_id=19)

        trc_v1 = self._check_trc(isd, self.isd19_core_ases, expected_version=1)

        as_ = isd.ases.filter(is_core=True).first()
        as_.update_core_keys()

        trc_v2 = self._check_trc(isd, self.isd19_core_ases, expected_version=2)
        trc_v2.verify(trc_v1)
        self._check_core_certs(isd)

        # Certs for non-core ASes not updated; will be updated as new TRC is disseminated
        for as_ in isd.ases.filter(is_core=False).iterator():
            self.assertEqual(
                as_.certificate_chain['0']['TRCVersion'],
                trc_v1.version
            )

    def _reset_trc_and_certificates(self, isd):
        isd.trc = None
        isd.trc_priv_keys = None
        isd.save()
        for as_ in isd.ases.iterator():
            as_.certificate_chain = None
            as_.core_certificate = None
            as_.save()

    def _check_trc(self, isd, expected_core_ases, expected_version=None):
        """
        Check the ISD's TRC and return it as a TRC object.
        :param ISD isd:
        :param [str] expected_core_ases: ISD-AS strings for all core ases
        :param int expected_version: optional
        :returns: TRC
        :rtype: TRC
        """
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

    def _check_core_certs(self, isd):
        for as_ in isd.ases.filter(is_core=True).iterator():
            self._check_core_cert(as_, isd.trc)
            self._check_cert_chain(as_, isd.trc)

    def _check_core_cert(self, as_, trc):
        self.assertIsNotNone(as_.core_certificate)
        cert = Certificate(as_.core_certificate)
        isd_as = as_.isd_as_str()
        cert.verify(isd_as, TRC(trc).core_ases[isd_as]['OnlineKey'])

    def _check_cert_chain(self, as_, trc):
        self.assertIsNotNone(as_.certificate_chain)
        json_cert_chain = json.dumps(as_.certificate_chain)
        cert_chain = CertificateChain.from_raw(json_cert_chain)
        cert_chain.verify(as_.isd_as_str(), TRC(trc))
