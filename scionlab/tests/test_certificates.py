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

import random
from django.test import TestCase
from scionlab.models.core import ISD, AS
from scionlab.tests import utils

from lib.errors import SCIONVerificationError


class TRCAndCoreASCertificateTestsSimple(TestCase):
    def test_empty_isd(self):
        isd = ISD.objects.create(isd_id=1, label='empty')

        # No TRC set unless explicitly created. This ISD is invalid either way!
        isd.init_trc_and_certificates()
        self.assertEqual(isd.trc['CoreASes'], {})
        self.assertEqual(isd.trc['Signatures'], {})
        self.assertEqual(isd.trc_priv_keys, {})

    def test_create_delete_create(self):
        isd = ISD.objects.create(isd_id=1, label='one')

        as1_id = 'ffaa:0:0101'
        as1_ia = '%i-%s' % (isd.isd_id, as1_id)
        AS.objects.create(isd, as1_id, is_core=True)

        trc_v1 = utils.check_trc_and_certs(self, 1, {as1_ia}, expected_version=1)

        AS.objects.filter(as_id=as1_id).delete()
        isd.refresh_from_db()

        trc_v2 = utils.check_trc_and_certs(self, 1, {}, expected_version=2, prev_trc=trc_v1)

        AS.objects.create(isd, as1_id, is_core=True)

        utils.check_trc_and_certs(self, 1, {as1_ia}, expected_version=3, prev_trc=trc_v2)

    def test_random_mutations(self):
        NUM_MUTATIONS = 66
        random.seed(5)

        isd_id = 1

        def make_as_id(i):
            return "ffaa:0:%.4x" % i

        def ia(as_id):
            return "%i-%s" % (isd_id, as_id)

        ISD.objects.create(isd_id=isd_id, label='some')

        prev_trc = None
        expected_version = 1
        expected_set = set()

        for i in range(NUM_MUTATIONS):
            if not expected_set or random.getrandbits(1):
                # add one: i has not been used yet
                as_id = make_as_id(i)
                expected_set.add(as_id)
                AS.objects.create(ISD.objects.get(isd_id=isd_id), as_id, is_core=True)
            else:
                as_id = random.sample(expected_set, 1)[0]
                expected_set.remove(as_id)
                # Let's test both ways:
                if random.getrandbits(1):
                    AS.objects.filter(as_id=as_id).delete()
                else:
                    AS.objects.get(as_id=as_id).delete()

            trc = utils.check_trc_and_certs(self,
                                            isd_id,
                                            {ia(as_id) for as_id in expected_set},
                                            expected_version=expected_version,
                                            prev_trc=prev_trc)
            expected_version += 1
            prev_trc = trc


class TRCAndCoreASCertificateTestsISD19(TestCase):
    fixtures = ['testtopo-ases']

    isd19_core_ases = ['19-ffaa:0:1301', '19-ffaa:0:1302']

    def test_create_initial(self):
        isd = ISD.objects.get(isd_id=19)

        _reset_trc_and_certificates(isd)
        self.assertEqual(isd.trc, None)
        self.assertEqual(isd.trc_priv_keys, None)
        isd.init_trc_and_certificates()

        utils.check_trc_and_certs(self, 19, self.isd19_core_ases, expected_version=1)

    def test_create_update(self):
        isd = ISD.objects.get(isd_id=19)

        trc_v1 = utils.check_trc(self, isd, self.isd19_core_ases, expected_version=1)
        utils.check_core_as_certs(self, isd)

        isd.update_trc_and_core_certificates()
        trc_v2 = utils.check_trc(self, isd, self.isd19_core_ases, expected_version=2)
        trc_v2.verify(trc_v1)
        utils.check_core_as_certs(self, isd)

        # XXX: this might have to be fixed if the grace period is set up. Sleep?
        isd.update_trc_and_core_certificates()
        trc_v3 = utils.check_trc(self, isd, self.isd19_core_ases, expected_version=3)
        trc_v3.verify(trc_v2)
        utils.check_core_as_certs(self, isd)

        with self.assertRaises(SCIONVerificationError):
            trc_v3.verify(trc_v1)

    def test_update_single_cert(self):
        isd = ISD.objects.get(isd_id=19)

        as_ = isd.ases.filter(is_core=False).first()

        # Generate fresh cert with same keys
        original_certificate_chain = as_.certificate_chain
        as_.generate_certificate_chain()
        as_.save()
        utils.check_cert_chain(self, as_, isd.trc)
        self.assertEqual(as_.certificate_chain['0']['Version'],
                         original_certificate_chain['0']['Version'] + 1)

        # Update keys and generate cert
        as_.update_keys()
        utils.check_cert_chain(self, as_, isd.trc)
        self.assertEqual(as_.certificate_chain['0']['Version'],
                         original_certificate_chain['0']['Version'] + 2)

    def test_update_core_cert(self):
        isd = ISD.objects.get(isd_id=19)

        trc_v1 = utils.check_trc(self, isd, self.isd19_core_ases, expected_version=1)

        AS.update_core_as_keys(isd.ases.filter(is_core=True))

        trc_v2 = utils.check_trc(self, isd, self.isd19_core_ases, expected_version=2)
        trc_v2.verify(trc_v1)
        utils.check_core_as_certs(self, isd)

        # Certs for non-core ASes not updated; will be updated as new TRC is disseminated
        for as_ in isd.ases.filter(is_core=False).iterator():
            self.assertEqual(
                as_.certificate_chain['0']['TRCVersion'],
                trc_v1.version
            )


def _reset_trc_and_certificates(isd):
    isd.trc = None
    isd.trc_priv_keys = None
    isd.save()
    for as_ in isd.ases.iterator():
        as_.certificate_chain = None
        as_.core_certificate = None
        as_.save()
