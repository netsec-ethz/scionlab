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
from scionlab.models.pki import Certificate
from scionlab.tests import utils


class TRCAndCoreASCertificateTestsSimple(TestCase):
    def test_empty_isd(self):
        isd = ISD.objects.create(isd_id=1, label='empty')
        # Explicitly try to create TRC, should not fail but is just a no-op:
        isd.update_trc_and_certificates()
        self.assertFalse(isd.trcs.exists())

    def test_create_delete_create(self):
        isd = ISD.objects.create(isd_id=1, label='one')

        as1_id = 'ffaa:0:101'
        as2_id = 'ffaa:0:102'
        AS.objects.create(isd, as1_id, is_core=True)
        utils.check_trc_and_certs(self, 1, {as1_id}, expected_version=1)

        AS.objects.create(isd, as2_id, is_core=True)
        utils.check_trc_and_certs(self, 1, {as1_id, as2_id}, expected_version=2)

        AS.objects.filter(as_id=as1_id).delete()
        utils.check_trc_and_certs(self, 1, {as2_id}, expected_version=3)

        AS.objects.create(isd, as1_id, is_core=True)
        utils.check_trc_and_certs(self, 1, {as1_id, as2_id}, expected_version=4)

    def test_random_mutations(self):
        NUM_MUTATIONS = 66
        random.seed(5)

        isd_id = 1

        def make_as_id(i):
            return "ffaa:0:%x" % i

        ISD.objects.create(isd_id=isd_id, label='some')

        expected_version = 1
        expected_set = set()

        for i in range(NUM_MUTATIONS):
            if not expected_set or random.getrandbits(1):
                # add one: i+1 has not been used yet
                as_id = make_as_id(i+1)
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

            # Skip check and version increment if expected_set is empty -- no TRCs are created
            # if there are no core ASes.
            if expected_set:
                utils.check_trc_and_certs(self,
                                          isd_id,
                                          expected_set,
                                          expected_version=expected_version)
                expected_version += 1


class TRCAndCoreASCertificateTestsISD19(TestCase):
    fixtures = ['testdata']

    isd19_core_ases = ['ffaa:0:1301', 'ffaa:0:1302']

    def test_create_initial(self):
        isd = ISD.objects.get(isd_id=19)

        _reset_trc_and_certificates(isd)
        isd.update_trc_and_certificates()

        utils.check_trc_and_certs(self, 19, self.isd19_core_ases, expected_version=1)

    def test_create_update(self):
        isd = ISD.objects.get(isd_id=19)
        utils.check_trc_and_certs(self, 19, self.isd19_core_ases, expected_version=1)

        isd.update_trc_and_certificates()
        utils.check_trc_and_certs(self, 19, self.isd19_core_ases, expected_version=2)

        isd.update_trc_and_certificates()
        utils.check_trc_and_certs(self, 19, self.isd19_core_ases, expected_version=3)

    def test_update_single_cert(self):
        isd = ISD.objects.get(isd_id=19)

        as_ = isd.ases.filter(is_core=False).first()

        # Generate fresh cert with same keys
        cert_chain0 = as_.certificates.latest(type=Certificate.CHAIN)
        as_.generate_certificate_chain()
        cert_chain1 = as_.certificates.latest(type=Certificate.CHAIN)
        utils.check_cert_chain(self, cert_chain1)
        self.assertEqual(cert_chain1.version, cert_chain0.version + 1)

        # Update keys and generate cert
        as_.update_keys()
        cert_chain2 = as_.certificates.latest(type=Certificate.CHAIN)
        utils.check_cert_chain(self, cert_chain2)
        self.assertEqual(cert_chain2.version, cert_chain1.version + 1)

    def test_update_core_cert(self):
        isd = ISD.objects.get(isd_id=19)
        utils.check_trc_and_certs(self, 19, self.isd19_core_ases, expected_version=1)

        AS.update_core_as_keys(isd.ases.filter(is_core=True))
        utils.check_trc_and_certs(self, 19, self.isd19_core_ases, expected_version=2)


def _reset_trc_and_certificates(isd):
    isd.trcs.all().delete()
    for as_ in isd.ases.iterator():
        as_.certificates.all().delete()
