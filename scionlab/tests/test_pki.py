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

import copy
from datetime import datetime, timedelta

from scionlab.models.core import ISD, AS
from scionlab.models.pki import Key
from scionlab.util import as_ids
from scionlab.defines import (
    DEFAULT_EXPIRATION,
    DEFAULT_TRC_GRACE_PERIOD,
)

from scionlab.scion import keys, trcs

from django.test import TestCase


class GenerateKeyTests(TestCase):

    def setUp(self):
        self.isd = ISD.objects.create(isd_id=1, label='Test')
        # bypass ASManager.create to avoid initializing keys
        as_id = 'ff00:0:110'
        self.AS = AS(
            isd=self.isd,
            as_id=as_id,
            as_id_int=as_ids.parse(as_id)
        )
        self.AS.save()

    def test_generate_decrypt_key(self):
        k = Key.objects.create(AS=self.AS, usage=Key.DECRYPT)
        self.assertIsNotNone(k)
        self.assertEqual(k.AS_id, self.AS.pk)
        self.assertEqual(k.version, 1)
        self.assertEqual(k.usage, Key.DECRYPT)
        self.assertEqual(k.not_after - k.not_before, DEFAULT_EXPIRATION)
        # XXX check encrypt/decrypt (c.f. test utils for "old" keys)

    def test_generate_sign_key(self):
        k = Key.objects.create(AS=self.AS, usage=Key.SIGNING)
        self.assertIsNotNone(k)
        self.assertEqual(k.AS_id, self.AS.pk)
        self.assertEqual(k.version, 1)
        self.assertEqual(k.usage, Key.SIGNING)
        self.assertEqual(k.not_after - k.not_before, DEFAULT_EXPIRATION)
        # XXX check sign/verify (c.f. test utils for "old" keys)


_ASID_1 = 'ff00:0:1'
_ASID_2 = 'ff00:0:2'


class GenerateTRCTests(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.isd1 = ISD.objects.create(isd_id=1, label='Test')

    def gen_trc_v1(self):
        """
        Helper: create initial version of TRC
        @returns trc, primary_ases, voting_offline
        """
        primary_ases = {
            _ASID_1: trcs.CoreKeys(
                issuing_grant=_gen_key(1),
                voting_online=_gen_key(1),
                voting_offline=_gen_key(1),
            )
        }

        voting_offline = {as_id: keys.voting_offline for as_id, keys in primary_ases.items()}

        not_before = datetime(2020, 2, 20)
        not_after = not_before + DEFAULT_EXPIRATION

        trc = trcs.generate_trc(self.isd1, 1, DEFAULT_TRC_GRACE_PERIOD, not_before, not_after,
                                primary_ases, None, None)

        return trc, primary_ases, voting_offline

    def gen_trc_update(self, primary_ases, prev_trc, prev_voting_offline):
        """
        Helper: create update TRC
        """

        # decode prev payload to find next version number
        # we dont need to do this in production, but here it serves as a little sanity check for
        # the payload.
        prev = trcs.decode_payload(prev_trc)
        prev_version = prev["trc_version"]
        self.assertGreaterEqual(1, prev_version)
        version = prev_version + 1

        # define validity time with arbitrary time offset from previous validity start.
        # Just for "fun", not really relevant.
        prev_not_before = datetime.fromtimestamp(prev['validity']['not_before'])
        not_before = prev_not_before + timedelta(days=31)
        not_after = not_before + DEFAULT_EXPIRATION

        trc = trcs.generate_trc(self.isd1, version, DEFAULT_TRC_GRACE_PERIOD, not_before, not_after,
                                primary_ases, prev_trc, prev_voting_offline)

        return trc

    def test_generate_initial(self):
        trc, primary_ases, _ = self.gen_trc_v1()

        # initial version, is signed by _all_ keys (as proof of possession)
        signatures = [(as_id, 'proof_of_possession', usage, key)
                      for as_id, keys in primary_ases.items()
                      for usage, key in keys._asdict().items()]
        self.assertTrue(trcs.verify(trc, signatures))

        # sanity check: if we mess with one of the signatures, it will not verify:
        trc_bad = copy.deepcopy(trc)
        trc_bad['signatures'][0]['signature'] = 'forged'
        self.assertFalse(trcs.verify(trc_bad, signatures))

    def test_update_offline(self):
        trc_v1, primary_ases_v1, voting_offline_v1 = self.gen_trc_v1()

        primary_ases_v2 = copy.deepcopy(primary_ases_v1)
        primary_ases_v2[_ASID_1] = primary_ases_v1[_ASID_1]._replace(voting_offline=_gen_key(2))

        trc_v2 = self.gen_trc_update(primary_ases_v2, trc_v1, voting_offline_v1)

        # Updating offline keys is a sensitive update and must be signed with previous offline keys
        # and all updated keys (proof of possession).
        signatures = [
            (as_id, 'vote', 'voting_offline', k.voting_offline) for as_id, k in primary_ases_v1.items()
        ] + [
            (as_id, 'proof_of_possession', 'voting_offline', k.voting_offline) for as_id, k in primary_ases_v2.items()
        ]
        self.assertTrue(trcs.verify(trc_v2, signatures))

    def test_update_online(self):
        trc_v1, primary_ases_v1, voting_offline_v1 = self.gen_trc_v1()

        primary_ases_v2 = copy.deepcopy(primary_ases_v1)
        primary_ases_v2[_ASID_1] = primary_ases_v1[_ASID_1]._replace(voting_online=_gen_key(2))

        trc_v2 = self.gen_trc_update(primary_ases_v2, trc_v1, voting_offline_v1)

        # Updating online keys is a regular update and is signed with online keys
        k_asid1_v2 = primary_ases_v2[_ASID_1]
        signatures = [
            (_ASID_1, 'vote', 'voting_offline', k_asid1_v2.voting_offline),
            (_ASID_1, 'proof_of_possession', 'voting_online', k_asid1_v2.voting_online),
        ]

        self.assertTrue(trcs.verify(trc_v2, signatures))

    def test_update_issuing(self):
        trc_v1, primary_ases_v1, voting_offline_v1 = self.gen_trc_v1()

        import pathlib, json
        pathlib.Path('/tmp/gen/ISD1/trcs/ISD1-V1.trc').write_text(json.dumps(trc_v1, indent=2))

        primary_ases_v2 = copy.deepcopy(primary_ases_v1)
        primary_ases_v2[_ASID_1] = primary_ases_v1[_ASID_1]._replace(issuing_grant=_gen_key(2))

        trc_v2 = self.gen_trc_update(primary_ases_v2, trc_v1, voting_offline_v1)

        pathlib.Path('/tmp/gen/ISD1/trcs/ISD1-V2.trc').write_text(json.dumps(trc_v2, indent=2))

        # Updating issuing grant keys is a regular update and is signed with online keys and all
        # updated keys (proof of possession).
        k_asid1_v2 = primary_ases_v2[_ASID_1]
        signatures = [
            (as_id, 'vote', 'voting_online', k.voting_online) for as_id, k in primary_ases_v1.items()
        ] + [
            (_ASID_1, 'proof_of_possession', 'issuing_grant', k_asid1_v2.issuing_grant),
        ]

        self.assertTrue(trcs.verify(trc_v2, signatures))


def _gen_key(version):
    """
    Generate a new signing key and return it as a trcs.Key info object.
    """
    priv = keys.generate_sign_key()
    pub = keys.public_sign_key(priv)
    return trcs.Key(version=version, priv_key=priv, pub_key=pub)
