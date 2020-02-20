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
from datetime import datetime

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


class GenerateTRCTests(TestCase):

    def test_generate_initial(self):
        isd = ISD.objects.create(isd_id=1, label='Test')

        primary_ases = {
            'ff00:0:110': trcs.CoreKeys(
                issuing_grant=_gen_key(1),
                voting_online=_gen_key(1),
                voting_offline=_gen_key(1),
            )
        }

        not_before = datetime(2020, 2, 20)
        not_after = not_before + DEFAULT_EXPIRATION

        trc = trcs.generate_trc(isd, 1, DEFAULT_TRC_GRACE_PERIOD, not_before, not_after,
                                primary_ases, None, None)

        # initial version, is signed by _all_ keys (as proof of posession)
        signing_keys = {as_id: keys._asdict() for as_id, keys in primary_ases.items()}
        self.assertTrue(trcs.verify(trc, signing_keys))

        # sanity check: if we mess with one of the signatures, it will not verify:
        trc_bad = copy.deepcopy(trc)
        trc_bad['signatures'][0]['signature'] = 'forged'
        self.assertFalse(trcs.verify(trc_bad, signing_keys))

        _ = trcs.decode_payload(trc)


def _gen_key(version):
    priv = keys.generate_sign_key()
    pub = keys.public_sign_key(priv)
    return trcs.Key(version=version, priv_key=priv, pub_key=pub)
