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

from scionlab.models.core import ISD, AS
from scionlab.models.pki import Key
from scionlab.util import as_ids
from scionlab.defines import DEFAULT_EXPIRATION

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
