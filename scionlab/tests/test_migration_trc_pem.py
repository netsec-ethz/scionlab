# Copyright 2021 ETH Zurich
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

from importlib import import_module
from django.test import SimpleTestCase

migration_trc_pem = import_module('scionlab.migrations.0005_trc_pem')

_b64der = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCBncmF2aWRhLg=="
_pem = """-----BEGIN TRC-----
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np
bmcgZWxpdCBncmF2aWRhLg==
-----END TRC-----
"""


class MigrateTRCPemTests(SimpleTestCase):
    def test_forward(self):
        pem = migration_trc_pem.trc_base64der_to_pem(_b64der)
        self.assertEqual(pem, _pem)
        # sanity check: ensure that lines have expected length
        bodyLines = pem.splitlines()[1:-1]
        self.assertEqual(len(bodyLines[0]), 64)
        self.assertLess(len(bodyLines[1]), 64)

    def test_backward(self):
        der = migration_trc_pem.trc_pem_to_base64der(_pem)
        self.assertEqual(der, _b64der)
