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

from unittest import TestCase
from parameterized import parameterized
from scionlab.util import as_ids


class ASIDTests(TestCase):
    @parameterized.expand([
        ('0:0:0', 0),
        ('0:0:1', 1),
        ('0:0:abcd', 0xABCD),
        ('0:1:0', 2**16),
        ('0:f00d:0', 0xF00D * 2**16),
        ('1:0:0', 2**32),
        ('3b73:0:0', 0x3B73 * 2**32),
        ('ff00:1:3a', 0xFF00 * 2**32 + 2**16 + 0x3A),
    ])
    def test_parse_format(self, as_id_str, expected_int):
        parsed = as_ids.parse(as_id_str)
        self.assertEqual(parsed, expected_int)

        parsed = as_ids.parse(as_id_str.upper())
        self.assertEqual(parsed, expected_int)

        formatted = as_ids.format(parsed)
        self.assertEqual(formatted, as_id_str.lower())

    @parameterized.expand([
        '',
        '0',
        '::',
        '0:0:abcde',
        '1-0:0:0',
        ' 0:0:0 ',
    ])
    def test_parse_fail(self, as_id_str):
        try:
            parsed = as_ids.parse(as_id_str)
        except ValueError:
            return
        self.fail("Expected failure, returned %x instead" % parsed)
