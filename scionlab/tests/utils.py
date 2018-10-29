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

import base64
import lib.crypto.asymcrypto


def check_as_keys(testcase, as_):
    """
    Check that keys of AS `as_` have been properly initialised
    :param unittest.TestCase testcase: The testcase to call assert on
    :param scionlab.models.AS as_: The AS with the key-pairs to check
    """

    testcase.assertIsNotNone(as_)
    testcase.assertIsNotNone(as_.sig_pub_key)
    testcase.assertIsNotNone(as_.sig_priv_key)
    testcase.assertIsNotNone(as_.enc_pub_key)
    testcase.assertIsNotNone(as_.enc_priv_key)

    m = "message".encode()

    # Sign a message and verify
    sig_pub_key = base64.b64decode(as_.sig_pub_key.encode())
    sig_priv_key = base64.b64decode(as_.sig_priv_key.encode())
    s = lib.crypto.asymcrypto.sign(m, sig_priv_key)
    testcase.assertTrue(lib.crypto.asymcrypto.verify(m, s, sig_pub_key))

    # Encode and decode a message for myself
    enc_pub_key = base64.b64decode(as_.enc_pub_key.encode())
    enc_priv_key = base64.b64decode(as_.enc_priv_key.encode())
    c = lib.crypto.asymcrypto.encrypt(m, enc_priv_key, enc_pub_key)
    d = lib.crypto.asymcrypto.decrypt(c, enc_priv_key, enc_pub_key)
    testcase.assertEqual(m, d)
