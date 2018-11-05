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

import re
import base64
import lib.crypto.asymcrypto


def check_as_keys(testcase, as_):
    """
    Check that keys of AS `as_` have been properly initialised
    :param unittest.TestCase testcase: The testcase to call assert on
    :param scionlab.models.AS as_: The AS with the key-pairs to check
    """
    testcase.assertIsNotNone(as_)
    _check_sig_keypair(testcase, as_.sig_pub_key, as_.sig_priv_key)
    _check_enc_keypair(testcase, as_.enc_pub_key, as_.enc_priv_key)
    testcase.assertIsNotNone(as_.master_as_key)
    _sanity_check_base64(testcase, as_.master_as_key)

def check_as_core_keys(testcase, as_):
    """
    Check that core AS keys of AS `as_` have been properly initialised
    :param unittest.TestCase testcase: The testcase to call assert on
    :param scionlab.models.AS as_: The AS with the key-pairs to check
    """
    testcase.assertIsNotNone(as_)
    _check_sig_keypair(testcase, as_.core_sig_pub_key, as_.core_sig_priv_key)
    _check_sig_keypair(testcase, as_.core_online_pub_key, as_.core_online_priv_key)
    _check_sig_keypair(testcase, as_.core_offline_pub_key, as_.core_offline_priv_key)

def _check_sig_keypair(testcase, sig_pub_key_b64, sig_priv_key_b64):
    """
    Check that this signing keypair was correctly created
    """
    testcase.assertIsNotNone(sig_pub_key_b64)
    testcase.assertIsNotNone(sig_priv_key_b64)
    _sanity_check_base64(testcase, sig_pub_key_b64)
    _sanity_check_base64(testcase, sig_priv_key_b64)

    m = "message".encode()

    # Sign a message and verify
    sig_pub_key = base64.b64decode(sig_pub_key_b64.encode())
    sig_priv_key = base64.b64decode(sig_priv_key_b64.encode())
    s = lib.crypto.asymcrypto.sign(m, sig_priv_key)
    testcase.assertTrue(lib.crypto.asymcrypto.verify(m, s, sig_pub_key))

def _check_enc_keypair(testcase, enc_pub_key_b64, enc_priv_key_b64):
    """
    Check that this encryption keypair was correctly created
    """
    testcase.assertIsNotNone(enc_pub_key_b64)
    testcase.assertIsNotNone(enc_priv_key_b64)
    _sanity_check_base64(testcase, enc_pub_key_b64)
    _sanity_check_base64(testcase, enc_priv_key_b64)

    m = "message".encode()

    # Encode and decode a message for myself
    enc_pub_key = base64.b64decode(enc_pub_key_b64.encode())
    enc_priv_key = base64.b64decode(enc_priv_key_b64.encode())
    c = lib.crypto.asymcrypto.encrypt(m, enc_priv_key, enc_pub_key)
    d = lib.crypto.asymcrypto.decrypt(c, enc_priv_key, enc_pub_key)
    testcase.assertEqual(m, d)

def _sanity_check_base64(testcase, s):
    """
    Check that string s looks like base64 encoded data
    """
    base64_pattern = re.compile(
        r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    )
    testcase.assertTrue(base64_pattern.match(s))
