# Copyright 2019 ETH Zurich
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

import string
from parameterized import parameterized
from timeit import default_timer as timer

from django.contrib.auth.hashers import mask_hash
from django.test import TestCase

from scionlab.models.user import User
from scionlab.util.hashers import SCryptPasswordHasher

# Test passwords imported from scion-coord (with *very* long salts)
IMPORTED_USERS = [
    ("foo@scionlab.org",
     "foofoofoo",
     "scrypt$15$8$1$tXoyAeZq147rGQujV2XROg2rWNgwwMEID4wqDUJ/Ter4Y6RhOTlQb5mKZ5rEFiwseXJBm7towaS8vzb"
     "E7nwchMCB9tpBUd6XzA9aHvfdxcs=$A89mQpiNlQ0996+mLTUUqdkdZ7XhJdiJGbbPx/doMqc="),
    ("bar@scionlab.org",
     "scionR0X",
     "scrypt$15$8$1$b0ae9yXjV1rYZbgCW3wfCKNuCA01MZ7nTpLuV/JaZsiqBYwrwdTyT2AYeHe7WkWL0WyJF9zO/VtPIFt"
     "UREiGZTyv/vTQ4C95tMuWlnM3W4Q=$DyL6FQdfl4J7en4Lc2+QKIHek09OMLoC3hJNobHTyv4="),
]


class SCryptPasswordHasherTests(TestCase):
    @parameterized.expand(IMPORTED_USERS)
    def test_imported(self, email, password, encoded):
        """
        Check that manually imported passwords from scion-coord can be verified.
        """
        h = SCryptPasswordHasher()
        self.assertTrue(h.verify(password, encoded))
        self.assertFalse(h.verify("bad_pass", encoded))

    def test_encode(self):
        """
        Encode a new password and check that it verifies correctly.
        """
        h = SCryptPasswordHasher()
        password = string.printable

        salt = h.salt()
        self.assertGreaterEqual(len(salt), 16)  # ~ 96 bits, base64 encoded

        encoded = h.encode(password, salt)

        self.assertTrue(h.verify(password, encoded))
        self.assertFalse(h.verify("bad_pass", encoded))

    def test_safe_summary(self):
        """
        safe_summary works on a newly encoded password
        """

        h = SCryptPasswordHasher()
        password = string.printable
        salt = h.salt()
        encoded = h.encode(password, salt)

        summary = h.safe_summary(encoded)
        self.assertEqual(summary['algorithm'], 'scrypt')
        self.assertEqual(summary['N'], 2**15)
        self.assertEqual(summary['r'], 8)
        self.assertEqual(summary['p'], 1)
        self.assertEqual(summary['salt'], mask_hash(salt, show=2))
        self.assertEqual(summary['hash'], mask_hash(encoded.split('$')[-1]))

    def test_harden_runtime(self):
        """
        Running harden_runtime for a password with lower than default N leads to (roughly) same
        runtime.

        This feature will probably not even be used, but since it is easy to implement we need to
        ensure that at least it won't break things.
        """
        h = SCryptPasswordHasher()
        password = string.printable
        salt = h.salt()

        encoded_8 = h.encode(password, salt, Nlog2=8)  # N==2**8 instead of 2**15
        start = timer()
        self.assertTrue(h.verify(password, encoded_8))
        h.harden_runtime(password, encoded_8)
        end = timer()
        time_8 = end - start

        encoded_15 = h.encode(password, salt)
        start = timer()
        self.assertTrue(h.verify(password, encoded_15))
        h.harden_runtime(password, encoded_15)
        end = timer()
        time_15 = end - start

        # within +-20%
        self.assertTrue(time_15 * 0.8 < time_8 < time_15 * 1.2,
                        "time_8: %f, time_15: %f" % (time_8, time_15))


class ImportedUserTests(TestCase):
    fixtures = []

    def setUp(self):
        for email, password, encoded in IMPORTED_USERS:
            user = User.objects.create_user(
                email=email,
                password=None
            )
            user.password = encoded
            user.is_active = True
            user.save()

    @parameterized.expand(IMPORTED_USERS)
    def test_login(self, email, password, encoded):
        self._assert_pwd_algo_scrypt(email)

        self.assertFalse(self.client.login(username=email, password="bad_pass"))
        self.assertTrue(self.client.login(username=email, password=password))

        # scrypt is not configured as default hasher, so the
        # password was re-hashed.
        self._assert_pwd_algo_not_scrypt(email)

        self.assertTrue(self.client.login(username=email, password=password))

    def _assert_pwd_algo_scrypt(self, email):
        pwd = self._get_user_pwd(email)
        self.assertEqual(pwd.split('$')[0], 'scrypt')

    def _assert_pwd_algo_not_scrypt(self, email):
        pwd = self._get_user_pwd(email)
        self.assertNotEqual(pwd.split('$')[0], 'scrypt')

    def _get_user_pwd(self, email):
        user = User.objects.get_by_natural_key(email)
        self.assertTrue(user.has_usable_password())
        return user.password
