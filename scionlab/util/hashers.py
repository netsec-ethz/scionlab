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

import base64
from collections import OrderedDict
from django.contrib.auth.hashers import BasePasswordHasher, mask_hash
from django.utils.crypto import constant_time_compare
from django.utils.translation import gettext_noop as _


class SCryptPasswordHasher(BasePasswordHasher):
    """
    Password hasher using the scrypt algorithm.
    """

    algorithm = "scrypt"
    library = ("scrypt", "scrypt",)
    Nlog2 = 15  # N == 2 ** 15 == 32768
    r = 8
    p = 1
    keyLen = 64

    def salt(self):
        # Use a b64-encoded salt because we need to store the imported salt values, which are
        # non-ascii.
        return _b64enc(super().salt().encode())

    def encode(self, password, salt, Nlog2=None, r=None, p=None, keyLen=None):
        assert password is not None
        assert salt and '$' not in salt
        Nlog2 = Nlog2 or self.Nlog2
        r = r or self.r
        p = p or self.p
        keyLen = keyLen or self.keyLen

        scrypt = self._load_library()
        hash = scrypt.hash(password, _b64dec(salt), 2**Nlog2, r, p, keyLen)
        return self._format(Nlog2, r, p, salt, _b64enc(hash))

    def verify(self, password, encoded):
        Nlog2, r, p, salt, hash = self._parse(encoded)
        keyLen = len(_b64dec(hash))
        encoded_2 = self.encode(password, salt, Nlog2, r, p, keyLen)
        return constant_time_compare(encoded, encoded_2)

    def safe_summary(self, encoded):
        Nlog2, r, p, salt, hash = self._parse(encoded)
        return OrderedDict([
            (_('algorithm'), self.algorithm),
            (_('N'), 2**Nlog2),
            (_('r'), r),
            (_('p'), p),
            (_('salt'), mask_hash(salt, show=2)),
            (_('hash'), mask_hash(hash)),
        ])

    def harden_runtime(self, password, encoded):
        Nlog2, r, p, salt, hash = self._parse(encoded)

        # get same number of iterations as with self.Nlog2:
        # 2**Nlog2 + sum(2**n for n in range(Nlog2, self.Nlog2)) = 2**self.Nlog2
        for n in range(Nlog2, self.Nlog2):
            self.encode(password, salt, n, r, p)

    def _parse(self, encoded):
        algorithm, Nlog2, r, p, salt, hash = encoded.split('$', 6)
        assert algorithm == self.algorithm
        return int(Nlog2), int(r), int(p), salt, hash

    def _format(self, Nlog2, r, p, salt, hash):
        return "%s$%d$%d$%d$%s$%s" % (self.algorithm, Nlog2, r, p, salt, hash)


def _b64enc(bytes):
    return base64.b64encode(bytes).decode('ascii').strip()


def _b64dec(string):
    return base64.b64decode(string.encode('ascii'))
