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

"""
Metadata and object creation procedure for the fixtures `testuser.yaml` and `testuser-admin.yaml`
"""

from scionlab.models.user import User

TESTUSER_EMAIL = 'scion@scionlab.org'
TESTUSER_PWD = 'scion'
TESTUSER_ADMIN_EMAIL = 'admin@scionlab.org'
TESTUSER_ADMIN_PWD = 'scion53cure'


def get_testuser():
    """ Return the User object for testuser """
    return User.objects.get(email=TESTUSER_EMAIL)


def get_testuser_admin():
    """ Return the User object for testuser """
    return User.objects.get(email=TESTUSER_EMAIL)


# Explicitly make `get_testuser` and `get_testuser_admin` not a test;
# nose thinks this looks like a test...
get_testuser.__test__ = False
get_testuser_admin.__test__ = False


def create_testuser():
    """
    Create a user `TESTUSER_EMAIL` with the password `TESTUSER_PWD`.
    :return: User
    """

    return User.objects.create_user(
        email=TESTUSER_EMAIL,
        password=TESTUSER_PWD
    )


def create_testuser_admin():
    """
    Create an admin-user `TESTUSER_ADMIN_EMAIL` with the password `TESTUSER_PWD`.
    :return: User
    """

    return User.objects.create_superuser(
        email=TESTUSER_ADMIN_EMAIL,
        password=TESTUSER_ADMIN_PWD,
    )
