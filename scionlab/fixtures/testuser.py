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

""" Metadata and object creation procedure for the fixture `testuser.yaml` """

from scionlab.models import User

TESTUSER_EMAIL = 'scion@example.com'
TESTUSER_PWD = 'scion'


def create_testuser():
    """
    Create a user `TESTUSER_EMAIL` with the password `TESTUSER_PWD`.
    :return: User
    """

    return User.objects.create_user(
        username=TESTUSER_EMAIL,
        email=TESTUSER_EMAIL,
        password=TESTUSER_PWD
    )
