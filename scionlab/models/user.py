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

from django.contrib.auth.models import User as auth_User
from django.conf import settings
from django.core.exceptions import ValidationError

from scionlab.models.user_as import UserAS


class User(auth_User):
    class Meta:
        proxy = True

    def max_num_ases(self):
        if self.is_staff:
            return settings.MAX_ASES_ADMIN
        return settings.MAX_ASES_USER

    def num_ases(self):
        return UserAS.objects.filter(owner=self).count()

    def check_as_quota(self):
        """
        Check if the user is allowed to create another AS.
        :raises: Validation error if quota is exceeded
        """
        if self.num_ases() >= self.max_num_ases():
            raise ValidationError("UserAS quota exceeded",
                                  code='user_as_quota_exceeded')
