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

from django.contrib.auth.backends import ModelBackend
from scionlab.models import User


class ProxyModelBackend(ModelBackend):
    """
    This specialisation of contrib.auth.backends.ModelBackend returns
    the Proxy-Model `scionlab.models.User` instead of the proxied `contrib.auth.User`.
    This allows using the additional features of `scionlab.models.User`
    e.g. on `request.user` in templates.

    Note: it would be nicer to simply override AUTH_USER_MODEL in the settings
    but for some reason (bug!?), a proxy model cannot be used in this context.

    Note: this is a hack, the auth-backend is the wrong place to put this; a
    django app can have multiple backends configured that are queried in sequence.
    Instead, the type returned by django.contrib.auth.get_user_model should be
    patched...
    """

    def get_user(self, user_id):
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None
