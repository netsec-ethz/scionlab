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

import logging

from django.urls import reverse_lazy

from django_registration.backends.activation.views import RegistrationView

from scionlab.forms.registration_form import RegistrationFormWithCaptcha


class UserRegistrationView(RegistrationView):
    success_url = reverse_lazy('registration_confirm')
    form_class = RegistrationFormWithCaptcha

    def register(self, form):
        logging.debug('Doing the user registration...')
        super().register(form)
        return
