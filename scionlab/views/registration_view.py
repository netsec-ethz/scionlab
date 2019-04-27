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

from django.urls import reverse_lazy
from django_registration.backends.activation.views import RegistrationView
from scionlab.models.user import User
from scionlab.forms.registration_form import RegistrationFormWithCaptcha, RegistrationResendForm


class UserRegistrationView(RegistrationView):
    success_url = reverse_lazy('registration_confirm')
    form_class = RegistrationFormWithCaptcha
    template_name = 'django_registration/registration_form.html'

    def register(self, form):
        return super().register(form)


class UserRegistrationResendView(RegistrationView):
    success_url = reverse_lazy('registration_confirm')
    form_class = RegistrationResendForm
    template_name = 'django_registration/registration_resend.html'

    def register(self, form):
        email = form.cleaned_data['email']
        user = User.objects.filter(email=email, is_active=False).first()
        if not user:
            return None  # Do nothing, just pretend it's successful.
        self.send_activation_email(user)
        return user
