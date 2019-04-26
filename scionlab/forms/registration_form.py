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

from django.forms import Form, EmailField
from django_registration.forms import RegistrationForm
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit
from crispy_forms.bootstrap import AppendedText
from snowpenguin.django.recaptcha2.fields import ReCaptchaField
from snowpenguin.django.recaptcha2.widgets import ReCaptchaWidget

from scionlab.models.user import User


class RegistrationFormWithCaptcha(RegistrationForm):
    class Meta(RegistrationForm.Meta):
        model = User
        fields = ('first_name', 'last_name', 'organisation', 'email', )

    captcha = ReCaptchaField(widget=ReCaptchaWidget(explicit=True, container_id='recaptcha-id'))

    def __init__(self, *args, **kwargs):
        self.helper = self._crispy_helper()
        super().__init__(*args, **kwargs)
        for f in ['first_name', 'last_name']:
            self.fields[f].required = True

    def _crispy_helper(self):
        """
        Create the crispy-forms FormHelper. The form will then be rendered
        using {% crispy form %} in the template.
        """
        helper = FormHelper()
        helper.attrs['id'] = 'id_user_as_form'
        helper.layout = Layout(
            AppendedText('email', '<span class="fa fa-envelope"/>'),
            AppendedText('first_name', '<span class="fa fa-user"/>'),
            AppendedText('last_name', '<span class="fa fa-user"/>'),
            AppendedText('organisation', '<span class="fa fa-briefcase"/>'),
            AppendedText('password1', '<span class="fa fa-lock"/>'),
            AppendedText('password2', '<span class="fa fa-repeat"/>'),
            'captcha',
            Submit('register', 'Register', css_class='btn-block'),
        )
        return helper


class RegistrationResendForm(Form):
    email = EmailField()
