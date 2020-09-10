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
import os
import re

from django.core import mail
from django.test import TestCase
from django.urls import reverse

from scionlab.models.user import User
from scionlab.settings.common import BASE_DIR
from scionlab.fixtures.testuser import (
    TESTUSER_EMAIL,
    TESTUSER_PWD
)


class ActivationRequiredTest(TestCase):
    def setUp(self):
        os.environ['RECAPTCHA_DISABLE'] = 'True'  # Disable captcha

    def tearDown(selfself):
        del os.environ['RECAPTCHA_DISABLE']  # Reenable captcha

    def test_render_activation_form(self):
        response = self.client.get(reverse('registration_form'))
        self.assertTemplateUsed(
            response,
            'django_registration/registration_form.html',
        )

    def test_render_resend_form(self):
        response = self.client.get(reverse('registration_resend'))
        self.assertTemplateUsed(
            response,
            'django_registration/registration_resend.html',
        )

    def test_activation_email(self):
        self._register()
        self._check_activation_email_sent()

    def test_resend_activation_email(self):
        self._register()
        self._check_activation_email_sent()

        response = self.client.post(
            reverse('registration_resend'),
            {
                'email': TESTUSER_EMAIL,
            },
            follow=True
        )
        self.assertTemplateUsed(
            response,
            'django_registration/registration_confirm.html',
        )

        self._check_activation_email_sent()

    def test_account_not_activated(self):
        """
        Check that an account which has not been activated cannot login
        """
        self._register()

        # Attempt log in:
        response = self.client.post(
            reverse('login'),
            {'username': TESTUSER_EMAIL, 'password': TESTUSER_PWD},
            follow=True
        )

        # We should still be on the login page
        self.assertEqual(len(response.redirect_chain), 0)

    def test_activate_account(self):
        self._register()
        activation_link = self._check_activation_email_sent()

        # Use the activation link
        response = self.client.get(
            activation_link,
            follow=True
        )
        self.assertTemplateUsed(
            response,
            'django_registration/activation_complete.html',
            "Expected account activation complete template."
        )

        user = User.objects.filter(email=TESTUSER_EMAIL).first()
        self.assertIsNotNone(user)
        self.assertTrue(user.is_active)

        # Attempt log in:
        response = self.client.post(
            reverse('login'),
            {'username': TESTUSER_EMAIL, 'password': TESTUSER_PWD},
            follow=True
        )
        # Check success
        self.assertTemplateUsed(
            response,
            'scionlab/user.html',
            "Expected user page template."
        )

    def _register(self):
        # Post registration:
        response = self.client.post(
            reverse('registration_form'),
            {
                'email': TESTUSER_EMAIL,
                'first_name': 'Test',
                'last_name': 'User',
                'organisation': 'SCIONLab',
                'password1': TESTUSER_PWD,
                'password2': TESTUSER_PWD,
            },
            follow=True
        )

        self.assertTemplateUsed(
            response,
            'django_registration/registration_confirm.html',
        )

        user = User.objects.filter(email=TESTUSER_EMAIL).first()
        self.assertIsNotNone(user)
        self.assertFalse(user.is_active)

    def _check_activation_email_sent(self):
        """
        Check for activation mail in mail.outbox and return contained activation link.
        """
        self.assertEqual(len(mail.outbox), 1)
        activation_mail = mail.outbox[0]
        self.assertEqual(activation_mail.recipients(), [TESTUSER_EMAIL])
        subject_template = os.path.join(BASE_DIR, 'scionlab', 'templates', 'django_registration',
                                        'activation_email_subject.txt')
        with open(subject_template) as f:
            activation_subject = f.read()
        self.assertEqual(activation_mail.subject, activation_subject)

        # Extract the link contained in the email
        msg = str(activation_mail.message().get_payload())
        links = re.findall(r'http://testserver(/registration/activate/\S*)', msg, re.MULTILINE)
        self.assertEqual(len(links), 1)
        link = links[0]

        mail.outbox.clear()

        return link
