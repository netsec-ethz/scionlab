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

    def test_account_not_activated(self):
        """
        Check that an account which has not been activated cannot login
        """

        login_url = reverse('login')

        response = self.client.get(login_url, follow=True)

        registration_url = reverse('registration_form')
        response = self.client.get(
            registration_url,
            follow=True
        )

        # Post registration:
        response = self.client.post(
            registration_url,
            {'email': TESTUSER_EMAIL,
             'first_name': 'Test',
             'last_name': 'User',
             'organisation': 'SCIONLab',
             'password1': TESTUSER_PWD,
             'password2': TESTUSER_PWD, },
            follow=True
        )

        # Check the correct activation email is created
        self.assertEqual(len(mail.outbox), 1)
        activation_mail = mail.outbox[0]
        self.assertEqual(activation_mail.recipients(), [TESTUSER_EMAIL])
        subject_template = os.path.join(BASE_DIR, 'scionlab', 'templates', 'django_registration',
                                        'activation_email_subject.txt')
        with open(subject_template) as f:
            activation_subject = f.read()
        self.assertEqual(activation_mail.subject, activation_subject)

        # Attempt log in:
        response = self.client.post(
            login_url,
            {'username': TESTUSER_EMAIL, 'password': TESTUSER_PWD},
            follow=True
        )

        # We should still be on the login page
        self.assertEqual(len(response.redirect_chain), 0)

        # Now we activate the account by using the link sent by email
        activation_mail_message = str(activation_mail.message().get_payload())
        links = re.findall(r'http://testserver(/\S*)', activation_mail_message, re.MULTILINE)

        dummy_activation_key = 'XXX'
        activation_url = reverse('django_registration_activate',
                                 kwargs={'activation_key': dummy_activation_key}).split(
            dummy_activation_key)[0]

        activation_link = ''
        for link in links:
            if activation_url in link:
                activation_link = link
                break

        self.assertNotEqual(activation_link, '')

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

        # Attempt log in:
        response = self.client.post(
            login_url,
            {'username': TESTUSER_EMAIL, 'password': TESTUSER_PWD},
            follow=True
        )

        # Check success
        self.assertTemplateUsed(
            response,
            'scionlab/user.html',
            "Expected user page template."
        )
