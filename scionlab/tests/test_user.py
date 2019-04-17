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
from django_webtest import WebTest
from scionlab.fixtures.testuser import (
    TESTUSER_EMAIL,
    TESTUSER_PWD
)


class LoginRequiredRedirectTests(TestCase):
    def setUp(self):
        os.environ['RECAPTCHA_DISABLE'] = 'True'  # Disable captcha

    def tearDown(selfself):
        del os.environ['RECAPTCHA_DISABLE']  # Reenable captcha

    fixtures = ['testuser']

    def test_not_logged_in(self):
        """
        A view with required login redirects to the login page if the user is
        not logged in.
        """
        requested_url = reverse('user')

        response = self.client.get(requested_url, follow=True)
        self.assertEqual(len(response.redirect_chain), 1)
        redirected_url = response.redirect_chain[0][0]

        expected_url = '%s?next=%s' % (reverse('login'), requested_url)
        self.assertEqual(redirected_url, expected_url)

        self.assertTemplateUsed(
            response,
            'registration/login.html',
            "Expected login template."
        )

        # Attempt log in:
        response = self.client.post(
            redirected_url,
            {'username': TESTUSER_EMAIL, 'password': TESTUSER_PWD},
            follow=True
        )
        # Now we should land on the originally requested page
        self.assertEqual(len(response.redirect_chain), 1)
        self.assertEqual(response.redirect_chain[0][0], requested_url)

    def test_logged_in(self):
        """
        A view with required login is accessible if the user is logged in.
        """
        login_success = self.client.login(username=TESTUSER_EMAIL, password=TESTUSER_PWD)
        self.assertTrue(login_success)

        response = self.client.get(reverse('user'))
        self.assertEqual(response.status_code, 200)

        self.assertTemplateNotUsed(
            response,
            'registration/login.html',
            "Expected no login template."
        )


class PasswordWebTests(WebTest):
    def setUp(self):
        os.environ['RECAPTCHA_DISABLE'] = 'True'  # Disable captcha

    def tearDown(selfself):
        del os.environ['RECAPTCHA_DISABLE']  # Reenable captcha

    fixtures = ['testuser']

    def test_reset_pwd(self):
        """
        Reset the password
        """
        reset_init_form = self.app.get(reverse('password_reset')).form
        reset_init_form['email'] = TESTUSER_EMAIL
        reset_init_form.submit()

        self.assertEqual(len(mail.outbox), 1)
        reset_mail = mail.outbox[0]
        self.assertEqual(reset_mail.recipients(), [TESTUSER_EMAIL])
        reset_mail_message = reset_mail.message().as_string()
        links = re.findall(r'http://testserver(/\S*)', reset_mail_message, re.MULTILINE)
        self.assertEqual(len(links), 1)
        reset_link = links[0]

        new_password = 'scionscion'
        pwd_form = self.app.get(reset_link).follow().form
        pwd_form['new_password1'] = pwd_form['new_password2'] = new_password
        pwd_changed = pwd_form.submit().follow()

        login_form = pwd_changed.click(linkid='id_login').form
        login_form['username'] = TESTUSER_EMAIL
        login_form['password'] = new_password
        response = login_form.submit()
        self.assertEqual(response.status_int, 302)
