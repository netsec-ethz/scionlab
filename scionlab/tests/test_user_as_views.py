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

from django.test import TestCase
from parameterized import parameterized, param
from django.urls import reverse
from django_webtest import WebTest
from scionlab.models import User, AttachmentPoint, VPN, DEFAULT_INTERFACE_PUBLIC_PORT
from scionlab.fixtures.testuser import TESTUSER_EMAIL
from scionlab.fixtures import testtopo
from scionlab.views.user_as_views import UserASForm


def _get_testuser():
    """ Return the User object for testuser """
    return User.objects.get(username=TESTUSER_EMAIL)


def _setup_vpn_attachment_point():
    """ Setup VPN for the first AP """
    # TODO(matzf): move to a fixture once the VPN stuff is somewhat stable
    ap = AttachmentPoint.objects.all()[0]
    ap.vpn = VPN.objects.create(server=ap.AS.hosts.first(),
                                subnet='10.0.8.0/8',
                                server_port=4321)
    ap.save()


class UserASFormTests(TestCase):
    fixtures = ['testuser', 'testtopo-ases-links']

    # Valid form parameters
    valid_form_params = [
        param(attachment_point="1", use_vpn=True),
        param(attachment_point="1", use_vpn=True, installation_type='VM'),
        param(attachment_point="1", use_vpn=True, installation_type='DEDICATED'),
        param(attachment_point="1", use_vpn=True, label="This is a label"),
        param(attachment_point="1", use_vpn=True, public_port=54321),
        param(attachment_point="1", public_ip='192.0.2.123'),
        param(attachment_point="1", public_ip='192.0.2.123', public_port=54321),
        param(attachment_point="1", use_vpn=True, public_ip='192.0.2.123'), # Ok to provide redundant IP
        param(attachment_point="2", public_ip='192.0.2.123'),
    ]
    # Invalid form parameters
    invalid_form_params = [
        param(attachment_point="1", use_vpn=False, public_ip=''), # Needs either VPN or public IP
        param(attachment_point="2", use_vpn=True), # AP 2 does not have VPN
    ]

    def setUp(self):
        _setup_vpn_attachment_point()

    def test_render_create(self):
        form = UserASForm(user=_get_testuser())
        self.assertIsNotNone(form.as_table())

    # Note: not all combinations, most parameters are independent
    @parameterized.expand(valid_form_params)
    def test_create_valid(self, **kwargs):
        """
        Check that the form is valid with the given values as user input,
        and saving the form results in a new UserAS object.
        """
        form_data = self._get_initial_dict()
        form_data.update(**kwargs)

        form = UserASForm(user=_get_testuser(), data=form_data)
        self.assertTrue(form.is_valid(), form.errors)

        user_as = form.save()
        self.assertIsNotNone(user_as)


    @parameterized.expand(invalid_form_params)
    def test_create_invalid(self, **kwargs):
        form_data = self._get_initial_dict()
        form_data.update(**kwargs)
        form = UserASForm(user=_get_testuser(), data=form_data)
        self.assertFalse(form.is_valid())

    def test_create_too_many(self):
        form_data = self._get_initial_dict()
        form_data.update(**self.valid_form_params[0].kwargs)

        for i in range(_get_testuser().max_num_ases()):
            form = UserASForm(user=_get_testuser(), data=form_data)
            self.assertTrue(form.is_valid(), form.errors) # Otherwise this test will not make sense
            form.save()

        form = UserASForm(user=_get_testuser(), data=form_data)
        self.assertFalse(form.is_valid())
        self.assertTrue(any(e.find("quota exceeded") >= 0 for e in form.non_field_errors()),
                        form.errors)

    @parameterized.expand(valid_form_params)
    def test_edit_render(self, **kwargs):
        """
        Check that the form can be instantiated with a UserAS, freshly created.
        The instantiated form should not show any changes if the same data is submitted.
        """
        form_data = self._get_initial_dict()
        form_data.update(**kwargs)

        # Create a UserAS with the given data
        create_form = UserASForm(user=_get_testuser(), data=form_data)
        self.assertTrue(create_form.is_valid(), create_form.errors)
        user_as = create_form.save()
        self.assertIsNotNone(create_form)

        # Check that the form can be instantiated for the object just created
        # and check that the forms initial values are the same as the
        # previously submitted values.
        edit_form_1 = UserASForm(user=_get_testuser(), instance=user_as, data=form_data)
        self.assertIsNotNone(edit_form_1.as_table())
        self.assertTrue(edit_form_1.is_valid(), edit_form_1.errors)
        self.assertFalse(edit_form_1.has_changed(), edit_form_1.changed_data)
        user_as_edited_1 = edit_form_1.save()
        self.assertEqual(user_as.pk, user_as_edited_1.pk)

        # Do it again!
        edit_form_2 = UserASForm(user=_get_testuser(), instance=user_as, data=form_data)
        self.assertTrue(edit_form_2.is_valid(), edit_form_2.errors)
        self.assertFalse(edit_form_2.has_changed(), edit_form_2.changed_data)
        user_as_edited_2 = edit_form_2.save()
        self.assertEqual(user_as.pk, user_as_edited_1.pk)

    def _get_initial_dict(self):
        """
        Return a dict containing the initial value for each UserAS form field
        """
        form = UserASForm(user=_get_testuser()) # only used to extract the initial values
        return { key: field.initial for (key, field) in form.fields.items() }


class _WebTestHack(WebTest):
    # XXX(matzf): temporary HACK!
    # See ProxyModelBackend for background.
    # Override UserModel with our User model, because django-webtest registers
    # their own auth-backend, effectively disabling our ProxyModelBackend.
    # By overriding django.contrib.auth.backends.UserModel, the
    # django-webtest's backend returns our ProxyModel and everything works.
    # Notes:
    #   Temporariliy setting AUTH_USER_MODEL = 'scionlab.User' almost works,
    #   but it looks like this value is cached somewhere...
    def _setup_auth(self):
        import django.contrib.auth.backends
        django.contrib.auth.backends.UserModel = User
        super()._setup_auth()

    def _patch_settings(self):
        import django.contrib.auth.backends
        self._UserModel = django.contrib.auth.backends.UserModel
        super()._patch_settings()

    def _unpatch_settings(self):
        import django.contrib.auth.backends
        django.contrib.auth.backends.UserModel = self._UserModel
        super()._unpatch_settings()


class UserASPageTests(_WebTestHack):
    fixtures = ['testuser', 'testtopo-ases-links']

    def test_create_as_button(self):
        self.app.set_user(TESTUSER_EMAIL)
        user_page = self.app.get(reverse('user'))
        create_page = user_page.click(description='Create a new SCIONLab AS',
                                      href=reverse('user_as_add'))
        self.assertEqual(create_page.status_int, 200)

    def test_create_as_button_no_quota(self):
        self.app.set_user(TESTUSER_EMAIL)

        # Use the create form to create the max number of ASes
        user_page = self.app.get(reverse('user'))
        create_page = user_page.click(description='Create a new SCIONLab AS',
                                      href=reverse('user_as_add'))
        create_page.form['public_ip'] = '192.0.2.123'
        for i in range(_get_testuser().max_num_ases()):
            create_page.form.submit().follow()

        # Now the quota should be exceeded
        user_page = self.app.get(reverse('user'))
        user_page.mustcontain('You have reached the maximum number of ASes and cannot create further ones.')
        self.assertEqual([], user_page.html.select('a[href="%s"]' % reverse('user_as_add')))

        # Just check: "accidentally" getting or submitting the form again to
        # create more ASes does not work
        response_failed = self.app.get(reverse('user_as_add'), expect_errors=True)
        self.assertEqual(response_failed.status_int, 403)
        response_failed = create_page.form.submit(expect_errors=True)
        self.assertEqual(response_failed.status_int, 403)


class UserASCreateTests(_WebTestHack):
    fixtures = ['testuser', 'testtopo-ases-links']

    @staticmethod
    def get_ap_strs():
        """ Get a str-list of attachment points from the testtopo-metadata """
        def as_str(asdef):
            return "%s-%s (%s)" % (asdef.isd_id, asdef.as_id, asdef.label)
        return [as_str(asdef) for asdef in testtopo.ases if asdef.is_ap]

    def setUp(self):
        _setup_vpn_attachment_point()
        self.attachment_points = self.get_ap_strs()

    def test_get_create_form(self):
        """ Check the initial values and options of the create UserAS form """
        self.app.set_user(TESTUSER_EMAIL)
        create_page = self.app.get(reverse('user_as_add'))
        form = create_page.form
        self.assertEqual([o[2] for o in form['attachment_point'].options],
                         self.attachment_points)
        self.assertEqual(form['public_port'].value,
                         str(DEFAULT_INTERFACE_PUBLIC_PORT))

    @parameterized.expand([
        (None, None),
        (0, None),
        (1, None),
        (0, 'Foo'),
        (0, 'naughty_'*500),
    ])
    def test_create(self, ap_index, label, expect_success=True):
        self.app.set_user(TESTUSER_EMAIL)
        create_page = self.app.get(reverse('user_as_add'))
        form = create_page.form
        if ap_index is not None:
            form['attachment_point'].select(text=self.attachment_points[ap_index])
        if label is not None:
            form['label'] = label
        response = form.submit()
        if not expect_success:
            self.assertEqual(response.status_int, 300)
            return
        #self.assertEqual(response.status_int, 200)
        #response.follow()
