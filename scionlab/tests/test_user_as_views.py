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
import yaml
import pathlib

from django.conf import settings
from django.test import TestCase
from parameterized import parameterized
from django.urls import reverse
from django_webtest import WebTest
from scionlab.models.user_as import UserAS, AttachmentPoint, AttachmentConf
from scionlab.defines import DEFAULT_PUBLIC_PORT
from scionlab.fixtures.testuser import get_testuser, TESTUSER_EMAIL
from scionlab.fixtures import testtopo
from scionlab.tests import utils
from scionlab.views.user_as_views import UserASForm


_FORM_CASES_FOLDER = os.path.join(settings.BASE_DIR, 'scionlab', 'tests', 'data', 'test_user_forms')
_QUOTA_EXCEEDED_MESSAGE = ('You have reached the maximum number of ASes '
                           'and cannot create further ones.')
_NO_USER_AS_MESSAGE = 'You currently have no registered SCIONLab ASes'
_test_ip = '192.1.2.111'
_test_start_port = 50000
_test_ipv6 = '2a00:1450:400a:801::2004'


def _create_ases_for_testuser(num):
    """ Create a number `num` UserASes for testuser """
    user = get_testuser()
    num_existing_ases = UserAS.objects.filter(owner=user).count()
    for i in range(num_existing_ases, num_existing_ases+num):
        ap = AttachmentPoint.objects.first()
        user_as = UserAS.objects.create(
            owner=user,
            installation_type=UserAS.VM,
            isd=ap.AS.isd,
            label="Testuser's AS number %i" % (i + 1),
        )
        att_conf = AttachmentConf(ap,
                                  _test_ip, _test_start_port + i,
                                  bind_ip=None, bind_port=None,
                                  use_vpn=False)
        user_as.update_attachments([att_conf])


def _get_form_fields(data, include_errors: bool = False):
    """
    :include_errors: includes the expected error string in the form (NOTE: this piece of information
                     should be removed from the returned dict before passing it to the Form)
    :returns Dict[Str, Any]: dictionary containing UserASForm and AttachmentLinksFormSet data
    """
    useras_defaults = {
        "user-as-label": "",
        "user-as-installation_type": "VM"
    }
    attachment_defaults = {
        "active": "on",
        "use_vpn": "",
        "attachment_point": "",
        "public_ip": "",
        "public_port": "50000",
        "bind_ip": "",
        "bind_port": ""
    }
    d = useras_defaults
    d['form-INITIAL_FORMS'] = 0
    d['form-TOTAL_FORMS'] = len(data['attachments'])
    d['form-MIN_NUM_FORMS'] = 0
    d['form-MAX_NUM_FORMS'] = UserAS.MAX_AP_PER_USERAS
    d['user-as-label'] = data.get('label', d['user-as-label'])
    d['user-as-installation_type'] = data.get('installation_type',
                                              d['user-as-installation_type'])
    for i, attachment in enumerate(data['attachments']):
        t = {}
        for k, v in attachment_defaults.items():
            # Update defaults with index of current item
            t['form-{}-{}'.format(i, k)] = v
        for k, v in attachment.items():
            t['form-{}-{}'.format(i, k)] = v
        d.update(t)
    if include_errors and 'error' in data:
        d['error'] = data['error']
    return d


def _form_has_single_ap(form_data):
    return form_data['form-TOTAL_FORMS'] == 1


def _get_forms_error_descs(form: UserASForm) -> str:
    """
    Return all the fields and non fields errors in the `UserASForm`, as well as
    all the fields, non fields, and non form errors of the `AttachmentConfForm`
    """
    formset = form.attachment_conf_form_set
    return '\n'.join(map(str, [form.errors, form.non_field_errors(),
                     formset.errors, formset.non_form_errors()]))


class UserASFormTests(TestCase):
    fixtures = ['testdata']

    # Valid form cases
    valid_cases_file_path = pathlib.Path(_FORM_CASES_FOLDER, 'valid_forms.yaml')
    valid_form_cases = yaml.safe_load(valid_cases_file_path.read_text())
    valid_forms_params = [_get_form_fields(c) for c in valid_form_cases]
    # Invalid form cases
    invalid_cases_file_path = pathlib.Path(_FORM_CASES_FOLDER, 'invalid_forms.yaml')
    invalid_form_cases = yaml.safe_load(invalid_cases_file_path.read_text())
    invalid_forms_params = [_get_form_fields(c) for c in invalid_form_cases]
    invalid_forms_params_with_errors = [_get_form_fields(c, include_errors=True)
                                        for c in invalid_form_cases]

    def test_render_create(self):
        form = UserASForm(user=get_testuser())
        self.assertIsNotNone(form.as_table())

    # Note: not all combinations, most parameters are independent
    @parameterized.expand(zip(valid_forms_params))
    def test_create_valid(self, form_data):
        """
        Check that the form is valid with the given values as user input,
        and saving the form results in a new UserAS object.
        """
        form = UserASForm(user=get_testuser(), data=form_data)
        error_descs = _get_forms_error_descs(form)
        self.assertTrue(form.is_valid(), error_descs)
        user_as = form.save()
        self.assertIsNotNone(user_as)

    @parameterized.expand(zip(invalid_forms_params_with_errors))
    def test_create_invalid(self, form_data):
        error_desc = form_data.pop('error', None)
        form = UserASForm(user=get_testuser(), data=form_data)
        self.assertFalse(form.is_valid())
        if error_desc:
            error_descs = _get_forms_error_descs(form)
            self.assertIn(error_desc, error_descs)

    def test_create_too_many(self):
        """
        Submitting the creation form with quota exceeded leads to
        a form-error.
        """
        form_data = UserASFormTests.valid_forms_params[0]

        for i in range(get_testuser().max_num_ases()):
            form = UserASForm(user=get_testuser(), data=form_data)
            # Check that form is valid, otherwise this test will not make sense
            self.assertTrue(form.is_valid(), form.errors)
            form.save()

        form = UserASForm(user=get_testuser(), data=form_data)
        self.assertFalse(form.is_valid())
        self.assertTrue(any(e.find("quota exceeded") >= 0 for e in form.non_field_errors()),
                        form.errors)

    @parameterized.expand(zip(valid_forms_params, valid_forms_params))
    def test_edit_render(self, initial_data, new_data):
        """
        The form can be instantiated with a (freshly created) UserAS.
        The instantiated form should accept and keep the valid new form data,
        and should not show any changes if the same data is resubmitted.
        """

        # Create a UserAS with the given data
        create_form = UserASForm(user=get_testuser(), data=initial_data)
        self.assertIsNotNone(create_form.as_table())
        self.assertTrue(create_form.is_valid(), create_form.errors)
        user_as = create_form.save()
        self.assertIsNotNone(user_as)

        # Submit a change
        edit_form_1 = UserASForm(user=get_testuser(), instance=user_as, data=new_data)
        self.assertIsNotNone(edit_form_1.as_table())
        self.assertTrue(edit_form_1.is_valid(), edit_form_1.errors)
        if initial_data == new_data:
            self.assertFalse(edit_form_1.has_changed(), edit_form_1.changed_data)
        else:
            self.assertTrue(edit_form_1.has_changed())
        user_as_edited_1 = edit_form_1.save()
        self.assertEqual(user_as.pk, user_as_edited_1.pk)

        # Instantiate form again, check that data is identical
        edit_form_2 = UserASForm(user=get_testuser(), instance=user_as, data=new_data)
        self.assertTrue(edit_form_2.is_valid(), edit_form_2.errors)
        self.assertFalse(edit_form_2.has_changed(), edit_form_2.changed_data)
        user_as_edited_2 = edit_form_2.save()
        self.assertEqual(user_as.pk, user_as_edited_2.pk)


class UserASPageTests(WebTest):
    fixtures = ['testdata']

    def test_create_as_button(self):
        """
        The main user page has a button/link to create new ASes.
        """
        self.app.set_user(TESTUSER_EMAIL)
        user_page = self.app.get(reverse('user'))
        create_page = user_page.click(description='Create a new SCIONLab AS',
                                      href=reverse('user_as_add'))
        self.assertEqual(create_page.status_code, 200)

    def test_create_as_button_no_quota(self):
        """
        If the AS quota has been exceeded, the Create AS page is not available
        anymore.
        """
        _create_ases_for_testuser(get_testuser().max_num_ases())

        self.app.set_user(TESTUSER_EMAIL)
        # The quota should be exceeded: the Create AS button is gone
        user_page = self.app.get(reverse('user'))
        user_page.mustcontain(_QUOTA_EXCEEDED_MESSAGE)
        add_links = user_page.html.find_all("a", href=reverse('user_as_add'))
        self.assertEqual([], add_links)

    def test_as_listing(self):
        """
        The main user page should contain a listing of the user's ASes with one link
        to the detail page for each of them.
        """
        def check_as_link_count(user_page, expected_count):
            links = user_page.html.find_all("a", href=lambda x: re.fullmatch(r"/user/as/\d*", x))
            self.assertEqual(expected_count, len(links), links)

        self.app.set_user(TESTUSER_EMAIL)

        # Start with no ASes
        self.assertFalse(UserAS.objects.filter(owner=get_testuser()).exists())
        user_page = self.app.get(reverse('user'))
        check_as_link_count(user_page, 0)
        self.assertTrue(_NO_USER_AS_MESSAGE in user_page, user_page)

        for n in range(get_testuser().max_num_ases()):
            _create_ases_for_testuser(1)
            user_page = self.app.get(reverse('user'))
            check_as_link_count(user_page, n+1)

        self.assertFalse(_NO_USER_AS_MESSAGE in user_page, user_page)


class UserASCreateTests(WebTest):
    fixtures = ['testdata']

    @staticmethod
    def get_ap_strs():
        """ Get a str-list of attachment points from the testtopo-metadata """
        def as_str(as_def):
            return "%s-%s (%s)" % (as_def.isd_id, as_def.as_id, as_def.label)
        return [as_str(as_def) for as_def in testtopo.ases if as_def.is_ap]

    def setUp(self):
        self.attachment_points = self.get_ap_strs()

    def test_get_create_form(self):
        """ Check the initial values and options of the create UserAS form """
        self.app.set_user(TESTUSER_EMAIL)
        create_page = self.app.get(reverse('user_as_add'))
        form = create_page.form
        # Ignore the default value which is just "---------"
        self.assertEqual(set(o[2] for o in form['form-0-attachment_point'].options if not o[1]),
                         set(self.attachment_points))
        self.assertEqual(form['form-0-public_port'].value,
                         str(DEFAULT_PUBLIC_PORT))

    @parameterized.expand(zip(filter(_form_has_single_ap, UserASFormTests.valid_forms_params)))
    def test_submit_create_form_valid(self, form_data):
        """ Submitting valid data creates the AS and forwards to the detail page """
        self.app.set_user(TESTUSER_EMAIL)
        create_page = self.app.get(reverse('user_as_add'))
        self._fill_form(create_page.form, **form_data)
        response = create_page.form.submit()

        user_as = UserAS.objects.filter(owner=get_testuser()).last()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location,
                         reverse('user_as_detail', kwargs={'pk': user_as.pk}))
        self.assertEqual(response.follow().status_code, 200)

        # submit the form again, forwards to the next AS:
        response_2 = create_page.form.submit()
        user_as_2 = UserAS.objects.filter(owner=get_testuser()).last()
        self.assertEqual(response_2.status_code, 302)
        self.assertEqual(response_2.location,
                         reverse('user_as_detail', kwargs={'pk': user_as_2.pk}))
        self.assertEqual(response_2.follow().status_code, 200)

    @parameterized.expand(zip(filter(_form_has_single_ap, UserASFormTests.invalid_forms_params)))
    def test_submit_create_form_invalid(self, form_data):
        """ Submitting invalid data bumps back to the form with error messages """
        self.app.set_user(TESTUSER_EMAIL)
        create_page = self.app.get(reverse('user_as_add'))
        self._fill_form(create_page.form, **form_data)
        response = create_page.form.submit()
        self.assertEqual(response.status_code, 200)

        nonfield_error_marker = b'<div class="alert alert-block alert-danger">'
        field_error_marker_re = br'<span id="error_\d+_[^"]*" class="invalid-feedback">'
        self.assertTrue(nonfield_error_marker in response.body
                        or re.search(field_error_marker_re, response.body))

    def test_get_create_form_no_quota(self):
        """ Getting the create page with quota exceeded is not allowed """
        _create_ases_for_testuser(get_testuser().max_num_ases())
        self.app.set_user(TESTUSER_EMAIL)
        response = self.app.get(reverse('user_as_add'), expect_errors=True)
        self.assertEqual(response.status_code, 403)

    def test_post_create_form_no_quota(self):
        """ Submitting the create form with quota exceeded is not allowed """
        self.app.set_user(TESTUSER_EMAIL)
        create_page = self.app.get(reverse('user_as_add'), expect_errors=True)

        _create_ases_for_testuser(get_testuser().max_num_ases())

        self._fill_form(create_page.form, **UserASFormTests.valid_forms_params[0])
        response = create_page.form.submit(expect_errors=True)
        self.assertEqual(response.status_code, 403)

    @staticmethod
    def _fill_form(form, **kwargs):
        for key, value in kwargs.items():
            form[key] = value


class UserASActivateTests(WebTest):
    fixtures = ['testdata']

    def test_cycle_active(self):
        def check_active(active, user_as, edit_page):
            self.assertEqual("Activate this AS" in edit_page, not active, edit_page)
            self.assertEqual("Deactivate this AS" in edit_page, active, edit_page)
            self.assertEqual(user_as.is_active(), active)

        _create_ases_for_testuser(3)
        user_as = UserAS.objects.filter(owner=get_testuser())[1]

        self.app.set_user(TESTUSER_EMAIL)
        user_page = self.app.get(reverse('user'))
        edit_page = user_page.click(href=reverse('user_as_detail', kwargs={'pk': user_as.pk})+'$')
        check_active(True, user_as, edit_page)

        edit_page = edit_page.forms['id_deactivate_form'].submit().maybe_follow()
        check_active(False, user_as, edit_page)

        edit_page = edit_page.forms['id_activate_form'].submit().maybe_follow()
        check_active(True, user_as, edit_page)


class UserASGetConfigTests(TestCase):
    fixtures = ['testdata']

    def test_get_config(self):
        _create_ases_for_testuser(get_testuser().max_num_ases())

        self.client.force_login(get_testuser())
        user_as_pks = [user_as.pk for user_as
                       in UserAS.objects.filter(owner=get_testuser()).iterator()]
        for pk in user_as_pks:
            response = self.client.get(reverse('user_as_config', kwargs={'pk': pk}))
            self.assertEqual(response.status_code, 200)
            utils.check_tarball_user_as(self, response, UserAS.objects.get(pk=pk))
