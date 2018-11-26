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
from django_webtest import WebTest
from django.forms.models import modelform_factory
from scionlab.models import AS, Link
from scionlab.tests import utils
from scionlab.admin import ASCreationForm, LinkAdminForm
from scionlab.fixtures.testuser import TESTUSER_ADMIN_EMAIL


class ASAdminTests(TestCase):
    fixtures = ['testtopo-isds']

    def test_create_as_form(self):
        as_id = 'ff00:bad:f00d'
        form_data = {
            'isd': 17,
            'as_id': as_id,
            'label': 'Test',
            'public_ip': '192.0.2.11'
        }
        # This mimicks what ModelAdmin does to create the form:
        form_factory = modelform_factory(AS, form=ASCreationForm, fields='__all__')
        form = form_factory(data=form_data)
        self.assertTrue(form.is_valid())
        form.save()

        as_ = AS.objects.get(as_id=as_id)
        self.assertEqual(as_.as_id, as_id)
        self.assertEqual(as_.isd.id, 17)
        self.assertEqual(as_.label, 'Test')
        utils.check_as_keys(self, as_)


class LinkAdminFormTests(TestCase):
    fixtures = ['testtopo-ases']

    def test_render_create(self):
        form = LinkAdminForm()
        self.assertIsNotNone(form.as_table())

    def test_create_link(self):
        as_a = AS.objects.first()
        as_b = AS.objects.last()
        form_data = dict(
            type=Link.PROVIDER,
            from_host=as_a.hosts.first().id,
            from_public_port=50000,
            from_internal_port=30000,
            to_host=as_b.hosts.first().id,
            to_public_port=50000,
            to_internal_port=30000,
        )
        form = LinkAdminForm(data=form_data)
        self.assertTrue(form.is_valid())
        link = form.save()
        self.assertIsNotNone(link)

        # Re-creating form with same data should result in no changes:
        edit_form = LinkAdminForm(instance=link, data=form_data)
        self.assertTrue(edit_form.is_valid(), edit_form.errors)
        self.assertFalse(edit_form.has_changed(), edit_form.changed_data)

    def test_render_edit(self):
        as_a = AS.objects.first()
        as_b = AS.objects.last()
        link = Link.objects.create_default(Link.PROVIDER, as_a, as_b)
        form = LinkAdminForm(instance=link)
        self.assertIsNotNone(form.as_table())

    def test_edit_link(self):
        as_a = AS.objects.first()
        as_b = AS.objects.last()
        link = Link.objects.create_default(Link.PROVIDER, as_a, as_b)

        form_data = dict(
            type=Link.PROVIDER,
            from_host=as_a.hosts.first().id,
            to_host=as_b.hosts.first().id,
            from_public_ip='192.0.2.1',
            from_public_port=50000,
            from_internal_port=30001,
            to_public_ip='192.0.2.2',
            to_public_port=50001,
            to_internal_port=30000,
        )
        form = LinkAdminForm(instance=link, data=form_data)
        self.assertTrue(form.is_valid())
        link = form.save()
        self.assertIsNotNone(link)
        self.assertEqual(link.interfaceA.public_ip, '192.0.2.1')
        self.assertEqual(link.interfaceA.public_port, 50000)
        self.assertEqual(link.interfaceA.internal_port, 30001)
        self.assertEqual(link.interfaceB.public_ip, '192.0.2.2')
        self.assertEqual(link.interfaceB.public_port, 50001)
        self.assertEqual(link.interfaceB.internal_port, 30000)

        # Re-creating form with same data should result in no changes:
        edit_form = LinkAdminForm(instance=link, data=form_data)
        self.assertTrue(edit_form.is_valid(), edit_form.errors)
        self.assertFalse(edit_form.has_changed(), edit_form.changed_data)


class LinkAdminViewTests(WebTest):
    fixtures = ['testuser-admin', 'testtopo-ases']

    def test_create_link(self):
        """
        Check that adding a link succeeds
        """
        self.app.set_user(TESTUSER_ADMIN_EMAIL)

        link_create_page = self.app.get('/admin/scionlab/link/add/')
        form = link_create_page.form

        as_a = AS.objects.first()
        as_b = AS.objects.last()

        form.select('type', value=Link.PROVIDER)
        form.select('from_host', text=str(as_a.hosts.first()))
        form.select('to_host', text=str(as_b.hosts.first()))
        form.submit(value="Save").follow()  # redirect on success

        link = Link.objects.get()
        self.assertEqual(link.type, Link.PROVIDER)
