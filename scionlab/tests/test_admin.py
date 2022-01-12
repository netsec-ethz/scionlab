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
from scionlab.models.core import AS, Link
from scionlab.tests import utils
from scionlab.admin import ASCreationForm, LinkAdminForm
from scionlab.fixtures.testuser import TESTUSER_ADMIN_EMAIL
from scionlab.models.core import ISD


class ASAdminTests(TestCase):
    fixtures = ['testdata']

    def test_create_as_form(self):
        as_id = 'ff00:bad:f00d'
        isd_17_pk = ISD.objects.get(isd_id=17).pk
        form_data = {
            'isd': isd_17_pk,
            'as_id': as_id,
            'label': 'Test',
            'mtu': 1234,
            'public_ip': '192.0.2.11'
        }
        # This mimicks what ModelAdmin does to create the form:
        form_factory = modelform_factory(AS, form=ASCreationForm, fields='__all__')
        form = form_factory(data=form_data)
        self.assertTrue(form.is_valid(), form.errors.as_data())
        form.save()

        as_ = AS.objects.get(as_id=as_id)
        self.assertEqual(as_.as_id, as_id)
        self.assertEqual(as_.isd.isd_id, 17)
        self.assertEqual(as_.label, 'Test')
        self.assertEqual(as_.mtu, 1234)
        utils.check_as_keys(self, as_)


class LinkAdminFormTests(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        Link.objects.all().delete()

    def test_render_create(self):
        form = LinkAdminForm()
        self.assertIsNotNone(form.as_table())

    def test_create_link(self):
        ases = AS.objects.iterator()
        as_a = next(ases)
        as_b = next(ases)
        form_data = dict(
            type=Link.PROVIDER,
            active=True,
            mtu=2345,
            from_host=as_a.hosts.first().pk,
            from_public_port=50000,
            to_host=as_b.hosts.first().pk,
            to_public_port=50000,
        )
        form = LinkAdminForm(data=form_data)
        self.assertTrue(form.is_valid(), form.errors.as_data())
        link = form.save()
        self.assertIsNotNone(link)

        # Re-creating form with same data should result in no changes:
        edit_form = LinkAdminForm(instance=link, data=form_data)
        self.assertTrue(edit_form.is_valid(), edit_form.errors)
        self.assertFalse(edit_form.has_changed(), edit_form.changed_data)

    def test_create_link_error(self):
        # Create an illegal loop-back link
        as_a = AS.objects.first()
        form_data = dict(
            type=Link.PROVIDER,
            active=True,
            mtu=2345,
            from_host=as_a.hosts.first().pk,
            from_public_port=50000,
            to_host=as_a.hosts.first().pk,
            to_public_port=50000,
        )
        form = LinkAdminForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('Loop AS-link', str(form.errors['__all__'][0]))

    def test_render_edit(self):
        ases = AS.objects.iterator()
        as_a = next(ases)
        as_b = next(ases)
        link = Link.objects.create_from_ases(Link.PROVIDER, as_a, as_b)
        form = LinkAdminForm(instance=link)
        self.assertIsNotNone(form.as_table())

    def test_edit_link(self):
        ases = AS.objects.iterator()
        as_a = next(ases)
        as_b = next(ases)
        link = Link.objects.create_from_ases(Link.PROVIDER, as_a, as_b)

        form_data = dict(
            type=Link.PROVIDER,
            active=True,
            mtu=2345,
            from_host=as_a.hosts.first().pk,
            to_host=as_b.hosts.first().pk,
            from_public_ip='192.0.2.1',
            from_public_port=50000,
            to_public_ip='192.0.2.2',
            to_public_port=50001,
        )
        form = LinkAdminForm(instance=link, data=form_data)
        self.assertTrue(form.is_valid(), form.errors.as_data())
        link = form.save()
        self.assertIsNotNone(link)
        self.assertEqual(link.type, Link.PROVIDER)
        self.assertEqual(link.active, True)
        self.assertEqual(link.mtu, 2345)
        self.assertEqual(link.interfaceA.public_ip, '192.0.2.1')
        self.assertEqual(link.interfaceA.public_port, 50000)
        self.assertEqual(link.interfaceB.public_ip, '192.0.2.2')
        self.assertEqual(link.interfaceB.public_port, 50001)

        # Re-creating form with same data should result in no changes:
        edit_form = LinkAdminForm(instance=link, data=form_data)
        self.assertTrue(edit_form.is_valid(), edit_form.errors)
        self.assertFalse(edit_form.has_changed(), edit_form.changed_data)


class LinkAdminViewTests(WebTest):
    fixtures = ['testdata']

    def setUp(self):
        Link.objects.all().delete()

    def test_create_link(self):
        """
        Check that adding a link succeeds
        """
        self.app.set_user(TESTUSER_ADMIN_EMAIL)

        link_create_page = self.app.get('/admin/scionlab/link/add/')
        form = link_create_page.form

        ases = AS.objects.iterator()
        as_a = next(ases)
        as_b = next(ases)

        form.select('type', value=Link.PROVIDER)
        form.select('from_host', text=str(as_a.hosts.first()))
        form.select('to_host', text=str(as_b.hosts.first()))
        form.submit(value="Save").follow()  # redirect on success

        link = Link.objects.get()
        self.assertEqual(link.type, Link.PROVIDER)

        # The variable `ases` is a  generator and it will be closed on it being garbage collected.
        # Its contains a reference to a cursor, that will attempt to work with the DB (closing
        # the query), when being deallocated.
        # Avoid that by closing it beforehand:
        ases = None
